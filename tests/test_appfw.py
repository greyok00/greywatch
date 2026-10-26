"""tests/test_appfw.py — the app firewall's own battery (rebuilt, in-suite)."""
import json
import subprocess
import socket
import struct
import pathlib

import sys
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

from appfw.base import Conn, LOCAL_SERVICE_PORTS, is_local_service
from appfw import rules as R
from appfw.policy import Policy, decide
from appfw.resolve import Resolver
from appfw.engine import Engine, read_enabled, write_enabled


def _conn(**kw):
    c = Conn()
    c.process_path = kw.get("process_path", "/usr/bin/curl")
    c.dst_host = kw.get("dst_host", "")
    c.dst_ip = kw.get("dst_ip", "")
    c.dst_port = kw.get("dst_port", 0)
    c.protocol = kw.get("protocol", "tcp")
    c.process_args = list(kw.get("process_args", []))
    return c


# ── rules ────────────────────────────────────────────────────────────────
def test_rule_validation_refuses_empty_operator():
    with pytest.raises(R.ValidationError):
        R.validate("x", "allow", "always", "process.path", "")
    with pytest.raises(R.ValidationError):
        R.validate("x", "nope", "always", "process.path", "/bin/x")
    with pytest.raises(R.ValidationError):
        R.validate("x", "allow", "always", "dst.port", "99999")
    rule = R.validate("appfw-app-curl", "deny", "always", "process.path",
                      "/usr/bin/curl")
    assert rule.op_kind == "process.path" and rule.created > 0


def test_store_persists_always_and_dedupes(tmp_path):
    st = R.RuleStore(tmp_path / "rules")
    st.add(R.rule_from_decision(
        _conn(process_path="/usr/bin/curl", dst_host="example.net"),
        "deny", "always"))
    # same operator+value → dedupe, even under a different name
    st.add(R.validate("dup", "allow", "always", "process.path",
                      "/usr/bin/curl"))
    files = list((tmp_path / "rules").glob("*.json"))
    assert len(files) == 1
    st2 = R.RuleStore(tmp_path / "rules")
    st2.reload()
    assert len(st2.all_rules()) == 1
    # a site rule with a wildcard host matches subdomains, not lookalikes
    st2.add(R.validate("ads", "deny", "always", "dst.host", "*.ads.example"))
    assert st2.decide(_conn(dst_host="www.ads.example")).action == "deny"
    # a look-alike host, from a NON-curl program: neither rule matches
    assert st2.decide(_conn(process_path="/usr/bin/other",
                            dst_host="notads.example")) is None


def test_session_rules_die_with_the_engine(tmp_path):
    st = R.RuleStore(tmp_path / "rules")
    st.add(R.validate("s", "allow", "until restart", "process.path",
                      "/usr/bin/python3"))
    assert st.decide(_conn(process_path="/usr/bin/python3")).action == "allow"
    assert st.session_purge() == 1
    assert st.decide(_conn(process_path="/usr/bin/python3")) is None


# ── policy chain ─────────────────────────────────────────────────────────
class FakeTrust:
    def __init__(self, allow=(), block=(), apps=None):
        self.allow, self.block = set(allow), set(block)
        self.apps = dict(apps or {})
        self.loads = 0
    def load(self):
        self.loads += 1
    def decide(self, host):
        if any(h in host for h in self.block):
            return "block"
        if any(h in host for h in self.allow):
            return "allow"
        return None
    def decide_app(self, path, args):
        return self.apps.get(path)


class FakeBlock:
    def __init__(self, everything=False):
        self.everything = everything
    def match(self, host):
        return self.everything


def test_trust_wins_over_blocklist_and_never_asks(tmp_path):
    tl = FakeTrust(allow=("google.com",), block=("ads.example",))
    policy = Policy(tmp_path, trust_list=tl, blocklist=FakeBlock(True))
    got = []
    act, dur, note, op = decide(_conn(dst_host="www.google.com"), policy,
                                ask=lambda s: got.append(s) or ("deny", "once"))
    assert (act, dur) == ("allow", "always") and op == "www.google.com"
    act, dur, note, op = decide(_conn(dst_host="x.ads.example"), policy)
    assert (act, dur) == ("deny", "always")
    assert not got


def test_trusted_program_beats_block_unknown(tmp_path):
    (tmp_path / "firewall-mode.json").write_text('{"block_unknown": true}')
    tl = FakeTrust(apps={"/usr/local/bin/ollama": "allow"})
    policy = Policy(tmp_path, trust_list=tl, blocklist=FakeBlock(True))
    act, dur, note, op = decide(
        _conn(process_path="/usr/local/bin/ollama",
              dst_host="example.net", dst_port=443), policy)
    assert (act, dur) == ("allow", "always")


def test_local_services_pass_even_in_block_unknown(tmp_path):
    (tmp_path / "firewall-mode.json").write_text('{"block_unknown": true}')
    policy = Policy(tmp_path, blocklist=FakeBlock(False))
    got = []
    for port in sorted(LOCAL_SERVICE_PORTS):
        c = _conn(dst_ip="127.0.0.1", dst_port=port)
        assert is_local_service(c)
        act, dur, *_ = decide(c, policy,
                              ask=lambda s: got.append(s) or ("deny", "once"))
        assert (act, dur) == ("allow", "once"), port
    assert not got
    c2 = _conn(dst_ip="203.0.113.9", dst_port=8888)   # remote: never local
    assert not is_local_service(c2)
    assert decide(c2, policy,
                  ask=lambda s: ("deny", "once"))[0] == "deny"


def test_learning_records_but_never_grants_permanent(tmp_path):
    import time
    (tmp_path / "learning.json").write_text(
        json.dumps({"until": time.time() + 60}))
    policy = Policy(tmp_path)
    act, dur, note, op = decide(_conn(dst_host="example.org", dst_port=443),
                                policy)
    assert (act, dur) == ("allow", "once")
    ledger = (tmp_path / "learning-seen.jsonl").read_text()
    assert "example.org" in ledger


def test_learning_expires_on_its_own(tmp_path):
    import time
    (tmp_path / "learning.json").write_text(
        json.dumps({"until": time.time() - 1}))
    policy = Policy(tmp_path)
    assert not policy.learning_active()
    act, dur, note, op = decide(_conn(dst_host="example.net"), policy)
    assert (act, dur) == ("allow", "once")   # expired learning grants nothing


def test_block_unknown_denies_untrusted_only(tmp_path):
    (tmp_path / "firewall-mode.json").write_text('{"block_unknown": true}')
    tl = FakeTrust(allow=("allowed.example",))
    policy = Policy(tmp_path, trust_list=tl)
    act, dur, *_ = decide(_conn(dst_host="new.example"), policy)
    assert (act, dur) == ("deny", "once")
    ledger = (tmp_path / "learning-seen.jsonl").read_text()
    assert "new.example" in ledger
    act, dur, *_ = decide(_conn(dst_host="www.allowed.example"), policy)
    assert (act, dur) == ("allow", "always")


def test_ask_spec_carries_the_five_options(tmp_path):
    policy = Policy(tmp_path)
    seen = {}
    def ask(spec):
        seen.update(spec)
        return ("allow", "always", "example.net")
    act, dur, note, op = decide(_conn(dst_host="example.net",
                                      process_path="/usr/bin/curl"),
                                policy, ask=ask)
    assert act == "allow" and op == "example.net"
    assert seen["id"].startswith("appfw:") and len(seen["options"]) == 5


def test_fail_open_on_chain_error(tmp_path):
    class Boom:
        def load(self): raise RuntimeError("boom")
        def decide(self, host): raise RuntimeError("boom")
        def match(self, host): raise RuntimeError("boom")   # error ≠ verdict
    policy = Policy(tmp_path, trust_list=Boom(), blocklist=Boom())
    act, dur, note, op = decide(_conn(dst_host="whatever.example"), policy)
    assert (act, dur) == ("allow", "once")   # fail-open, never a lockout


# ── resolve (fake /proc tree) ────────────────────────────────────────────
def _fake_proc(tmp_path):
    netdir = tmp_path / "net"
    netdir.mkdir(parents=True)
    (netdir / "tcp").write_text(
        "  sl local_address rem_address st tx_rx tr retrnsmt uid timeout inode\n"
        "  0: 0100007F:3039 08080808:01BB 01 00000000:00000000 00:00000000"
        " 0000     0        0 12345 1 \n")
    pid = tmp_path / "999"
    (pid / "fd").mkdir(parents=True)
    (pid / "fd" / "1").symlink_to("socket:[12345]")
    (pid / "exe").symlink_to("/usr/bin/curl")
    (pid / "cmdline").write_bytes(b"/usr/bin/curl\0https://example.net\0")
    return tmp_path


def test_resolver_fills_pid_and_path(tmp_path):
    root = _fake_proc(tmp_path)
    r = Resolver(str(root))
    c = Conn(protocol="tcp", src_ip="127.0.0.1", src_port=0x3039,
             dst_ip="8.8.8.8", dst_port=0x01BB)
    r.resolve(c)
    assert c.pid == 999
    assert c.process_path.endswith("curl")
    assert "https://example.net" in c.process_args


def test_resolver_cache_survives_until_ttl(tmp_path):
    root = _fake_proc(tmp_path)
    r = Resolver(str(root))
    c = Conn(protocol="tcp", src_ip="127.0.0.1", src_port=0x3039,
             dst_ip="8.8.8.8", dst_port=0x01BB)
    r.resolve(c)
    (root / "net" / "tcp").unlink()      # proc tree vanishes mid-connection
    c2 = Conn(protocol="tcp", src_ip="127.0.0.1", src_port=0x3039,
              dst_ip="8.8.8.8", dst_port=0x01BB)
    r.resolve(c2)
    assert c2.pid == 999                 # served from the cache


# ── engine ───────────────────────────────────────────────────────────────

class _FakeSub:
    DEVNULL = -3
    STDOUT = -2
    @staticmethod
    def run(args, **k):                     # nft install/remove: rc 0
        return type("R", (), {"returncode": 0})()

    @staticmethod
    def Popen(argv, env=None, **k):
        return subprocess.Popen([sys.executable,
                                 str(ROOT / "tests" / "fake_worker.py"), "2"],
                                env=env, **k)


def _worker_engine(tmp_path, monkeypatch, events):
    fake = ROOT / "tests" / "fake_worker.py"
    fake.chmod(0o755)
    monkeypatch.setattr("appfw.engine.ENGINE_BIN", fake)
    monkeypatch.setattr("appfw.engine.subprocess", _FakeSub())
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "enable.json").write_text(
        json.dumps({"enabled": True}) + "\n")
    eng = Engine(tmp_path, on_event=events.append, socket_dir=str(tmp_path))
    return eng


def test_engine_refuses_to_arm_without_the_owner_switch(tmp_path):
    assert not Engine(tmp_path, socket_dir=str(tmp_path)).start()


def test_engine_cycles_cleanly_with_the_worker_transport(tmp_path,
                                                        monkeypatch):
    events = []
    eng = _worker_engine(tmp_path, monkeypatch, events)
    for _ in range(2):                      # stop→start stays honest
        assert eng.start() and eng.running
        eng.stop()
        assert not eng.running
    assert read_enabled(tmp_path)           # the owner switch is untouched


def test_enable_file_corrupt_counts_as_off(tmp_path):
    write_enabled(tmp_path, True)
    assert read_enabled(tmp_path)
    (tmp_path / "appfw" / "enable.json").write_text("{not json}")
    assert not read_enabled(tmp_path)       # never silently armed
