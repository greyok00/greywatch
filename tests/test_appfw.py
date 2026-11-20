import json
import subprocess
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
    c.pid = kw.get("pid", 0)
    c.dst_host = kw.get("dst_host", "")
    c.dst_ip = kw.get("dst_ip", "")
    c.dst_port = kw.get("dst_port", 0)
    c.protocol = kw.get("protocol", "tcp")
    c.process_args = list(kw.get("process_args", []))
    return c


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
    st.add(R.validate("dup", "allow", "always", "process.path",
                      "/usr/bin/curl"))
    files = list((tmp_path / "rules").glob("*.json"))
    assert len(files) == 1
    st2 = R.RuleStore(tmp_path / "rules")
    st2.reload()
    assert len(st2.all_rules()) == 1
    st2.add(R.validate("ads", "deny", "always", "dst.host", "*.ads.example"))
    assert st2.decide(_conn(dst_host="www.ads.example")).action == "deny"
    assert st2.decide(_conn(process_path="/usr/bin/other",
                            dst_host="notads.example")) is None


def test_session_rules_die_with_the_engine(tmp_path):
    st = R.RuleStore(tmp_path / "rules")
    st.add(R.validate("s", "allow", "until restart", "process.path",
                      "/usr/bin/python3"))
    assert st.decide(_conn(process_path="/usr/bin/python3")).action == "allow"
    assert st.session_purge() == 1
    assert st.decide(_conn(process_path="/usr/bin/python3")) is None


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
    # Rebuild 2026-11-11: the trust lane is the PROGRAM lane; a named
    # site entry no longer auto-answers the packet chain (site rules
    # live in the dnsmasq feed lane; RuleStore site rules still fire).
    tl.apps = {"/usr/bin/curl": "allow"}
    policy = Policy(tmp_path, trust_list=tl, blocklist=FakeBlock(True))
    got = []
    act, dur, note, op = decide(_conn(dst_host="www.google.com"), policy,
                                ask=lambda s: got.append(s) or ("deny", "once"))
    assert (act, dur) == ("allow", "always") and op is None
    assert got == []                          # trusted program never asks
    act, dur, note, op = decide(
        _conn(dst_host="x.ads.example", process_path="/usr/bin/other"),
        policy, ask=lambda s: ("deny", "once"))
    assert (act, dur) == ("deny", "once")    # the blocklist still denies
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
    act, dur, note, op = decide(_conn(dst_host="example.org", dst_port=443,
                                      pid=1234), policy)
    assert (act, dur) == ("allow", "once")
    ledger = (tmp_path / "learning-seen.jsonl").read_text()
    assert "example.org" in ledger


def test_learning_expires_on_its_own(tmp_path):
    import time
    (tmp_path / "learning.json").write_text(
        json.dumps({"until": time.time() - 1}))
    policy = Policy(tmp_path)
    assert not policy.learning_active()
    act, dur, note, op = decide(_conn(dst_host="example.net", pid=1234),
                                policy)
    assert (act, dur) == ("allow", "once")   # expired learning grants nothing


def test_block_unknown_denies_untrusted_only(tmp_path):
    (tmp_path / "firewall-mode.json").write_text('{"block_unknown": true}')
    tl = FakeTrust(allow=("allowed.example",))
    policy = Policy(tmp_path, trust_list=tl)
    act, dur, *_ = decide(
        _conn(dst_host="new.example", process_path="/usr/bin/app"), policy)
    assert (act, dur) == ("deny", "once")
    ledger = (tmp_path / "learning-seen.jsonl").read_text()
    assert "new.example" in ledger
    # Rebuild 2026-11-11: the trusted lane is PROGRAM-level (what the
    # chain still honors); the site-lane auto-verdict is superseded by
    # the threat-level chain (site blocking lives in the dnsmasq lane).
    tl2 = FakeTrust(apps={"/usr/bin/app": "allow"})
    policy2 = Policy(tmp_path, trust_list=tl2)
    act2, dur2, note2, _op = decide(
        _conn(dst_host="www.allowed.example", process_path="/usr/bin/app"),
        policy2)
    assert (act2, dur2) == ("allow", "always")
    assert "trusted program" in note2.lower()


def test_ask_spec_carries_every_answer(tmp_path):
    policy = Policy(tmp_path)
    seen = {}
    def ask(spec):
        seen.update(spec)
        return ("allow", "always", None)
    # The card lane exists for ATTRIBUTED programs only (owner 2026-11-12:
    # an unattributable flow can never be answered by a human, so it must
    # never open a question). A resolved pid keeps this test on that lane.
    act, dur, note, op = decide(_conn(dst_host="8.8.8.8",
                                      process_path="/tmp/stealer.py",
                                      pid=1234),
                                policy, ask=ask)
    assert act == "allow" and op is None
    assert seen["id"].startswith("appfw:")
    ids = [o["id"] for o in seen["options"]]
    # The owner could always allow and never always block (owner report
    # 2026-10-28): both persistent answers survive the rebuild; the
    # site-lane options are superseded (rebuild design §6.1).
    assert {"deny-once", "allow-once", "allow-always", "block-always"} == set(ids)
    assert seen["path"] == "/tmp/stealer.py" and seen["host"] == "8.8.8.8"
    assert seen["level"] == "L3"             # new contact, clean feeds
    assert seen["score"] >= 55


def test_unknown_app_never_opens_a_card(tmp_path):
    """A ghost program never mints a card - but it is no longer condemned.

    The no-flood law (2026-11-10, reinforced 2026-11-12) is about the
    MEDIUM: a stack of "<unknown> wants internet access" asks no human a
    question a human could answer, so no card. That part stands.

    The old version of this test also pinned the VERDICT to deny, and that
    half was the bug (owner 2026-11-13, "it's blocking all my hotmail
    connections"): mail hosts failed attribution while attributed traffic
    sailed through, so the one thing that broke was the traffic the owner
    could neither see nor answer. A guard that changes the answer is not a
    guard - with no config readable, an answerable-by-nobody flow fails
    OPEN. Silence is the guard's job; lockout is not.
    """
    policy = Policy(tmp_path)             # no config: nothing configured
    called = []
    def ask(spec):
        called.append(spec)
        return ("allow", "always", None)   # a wrong allow must never ride
    act, dur, note, op = decide(_conn(dst_host="example.net",
                                      process_path=""),
                                policy, ask=ask)
    assert called == []                    # no card minted, ever
    assert (act, dur) == ("allow", "once"), (
        "an unattributable flow with no config must not be silently denied")
    assert "unattributable" in note.lower()
    assert op is None


def test_unknown_app_is_denied_when_the_owner_configured_deny(tmp_path):
    """The guard still honours a stated choice: deny-once means deny."""
    import json as _json
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "config.json").write_text(
        _json.dumps({"headless_ask": "deny-once"}))
    act, _dur, note, _op = decide(_conn(dst_host="example.net",
                                        process_path=""),
                                  Policy(tmp_path), ask=None)
    assert act == "deny", "a configured deny-once must still deny"
    assert "deny-once" in note


def test_attributed_app_still_opens_a_card_at_l3(tmp_path):
    # The flood guard fires on identity-doubt only: a real program with a
    # resolved pid still gets its full-analysis card (the lane the owner
    # does want to see, because they can actually answer it).
    policy = Policy(tmp_path)
    seen = {}
    def ask(spec):
        seen.update(spec)
        return ("deny", "once", None)
    decide(_conn(dst_host="example.net", process_path="/tmp/stealer.py",
                 pid=999), policy, ask=ask)
    assert seen.get("level") == "L3"
    assert seen.get("id", "").startswith("appfw:")
    ids = [o["id"] for o in seen.get("options", [])]
    assert "deny-once" in ids and "allow-once" in ids


def test_registry_lookup_never_prompts(tmp_path):
    # The identity card runs whois; that socket lives for milliseconds, so
    # attribution often misses it and the prompt would say "<unknown> wants
    # access" and auto-deny — which is exactly what killed the card live
    # after the 2026-10-28 install (event: deny <unknown> → …:43).
    policy = Policy(tmp_path)
    got = []
    act, dur, note, op = decide(
        _conn(dst_ip="193.0.6.135", dst_port=43), policy,
        ask=lambda s: got.append(s) or ("deny", "once"))
    assert (act, dur) == ("allow", "once")
    assert "registry lookup" in note and not got


def test_fail_open_on_chain_error(tmp_path):
    class Boom:
        def load(self): raise RuntimeError("boom")
        def decide(self, host): raise RuntimeError("boom")
        def match(self, host): raise RuntimeError("boom")   # error ≠ verdict
    policy = Policy(tmp_path, trust_list=Boom(), blocklist=Boom())
    # attributable fixture (pid set): the fail-open contract is about CHAIN
    # errors, not the unattributable flood guard, which fires earlier.
    act, dur, note, op = decide(_conn(dst_host="whatever.example",
                                      pid=1234), policy)
    assert (act, dur) == ("allow", "once")   # fail-open, never a lockout


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
                                                        monkeypatch,
                                                        assume_kernel_modules):
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


def test_operator_site_block_still_blocks_silently(tmp_path):
    """Review I8: until the dnsmasq lane installs, an operator's site
    block entry keeps a deterministic packet-layer effect: silent deny,
    never a card (sites never interrogate — gate 3)."""
    try:
        from core.settings import TrustList
    except ImportError:
        import pytest
        pytest.skip("the v4 settings page retired the v3 trust list")
    tl = TrustList(tmp_path / "trust.json")   # isolated: never the live file
    tl.add("blocked.example", "block")
    policy = Policy(tmp_path, trust_list=tl)
    policy._site_blocks = tl        # same wiring the daemon installs (I8)
    spy_specs = []
    act, dur, note, op = decide(_conn(dst_host="deep.sub.blocked.example",
                                      process_path="/usr/bin/curl"),
                                policy,
                                ask=lambda s: spy_specs.append(s) or
                                ("allow", "once"))
    assert (act, dur) == ("deny", "once")
    assert spy_specs == []            # sites never ask
    assert "site block" in note.lower()
    # a suffix of the block entry matches subdomains (same rule as the lists)
    act2, *_ = decide(_conn(dst_host="blocked.example",
                            process_path="/usr/bin/curl", pid=555), policy)
    assert act2 == "deny"
    # unrelated host unaffected
    act3, *_ = decide(_conn(dst_host="other.example",
                            process_path="/usr/bin/curl", pid=555), policy)
    assert act3 == "allow"


def test_policy_reads_the_canonical_appfw_config_path(tmp_path):
    """The bug that blocked the owner's mail (2026-11-13).

    The config lives at <data>/appfw/config.json — what appfw.config writes,
    what the wizard writes, what the daemon's _headless_ask reads. Policy
    looked at <data>/config.json, which does not exist on a real install, so
    every config read fell through to its default. The owner set
    headless_ask=allow-once; the chain read deny-once and refused every
    unattributed first contact, mail hosts included, while the UI showed the
    right setting the whole time.
    """
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "config.json").write_text(
        '{"headless_ask": "allow-once"}')
    pol = Policy(tmp_path)
    assert pol.configured_headless_ask() == "allow-once", (
        "Policy ignored <data>/appfw/config.json")
    assert pol.headless_ask() == "allow-once"
    assert pol._fallback_answer() == "allow"


def test_legacy_flat_config_still_honoured(tmp_path):
    """An older install that wrote <data>/config.json must not break."""
    (tmp_path / "config.json").write_text('{"headless_ask": "deny-once"}')
    pol = Policy(tmp_path)
    assert pol.headless_ask() == "deny-once"


def test_canonical_beats_legacy_when_both_exist(tmp_path):
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "config.json").write_text(
        '{"headless_ask": "allow-once"}')
    (tmp_path / "config.json").write_text('{"headless_ask": "deny-once"}')
    assert Policy(tmp_path).headless_ask() == "allow-once"


def test_unattributed_mail_connection_is_allowed_under_allow_once(tmp_path):
    """End to end, the exact shape from the owner's ledger:
    '<unknown> -> 40.104.2.18:443' with allow-once configured."""
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "config.json").write_text(
        '{"headless_ask": "allow-once"}')
    pol = Policy(tmp_path)
    act, dur, note, _ = decide(_conn(dst_ip="40.104.2.18", dst_port=443,
                                     process_path="", pid=0),
                               pol, store=None, ask=None)
    assert (act, dur) == ("allow", "once"), (
        f"owner's mail connection was {act}: {note}")
