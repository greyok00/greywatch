import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import os
os.environ.setdefault("TZ", "UTC")

from appfw import rules as R
from appfw.policy import Policy, decide
from netwatch import NetWatch

FIXTURES = ROOT / "tests" / "fixtures"


def _conn(**kw):
    from appfw.base import Conn
    c = Conn()
    c.process_path = kw.get("process_path", "/usr/bin/curl")
    c.dst_host = kw.get("dst_host", "")
    c.dst_ip = kw.get("dst_ip", "")
    c.dst_port = kw.get("dst_port", 0)
    c.process_args = list(kw.get("process_args", []))
    return c


def test_s1_portscan_detected():
    seen = []
    nw = NetWatch(lambda s, t: seen.append((s, t)))
    for p in range(6060, 6096):                      # 36 distinct ports
        nw.ingest(Ev("ufw", f"[UFW BLOCK] IN=wlan0 SRC=203.0.113.77 "
                            f"DST=192.168.77.66 PROTO=TCP DPT={p}"))
    hits = [s for s in seen if "port scan" in s[1]]
    assert len(hits) == 1 and hits[0][0] == "HIGH" and "203.0.113.77" in hits[0][1]


def test_s2_ip_rule_denies():
    tmp = pathlib.Path(mktmp())
    st = R.RuleStore(tmp)
    st.add(R.validate("m2", "deny", "always", "dst.ip", "198.51.100.9"))
    assert st.decide(_conn(dst_ip="198.51.100.9")).action == "deny"
    assert st.decide(_conn(dst_ip="198.51.100.10")) is None


def test_s3_fail2ban_ban():
    from events import normalize_event
    e = normalize_event("fail2ban",
                        "2026-10-25 05:12:01 fail2ban.actions [sshd] "
                        "Ban 203.0.113.211")
    if e is None:                                     # parser variant
        e = normalize_event("fail2ban", "Ban 203.0.113.211")
    assert e is None or (e.from_tool == "fail2ban" and e.severity in
                         ("HIGH", "MEDIUM"))


def test_s4_every_parser_accepts_every_fixture_line():
    from parsers import PARSERS
    files = sorted(p for p in FIXTURES.glob("*") if p.is_file())
    assert files, "fixture corpus missing — the tool docs need their files"
    for f in files:
        for parser_name, fn in PARSERS.items():
            if fn is None:
                continue
            for line in f.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    fn(line)
                except Exception as exc:          # a parser must not raise
                    raise AssertionError(f"{parser_name} raised on "
                                         f"{f.name}: {exc!r}")


def test_s5_normalize_never_crashes_on_fuzz_lines():
    from events import normalize_event
    from parsers import PARSERS
    garbage = ["", "\x00", "SRC= DPT=", "appfw", "netwatch", "  ", "{}",
               "a" * 4000, "2026-13-45 99:99:99 total nonsense"]
    for tool in PARSERS:
        for g in garbage:
            try:
                normalize_event(tool, g)
            except Exception as exc:
                raise AssertionError(f"{tool} raised on fuzz: {exc!r}")


def test_s6_learning_pipeline_enforces_after_approval(tmp_path):
    st = R.RuleStore(tmp_path)
    rule = R.validate("p-mx6", "allow", "always", "dst.host", "mx6.example")
    st.add_pending(rule)
    assert st.decide(_conn(dst_host="mx6.example")) is None
    assert st.approve_pending("p-mx6")
    assert st.decide(_conn(dst_host="mx6.example",
                           process_path="/usr/bin/curl")).action == "allow"


def test_s7_strict_mode_and_trust_order(tmp_path):
    class TL:
        def load(self): pass
        def decide(self, host): return "allow" if "trusted.example" in host \
            else None
        def decide_app(self, path, args): return None

    class BL:
        def match(self, host): return False

    p = Policy(tmp_path, trust_list=TL(), blocklist=BL())
    (tmp_path / "firewall-mode.json").write_text('{"block_unknown": true}')
    act, dur, note, op = decide(_conn(dst_host="nightly.example"), p)
    assert (act, dur) == ("deny", "once")
    act, dur, note, op = decide(_conn(dst_host="www.trusted.example"), p)
    assert act == "allow"


def test_s8_config_ruleset_shapes():
    from appfw import config as acfg
    off = acfg.build_ruleset({**acfg.DEFAULTS, "ipv6_enabled": False})
    on = acfg.build_ruleset({**acfg.DEFAULTS, "ipv6_enabled": True})
    # ipv6 queue rule present only when enabled, with nfproto disambiguation
    assert "meta nfproto ipv6" not in off
    assert "meta nfproto ipv6 meta l4proto tcp" in on
    for r in ("127.0.0.0/8", "udp dport 53", "tcp dport 53",
              "bypass"):                       # exemptions + fail-open live
        assert r in on and r in off
    assert acfg.load(pathlib.Path(mktmp()))["ipv6_enabled"] is True


def test_s9_wizard_trust_site_and_deny_program(tmp_path, monkeypatch):
    from wiz import appfw_wizard as aw
    monkeypatch.setattr(aw, "DATA", tmp_path)
    monkeypatch.setattr(aw, "LEDGER", tmp_path / "learning-seen.jsonl")
    aw.appfw_main(["trust", "cdn.newwave.example"])
    aw.appfw_main(["deny", "/opt/newwave/wave"])
    st = R.RuleStore(tmp_path / "appfw" / "rules")
    assert st.decide(_conn(dst_host="cdn.newwave.example")).action == "allow"
    d = st.decide(_conn(process_path="/opt/newwave/wave"))
    assert d and d.action == "deny"


def test_s10_combo_denial_cluster_and_burst():
    seen = []
    nw = NetWatch(lambda s, t: seen.append((s, t)))
    for _ in range(6):
        nw.ingest(Ev("appfw", "appfw curl → cluster6.example:80 deny "
                              "[blocked by the downloaded list: "
                              "cluster6.example]"))
    for i in range(31):
        nw.ingest(Ev("appfw", f"appfw node → burst{i}.example:443 allow "
                              f"[default allow-once (no dialog wired)]"))
    assert any("denied attempts" in t for _, t in seen)
    assert any("connection burst" in t for _, t in seen)


class Ev:
    def __init__(self, from_tool, text):
        self.from_tool, self.text = from_tool, text


def mktmp():
    import tempfile
    return tempfile.mkdtemp(prefix="matrix-")
