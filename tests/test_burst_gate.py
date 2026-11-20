import json

import pytest

from eventgate import BurstGate, host_from_text


class Clock:
    def __init__(self, t=0.0):
        self.t = t
    def __call__(self):
        return self.t
    def advance(self, s):
        self.t += s


def _ev(text="deny <unknown> → 10.0.0.1:443", tool="appfw", **kw):
    return {"from_tool": tool, "severity": "MEDIUM", "text": text,
            "nist_func": "PROTECT", "nist_control": [], "cves": [],
            "interaction": None, **kw}


def test_first_deny_admits_and_repeats_suppress():
    g = BurstGate(clock=Clock(), host=_host_of, max_admit=1)
    assert g.admit(_ev()) is True
    for _ in range(500):
        assert g.admit(_ev()) is False


def _host_of(ev):
    return "10.0.0.1"


def test_window_close_emits_one_honest_collapse_line():
    c = Clock()
    g = BurstGate(clock=c, host=_host_of, window=60.0, max_admit=3)
    g.admit(_ev())
    n = 0
    for i in range(497):
        if g.admit(_ev()):
            n += 1
    assert n == 2                    # max_admit total inside the window
    c.advance(61.0)
    collapsed = g.admit(_ev())
    assert collapsed is True         # new window admits a fresh line
    lines = g.collapse_lines()
    assert len(lines) == 1
    ev = json.loads(lines[0])
    assert ev["from_tool"] == "appfw"
    assert "suppressed" in ev["text"] and "495" in ev["text"]  # 498 - 3 admitted


def test_distinct_hosts_are_never_gated_against_each_other():
    g = BurstGate(clock=Clock(), host=_host_of, max_admit=1)
    assert g.admit(_ev("deny x → 10.0.0.1:1")) is True
    for _ in range(10):
        assert g.admit(_ev("deny x → 10.0.0.2:2")) is False  # same host fn
    g2 = BurstGate(clock=Clock(), host=lambda ev: str(abs(hash(ev["text"])) % 7))
    assert g2.admit(_ev("deny a")) is True
    assert g2.admit(_ev("deny b")) is True


def test_allows_and_criticals_never_suppressed():
    c = Clock()
    g = BurstGate(clock=c, host=_host_of, max_admit=1)
    g.admit(_ev("deny prime", severity="LOW"))   # window opens on the deny
    for _ in range(200):
        assert g.admit(_ev("allow <curl> → 10.0.0.9:443")) is True
        assert g.admit(_ev("BLOCK high 10.0.0.8", severity="HIGH")) is True
        assert g.admit(_ev("deny mid", severity="LOW")) is False


def test_malformed_lines_gate_by_tool():
    c = Clock()
    g = BurstGate(clock=c, host=lambda ev: "malformed", max_admit=1,
                  suppression="all")
    g.admit(_ev("junk line 1", tool="appfw"))
    out = []
    for i in range(99):
        if g.admit(_ev(f"junk line {i}", tool="appfw")):
            out.append(i)
    assert out == []
    assert g.admit(_ev("junk", tool="auditd")) is True   # other tool: own key
    c.advance(61.0)
    assert g.admit(_ev("junk again", tool="appfw")) is True


def test_many_distinct_hosts_cannot_multiply_the_per_key_share():
    """The hole the bubble cap had, in the feed: a port scan touches a
    DIFFERENT host for every connection, so per-(tool,host) admits 3 each.

    Measured on the live 11-12 ledger: the per-key rule admitted 4,826 of
    11,483 storm rows. The window is what a human reads, so the window is
    what gets bounded.
    """
    g = BurstGate(clock=Clock(), host=host_from_text, window=60.0,
                  max_admit=3, global_admit=60)
    admitted = 0
    for i in range(2000):
        ev = _ev(f"deny x → 198.51.{(i // 256) % 256}.{i % 256}:443")
        if g.admit(ev):
            admitted += 1
    assert admitted <= 60, (
        f"2000 distinct hosts admitted {admitted} rows; the window budget "
        f"is 60")


def test_the_global_cap_still_tells_the_human_the_scale():
    """A cap that goes silent is the failure the cap exists to prevent."""
    c = Clock()
    g = BurstGate(clock=c, host=host_from_text, window=60.0,
                  max_admit=3, global_admit=5)
    for i in range(100):
        g.admit(_ev(f"deny x → 10.9.0.{i}:443"))
    c.advance(61.0)
    g.admit(_ev("deny x → 10.9.9.9:443"))
    lines = g.collapse_lines()
    assert lines, "the window closed over a folded pile and said nothing"
    said = " ".join(json.loads(l)["text"] for l in lines)
    assert "suppressed" in said
