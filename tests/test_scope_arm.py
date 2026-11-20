"""Safe-by-default scope refresh + feed-set enforcement (review C2/C1).

refresh() must be a NO-OP unless the engine is explicitly in nft-scope
mode (arm switch) — dual-table operation on an armed machine is the
review's blackhole scenario. Rendered feed sets must carry DROP rules
that consume them (a set with no consumer inert by construction).
"""
from __future__ import annotations

import pytest

import appfw.enforce as enforce


class _FakeEngine:
    policy = None


def test_refresh_noop_by_default(monkeypatch):
    """No explicit nft-scope config ⇒ no swap, ever (safe default)."""
    called = []
    monkeypatch.setattr(enforce, "_scan_procs", lambda: {})
    monkeypatch.setattr(enforce.ruleset, "swap_ruleset",
                        lambda *a, **k: called.append(1) or True)
    snap = enforce.refresh("/tmp/x", app_rules={}, trusted=set(),
                           baseline_apps=set(), state=None, mode="nfqueue")
    assert called == []
    assert snap.swapped is False


def test_refresh_swaps_when_moded(monkeypatch):
    called = []
    monkeypatch.setattr(enforce, "_scan_procs", lambda: {
        1: ("/usr/bin/firefox", "app-firefox.scope",
            "user.slice/user-1000.slice/user@1000.service"
            "/app.slice/app-firefox.scope")})
    monkeypatch.setattr(enforce.ruleset, "swap_ruleset",
                        lambda text: called.append(text) or True)
    snap = enforce.refresh("/tmp/x", app_rules={}, trusted={"/usr/bin/firefox"},
                           baseline_apps=set(), state=None, mode="nft-scope")
    assert len(called) == 1
    assert snap.swapped is True
    assert 'socket cgroupv2 level 5 "app-firefox.scope"' in called[0]


def test_feed_set_consumers_in_rendered_text():
    text = enforce.ruleset.render_ruleset(
        [], {"firehol-l1": {"203.0.113.7"}}, catch=True)
    assert "ip daddr @gw_firehol-l1 drop" in text
    assert "set gw_firehol-l1 {" in text


def test_empty_sets_drop_nothing_but_still_valid():
    text = enforce.ruleset.render_ruleset([], {}, catch=True)
    assert "counter return" in text      # safe placeholder consumer
    assert "GW-DENY" in text


def test_greywatch2_deleted_on_stop_and_execstoppost():
    """Re-review I2: switch-off/mode-flip/restart must DELETE greywatch2 —
    a stale catch-drop table outliving 'off' is a silent outage."""
    import pathlib
    REPO = pathlib.Path(__file__).resolve().parent.parent
    engine_txt = (REPO / "appfw" / "engine.py").read_text()
    # the argv-form delete rides engine.stop's nft-scope branch
    assert '"delete", "table", "inet", "greywatch2"' in engine_txt, \
        "engine stop must remove the kernel-lane table when it owned one"
    unit = (REPO / "doc" / "greywatch.service").read_text()
    assert "greywatch2" in unit and "greywatch_appfw" in unit, \
        "ExecStopPost must clean both tables"


def test_kernel_lane_exempts_before_feed_drops():
    """Re-review I5(kernel): loopback/LAN/DNS accepts must ride INSIDE
    the feed-guard chain (priority -5) BEFORE the set drops — one
    hostile feed row must never blackhole the resolver or the LAN."""
    from appfw.ruleset import render_ruleset
    text = render_ruleset([], {"urlhaus": {"8.8.8.8"}}, catch=True)
    guard = text.split("chain feed-guard {")[1].split("chain egress")[0]
    accept_idx = guard.find("127.0.0.0/8 accept")
    drop_idx = guard.find("ip daddr @gw_urlhaus drop")
    assert 0 <= accept_idx < drop_idx, guard
    assert "ip6 daddr ::1 accept" in guard, "v6 loopback exempt too"


def test_egress_chain_also_exempts_v6_and_tcp53():
    """Re-review 3 I-1: the egress chain (priority 0, before catch)
    carries ::1 and TCP-53 too — not only feed-guard."""
    from appfw.ruleset import render_ruleset
    text = render_ruleset([], {"urlhaus": {"8.8.8.8"}}, catch=True)
    egress = text.split("chain egress {")[1].split("\n    }")[0]
    accept_idx = egress.find("127.0.0.0/8 accept")
    v6_idx = egress.find("ip6 daddr ::1 accept")
    tcp53_idx = egress.find("tcp dport 53 accept")
    catch_idx = egress.find("GW-DENY")
    assert 0 <= accept_idx < v6_idx < catch_idx, egress
    assert 0 <= accept_idx < tcp53_idx < catch_idx, egress


def test_engine_stop_teardown_keys_on_armed_mode_not_stale_config():
    """Re-review 3 I-2: a live flip nft-scope→nfqueue runs stop() with
    the file already 'nfqueue' — the teardown must key on self.mode."""
    import pathlib, sys
    REPO = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(REPO))
    import subprocess as sp
    import appfw.engine as eng_mod
    import appfw.ruleset as rs

    eng = eng_mod.Engine.__new__(eng_mod.Engine)
    eng.data_dir = pathlib.Path("/tmp/does-not-exist-gw")
    eng.mode = "nft-scope"                    # armed as kernel lane
    eng._stop = __import__("threading").Event()
    eng.running = False
    eng._proc = None
    eng._events_sock = None
    eng._events_path = pathlib.Path("/tmp/does-not-exist-gw/none.sock")
    eng._control_path = pathlib.Path("/tmp/does-not-exist-gw/none.ctl")
    eng._reader = None
    eng._reader_gen = 0
    eng.on_event = lambda *a, **k: None
    calls = []
    orig_run = rs._run
    rs._run = lambda cmd, timeout=0: calls.append(cmd) or True
    try:
        # config file absent → engine_mode() = nfqueue; stop must STILL delete
        eng.stop("flip")
    finally:
        rs._run = orig_run
    assert any("greywatch2" in c for c in calls), calls
