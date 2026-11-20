"""enforce: the scope-mode enforcement core (plan Task 7b, design §6).

Known apps are enforced IN KERNEL from scope rules rendered from live
process truth; unscoped connections hit the catch rule (kernel DENY +
LOG), the daemon tails the kernel log, attributes the connection with
the engine's own resolver, runs the same decide() chain, and a card
answer applies onward (design choice (b): the kernel already dropped it;
Allow makes retries succeed).
"""
from __future__ import annotations

import pytest

import appfw.enforce as enforce


# ------------------------------------------------------- scope snapshot


def test_snapshot_verdicts_from_app_rules_and_baseline(monkeypatch):
    procs = {
        11: ("/usr/bin/firefox", "app-gnome-firefox@100.scope",
            "user.slice/app-gnome-firefox@100.scope"),
        22: ("/usr/bin/curl", "app-curl@42.scope",
            "user-1000.slice/app-curl@42.scope"),
        33: ("/tmp/sneak", "app-sneak@7.scope",
            "user-1000.slice/app-sneak@7.scope"),
    }
    monkeypatch.setattr(enforce, "_scan_procs", lambda: procs)
    app_rules = {"/usr/bin/curl": "deny"}
    baseline_apps = {"/usr/bin/firefox"}
    snap = enforce.snapshot(app_rules=app_rules,
                            trusted={"/usr/bin/firefox"},
                            baseline_apps=baseline_apps)
    assert snap.scopes == {
        "app-gnome-firefox@100.scope": "allow",       # trusted/baseline app
        "app-curl@42.scope": "deny",                  # explicit app rule
        "app-sneak@7.scope": None,                    # unknown: catch path
    }


def test_snapshot_unscoped_process_becomes_catch_not_rule(monkeypatch):
    monkeypatch.setattr(enforce, "_scan_procs",
                        lambda: {5: ("/usr/bin/weird", "", "")})
    snap = enforce.snapshot(app_rules={}, trusted=set(), baseline_apps=set())
    assert snap.scopes == {}
    assert snap.unscoped_pids == [5]


def test_snapshot_dedupes_scope_conflicts_prefers_deny(monkeypatch):
    # two processes share one scope: a deny vote wins (fail-closed)
    monkeypatch.setattr(enforce, "_scan_procs", lambda: {
        1: ("/usr/bin/a", "app-shared@1.scope", "app-shared@1.scope"),
        2: ("/usr/bin/b", "app-shared@1.scope", "app-shared@1.scope"),
    })
    snap = enforce.snapshot(app_rules={"/usr/bin/a": "allow",
                                       "/usr/bin/b": "deny"},
                            trusted=set(), baseline_apps=set())
    assert snap.scopes == {"app-shared@1.scope": "deny"}


# ------------------------------------------------------------- rendering


def test_refresh_swaps_only_on_change(monkeypatch):
    swaps = []
    monkeypatch.setattr(enforce.ruleset, "swap_ruleset",
                        lambda text: swaps.append(text) or True)
    monkeypatch.setattr(enforce, "_scan_procs", lambda: {
        1: ("/usr/bin/firefox", "app-firefox.scope",
            "user.slice/user-1000.slice/user@1000.service"
            "/app.slice/app-firefox.scope")})
    state = enforce.refresh("/tmp/does-not-matter", app_rules={},
                            trusted={"/usr/bin/firefox"},
                            baseline_apps=set(), state=None,
                            mode="nft-scope")
    assert len(swaps) == 1
    again = enforce.refresh("/tmp/does-not-matter", app_rules={},
                            trusted={"/usr/bin/firefox"},
                            baseline_apps=set(), state=state)
    assert again.swapped is False
    assert len(swaps) == 1                      # unchanged: no churn


def test_rendered_ruleset_carries_snapshot(monkeypatch):
    monkeypatch.setattr(enforce, "_scan_procs", lambda: {
        1: ("/usr/bin/firefox", "app-firefox.scope",
            "user.slice/user-1000.slice/user@1000.service"
            "/app.slice/app-firefox.scope")})
    state = enforce.refresh("/tmp/does-not-matter", app_rules={},
                            trusted={"/usr/bin/firefox"},
                            baseline_apps=set(), state=None,
                            mode="nft-scope")
    assert 'socket cgroupv2 level 5 "app-firefox.scope"' in state.text


# ----------------------------------------------------------- log tailer


KERNEL_LINE = ('kernel: [12345.6] GW-DENY IN= OUT=eth0 SRC=10.0.0.5 '
                'DST=203.0.113.7 LEN=60 TOS=0.00 PREC=0x00 TTL=64 '
                'ID=0 DF PROTO=TCP SPT=51344 DPT=443 WINDOW=64240 ')


def test_tailer_parses_and_decides(monkeypatch):
    decided = []

    class FakePolicy:
        data_dir = "/tmp/anything"
        def feed_verdict(self, host): return (None, None)
        def anomaly_flags(self, path, host, port):
            return {"first_contact": True, "quiet_app": False,
                    "new_port_class": True}
        def baseline_verdict(self, path, host, port): return None
        def block_unknown(self): return False

    class FakeResolver:
        def resolve(self, conn):
            conn.process_path = "/usr/bin/mystery"
            conn.pid = 4242
            conn.app_name = "mystery"

    class NoAsk:
        pass

    verdict = enforce.evaluate_connection(
        KERNEL_LINE, policy=FakePolicy(), resolver=FakeResolver())
    assert verdict is not None
    app, dst, port, action = verdict[0], verdict[1], verdict[2], verdict[3]
    assert dst == "203.0.113.7" and port == 443
    assert action in ("allow", "deny")
    assert len(verdict) == 6          # duration + resolved path ride along (C3)
    decided.append(verdict)


def test_tailer_ignores_non_greywatch_lines():
    assert enforce.evaluate_connection(
        "kernel: [1.0] other subsystem noise", policy=None,
        resolver=None) is None
    assert enforce.evaluate_connection(
        "plain text without fields", policy=None, resolver=None) is None


def test_tailer_never_crashes_on_hostile_line():
    garbage = "GW-DENY SRC=999.999.999.999 DST=not-an-ip PROTO=TCP " \
              "SPT=abc DPT=99999"
    assert enforce.evaluate_connection(garbage, policy=None,
                                       resolver=None) is None


def test_catch_answer_always_writes_store_rule():
    """Review C3: "answer applies onward" — an Always answer on a
    catch-path card must become a stored process.path rule the next
    refresh renders (retry promise, not an un-drop)."""
    stored = {}

    class FakeStore:
        def add(self, rule):
            stored[rule.op_value] = rule

    verdict_flag = enforce.apply_catch_answer(
        ("mystery", "203.0.113.7", 443, "allow", "always"),
        process_path="/usr/bin/mystery", store=FakeStore())
    assert verdict_flag is True
    rule = stored["/usr/bin/mystery"]
    assert rule.op_kind == "process.path" and rule.action == "allow"
    assert rule.duration == "always"


def test_catch_answer_once_writes_no_rule():
    stored = {}

    class FakeStore:
        def add(self, rule):
            stored[rule.op_value] = rule

    verdict_flag = enforce.apply_catch_answer(
        ("mystery", "203.0.113.7", 443, "deny", "once"),
        process_path="/usr/bin/mystery", store=FakeStore())
    assert verdict_flag is False
    assert stored == {}


def test_catch_answer_without_path_writes_no_rule():
    stored = {}

    class FakeStore:
        def add(self, rule):
            stored[rule.op_value] = rule

    verdict_flag = enforce.apply_catch_answer(
        ("unknown", "203.0.113.7", 443, "allow", "always"),
        process_path="", store=FakeStore())
    assert verdict_flag is False
    assert stored == {}


def test_refresh_carries_full_cgroup_path_depth_through_render():
    """Re-review C (final): the live FULL cgroup path must reach the
    renderer — production real path shapes to level 5, not level 1."""
    import pathlib
    procs = {
        1: ("/usr/bin/firefox",
            "app-gnome-firefox@4123.scope",
            "user.slice/user-1000.slice/user@1000.service"
            "/app.slice/app-gnome-firefox@4123.scope"),
        2: ("/usr/bin/curl",
            "app-curl@9.scope",
            "system.slice/app-curl@9.scope"),
    }
    texts = []
    import appfw.ruleset as rs
    monkeypatched = rs.swap_ruleset
    orig = enforce.ruleset.swap_ruleset
    try:
        enforce.ruleset.swap_ruleset = lambda t: texts.append(t) or True
        snap = enforce.refresh("/tmp/x",
                               app_rules={"/usr/bin/curl": "deny"},
                               trusted={"/usr/bin/firefox"},
                               baseline_apps=set(), state=None,
                               procs=procs, mode="nft-scope")
    finally:
        enforce.ruleset.swap_ruleset = orig
    assert len(texts) == 1
    # desktop slice at depth 5 gets level 5 (the re-review's exact claim)
    assert 'socket cgroupv2 level 5 "app-gnome-firefox@4123.scope"' in texts[0]
    # system.slice member at depth 2 gets level 2
    assert 'socket cgroupv2 level 2 "app-curl@9.scope"' in texts[0]
    # and snapshot scope keys stay basename (the merge contract)
    assert snap.scopes == {
        "app-gnome-firefox@4123.scope": "allow",
        "app-curl@9.scope": "deny",      # explicit app rule (deny wins)
    }
