"""install.sh --check carries the design's acceptance gates (Task 8).

String-contract tests: the self-test must assert the §8 gates in
machine-readable form BEFORE anything ships (consolidated-build law).
"""
from __future__ import annotations

import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
INSTALL = (REPO / "install.sh").read_text()


def test_check_gates_function_exists_and_is_wired():
    assert "check_gates()" in INSTALL
    assert "check_gates" in INSTALL.split("do_check()")[1]


def test_gate_scan_caps_present_in_staged_and_live_paths():
    # staged: cap drop-in confs are staged AND checked
    assert "clamav-daemon-limits.conf" in INSTALL
    assert "limits.conf" in INSTALL
    # live: the drop-in path is verified to exist
    assert "clamav-daemon.service.d/limits.conf" in INSTALL
    assert "freshclam.service.d/limits.conf" in INSTALL


def test_gate_boot_timer_parse_present():
    assert "greywatch-feeds.timer" in INSTALL
    assert "OnBootSec" in INSTALL


def test_gate_watchdog_and_feeds_timers_enabled():
    assert INSTALL.count("greywatch-watchdog.timer") >= 2   # enable + check
    assert INSTALL.count("greywatch-feeds.timer") >= 2


def test_gate_loopback_exemption_is_ordered_before_feed_lane():
    policy_path = REPO / "appfw" / "policy.py"
    text = policy_path.read_text()
    loopback = text.find("is_local_service(conn")
    feeds_lane = text.find("policy.feed_verdict(host)")
    assert 0 < loopback < feeds_lane, "local-service exemption must precede feeds"


def test_gate_dnsmasq_conf_installed_and_checked():
    """Review I3: 'every browser identically protected' must be a
    machine-checked gate, not an aspiration."""
    assert "webguard-blocklist.conf" in INSTALL
    assert "dnsmasq" in INSTALL.lower()
    assert "gate" in INSTALL and "dnsmasq" in INSTALL.split("check_gates")[1]


def test_gate_mode_switch_is_the_one_authority():
    """Review C2/I3: the arm-switch honor gate — check_gates must verify
    exactly one verdict lane config, and the daemon gates the kernel
    lane behind config.engine_mode."""
    assert "engine_mode" in (REPO / "greywatch_daemon.py").read_text()
    daemon_txt = (REPO / "appfw" / "engine.py").read_text()
    assert "_queue_lane_mode" in daemon_txt


def test_gate_single_dedupe_clock():
    """Review I3: one repeat-window clock — the ask gate's window is
    the only bombarding-control, and the catch lane's grouped rows use
    it via _notice dedupe (no second clock invented)."""
    assert INSTALL.count("ask_repeat_window_sec") <= 1
