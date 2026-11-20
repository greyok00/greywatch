"""The desk wrap caps (visual sweep, 2026-11-04).

GTK4 measures a wrapped, un-ellipsized label's minimum width as its
single-line width. The scans desk's three longest sentences (the page
legend, the feed's foot, the dossier's empty state) therefore demanded
~1170-1290px each, the feed+dossier split reached 1736px, and an 1320px
window opened the page horizontally scrolled with both edges cut. The
caps keep the paint (wrap decides the lines) while killing the demand;
these pins hold the page's minimum under a 1280px window.
"""
import pathlib

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

LONG = "word " * 60

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_desk_feed_foot_and_empty_state_cannot_demand_full_line_width():
    from ui.desk import DeskFeed
    feed = DeskFeed(foot=LONG)
    assert feed._foot_w.get_max_width_chars() == 96
    feed.set_empty(LONG)
    assert feed._empty.get_max_width_chars() == 96


def test_desk_dossier_empty_lead_is_capped():
    from ui.desk import DeskDossier
    d = DeskDossier("DOSSIER")
    d.fill_empty(LONG)
    kid = d._detail.get_first_child()
    assert kid.get_max_width_chars() == 72


def test_scan_console_legend_is_capped():
    from ui.scanview import ScanConsole
    console = ScanConsole(
        ROOT / "data", on_explain=lambda *_a: None,
        on_scan=lambda *_a: None, on_show=lambda *_a: None,
        on_navigate=lambda *_a: None)
    assert console.legend.get_max_width_chars() == 96
    # the desk must ask for less than the narrowest window it runs in —
    # measured AFTER a real paint, the way the window shows it (2026-11-04:
    # the legend/foot/dossier caps took the painted desk from 1736px to a
    # width that fits both 1320px and 1280px windows)
    run = {"scan_id": "pin-1", "key": "full", "state": "done",
           "started_at": "2026-11-04T08:00:00+00:00",
           "ended_at": "2026-11-04T08:20:00+00:00", "note": "",
           "throttle": True,
           "scanners": {k: {"state": "done", "order": i,
                            "counter_label": "files", "count": 18234,
                            "current": None, "waiting_for": "",
                            "findings": 0, "warned": False,
                            "started_at": "2026-11-04T08:00:00+00:00",
                            "ended_at": "2026-11-04T08:19:00+00:00",
                            "detail": "", "exit_code": 0,
                            "duration_s": 60.0, "log": [], "log_offset": 0,
                            "unit": ""}
                        for i, k in enumerate(
                            ("clamav", "rkhunter", "lynis", "aide"))},
           "real_findings": 0, "routine_findings": 2,
           "sequence": ["clamav", "rkhunter", "lynis", "aide"],
           "updated": "2026-11-04T08:20:00+00:00"}
    console.paint(run, [
        {"scan_id": "pin-1", "tool": "clamav",
         "ts": "2026-11-04T08:19:00+00:00", "severity": "MEDIUM",
         "text": "A program file sat in the temp folders it sweeps",
         "routine": False},
        {"scan_id": "pin-1", "tool": "rkhunter",
         "ts": "2026-11-04T08:18:00+00:00", "severity": "LOW",
         "text": "Hidden file checks: none suspicious", "routine": True}])
    # a paint pass may need a full layout cycle for every row's label
    width = console.measure(Gtk.Orientation.HORIZONTAL, -1)[1]
    assert width < 1280, f"scans desk demands {width}px"