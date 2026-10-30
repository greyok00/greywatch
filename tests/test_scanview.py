import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
pytest.importorskip("gi")
import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
from gi.repository import GLib  # noqa: E402

from ui.scanview import ScanView, card_text, read_history  # noqa: E402


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        while ctx.pending():
            ctx.iteration(False)


LIVE = {
    "scan_id": "20261030T074500-a1b2", "key": "scan-all", "state": "running",
    "started_at": "2026-10-30T07:45:00+00:00", "ended_at": None, "note": "",
    "scanners": {
        "clamav": {"state": "running", "counter_label": "files scanned",
                   "count": 1284, "current": "/home/grey/x.bin",
                   "findings": 2, "detail": ""},
        "rkhunter": {"state": "failed", "counter_label": "checks completed",
                     "count": 3, "current": "", "findings": 0,
                     "detail": "not installed"},
        "lynis": {"state": "done", "counter_label": "tests completed",
                  "count": 120, "current": "", "findings": 0, "detail": ""},
    },
    "real_findings": 2, "routine_findings": 12,
}


def test_card_text_speaks_plainly_and_names_failures():
    assert "Scanning" in card_text("clamav", LIVE)
    assert "1,284" in card_text("clamav", LIVE)
    assert "not installed" in card_text("rkhunter", LIVE)
    assert card_text("aide", LIVE) == ""
    assert card_text("clamav", None) == ""
    done = {"scanners": {"lynis": {"state": "done", "count": 120,
                                   "counter_label": "tests completed",
                                   "findings": 0, "detail": ""}}}
    assert "clean" in card_text("lynis", done)


def test_rows_findings_and_routine_fold(tmp_path):
    (tmp_path / "scan-findings.jsonl").write_text("\n".join(json.dumps(r) for r in (
        {"scan_id": LIVE["scan_id"], "tool": "clamav", "severity": "HIGH",
         "text": "Infected file: /tmp/e", "routine": False},
        {"scan_id": LIVE["scan_id"], "tool": "rkhunter", "severity": "HIGH",
         "text": "Warning: Hidden file found: /etc/.x", "routine": True},
        {"scan_id": LIVE["scan_id"], "tool": "lynis", "severity": "HIGH",
         "text": "Warning: hidden", "routine": True},
    )) + "\n")
    view = ScanView(tmp_path)
    view.paint(LIVE, view._findings_for(LIVE))
    pump()
    assert "1,284" in view.row_widgets["clamav"]["count"].get_text()
    assert "not installed" in view.row_widgets["rkhunter"]["current"].get_text()
    assert view.findings_box.get_first_child() is not None
    assert "2 routine notices" in view.routine_expander.get_label()
    assert "2 finding" in view.headline.get_text()
    view.unparent()


def test_history_lists_finished_scans_and_can_be_pinned(tmp_path):
    d = tmp_path / "scans"
    d.mkdir()
    (d / "20261030T070000-aaaa.json").write_text(json.dumps(
        {"scan_id": "20261030T070000-aaaa", "key": "yara-tmp-scan",
         "state": "done", "ended_at": "2026-10-30T07:00:10+00:00",
         "scanners": {}, "real_findings": 0, "routine_findings": 0}))
    assert len(read_history(tmp_path)) == 1
    view = ScanView(tmp_path)
    view.refresh()
    pump()
    assert view.history.get_first_child() is not None
    view.pin("20261030T070000-aaaa")
    assert view._pinned == "20261030T070000-aaaa"
    view.show_live()
    assert view._pinned is None
    view.unparent()


def test_an_empty_state_explains_what_will_happen(tmp_path):
    view = ScanView(tmp_path)
    view.refresh()
    pump()
    assert "No scan yet" in view.headline.get_text()
    assert view.row_widgets["clamav"]["state"].get_text() == "—"
    view.unparent()
