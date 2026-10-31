import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
pytest.importorskip("gi")
import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ui.scanview import (  # noqa: E402
    SEVERITY_MEANING, ScanConsole, card_text, finding_path, read_history,
    when_label)


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
        "lynis": {"state": "queued", "counter_label": "tests completed",
                  "count": 0, "current": "", "findings": 0, "detail": "",
                  "waiting_for": "Antivirus"},
    },
    "real_findings": 2, "routine_findings": 12,
}


def test_card_text_speaks_plainly_and_names_failures():
    assert "Scanning" in card_text("clamav", LIVE)
    assert "1,284" in card_text("clamav", LIVE)
    assert "not installed" in card_text("rkhunter", LIVE)
    assert card_text("aide", LIVE) == ""
    assert card_text("clamav", None) == ""
    assert "starts after Antivirus" in card_text("lynis", LIVE)


def test_the_row_label_gets_short_words_that_fit():
    text = card_text("clamav", LIVE)
    assert "1,284 files" in text and "files scanned" not in text
    assert "2 findings" in text


def test_a_severity_word_carries_its_meaning():
    # The owner read a bare red "HIGH" and asked what it was for. Every
    # severity now has a sentence beside it in the legend and the dialog.
    assert SEVERITY_MEANING["HIGH"] == "needs your attention now"
    assert SEVERITY_MEANING["MEDIUM"] == "review when you have a moment"
    view = ScanConsole(pathlib.Path("/tmp/none"))
    assert "High findings need a decision" in view.legend.get_text()
    view.unparent()


def test_a_finding_names_the_file_it_can_act_on():
    assert finding_path(
        "Infected file: /tmp/eicar.com (Eicar-Signature)") == "/tmp/eicar.com"
    assert finding_path("Eicar-Sig /tmp/x.bin") == "/tmp/x.bin"
    assert finding_path(
        "Changed since the file-integrity baseline: /etc/passwd"
    ) == "/etc/passwd"
    assert finding_path("Warning: Hidden file found") is None


def test_rows_findings_and_routine_fold(tmp_path):
    (tmp_path / "scan-findings.jsonl").write_text("\n".join(json.dumps(r) for r in (
        {"scan_id": LIVE["scan_id"], "tool": "clamav", "severity": "HIGH",
         "text": "Infected file: /tmp/e", "routine": False},
        {"scan_id": LIVE["scan_id"], "tool": "rkhunter", "severity": "HIGH",
         "text": "Warning: Hidden file found: /etc/.x", "routine": True},
        {"scan_id": LIVE["scan_id"], "tool": "lynis", "severity": "HIGH",
         "text": "Warning: hidden", "routine": True},
    )) + "\n")
    view = ScanConsole(tmp_path)
    view.paint(LIVE, view._findings_for(LIVE))
    pump()
    first = view.findings_box.get_first_child()
    assert isinstance(first, Gtk.Button)
    assert first.has_css_class("gw-finding")
    assert "2 routine notices" in view.routine_expander.get_label()
    assert "2 finding" in view.headline.get_text()
    view.unparent()


def test_every_finding_is_a_button_that_opens_its_meaning():
    view = ScanConsole(pathlib.Path("/tmp/none"))
    row = view._finding_row({"tool": "clamav", "severity": "HIGH",
                             "text": "Infected file: /tmp/e"})
    assert isinstance(row, Gtk.Button)
    assert "needs your attention now" in row.get_tooltip_text()
    view.unparent()


def test_history_chips_read_as_a_local_moment():
    import datetime
    raw = "2026-10-31T02:56:00+00:00"
    want = datetime.datetime.fromisoformat(raw).astimezone().strftime(
        "%b %d, %H:%M")
    assert when_label(raw) == want
    assert "T" not in when_label(raw)
    assert when_label("not a date") == "not a date"[:16]
    assert when_label("") == ""


def test_history_lists_finished_scans_and_can_be_pinned(tmp_path):
    d = tmp_path / "scans"
    d.mkdir()
    (d / "20261030T070000-aaaa.json").write_text(json.dumps(
        {"scan_id": "20261030T070000-aaaa", "key": "yara-tmp-scan",
         "state": "done", "ended_at": "2026-10-30T07:00:10+00:00",
         "scanners": {}, "real_findings": 0, "routine_findings": 0}))
    assert len(read_history(tmp_path)) == 1
    view = ScanConsole(tmp_path)
    view.refresh()
    pump()
    assert view.history.get_first_child() is not None
    view.pin("20261030T070000-aaaa")
    assert view._pinned == "20261030T070000-aaaa"
    view.show_live()
    assert view._pinned is None
    view.unparent()


def test_the_findings_pane_shrinks_to_its_content(tmp_path):
    view = ScanConsole(tmp_path)
    scrollers = [w for w in _walk(view) if isinstance(w, Gtk.ScrolledWindow)]
    assert scrollers, "the findings list scrolls"
    assert scrollers[0].get_propagate_natural_height() is True
    assert scrollers[0].get_max_content_height() == 260
    view.unparent()


def test_past_six_findings_a_show_all_button_opens_every_row(tmp_path):
    # The pane shows about six rows; without a doorway the cut-off row read
    # as "only six findings" (owner, 2026-10-31).
    rows = [{"scan_id": "s1", "tool": "aide", "severity": "HIGH",
             "text": f"Changed since the file-integrity baseline: /f{i}",
             "routine": False} for i in range(9)]
    view = ScanConsole(tmp_path)
    win = Gtk.Window()
    win.set_child(view)
    view.paint({"scanners": {}}, rows)
    pump()
    assert view.more_btn.get_visible()
    assert view.more_btn.get_label() == "Show all 9 findings"
    view._show_all_findings()
    pump()
    dialogs = [w for w in Gtk.Window.list_toplevels()
               if isinstance(w, Gtk.Dialog)
               and w.get_title() == "All findings"]
    assert dialogs, "the dialog opens"
    scroller = next(w for w in _walk(dialogs[0].get_content_area())
                    if isinstance(w, Gtk.ScrolledWindow))
    box = next(w for w in _walk(scroller) if isinstance(w, Gtk.Box))
    count, child = 0, box.get_first_child()
    while child is not None:
        count += 1
        child = child.get_next_sibling()
    assert count == 9                     # every finding, not the six on top
    # Six or fewer: no button, the pane is the whole list.
    view.paint({"scanners": {}}, rows[:6])
    pump()
    assert not view.more_btn.get_visible()
    for d in dialogs:
        d.destroy()
    win.destroy()


def _walk(widget):
    child = widget.get_first_child()
    while child is not None:
        yield child
        yield from _walk(child)
        child = child.get_next_sibling()


def test_an_empty_state_explains_what_will_happen(tmp_path):
    view = ScanConsole(tmp_path)
    view.refresh()
    pump()
    assert "No scan yet" in view.headline.get_text()
    assert "Nothing to report yet" in view.findings_box.get_first_child(
    ).get_text()
    view.unparent()
