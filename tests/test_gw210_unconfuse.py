"""The unconfuse wave: every log list says how to resolve a row.

Owner directive, 2026-11-06/07: the log lists (tools, scans, the
hunter, and the mega Activity Log) each carry their own list and their
own fix affordances, with no visible way to get from one to the page
that owns the event. Every list now says "click a row to resolve it",
and every surface carries one quiet "Open the Activity Log" link and
one quiet jump to the page that manages that lane. This file pins the
affordances at every surface.
"""
import json
import pathlib
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("gi")
import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ui.scanview import ScanConsole  # noqa: E402
from ui.toolsdesk import ToolsDesk  # noqa: E402

RECORD_LABEL = "Open the Activity Log"
JUMP_TOOLTIP = "The page that manages this kind of event."


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        while ctx.iteration(False):
            pass


def _walk(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        out.append(c)
        out.extend(_walk(c))
        c = c.get_next_sibling()
    return out


def _button_by_label(root, label):
    for w in _walk(root):
        if isinstance(w, Gtk.Button) and str(w.get_label() or "") == label:
            return w
    return None


def _registry():
    return [{"name": "clamav", "unit": "clamav.service"}]


def _fact(name, scan_state=None):
    return {"name": name, "state": "GREEN", "paused": False,
            "quiet": False, "unit": f"{name}.service", "installed": True,
            "label": name.upper(), "event": None,
            "last_scan": ({"state": scan_state, "detail": "stopped",
                           "exit_code": 137, "started_at":
                           "2026-11-06T07:00:00+00:00"}
                          if scan_state else {}),
            "live_scan": None}


# ---- Scans console ---------------------------------------------------------
class TestScanConsoleRecordLink:
    def test_a_record_link_leads_the_console(self, tmp_path):
        view = ScanConsole(tmp_path, on_navigate=lambda _k: None)
        btn = _button_by_label(view, RECORD_LABEL)
        assert btn is not None
        assert btn.get_tooltip_text() == "Every scan event, with a fix card per row."
        view.unparent()

    def test_pressing_it_walks_to_the_activity_log(self, tmp_path):
        shown = []
        view = ScanConsole(tmp_path, on_navigate=shown.append)
        _button_by_label(view, RECORD_LABEL).emit("clicked")
        pump()
        assert shown == ["auditlog"]
        view.unparent()


# ---- Hunter ----------------------------------------------------------------
class TestHunterRecordLink:
    def test_a_record_link_lives_on_the_hunter(self, tmp_path):
        from ui.hunterview import HunterPanel
        view = HunterPanel(tmp_path, on_navigate=lambda _k: None)
        btn = _button_by_label(view, RECORD_LABEL)
        assert btn is not None
        assert btn.get_tooltip_text() == "Every hunter event, with a fix card per row."
        view.unparent()

    def test_pressing_it_walks_to_the_activity_log(self, tmp_path):
        from ui.hunterview import HunterPanel
        shown = []
        view = HunterPanel(tmp_path, on_navigate=shown.append)
        _button_by_label(view, RECORD_LABEL).emit("clicked")
        pump()
        assert shown == ["auditlog"]
        view.unparent()


# ---- Tools desk ------------------------------------------------------------
class TestToolsDeskRecordLink:
    def test_the_record_link_says_where_it_goes(self):
        shown = []
        desk = ToolsDesk(_registry(), on_navigate=shown.append,
                         on_select=None, on_refresh=None,
                         on_filter=None, on_details=None, on_control=None)
        desk.selected = "clamav"
        desk.paint({"clamav": _fact("clamav")}, [],
                   "2026-11-06T07:00:00+00:00")
        desk.fill_dossier("clamav")
        btn = _button_by_label(desk, RECORD_LABEL)
        assert btn is not None
        btn.emit("clicked")
        assert shown == ["logs"]      # the shell's legacy map lands on auditlog
        desk.unparent()

    def test_without_a_navigator_the_desk_stays_inert(self):
        desk = ToolsDesk(_registry())
        desk.selected = "clamav"
        desk.fill_dossier("clamav")
        desk.paint({"clamav": _fact("clamav")}, [],
                   "2026-11-06T07:00:00+00:00")
        assert _button_by_label(desk, RECORD_LABEL) is None
        desk.unparent()


# ---- The mega log's own affordance -----------------------------------------
class TestMegaLogAffordance:
    """The Activity Log now tells you the row is pressable, and the fix
    card carries the jump to the page that manages the lane."""

    def test_the_log_says_rows_are_pressable_in_source(self):
        src = (ROOT / "ui" / "logsdesk.py").read_text()
        assert "Click a row to resolve it" in src
        # the same words live on the view: hovering a row explains itself
        assert "query-tooltip" in src and "_log_row_tooltip" in src

    def test_mega_log_jump_targets_match_the_lane(self, monkeypatch):
        shown = []
        from ui.logsdesk import LogsDeskMixin
        import ui.logsdesk as logmod

        presented = []
        monkeypatch.setattr(logmod, "present_now",
                            lambda d: presented.append(d))
        host = type("_Host", (Gtk.Window, LogsDeskMixin), {
            "_log_threat_actions": lambda self, ev, acts: None,
            "_log_tool_actions": lambda self, ev, acts: None,
            "_copy_log_row": lambda self, *a, **k: None,
            "_show": shown.append,
        })()
        for ev, lane in ((
                {"ts": "2026-11-06T07:00:00+00:00",
                 "from_tool": "responderd", "severity": "HIGH",
                 "text": "quarantine: evil.bin"}, "threat"),
                ({"ts": "2026-11-06T07:01:00+00:00",
                  "from_tool": "clamav", "severity": "INFO",
                  "text": "check-in: idle"}, "tool")):
            host._log_action_card(ev, lane)
        assert len(presented) == 2

        buttons = {kind: [b for b in _walk(dlg)
                          if isinstance(b, Gtk.Button)]
                   for kind, dlg in
                   (("threat", presented[0]), ("tool", presented[1]))}
        labels = {kind: {str(b.get_label() or "") for b in bs}
                  for kind, bs in buttons.items()}
        assert "Open Firewall" in labels["threat"]
        assert "Open Services" not in labels["threat"]
        assert "Open Services" in labels["tool"]
        assert "Open Firewall" not in labels["tool"]

        jump = [b for b in buttons["threat"]
                if str(b.get_label()) == "Open Firewall"][0]
        jump.emit("clicked")
        assert shown == ["defense"]
        for dlg in presented:
            dlg.destroy()

    def test_the_log_says_rows_are_pressable_in_source(self):
        src = (ROOT / "ui" / "logsdesk.py").read_text()
        assert "Click a row to resolve it" in src
        # the same words live on the view: hovering a row explains itself
        assert "query-tooltip" in src and "_log_row_tooltip" in src
