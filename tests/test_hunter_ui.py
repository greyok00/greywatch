"""The Hunter card: a real GTK widget over tmp hunter files.

The panel holds no hunt state of its own — it renders what the hunter
process wrote and answers nothing itself. These tests pin exactly that:
the request file is presence-only, the HAR import is a plain copy with the
same size cap the parser enforces, the AI toggle persists into config.json
without dropping foreign keys, and the unread pointer moves when the card
is seen."""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
pytest.importorskip("gi")
import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from hunter import store, web  # noqa: E402
from ui import hunterview  # noqa: E402


def _finding_row_fixture(data_dir):
    store.append_finding(data_dir, {
        "id": "beef", "ts": "2026-11-03T10:00:00+00:00",
        "rule": "download-double-extension",
        "title": "A download tried to look like a document",
        "what": "“invoice.pdf.exe” landed in Downloads.",
        "next": "Delete it.", "severity": "HIGH",
        "facts": ["path=/x/invoice.pdf.exe"], "evidence": [],
        "hunter": "1"})
    store.append_defender(data_dir, {
        "ts": "2026-11-03T10:00:01+00:00", "kind": "rule",
        "finding_id": "beef", "severity": "HIGH",
        "text": "A file named like a document is a program.",
        "hint": "Delete it."})
    store.write_live(data_dir, {"hunter": 1,
                                "ts": "2026-11-03T10:00:02+00:00",
                                "findings_total": 1, "unread": 1})


def test_request_hunt_is_presence_only(tmp_path):
    hunterview.request_hunt(tmp_path)
    assert store.request_path(tmp_path).read_text() == "{}\n"


def test_import_har_copies_into_the_inbox_and_refuses_oversize(
        tmp_path, monkeypatch):
    src = tmp_path / "capture"
    src.write_text(json.dumps({"log": {"entries": []}}))
    verdict = hunterview.import_har(tmp_path, src)
    assert "Imported" in verdict
    copied = list(store.inbox_dir(tmp_path).glob("*"))
    assert len(copied) == 1 and copied[0].name == "capture.har"
    json.loads(copied[0].read_text())
    # The parser's cap is the import's cap: nothing gets in it cannot read.
    monkeypatch.setattr(web, "HAR_MAX_BYTES", 10)
    assert "too large" in hunterview.import_har(tmp_path, src)
    assert len(list(store.inbox_dir(tmp_path).glob("*"))) == 1


def test_panel_renders_findings_and_ask_hands_the_finding_to_the_chat(
        tmp_path):
    asked = []

    def on_ask(question, finding=None):
        asked.append(question)

    panel = hunterview.HunterPanel(str(tmp_path), on_ask=on_ask)
    _finding_row_fixture(tmp_path)
    panel.refresh(force=True)
    rows = [w for w in panel._list.observe_children()
            if hasattr(w, "_gw_finding_id")]
    assert len(rows) == 1            # the newest finding, newest-first
    # The dossier's ask action calls the chat with the finding's story,
    # not its raw id.
    panel._select_finding("beef")
    stack, buttons = list(panel._detail.observe_children()), []
    while stack:
        w = stack.pop(0)
        if isinstance(w, Gtk.Button):
            buttons.append(w)
        stack.extend(w.observe_children())
    labels = [b.get_child().get_text() for b in buttons]
    assert "Ask about this" in labels and "Copy facts" in labels
    ask_btn = next(b for b in buttons
                   if b.get_child().get_text() == "Ask about this")
    ask_btn.emit("clicked")
    assert len(asked) == 1
    assert "hunter finding" in asked[0]
    assert "invoice.pdf.exe" in asked[0] or "document" in asked[0]


def test_mark_seen_moves_the_pointer_and_clears_badge(tmp_path):
    _finding_row_fixture(tmp_path)
    assert hunterview.unread_notes(tmp_path) == 1
    hunterview.HunterPanel(str(tmp_path)).mark_seen()
    assert hunterview.unread_notes(tmp_path) == 0
    pointer = json.loads(store.config_path(tmp_path).read_text())["read_until"]
    assert pointer == "2026-11-03T10:00:01+00:00"


def test_ai_toggle_persists_without_dropping_foreign_keys(tmp_path):
    cfg_path = store.config_path(tmp_path)
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text(json.dumps({"read_until": "z", "custom": 5}))
    panel = hunterview.HunterPanel(str(tmp_path))
    panel._on_ai_toggle(panel._ai_switch, False)
    doc = json.loads(cfg_path.read_text())
    assert doc == {"read_until": "z", "custom": 5, "enabled": False}
    assert hunterview.ai_enabled(tmp_path) is False
    panel._on_ai_toggle(panel._ai_switch, True)
    assert hunterview.ai_enabled(tmp_path) is True
    # No config at all: the switch defaults to on, and the handler works.
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    assert hunterview.ai_enabled(fresh) is True
    hunterview.HunterPanel(str(fresh))._on_ai_toggle(None, False)
    assert hunterview.ai_enabled(fresh) is False


def test_panel_stays_silent_when_the_hunter_wrote_nothing_new(tmp_path):
    doc = {"hunter": 1, "ts": "2026-11-03T10:00:02+00:00",
           "findings_total": 1, "unread": 1}
    store.write_live(tmp_path, doc)
    _finding_row_fixture(tmp_path)
    panel = hunterview.HunterPanel(str(tmp_path))
    panel.refresh(force=True)
    rows1 = list(panel._list.observe_children())
    panel.refresh()               # same ts: the render is skipped
    rows2 = list(panel._list.observe_children())
    assert [str(r) for r in rows1] == [str(r) for r in rows2]
    # A new live timestamp repaints.
    doc["ts"] = "2026-11-03T11:00:00+00:00"
    store.write_live(tmp_path, doc)
    panel.refresh()
    assert panel._shown_ts == "2026-11-03T11:00:00+00:00"

def test_cover_tile_reports_the_watcher_and_intel(tmp_path):
    panel = hunterview.HunterPanel(str(tmp_path))
    # The intel age rides the wall clock: a fixed stamp crossed the chip's
    # 31-character budget once the real age passed 100 h (2026-11-07), so
    # the pin now rides a stamp derived from now (was 2026-11-03T09:00+00).
    import datetime as dt
    fresh = (dt.datetime.now(dt.timezone.utc)
             - dt.timedelta(hours=2)).isoformat()
    store.write_live(tmp_path, {
        "hunter": 1, "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
        "watcher": {"state": "watching", "port": 9229},
        "intel": {"enabled": True, "last_ok": fresh,
                  "ages": {"openphish": fresh}}})
    panel.refresh(force=True)
    text = panel._watcher_tile.get_text()
    assert "watching" in text and "intel" in text, text
    # A live doc from before the wave keeps the old quiet line.
    store.write_live(tmp_path, {"hunter": 1,
                                "ts": "2026-11-03T10:01:02+00:00"})
    panel.refresh(force=True)
    assert "browser wave" in panel._watcher_tile.get_text()


def test_watcher_line_stays_short():
    assert len(hunterview._watcher_line({
        "watcher": {"state": "watching"},
        "intel": {"enabled": True, "ages": {}}})) <= 31
