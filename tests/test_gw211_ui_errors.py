"""GW-A1..A5 (cannot-fail Wave A): user-visible honest failures.

Pins:
  A1 - a finished action whose record write fails says so and stays
       open; the exception never escapes into GTK.
  A2 - a scan request that never reached disk says why where the scan
       controls live; the success path still navigates.
  A3 - helper_detail makes a single safe, truncated, last-line render
       of a helper's exit code and stderr; one consumer shows it.
  A4 - the Home verdict never promises health over a stale snapshot.
  A5 - forward-compat renderers (scan_request digest, doctor rows)
       render present data and render NOTHING when the keys are
       absent, so today's behavior is a pinned contract.
"""
import json
import pathlib
import sys
import types


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

import ui.decisionlist as dl  # noqa: E402
import ui.homepage as homepage  # noqa: E402
import ui.settingsdesk as settingsdesk  # noqa: E402
import ui.scanview as scanview  # noqa: E402
import ui.console as console_mod  # noqa: E402
from ui.decisionlist import RECORD_NOTE  # noqa: E402


def _labels(box):
    """Direct child labels of a Gtk.Box, in order."""
    out, child = [], box.get_first_child()
    while child is not None:
        if isinstance(child, Gtk.Label):
            out.append(child)
        child = child.get_next_sibling()
    return out


def _opt(helper="pw-block", oid="block:1"):
    return {"id": oid, "label": "Block it", "helper": helper,
            "args": ["arg", "1"]}


# ---------------------------------------------------------------- A1

def test_record_failure_says_so_and_never_raises(monkeypatch, tmp_path):
    """decisionlist._after_answer: the helper finished, record_answer
    raised - the card says the write-down failed and the card stays."""
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(dl, "record_answer", boom)
    buttons = [Gtk.Button(label="x")]
    state = Gtk.Label(xalign=0)
    win = dl.DecisionsWindow()
    try:
        win._after_answer("d1", _opt(), buttons, state, 0)
        txt = state.get_text()
        assert "could not be written down" in txt
        assert RECORD_NOTE in txt
        assert state.get_visible()
        # no auto retry, no re-render: build_rows would have rebuilt the
        # list; the honest sentence is the whole outcome
        assert "did finish" in txt
    finally:
        win.destroy()


def test_record_failure_in_console_gate_says_so(monkeypatch, tmp_path):
    """console.OverviewPage._after_answer, same contract on the gate."""

    def boom(*a, **k):
        raise OSError("read-only disk")
    monkeypatch.setattr(dl, "record_answer", boom)
    probe = types.SimpleNamespace(_answering={"d1"}, _win=None,
                                  _data_dir=lambda: tmp_path)
    buttons = [Gtk.Button(label="x")]
    state = Gtk.Label(xalign=0)
    console_mod.OverviewPage._after_answer(probe, "d1", _opt(), buttons,
                                           state, 0)
    assert "could not be written down" in state.get_text()


def test_record_failure_reached_record_layer(monkeypatch, tmp_path):
    """answer_record absorbs the failure (returns False) instead of
    letting it travel to the GTK callback."""
    def boom(*a, **k):
        raise OSError("x")
    monkeypatch.setattr(dl, "record_answer", boom)
    assert dl.answer_record(tmp_path, "d1", "block:1") is False


def test_rc_nonzero_reports_helper_detail_and_reenables():
    """The rc!=0 branch (unchanged shape): buttons come back and the
    rendered detail carries the exit code (A3 consumer, end to end)."""
    buttons = [Gtk.Button(label="x")]
    state = Gtk.Label(xalign=0)
    win = dl.DecisionsWindow()
    try:
        win._after_answer("d1", _opt(), buttons, state, 65, "boom")
        txt = state.get_text()
        assert "did not finish" in txt
        assert "exit code 65" in txt
        assert all(b.get_sensitive() for b in buttons)
    finally:
        win.destroy()


# ---------------------------------------------------------------- A2

class _ScanWin:
    """Just the attributes _start_scan touches."""

    def __init__(self, scan_result, console):
        self._request_scan = lambda mode: scan_result
        self._assistant_pending = None
        self.services_page = types.SimpleNamespace(scanconsole=console)
        self.nav = []
        self._show = lambda key: self.nav.append(key)


def test_scan_start_failure_says_why(monkeypatch):
    import ui.scanview as sv
    console = sv.ScanConsole(pathlib.Path("/tmp/gw-test-scan"))
    try:
        w = _ScanWin((False, "disk full"), console)
        from ui.window import MainWindow
        MainWindow._start_scan(w, None, {"key": "full", "title": "Full"},
                               allowed=True)
        assert console.note.get_visible()
        assert console.note.get_text() == \
            "the scan could not start: disk full"
        assert w.nav == []          # failure navigates nowhere
    finally:
        console.unparent()


def test_scan_start_success_still_navigates():
    notes = []
    console = types.SimpleNamespace(show_scan_note=notes.append)
    w = _ScanWin((True, "full"), console)
    from ui.window import MainWindow
    MainWindow._start_scan(w, None, {"key": "full", "title": "Full"},
                           allowed=True)
    assert w.nav == ["scans"]       # the console page, task 10 re-root
    assert notes == []              # success writes no note


# ---------------------------------------------------------------- A3

def test_helper_detail_last_line_only_and_safe():
    line = "line one\n\x1b[31mboom\x1b[0m ctrl:\x07 end" + "x" * 400
    got = dl.helper_detail(65, line)
    assert got.startswith("exit code 65: ")
    assert "boom" in got
    assert "line one" not in got           # last line only
    assert "\x1b" not in got and "\x07" not in got   # control chars gone
    assert len(got) <= 200 + len("exit code 65: ")


def test_helper_detail_no_exit():
    assert dl.helper_detail(-1, "") == "the helper could not run."
    assert dl.helper_detail(-1, None).endswith(".")


# ---------------------------------------------------------------- A4

def _status(tmp_path, updated, mtime=None):
    snap = tmp_path / "status.json"
    doc = {"tools": {}, "pending_decisions": 0, "updated": updated}
    snap.write_text(json.dumps(doc))
    if mtime is not None:
        import os
        os.utime(snap, (mtime, mtime))
    return snap


def test_home_fresh_snapshot_has_no_staleness(tmp_path, monkeypatch):
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    _status(tmp_path, now)
    verdict, ctx = homepage.suite_summary(tmp_path)
    assert "older than 90 s" not in ctx


def test_home_stale_stamp_names_the_wait(tmp_path):
    import datetime as dt
    old = (dt.datetime.now(dt.timezone.utc)
           - dt.timedelta(seconds=120)).isoformat()
    _status(tmp_path, old)
    verdict, ctx = homepage.suite_summary(tmp_path)
    assert "snapshot is older than 90 s - waiting for the daemon" in ctx


def test_home_mtime_fallback_when_stamp_is_junk(tmp_path):
    import os
    import time as t
    snap = _status(tmp_path, "not-a-stamp")
    os.utime(snap, (t.time() - 200, t.time() - 200))
    verdict, ctx = homepage.suite_summary(tmp_path)
    assert "waiting for the daemon" in ctx


def test_home_junk_stamp_fresh_mtime_is_not_stale(tmp_path):
    snap = _status(tmp_path, "not-a-stamp")
    assert homepage._snapshot_age({"updated": "not-a-stamp"}, snap) \
        is not None
    verdict, ctx = homepage.suite_summary(tmp_path)
    assert "older than 90 s" not in ctx


def test_home_unreadable_status_is_starting(tmp_path):
    (tmp_path / "status.json").write_text("{broken")
    verdict, ctx = homepage.suite_summary(tmp_path)
    assert verdict == "The suite is starting"


# ---------------------------------------------------------------- A5

class _StubWin:
    """The window surface OverviewPage's constructor touches."""
    registry = []
    chat_llm = None

    def _get_status(self):
        return {}

    def _get_recent(self):
        return []

    def _assistant_intent(self, *_a, **_k):
        pass


def _overview(monkeypatch, tmp_path):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return console_mod.OverviewPage(win=_StubWin())


def test_overview_renders_nothing_for_helperless_rows_and_request(
        monkeypatch, tmp_path):
    """A5, variant-3 face (rebuild round 2, task 5): the digest's
    advisory rows carry no helper, so they are not items with buttons -
    the needs-you section stays hidden - and an unpicked-up
    scan_request digest (forward-compat GW-C1) is tolerated with no
    fake row rendered for it."""
    page = _overview(monkeypatch, tmp_path)
    page.refresh({
        "updated": "2026-11-06T09:00:00+00:00", "recent": [],
        "scan_request": {"present": True, "age_s": 5},
        "pending_list": [
            {"id": "hunter:adv", "source": "browser-watch",
             "kind": "advisory", "title": "scan finished", "detail": "",
             "ts": "", "options": [{"id": "note", "label": "Noted"}],
             "spec": {"id": "hunter:adv", "subject": "scan finished",
                      "options": [{"id": "note", "label": "Noted"}]}}]})
    assert not page.needs_you_box.get_visible()
    assert page.action_buttons() == []


def test_overview_absent_keys_render_nothing(monkeypatch, tmp_path):
    page = _overview(monkeypatch, tmp_path)
    page.refresh({"updated": "2026-11-06T09:00:00+00:00", "recent": []})
    assert not page.needs_you_box.get_visible()
    assert page.action_buttons() == []


def test_scanconsole_show_request_appends_once():
    cons = scanview.ScanConsole(pathlib.Path("/tmp/gw-test-scan"))
    try:
        cons.show_request(None)                 # absent: no note
        assert not cons.note.get_visible()
        cons.show_request({"present": True, "age_s": 7})
        assert cons.note.get_visible()
        assert "scan request is on disk" in cons.note.get_text()
    finally:
        cons.unparent()


def test_settings_doctor_rows_absent_key_renders_nothing(
        monkeypatch, tmp_path):
    monkeypatch.setattr(settingsdesk, "_data_dir", lambda: tmp_path)
    probe = types.SimpleNamespace(_doctor_label=Gtk.Label(xalign=0))
    settingsdesk.SettingsDeskMixin._paint_doctor_rows(probe)
    assert not probe._doctor_label.get_visible()


def _needs_you_publish(tmp_path, items):
    """Publish the daemon's pending_list on disk (what the needs-you
    section reads through _status_path_rows)."""
    (tmp_path / "status.json").write_text(json.dumps(
        {"updated": "2026-11-06T09:00:00+00:00", "pending_list": items}))


_NEEDS_YOU_ITEM = {
    "id": "responderd:q1", "source": "responderd", "kind": "question",
    "title": "'evil.bin' was quarantined", "detail": "", "ts": "",
    "options": [{"id": "keep", "label": "Keep quarantined",
                 "helper": "keep-quarantine"}],
    "spec": {"id": "responderd:q1",
             "subject": "'evil.bin' was quarantined",
             "question": "Keep it locked away?",
             "options": [{"id": "keep", "label": "Keep quarantined",
                          "helper": "keep-quarantine"}]}}


def test_needs_you_reappears_when_a_row_arrives(monkeypatch, tmp_path):
    """The bug-9 law, the return trip: hidden while empty, back with its
    title and real, working buttons when a decision that asks something
    is published - not an empty-looking card."""
    page = _overview(monkeypatch, tmp_path)
    page.refresh({"updated": "2026-11-06T09:00:00+00:00", "recent": []})
    assert not page.needs_you_box.get_visible()
    _needs_you_publish(tmp_path, [_NEEDS_YOU_ITEM])
    page.refresh({"updated": "2026-11-06T09:00:00+00:00", "recent": []})
    assert page.needs_you_box.get_visible()
    assert any("needs" in (w.get_text() or "").lower() or
               "Needs you" in (w.get_text() or "")
               for w in _labels(page.needs_you_box)
               if isinstance(w, Gtk.Label))
    buttons = page.action_buttons()
    assert len(buttons) == 1
    assert str(buttons[0].get_label() or "") == "Keep quarantined"


def test_needs_you_hides_again_when_the_rows_leave(monkeypatch, tmp_path):
    """And the reverse trip: once the list is answered away, the section
    and its title are gone again, twice in a row."""
    page = _overview(monkeypatch, tmp_path)
    _needs_you_publish(tmp_path, [_NEEDS_YOU_ITEM])
    page.refresh({"updated": "2026-11-06T09:00:00+00:00", "recent": []})
    assert page.needs_you_box.get_visible()
    _needs_you_publish(tmp_path, [])
    page.refresh({"updated": "2026-11-06T09:00:00+00:00", "recent": []})
    assert not page.needs_you_box.get_visible()
    page.refresh({"updated": "2026-11-06T09:00:00+00:00", "recent": []})
    assert not page.needs_you_box.get_visible()


def test_settings_doctor_rows_paint_when_present(monkeypatch, tmp_path):
    (tmp_path / "status.json").write_text(json.dumps({
        "doctor": [{"lane": "tools", "verdict": "READY", "text": "all up",
                    "ts": "2026-11-07T00:00:00+00:00"}]}))
    monkeypatch.setattr(settingsdesk, "_data_dir", lambda: tmp_path)
    probe = types.SimpleNamespace(_doctor_label=Gtk.Label(xalign=0))
    settingsdesk.SettingsDeskMixin._paint_doctor_rows(probe)
    assert probe._doctor_label.get_visible()
    assert "tools" in probe._doctor_label.get_text()
    assert "READY" in probe._doctor_label.get_text()
