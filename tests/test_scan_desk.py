"""The three-tier scan desk: full pass, per-scanner row (disabled while
its scanner runs), a read-only schedule card, and a refresh path with
no main-thread subprocess (the page-switch freeze class, owner
2026-11-18)."""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "scan-whitelist.json").write_text(json.dumps(
        {"entries": []}))
    (tmp_path / "quarantine.jsonl").write_text("")
    return tmp_path


class _Win:
    notes = []

    def note(self, text):
        self.notes.append(text)

    def has_page(self, label):
        return True


def _texts(widget):
    out = []

    def walk(w):
        if isinstance(w, Gtk.Label):
            out.append(w.get_text())
        c = w.get_first_child()
        while c is not None:
            walk(c)
            c = c.get_next_sibling()

    walk(widget)
    return " ".join(out)


# ------------------------------------------------ the Security scan block
# Owner 2026-11-19: one scan block on Security Overview owns Quick scan,
# Deep scan, and the one job panel. It never sends "full" or "scan-all".


def _page(state, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(state))
    (state / "posture.json").write_text(json.dumps({"score": 57,
                                                    "inputs": {}}))
    (state / "status.json").write_text(json.dumps({"tools": {}}))
    from ui import security
    win = _Win()
    win.scan_monitor = None
    body = Gtk.Box()
    body._gw_window = win
    body._gw_slots = {}
    return security, body


def test_the_scan_block_has_quick_deep_and_a_job_panel(state, monkeypatch):
    security, body = _page(state, monkeypatch)
    card = security._scan_block(body._gw_window, body)
    labels = [b.get_label() for b in _buttons(card)]
    assert "Quick scan" in labels
    assert "Deep scan" in labels
    assert body._gw_scan["panel"] is not None
    assert body._gw_scan["panel"].chart is not None
    assert not any("Full scan" in label for label in labels)


def test_quick_scan_files_the_frequent_antivirus_key(state, monkeypatch):
    security, body = _page(state, monkeypatch)
    security._scan_block(body._gw_window, body)
    from scan_session import request_path, validate_request
    security._start_scan(body, "clamav-frequent")
    rid, key = validate_request(
        json.loads(request_path(state).read_text()))
    assert key == "clamav-frequent"
    assert body._gw_scan["pending"] is not None


def test_deep_scan_asks_first(state, monkeypatch):
    security, body = _page(state, monkeypatch)
    security._scan_block(body._gw_window, body)
    monkeypatch.setattr(security.actions, "ask", lambda *a, **k: False)
    security._start_scan(body, "clamav-home")
    assert not (state / "scan-request.json").exists()
    monkeypatch.setattr(security.actions, "ask", lambda *a, **k: True)
    security._start_scan(body, "clamav-home")
    assert (state / "scan-request.json").exists()


def test_a_running_job_moves_the_panel_and_disables_starts(state,
                                                          monkeypatch):
    security, body = _page(state, monkeypatch)
    security._scan_block(body._gw_window, body)
    security._apply_scan(body, {
        "state": "running", "scan_id": "20261119T120000-a1b2",
        "started_at": "2026-11-19T12:00:00+00:00",
        "scanners": {"clamav": {
            "state": "running", "percent": 0.42, "count": 100,
            "counter_label": "files scanned", "current": "/a.bin"}}})
    panel = body._gw_scan["panel"]
    assert "42" in panel.status.get_text()
    assert not body._gw_scan["quick"].get_sensitive()
    assert not body._gw_scan["deep"].get_sensitive()
    assert panel.pause.get_sensitive()


def test_a_rebuild_keeps_a_filed_request_and_its_note(state, monkeypatch):
    # status.json is rewritten every 60 seconds, and that rebuild must not
    # hand back a fresh idle block while the request is still on file.
    security, body = _page(state, monkeypatch)
    security._refresh_into(body)
    security._start_scan(body, "clamav-frequent")
    pending = body._gw_scan["pending"]
    request_id = body._gw_scan["request_id"]
    assert pending is not None
    assert request_id
    assert "Starting the scan." in body._gw_scan["panel"].status.get_text()
    security._refresh_into(body)
    assert body._gw_scan["pending"] == pending
    assert body._gw_scan["request_id"] == request_id
    assert body._gw_scan["pending_token"] is not None
    assert "Starting the scan." in body._gw_scan["panel"].status.get_text()
    assert not body._gw_scan["quick"].get_sensitive()
    assert not body._gw_scan["deep"].get_sensitive()


def test_a_rebuild_keeps_the_job_chart_history(state, monkeypatch):
    security, body = _page(state, monkeypatch)
    security._refresh_into(body)
    security._start_scan(body, "clamav-frequent")
    request_id = body._gw_scan["request_id"]
    security._apply_scan(body, {
        "state": "running", "scan_id": request_id,
        "started_at": "2026-11-19T12:00:00+00:00",
        "scanners": {"clamav": {"state": "running", "percent": 0.4,
                                 "count": 10,
                                 "counter_label": "files scanned"}}})
    before = list(body._gw_scan["panel"]._history)
    assert before
    security._refresh_into(body)
    after = list(body._gw_scan["panel"]._history)
    assert after[:len(before)] == before


def test_the_timeout_clears_only_its_own_request(state, monkeypatch):
    security, body = _page(state, monkeypatch)
    security._refresh_into(body)
    security._start_scan(body, "clamav-frequent")
    token = body._gw_scan["pending_token"]
    assert token is not None
    body._gw_scan["pending_token"] = token + 1
    security._scan_pending_timeout(body, token)
    assert body._gw_scan["pending"] is not None
    security._scan_pending_timeout(body, token + 1)
    assert body._gw_scan["pending"] is None
    assert body._gw_scan["pending_token"] is None
    assert "did not answer" in body._gw_scan["panel"].status.get_text()


# ------------------------------------------------ controls and tracking
# Owner 2026-11-19: start/resume/pause/cancel in the scan area, live
# percent, and a tracker that survives a page switch.


def _buttons(widget):
    out = []

    def walk(w):
        if isinstance(w, Gtk.Button):
            out.append(w)
        child = w.get_first_child()
        while child is not None:
            walk(child)
            child = child.get_next_sibling()

    walk(widget)
    return out


def test_the_tracker_keeps_the_document_across_page_switches(state):
    from ui import scanmonitor
    (state / "scan-live.json").write_text(json.dumps(
        {"state": "running", "scan_id": "20261119T120000-a1b2",
         "scanners": {"clamav": {"state": "running", "percent": 0.5}}}))
    seen = []
    monitor = scanmonitor.ScanMonitor()
    monitor.subscribe(seen.append)
    assert monitor.live == {}          # no beat yet
    monitor._beat()
    assert seen and seen[-1]["scan_id"] == "20261119T120000-a1b2"
    # a second page subscribing now paints immediately from the copy
    late = []
    monitor.subscribe(late.append)
    assert late and late[0]["scan_id"] == "20261119T120000-a1b2"


def test_the_security_page_does_not_rebuild_on_an_unchanged_return(state):
    (state / "posture.json").write_text(json.dumps({"score": 57,
                                                    "inputs": {}}))
    (state / "status.json").write_text(json.dumps({"tools": []}))
    from ui import security
    win = _Win()
    win.scan_monitor = None
    scroll = security.build(win)
    body = scroll._gw_body
    first = body.get_first_child()
    security.refresh(scroll)
    assert body.get_first_child() is first


def test_the_virus_card_keeps_only_its_status_lines(state):
    (state / "posture.json").write_text(json.dumps({"score": 57,
                                                    "inputs": {}}))
    (state / "status.json").write_text(json.dumps({"tools": []}))
    from ui import security
    page = Gtk.Box()
    win = _Win()
    win.scan_monitor = None
    page._gw_window = win
    card = security.virus_card(win, page)
    labels = [b.get_label() for b in _buttons(card)]
    # The scan controls moved to the scan block; the card is status only.
    assert labels == [], labels
    text = _texts(card).lower()
    assert "signatures" in text
    assert "last finding" in text


# ------------------------------------------------ patch action feedback
def test_patch_affected_shows_pending_then_reports(state, monkeypatch):
    from ui import security
    monkeypatch.setattr(
        security.cliapi, "call",
        lambda *a, **k: (0, "patched the affected packages", ""))
    win = _Win()
    win.notes = []
    page = Gtk.Box()
    page._gw_window = win
    card = security.updates_card(win, page)
    button = next(b for b in _buttons(card)
                  if b.get_label() == "Patch affected packages")
    button.emit("clicked")
    assert button.get_label() == "Patching..."
    assert not button.get_sensitive()
    import time
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(200):
        ctx.iteration(False)
        time.sleep(0.005)
    assert button.get_label() == "Patch affected packages"
    assert button.get_sensitive()
    status = page._gw_slots["updates"]["status"].get_text().lower()
    assert "patched the affected packages" in status
