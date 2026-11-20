"""Pins for the per-tool desk's action bar, job panel and refresh."""

from __future__ import annotations

import json
import threading
import time

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from tests.test_ui_v4 import _ShellStub
from ui import tooldesk


def _fake_tool(tid):
    return {"tool": tid, "label": tid, "unit": "psad.service",
            "state": "RED", "last_event": "2026-11-19T12:00:00+00:00",
            "events": []}


def _walk(widget):
    child = widget.get_first_child() if hasattr(widget, "get_first_child") \
        else None
    while child is not None:
        yield child
        yield from _walk(child)
        child = child.get_next_sibling()


def _body(page):
    return getattr(page, "_gw_body", page)


def _buttons(page):
    return [w for w in _walk(_body(page)) if isinstance(w, Gtk.Button)]


def _button(page, label):
    for button in _buttons(page):
        if button.get_label() == label:
            return button
    raise AssertionError(f"no button labelled {label!r}")


def _texts(page):
    return " ".join(w.get_text() for w in _walk(_body(page))
                    if isinstance(w, Gtk.Label))


def _pump(seconds=3.0):
    end = time.monotonic() + seconds
    context = GLib.MainContext.default()
    while time.monotonic() < end:
        while context.pending():
            context.iteration(False)
        time.sleep(0.01)


def test_a_service_desk_shows_start_stop_and_restart(tmp_path, monkeypatch):
    from ui import cliapi
    monkeypatch.setattr(cliapi, "jcall",
                        lambda *a, **k: _fake_tool("psad"))
    page = tooldesk.build(_ShellStub(), "Port Scan Watch", ("psad",),
                          "psad")
    labels = [b.get_label() for b in _buttons(page)]
    for wanted in ("Start", "Stop", "Restart"):
        assert wanted in labels
    assert page._gw_tool_ids == ("psad",)


def test_a_check_desk_starts_its_scan_and_shows_a_job_panel(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import cliapi
    monkeypatch.setattr(cliapi, "jcall",
                        lambda *a, **k: _fake_tool("rkhunter"))
    page = tooldesk.build(_ShellStub(), "Rootkit", ("rkhunter",),
                          "rkhunter")
    button = _button(page, "Run check")
    button.emit("clicked")
    from scan_session import request_path, validate_request
    _rid, key = validate_request(
        json.loads(request_path(tmp_path).read_text()))
    assert key == "rkhunter"
    assert page._gw_job_panel is not None


def test_refresh_reads_the_tool_again(tmp_path, monkeypatch):
    from ui import cliapi
    calls = []
    monkeypatch.setattr(cliapi, "jcall",
                        lambda *a, **k: calls.append(a) or _fake_tool("psad"))
    page = tooldesk.build(_ShellStub(), "Port Scan Watch", ("psad",),
                          "psad")
    calls.clear()
    tooldesk.refresh(page)
    _pump()
    assert calls and calls[0][0] == "tool"


def test_build_does_not_block_on_the_cli(tmp_path, monkeypatch):
    from ui import cliapi
    gate = threading.Event()
    started = threading.Event()

    def slow(*_a, **_k):
        started.set()
        gate.wait(10)
        return _fake_tool("psad")

    monkeypatch.setattr(cliapi, "jcall", slow)
    page = tooldesk.build(_ShellStub(), "Port Scan Watch", ("psad",),
                          "psad")
    try:
        assert started.wait(5)
        assert "Reading the tool..." in _texts(page)
    finally:
        gate.set()
    _pump()
    assert "Down" in _texts(page)


def test_refresh_repaints_the_state_word(tmp_path, monkeypatch):
    from ui import cliapi
    doc = _fake_tool("psad")
    monkeypatch.setattr(cliapi, "jcall", lambda *_a, **_k: dict(doc))
    page = tooldesk.build(_ShellStub(), "Port Scan Watch", ("psad",),
                          "psad")
    _pump()
    assert "Down" in _texts(page)
    doc["state"] = "GREEN"
    tooldesk.refresh(page)
    _pump()
    texts = _texts(page)
    assert "Live" in texts
    assert "Down" not in texts


def test_stop_and_restart_confirm_while_start_does_not(tmp_path,
                                                        monkeypatch):
    import cli
    from ui import actions, cliapi
    monkeypatch.setattr(cliapi, "jcall",
                        lambda *_a, **_k: _fake_tool("psad"))
    monkeypatch.setattr(cli, "helper_exec", lambda *_a, **_k: 0)
    monkeypatch.setattr(cli, "helper_last_err", lambda: "")
    seen = []

    def asked(parent, title, body, accept="Continue"):
        seen.append(title)
        return False

    monkeypatch.setattr(actions, "ask", asked)
    page = tooldesk.build(_ShellStub(), "Port Scan Watch", ("psad",),
                          "psad")
    _button(page, "Start").emit("clicked")
    _button(page, "Stop").emit("clicked")
    _button(page, "Restart").emit("clicked")
    _pump()
    assert seen == ["Stop", "Restart"]
