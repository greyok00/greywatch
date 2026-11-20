"""The chat's scan intent points at the Security Center instead of
starting or requesting a scan (owner 2026-11-19: one scan door, the
Security Center scan block). No request file lands and the audit row
records the intent as not performed."""
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
    return tmp_path


def test_the_chat_scan_intent_points_to_security(state):
    from ui import assistant_page
    page = Gtk.Box()
    shown = []
    win = type("W", (), {"show_page": lambda s, n: shown.append(n),
                          "note": lambda s, t: None})()
    page._gw_window = win
    host = assistant_page._ChatHost(page)
    host._do_scan("full")
    assert shown == ["Security Center"]
    assert not (state / "scan-request.json").exists()


def test_the_chat_scan_intent_is_recorded_as_not_performed(state,
                                                           monkeypatch):
    from ui import assistant_page
    from assistant import audit
    recorded = []
    monkeypatch.setattr(audit, "record",
                        lambda a, t, ok: recorded.append((a, t, ok)))
    page = Gtk.Box()
    win = type("W", (), {"show_page": lambda s, n: None,
                          "note": lambda s, t: None})()
    page._gw_window = win
    host = assistant_page._ChatHost(page)
    host._do_scan("clamav")
    assert recorded and recorded[0] == ("scan", "clamav", False)


def test_the_chat_no_longer_maps_settings_to_help():
    from ui import assistant_page
    assert "settings" not in assistant_page._PAGES
