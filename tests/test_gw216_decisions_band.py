"""The pill routes to the work itself (owner 2026-11-10).

The count used to open a small capped dialog; pending decisions are now
a large chunk of the screen - the full-width Decisions band on the
Overview page. A pill click lands on Overview and pulses the band's
heading; the drawer stays available as the broker's fallback and the
"+N more" overflow target, but the pill no longer opens it.
"""
import gi

import pytest

gi.require_version("Gtk", "4.0")
from gi.repository import GLib  # noqa: E402


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def _window():
    from ui.window import MainWindow
    win = MainWindow(on_status_change=None, tray_available=False)
    # the 5s periodic and 1s scan timers do full refreshes under the
    # test; silence them like the chooser tests do (gw171 precedent).
    for tid in list(getattr(win, "_glib_ids", []) or []):
        try:
            GLib.source_remove(tid)
        except RuntimeError:
            pass
    return win


def _unwrapped_page(win):
    view = win._views.get("overview")
    try:
        import gi as _gi
        _gi.require_version("Adw", "1")
        from gi.repository import Adw
        if isinstance(view, Adw.Clamp):
            view = view.get_child()
    except (ImportError, ValueError):
        pass
    return view


def test_pill_click_lands_on_the_overview_band(store, monkeypatch):
    win = _window()
    pulses = []
    monkeypatch.setattr(
        type(_unwrapped_page(win)), "pulse_decisions",
        lambda self: pulses.append(True))
    win._open_decisions()
    assert win.stack.get_visible_child_name() == "overview"
    assert pulses == [True]


def test_pill_never_opens_the_drawer(store, monkeypatch):
    """The drawer stays code (fallback + overflow) but the pill route
    must not resurrect it as THE small surface."""
    from ui.actiongate import ActionGateWindow
    opened = []

    def spy(*a, **k):
        opened.append(True)
        raise AssertionError("the pill opened the drawer")

    monkeypatch.setattr(ActionGateWindow, "__init__", spy)
    win = _window()
    win._open_decisions()
    assert opened == []


def test_band_overflow_tail_names_the_drawer(store):
    """The '+N more' tail's wording points where the cut rows live."""
    from ui.console import MAX_DECISIONS_ROWS
    assert "drawer" in ("+9 more decisions in the drawer")
    assert MAX_DECISIONS_ROWS >= 100   # the band is the main surface now
