# tests/test_ui_actions.py
import time
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib
import pytest
from ui import actions


def test_a_button_without_a_handler_is_refused():
    with pytest.raises(actions.ActionError):
        actions.action_button("Run", None)


def test_an_insensitive_button_does_nothing_even_when_activated():
    calls = []
    button = actions.action_button("Run", lambda: calls.append(1))
    button.set_sensitive(False)
    button.emit("clicked")
    button.activate()
    assert calls == []


def test_a_confirmation_can_stop_the_action(monkeypatch):
    calls = []
    monkeypatch.setattr(actions, "ask", lambda *a, **k: False)
    button = actions.action_button("Stop", lambda: calls.append(1),
                                   confirm="Stop the lane?")
    button.emit("clicked")
    assert calls == []


def test_a_destroyed_parent_makes_ask_return_false():
    import faulthandler
    faulthandler.dump_traceback_later(5, exit=True)
    window = Gtk.Window(title="Parent")
    window.present()

    def close_parent():
        window.destroy()
        return False

    GLib.timeout_add(50, close_parent)
    try:
        assert actions.ask(window, "Stop", "Stop the lane?") is False
    finally:
        faulthandler.cancel_dump_traceback_later()


def test_async_sets_pending_then_restores_the_button():
    calls = []
    button = actions.action_button("Go", lambda: None)
    actions.run_async(button, lambda: 7, calls.append, pending="Working...")
    assert button.get_label() == "Working..."
    assert not button.get_sensitive()
    ctx = GLib.main_context_default()
    for _ in range(200):
        ctx.iteration(False)
        time.sleep(0.005)
    assert calls == [7]
    assert button.get_label() == "Go"
    assert button.get_sensitive()
