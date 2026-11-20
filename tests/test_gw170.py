"""GW-170 pins: no modal grabs in the decision + wizard surfaces.

A modal child makes marco intercept the parent's titlebar close button
and bounce it at the child, so the window underneath cannot be closed
(owner: "the setup wizard shakes but I can't close it", 2026-11-04).
Nothing that greywatch raises as a dialog may be modal; popups attach to
the dashboard, never to whatever window happens to be active.
"""
import gi
import pytest

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

pytestmark = pytest.mark.gtk

import ui.decisions as UD  # noqa: E402


class _FakeApp:
    def __init__(self, wins, active):
        self._wins = wins
        self._active = active

    def get_windows(self):
        return self._wins

    def get_active_window(self):
        return self._active


def _spec(i):
    return {"id": f"responderd:{i}", "question": "Keep or restore?",
            "options": [{"id": "keep", "label": "Keep quarantined"}]}


def test_main_window_picker_prefers_the_dashboard():
    other = Gtk.Window()
    mine = type("MainWindow", (Gtk.Window,), {})()
    mine.set_visible(True)
    assert UD._main_window(_FakeApp([other, mine], other)) is mine, \
        "popups must attach to the dashboard, not to the active window"


def test_main_window_picker_falls_back_to_active():
    other = Gtk.Window()
    assert UD._main_window(_FakeApp([], other)) is other


def test_decision_popup_is_never_modal():
    from ui.decisions import DecisionBroker

    broker = DecisionBroker()
    broker._show_dialog(_spec(5), eyebrow="Protection", tag="t")
    dlg = broker._tagged["t"]
    try:
        assert dlg.get_modal() is False, \
            "a modal popup freezes the window under it (GW-170)"
        assert dlg.get_transient_for() is None or \
            type(dlg.get_transient_for()).__name__ == "MainWindow", \
            "popup parent must be the dashboard when one exists"
    finally:
        dlg.destroy()


def test_tool_chooser_is_not_modal():
    from ui.wizard import ToolChooser

    chooser = ToolChooser(on_pick=lambda k: None)
    try:
        assert chooser.get_modal() is False, \
            "a modal hub blocks clicks and closes everywhere else"
    finally:
        chooser.destroy()


def test_setup_confirm_dialog_is_not_modal():
    from wizard.ui_pages import SetupWizard

    wiz = SetupWizard(win=None)
    dlg = wiz._ask_confirm(None)
    try:
        assert dlg.get_modal() is False, \
            "the apply confirm must not lock the wizard window"
    finally:
        dlg.destroy()


@pytest.mark.gtk
def test_wizard_still_closes_with_confirm_open():
    # The regression shape: confirm dialog up, owner clicks the wizard's
    # own close button. GTK must close the wizard; the confirm (transient,
    # destroy-with-parent) goes with it.
    from wizard.ui_pages import SetupWizardWindow

    win = SetupWizardWindow()
    try:
        dlg = Gtk.Dialog(title="confirm")
        dlg.set_transient_for(win)
        dlg.set_destroy_with_parent(True)
        dlg.present()
        win.close()
        _pump_until(lambda: not win.get_mapped(), seconds=5.0)
        assert not win.get_mapped(), \
            "the wizard must close even with a dialog over it"
    finally:
        win.destroy()


def _pump_until(pred, seconds):
    from gi.repository import GLib as gl
    ctx = gl.main_context_default()
    end = gl.get_monotonic_time() + int(seconds * 1e6)
    while gl.get_monotonic_time() < end:
        for _ in range(500):         # bounded: a pending storm
            # must never pin the harness (load-livelock fix 11-07)
            if not ctx.pending():
                break
            ctx.iteration(False)
            if gl.get_monotonic_time() > end:
                return               # one dispatch may itself run long

        if pred():
            return
        ctx.iteration(True)
