"""GW-174: every task popup opens at its content's height - no inner scroll.

The owner hit the same wall three ways ("the wizard box requires
scrolling... it should be large enough to fit all items inside one
window popup"): the setup wizard window, the tool chooser hub and the
rule wizard each shipped a fixed or floored height over an internal
ScrolledWindow, so the content a popup exists to show needed scrolling
inside the popup itself. Now each one measures its own content at the
reading width (GTK's widget.measure(VERTICAL, width) reports the full
natural height because the task scrollers use AUTOMATIC policy) and
opens at the taller of that and its screen-fraction floor. The internal
scroller remains as what happens when a panel is genuinely smaller than
the content, never as the default way to read a page.

Also pins the GW-178 sweep: no greywatch window may call
set_default_size with a raw fixed-pixel pair - every dialog routes
through the ui/metrics.py fraction helpers, and the only tolerated
literal is RuleWizard's pre-measure floor, overwritten by its measured
default before the window is ever shown.
"""
import pathlib
import re

import gi
import pytest

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib  # noqa: E402

pytestmark = pytest.mark.gtk

ROOT = pathlib.Path(__file__).resolve().parents[1]


def pump(n=60):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


def test_setup_wizard_window_fits_the_tallest_step():
    from ui import metrics
    from wizard.ui_pages import SetupWizardWindow

    win = SetupWizardWindow(parent=None, open_dashboard=lambda: None,
                            open_chooser=lambda: None)
    try:
        pump(40)
        w, h = win.get_default_size()
        base_w = metrics.wizard_size()[0]
        assert w == metrics.fit_window(base_w, -1,
                                       *metrics.screen_size())[0], \
            "the wizard must keep the task-scale width (GW-171 rule)"
        # The reading column the constructor measures at: GW-174 grew the
        # height from this measurement, so it cannot be smaller than it.
        column = metrics.span(w, 0.82, 540, 700)
        _mn, natural = win.wizard.measure(
            Gtk.Orientation.VERTICAL, column)[:2]
        assert h >= natural, (
            f"wizard window {h}px < the stack's natural {natural}px at the "
            f"reading column - a step would open with an internal scroll")
    finally:
        win.destroy()
        pump(10)


def test_tool_chooser_hub_fits_the_card_grid():
    from ui import metrics
    from ui.wizard import ToolChooser

    chooser = ToolChooser(on_pick=lambda k: None)
    try:
        pump(40)
        w, h = chooser.get_default_size()
        chooser_w = metrics.chooser_size()[0]
        assert w == chooser_w
        _mn, natural = chooser.measure(
            Gtk.Orientation.VERTICAL, w)[:2]
        assert h >= natural, (
            f"chooser {h}px < natural {natural}px - the picker list would "
            "scroll inside the hub (the fixed scroll floor is gone)")
    finally:
        chooser.destroy()
        pump(10)


def test_rule_wizard_height_follows_the_pages():
    from ui.wizard import RuleWizard

    wiz = RuleWizard(tool="ufw", parent=None)
    try:
        pump(40)
        w, h = wiz.get_default_size()
        _mn, natural = wiz.measure(Gtk.Orientation.VERTICAL, w)[:2]
        assert h >= 480, "the pre-measure floor fell out of RuleWizard"
        assert h >= natural, (
            f"rule wizard {h}px < its pages' natural {natural}px - a page "
            "would clip behind the assistant's internal scroll")
    finally:
        wiz.destroy()
        pump(10)


def test_no_window_ships_a_fixed_pixel_size_anymore():
    """GW-178 sweep: every set_default_size takes a metrics fraction or a
    measured value; the two literals left are deliberate: RuleWizard's
    pre-measure floor (its measured default overwrites it before the
    window shows) and the mini tile's fixed 150px floating pill."""
    offenders = []
    for py in list(ROOT.glob("ui/*.py")) + list(ROOT.glob("wizard/*.py")):
        for line in py.read_text().splitlines():
            if re.search(r"set_default_size\(\s*\d", line):
                offenders.append(line.strip())
    assert offenders == sorted([
        "self.set_default_size(150, 150)",
        "self.set_default_size(700, 480)"]), offenders


def test_popup_and_dialog_helpers_stay_within_their_bands():
    from ui import metrics

    sw, sh = metrics.screen_size()
    if not sw or not sh:
        # displayless pins
        assert metrics.popup_size() == (560, -1)
        assert metrics.dialog_size() == (760, 540)
    pw, ph = metrics.popup_size()
    assert ph == -1, "ask popups stay content-height for the buttons"
    dw, dh = metrics.dialog_size()
    assert 520 <= pw <= 640, pw
    assert 660 <= dw <= 980, dw
    assert 540 <= dh <= 720, dh
