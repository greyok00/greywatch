"""Bug-sweep sizing checks that need a real (or Xvfb) display:

- the setup wizard's stack scroller CLAIMS the spare height (the S1 slit:
  without vexpand the page showed through a 38px scrollbar-minimum band);
- the preview table's columns fit the 768px page card at the wizard
  window's default size (no cut "App|" header);
- the preview card stays height-bounded (scrolls, never eats the window);
- Pause/Resume/Details dim with no selection and light up with one (B5).
"""
import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib  # noqa: E402


def _gtk_ready() -> bool:
    try:
        if not Gtk.init_check():
            return False
        from gi.repository import Gdk
        return Gdk.Display.get_default() is not None
    except Exception:
        return False


if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display, never the owner's desktop.", allow_module_level=True)
if not _gtk_ready():
    pytest.skip("no display available", allow_module_level=True)


def pump(n=30):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


@pytest.fixture
def sw_win():
    from wizard.ui_pages import SetupWizardWindow
    w = SetupWizardWindow(parent=None, open_dashboard=lambda: None,
                          open_chooser=lambda: None)
    w.present()
    pump(30)
    yield w
    w.destroy()
    pump(10)


def test_stack_scroller_fills_the_window(sw_win):
    kid = sw_win.get_child()
    sc = next(w for w in _walk(kid) if isinstance(w, Gtk.ScrolledWindow))
    # The S1 slit: the scroller's allocation must be the box's spare
    # height, not its 38px scrollbar minimum.
    kid_h = kid.get_height()
    assert sc.get_height() >= 300, (
        f"stack scroller got {sc.get_height()}px of {kid_h}px — the page "
        f"shows through a slit (S1 regression)")
    page = sw_win.wizard.stack.get_visible_child()
    assert page is not None
    assert page.get_height() >= min(500, sc.get_height() - 40)


def test_preview_columns_fit_the_page_card(sw_win):
    """Measurement, not allocation: the treeview's horizontal minimum
    (fixed column widths) must fit a 800px wizard floor — at the design
    960px default the sum measured 730px against a 730px view."""
    sw_win.wizard._step("preview")
    pump(30)
    view = sw_win.wizard._table_view
    mn = view.measure(Gtk.Orientation.HORIZONTAL, -1)[0]
    assert 0 < mn <= 745, (
        f"preview table needs {mn}px — past 745 the headers clip in the "
        f"800px wizard floor")


def test_preview_table_scroller_is_bounded(sw_win):
    sw_win.wizard._step("preview")
    pump(20)
    # max_content_height is set, so the card can never eat the window.
    assert sw_win.wizard._table_wrap.get_max_content_height() == 400


def _walk(w):
    ch = w.get_first_child()
    while ch is not None:
        yield ch
        ch = ch.get_next_sibling()


def test_selection_buttons_follow_selection():
    """B5: the footer trio dims with no selection and acts once one is
    picked — sync runs wherever _selected_tool changes."""
    from ui.window import MainWindow

    seen = []

    class Btn:
        def set_sensitive(self, v):
            seen.append(v)

    fake = type("W", (), {})()
    fake._selected_tool = None
    fake.pause_btn, fake.resume_btn, fake.details_btn \
        = Btn(), Btn(), Btn()
    MainWindow._sync_selection_buttons(fake)
    assert seen == [False, False, False]

    fake._selected_tool = "ufw"
    MainWindow._sync_selection_buttons(fake)
    assert seen == [False, False, False, True, True, True]


@pytest.fixture
def main_win(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui.window import MainWindow
    w = MainWindow()
    w.present()
    pump(30)
    yield w
    w.destroy()
    pump(5)


def test_chat_feed_keeps_a_floor(main_win):
    """Wave-3 sweep: at the 1028x706 window floor the transcript scroller
    squeezed to a ~30px slit (one clipped line). A 160px size-request
    floor keeps a turn readable; the activity table below yields."""
    panel = main_win.assistant_panel
    req_w, req_h = panel._stream_scroll.get_size_request()
    assert req_h == 160


def test_rule_wizard_sidebar_fits_the_longest_title():
    """Wave-3 sweep: Gtk.Assistant's sidebar labels clip hard at the
    sidebar edge (nothing ellipsizes them), so the default width must
    cover the longest page title."""
    from ui.wizard import RuleWizard

    wz = RuleWizard("arpwatch", parent=None)     # longest titles
    pump(20)
    w, _h = wz.get_default_size()
    assert w > 700, f"arpwatch wizard unchanged at {w}px"
    widest = 0
    for i in range(wz.get_n_pages()):
        probe = Gtk.Label(label=wz.get_page(
            wz.get_nth_page(i)).get_property("title") or "")
        widest = max(widest, probe.measure(
            Gtk.Orientation.HORIZONTAL, -1)[1])
    assert w >= widest + 500, (
        f"wizard {w}px vs longest title {widest}px — the sidebar clips")
    wz.destroy()