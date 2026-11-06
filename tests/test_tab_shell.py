import os
import sys
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


@pytest.fixture(scope="module")
def win():
    from ui.window import MainWindow
    w = MainWindow()
    w.present()
    pump(30)
    yield w
    w.destroy()


# The rail, wave D: the two-system directive made into navigation.
RAIL_KEYS = ("home", "thunter", "defense", "scans", "protect", "tools",
             "harden", "logs", "settings", "help")


def rail_row_label(btn):
    """The rail row is a horizontal box: drawn glyph, name, badge; the
    page name is the first Gtk.Label carrying gw-rail-label."""
    child = btn.get_child()
    for piece in child:
        if isinstance(piece, Gtk.Label) \
                and piece.has_css_class("gw-rail-label"):
            return piece.get_text()
    return ""


def glyph_area(win, key):
    return getattr(win, "_symbols", {}).get(key)


def test_rail_renders_grouped(win):
    """The shell the owner approved, wave D: grouped pages down the left
    edge (Watch, Defense, Care, System), every rail row carries its
    glyph-plus-label, the bar carries the .gw-rail class."""
    from ui.shell import RAIL
    assert tuple(win._tabs) == RAIL_KEYS == \
        tuple(k for _g, rows in RAIL for k, _l in rows)
    from ui.themes import gtk_css, load_themes
    css = gtk_css(load_themes()["aperture"])
    for key in RAIL_KEYS:
        assert rail_row_label(win._tabs[key]), key
    assert "gw-rail" in win.rail_bar.get_css_classes()
    assert ".gw-rail-head" in css and "text-transform: uppercase" in css
    assert "button.gw-active" in css and ".gw-badge" in css


def test_launch_opens_home_with_ai(win):
    """Home is the main screen: the assistant conversation lives there."""
    assert win.stack.get_visible_child_name() == "home"
    page = win.stack.get_visible_child()
    assert page is not None
    parent, found = win.assistant_panel.get_parent(), False
    while parent is not None and not found:
        found = parent is page
        parent = parent.get_parent()
    assert found, "the assistant conversation is not on the Home page"
    assert "gw-active" in win._tabs["home"].get_css_classes()


def test_defense_is_a_real_stack_page(win):
    win._show("defense")
    pump(10)
    assert win.stack.get_visible_child_name() == "defense"
    # The defense desk built and painted: the view exists, its section
    # bodies exist, and its side-line class puts it in the threat lane.
    view = win.defense_view
    assert view is not None
    assert view._blocked is not None and view._asks is not None \
        and view._armor is not None
    assert "gw-lane-threat" in view.get_css_classes()
    assert rail_row_label(win._tabs["defense"]) == "Defense"


def test_every_page_switches(win):
    for key in RAIL_KEYS:
        win._show(key)
        pump(6)
        assert win.stack.get_visible_child_name() == key, key
        assert "gw-active" in win._tabs[key].get_css_classes(), key
        for other in RAIL_KEYS:
            if other != key:
                assert "gw-active" not in win._tabs[other].get_css_classes()


def test_every_row_carries_a_symbol(win):
    """One drawn glyph per row - no row is text-only, nothing shares a
    DrawingArea."""
    seen = set()
    for key in RAIL_KEYS:
        sym = glyph_area(win, key)
        assert sym is not None, key
        assert sym not in seen, f"{key} reuses another row's glyph"
        seen.add(sym)
    from ui.themes import gtk_css, load_themes
    css = gtk_css(load_themes()["aperture"])
    assert ".gw-rail button.gw-active" in css


def test_symbol_activation_follows_the_shown_page(win):
    win._show("scans")
    pump(4)
    assert getattr(win._symbols["scans"], "_gw_active") is True
    assert getattr(win._symbols["home"], "_gw_active") is False
    win._show("defense")
    pump(4)
    assert getattr(win._symbols["defense"], "_gw_active") is True
    assert getattr(win._symbols["scans"], "_gw_active") is False


def test_legacy_keys_keep_working(win):
    """Assistant intents and older callers still say 'security' and
    'deep'; they land on the Protections page through one central map."""
    for old, new in (("security", "protect"), ("deep", "protect")):
        win._show(old)
        pump(6)
        assert win.stack.get_visible_child_name() == new, old


def test_rail_badge_counts_unread(win):
    win.set_badge("thunter", 2)
    pump(4)
    badge = win._badges["thunter"]
    assert badge.get_visible() and badge.get_text() == "2"
    win.set_badge("thunter", 0)
    pump(4)
    assert not badge.get_visible()


def test_defense_badge_is_reachable_too(win):
    """The Defense desk is a first-class rail row: its badge obeys the
    same counts as the hunter's."""
    win.set_badge("defense", 1)
    pump(4)
    assert win._badges["defense"].get_text() == "1"
    assert win._badges["defense"].get_visible()
    win.set_badge("defense", 0)
    pump(4)
    assert not win._badges["defense"].get_visible()


def test_setup_launcher_reachable(win):
    """The wizard stays; the shell carries its launcher (header bar)."""
    assert win.setup_btn is not None
    assert win.setup_btn.get_sensitive()


def test_thunter_feed_paints_the_moment_the_page_opens(tmp_path):
    """GW-118 (2026-11-03): the feed relied on the one-second live tick,
    so a freshly opened page could show its empty state first. Opening
    the page must render what the hunter already wrote, with no timer."""
    from hunter import store
    from ui.window import MainWindow
    store.append_finding(tmp_path, {
        "id": "gw118", "ts": "2026-11-03T11:00:00+00:00",
        "rule": "rule-gw118", "title": "Download used a double extension",
        "what": "What happened.", "next": "Next step.",
        "severity": "HIGH", "facts": [], "evidence": [], "hunter": "1"})
    store.append_defender(tmp_path, {
        "ts": "2026-11-03T11:01:00+00:00", "kind": "rule",
        "finding_id": "gw118", "severity": "HIGH",
        "text": "Note.", "hint": "Hint."})
    w = MainWindow()
    w.present()
    pump(10)
    w.data_dir = tmp_path
    try:
        w._show("thunter")
        pump(5)
        panel = w.hunter_panel
        assert panel is not None and panel.data_dir == tmp_path
        assert panel._findings, "the feed is empty right after the page opens"
        rows = [x for x in panel._list.observe_children()
                if hasattr(x, "_gw_finding_id")]
        assert len(rows) == 1
    finally:
        w.destroy()
