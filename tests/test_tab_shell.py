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


TABS = ("home", "scans", "protect", "tools", "thunter", "settings")


def tab_label_text(btn):
    """The tab plate (GW-121) is a vertical box: a drawn symbol over a
    row (label + badge); the name is the first Gtk.Label in the plate."""
    child = btn.get_child()
    if isinstance(child, Gtk.Label):
        return child.get_text()
    for piece in child:
        if isinstance(piece, Gtk.Box):
            for c in piece:
                if isinstance(c, Gtk.Label):
                    return c.get_text()
    return ""


def tab_symbol_area(win, key):
    """The DrawingArea each tab carries for its glyph (GW-121 plates)."""
    return getattr(win, "_symbols", {}).get(key)


def test_six_tabs_render(win):
    """The shell the owner approved, GW-121 order: the suite pages
    (Home, Scans, Protections, Tools) lead, Threat Hunter supports them,
    Settings lasts — one bar, uppercase mono labels. The uppercase is
    the `.gw-tab-label` CSS (text-transform), so the pin is the class
    plus its rule, not the raw text."""
    assert tuple(win._tabs) == TABS
    from ui.themes import gtk_css, load_themes
    css = gtk_css(load_themes()["aperture"])
    for key in TABS:
        assert tab_label_text(win._tabs[key]), key
    assert "gw-tabs" in win.tab_bar.get_css_classes()
    assert "text-transform: uppercase; font-family:" in css
    assert ".gw-badge" in css and "background-color:" in css


def test_launch_opens_home_with_ai(win):
    """Home is the main screen: the assistant conversation lives there."""
    assert win.stack.get_visible_child_name() == "home"
    page = win.stack.get_visible_child()
    assert page is not None
    # The chat must be a descendant of the page the stack shows.
    parent, found = win.assistant_panel.get_parent(), False
    while parent is not None and not found:
        found = parent is page
        parent = parent.get_parent()
    assert found, "the assistant conversation is not on the Home page"
    assert "gw-tab-on" in win._tabs["home"].get_css_classes()


def test_thunter_is_a_real_stack_page(win):
    win._show("thunter")
    pump(10)
    assert win.stack.get_visible_child_name() == "thunter"
    # The hunter's own panel is the page body: same component that renders
    # findings.jsonl today, promoted to its own tab.
    assert win.hunter_panel is not None
    assert tab_label_text(win._tabs["thunter"]) == "Threat Hunter"


def test_every_tab_switches(win):
    for key in TABS:
        win._show(key)
        pump(6)
        assert win.stack.get_visible_child_name() == key, key
        assert "gw-tab-on" in win._tabs[key].get_css_classes(), key
        for other in TABS:
            if other != key:
                assert "gw-tab-on" not in win._tabs[other].get_css_classes()


def test_every_tab_carries_a_symbol(win):
    """GW-121 plates: every tab carries its own drawn glyph widget — no
    tab is text-only, nothing shares one DrawingArea."""
    seen = set()
    for key in TABS:
        sym = tab_symbol_area(win, key)
        assert sym is not None, key
        assert sym not in seen, f"{key} reuses another tab's glyph"
        seen.add(sym)
    # The glyphs are painted in the shell's own style sheet, so a plate
    # bar without the rule would draw invisible.
    from ui.themes import gtk_css, load_themes
    css = gtk_css(load_themes()["aperture"])
    assert ".gw-tabs" in css and "border-radius: 10px" in css
    assert "button.gw-tab-on" in css and "border-color:" in css


def test_symbol_activation_follows_the_shown_tab(win):
    """GW-121: the active tab's glyph draws in accent, every resting one
    in ink_soft — the same flip that moves `gw-tab-on`, not a redraw on
    a timer."""
    win._show("scans")
    pump(4)
    assert getattr(win._symbols["scans"], "_gw_active") is True
    assert getattr(win._symbols["home"], "_gw_active") is False
    win._show("thunter")
    pump(4)
    assert getattr(win._symbols["thunter"], "_gw_active") is True
    assert getattr(win._symbols["scans"], "_gw_active") is False


def test_suite_card_leads_home(win):
    """GW-121 suite first: on Home the protections verdict card sits ABOVE
    the hunter digest and above the conversation — the suite reads before
    the hunter that supports it. The walk is document order over the
    whole page, so the aperture clamp's single wrap point cannot move
    what the owner reads first."""
    page = win._views["home"]
    order = []

    def walk(x):
        for c in x.observe_children():
            order.append(c)
            walk(c)

    walk(page)
    if win.suite_card not in order:
        order = [page] + order
    assert win.suite_card in order, "the suite verdict card is not on Home"
    after = order[order.index(win.suite_card) + 1:]
    assert win.digest in after, "digest must follow the suite card"
    panel = getattr(win, "assistant_panel", None)
    if panel is not None:
        assert panel in after, "chat must follow the suite card"


def test_legacy_chat_keys_keep_working(win):
    """Assistant intents and older callers still say 'security' and 'deep';
    they land on the Protections page through one central map."""
    for old, new in (("security", "protect"), ("deep", "protect")):
        win._show(old)
        pump(6)
        assert win.stack.get_visible_child_name() == new, old


def test_thunter_badge_counts_unread(win):
    win.set_badge("thunter", 2)
    pump(4)
    badge = win._badges["thunter"]
    assert badge.get_visible() and badge.get_text() == "2"
    win.set_badge("thunter", 0)
    pump(4)
    assert not badge.get_visible()


def test_setup_launcher_reachable(win):
    """The wizard stays; the shell carries its launcher (header bar)."""
    assert win.setup_btn is not None
    assert win.setup_btn.get_sensitive()

def test_thunter_feed_paints_the_moment_the_tab_opens(tmp_path,
                                                      monkeypatch):
    """GW-118 (2026-11-03): the feed relied on the one-second live tick,
    so a freshly opened tab could show its empty state first. Opening the
    tab must render what the hunter already wrote, with no timer."""
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
        assert panel._findings, "the feed is empty right after the tab opens"
        rows = [x for x in panel._list.observe_children()
                if hasattr(x, "_gw_finding_id")]
        assert len(rows) == 1
    finally:
        w.destroy()
