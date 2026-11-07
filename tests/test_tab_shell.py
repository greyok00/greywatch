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
    # _glib_ids[0] is the 5s periodic refresh, which recomputes the
    # Firewall badge from the machine's live data dir; a tick landing
    # inside a pump() would rewrite a badge under an active assertion.
    # These tests assert the shell's own badge API, so the machine tick
    # is silenced (the 1s scan tick stays: it paints scan state only).
    if getattr(w, "_glib_ids", None):
        GLib.source_remove(w._glib_ids[0])
        w._glib_ids.remove(w._glib_ids[0])
    yield w
    w.destroy()


# The rail, rebuild Phase 4: four pages, then the footer pair.
RAIL_KEYS = ("overview", "defense", "services", "auditlog",
             "settings", "help")


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


def test_rail_renders_four_pages_and_a_footer(win):
    """The rail the rebuild approved: the four pages down the bar, the
    Settings/Help pair pinned at its bottom, every row carries its
    glyph-plus-label, the bar carries the .gw-rail class."""
    from ui.shell import RAIL, RAIL_FOOTER
    assert tuple(win._tabs) == RAIL_KEYS == \
        tuple(k for _g, rows in RAIL for k, _l in rows) + \
        tuple(k for _g, rows in (RAIL_FOOTER,) for k, _l in rows)
    old_rail_keys = ("home", "thunter", "scans", "protect", "tools",
                     "harden", "logs")
    for gone in old_rail_keys:
        assert gone not in shell_rail_keys(), gone
    from ui.themes import gtk_css, load_themes
    css = gtk_css(load_themes()["aperture"])
    for key in RAIL_KEYS:
        assert rail_row_label(win._tabs[key]), key
    assert rail_row_label(win._tabs["overview"]) == "Overview"
    assert rail_row_label(win._tabs["defense"]) == "Firewall"
    assert rail_row_label(win._tabs["services"]) == "Services"
    assert rail_row_label(win._tabs["auditlog"]) == "Activity Log"
    assert "gw-rail" in win.rail_bar.get_css_classes()
    assert "button.gw-active" in css and ".gw-badge" in css


def shell_rail_keys():
    from ui import shell
    return set(k for _g, rows in (shell.RAIL + (shell.RAIL_FOOTER,))
               for k, _l in rows)


def test_launch_opens_overview_with_ai(win):
    """Overview is the main screen: the assistant conversation lives on
    its right column."""
    assert win.stack.get_visible_child_name() == "overview"
    page = win.stack.get_visible_child()
    assert page is not None
    parent, found = win.overview_page._assistant.get_parent(), False
    while parent is not None and not found:
        found = parent is page
        parent = parent.get_parent()
    assert found, "the assistant conversation is not on the Overview page"
    assert "gw-active" in win._tabs["overview"].get_css_classes()


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
    assert rail_row_label(win._tabs["defense"]) == "Firewall"


def test_activity_log_is_a_real_stack_page(win):
    win._show("auditlog")
    pump(10)
    assert win.stack.get_visible_child_name() == "auditlog"
    page = win.auditlog_page
    assert page._decisions is not None and page._quarantines is not None
    assert rail_row_label(win._tabs["auditlog"]) == "Activity Log"


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
    win._show("services")
    pump(4)
    assert getattr(win._symbols["services"], "_gw_active") is True
    assert getattr(win._symbols["overview"], "_gw_active") is False
    win._show("defense")
    pump(4)
    assert getattr(win._symbols["defense"], "_gw_active") is True
    assert getattr(win._symbols["services"], "_gw_active") is False


def test_retired_keys_keep_working(win):
    """Assistant intents and older callers still say 'harden' or 'scans';
    each lands on the page that absorbed it through one central map."""
    from ui.window import _LEGACY_PAGE as routes
    for old, new in (("home", "overview"), ("thunter", "defense"),
                     ("scans", "services"), ("protect", "services"),
                     ("tools", "services"), ("harden", "services"),
                     ("logs", "auditlog")):
        assert routes.get(old) == new, old
        win._show(old)
        pump(6)
        assert win.stack.get_visible_child_name() == new, old


def test_rail_badge_counts_unread(win):
    win.set_badge("defense", 2)
    pump(4)
    badge = win._badges["defense"]
    assert badge.get_visible() and badge.get_text() == "2"
    win.set_badge("defense", 0)
    pump(4)
    assert not badge.get_visible()


def test_footer_pages_carry_badges_too(win):
    """Every rail row obeys the same badge contract, footer included."""
    win.set_badge("settings", 1)
    pump(4)
    assert win._badges["settings"].get_text() == "1"
    assert win._badges["settings"].get_visible()
    win.set_badge("settings", 0)
    pump(4)
    assert not win._badges["settings"].get_visible()


def test_setup_launcher_reachable(win):
    """The wizard stays; the shell carries its launcher (header bar)."""
    assert win.setup_btn is not None
    assert win.setup_btn.get_sensitive()


def test_firewall_page_renders_the_published_browser_watch_digest(
        win, monkeypatch):
    """GW-118 re-rooted (Phase 4): the feed relied on the one-second live
    tick, so a freshly opened page could show its empty state first.
    The Firewall page must render the daemon's published digest the
    moment it opens, with no timer."""
    import ui.window as W
    snap = {
        "browser_watch": [{
            "id": "gw118", "ts": "2026-11-03T11:00:00+00:00",
            "rule": "rule-gw118",
            "title": "Download used a double extension",
            "what": "What happened.", "next": "Next step.",
            "severity": "HIGH", "facts": [], "evidence": [],
            "hunter": "1", "asset": "browser"}],
    }
    monkeypatch.setattr(W.daemon_mod, "load_status",
                        lambda *a, **k: dict(snap))
    win._show("defense")
    pump(5)
    view = win.defense_view
    assert view._watch is not None
    text = " ".join(str(lbl.get_text()) for lbl in _labels(view._watch))
    assert "double extension" in text


def _labels(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        if isinstance(c, Gtk.Label):
            out.append(c)
        out.extend(_labels(c))
        c = c.get_next_sibling()
    return out
