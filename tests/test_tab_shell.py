import os
import sys
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ui import shell  # noqa: E402 — the rail's shape is pinned module-wide

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


# The rail, rebuild round 2 (task 2): the owner's ten-page menu restored.
# Overview is the home row; these are the nine menu rows in group order.
RAIL_KEYS = ("scans", "protect", "tools", "harden", "defense", "thunter",
             "logs", "settings", "help")

RAIL_LABELS = ("Scans", "Protections", "Tools", "Harden", "Firewall",
               "Browser Watch", "Activity Log", "Settings", "Help")


def test_rail_groups_and_order():
    rows = [k for keys in shell.RAIL for k in keys]
    assert rows == list(RAIL_KEYS)
    assert shell.HEADINGS == ("Overview", "Care", "Defense", "System")


def test_rail_never_collapses():
    assert not hasattr(shell, "NARROW_RAIL") and not hasattr(shell, "collapse_rail")
    assert not hasattr(shell, "rail_pinned")


def test_rail_width_is_five_percent():
    """rail_size = max(150, min(200, round(w*0.05))): 150 floors the
    labels, 200 caps the widest panels."""
    assert shell.rail_size(1200) == 150        # the floor holds labels
    assert shell.rail_size(2400) == 150        # 5% = 120 -> the floor wins
    assert shell.rail_size(3600) == 180
    assert shell.rail_size(9999) == 200        # the cap holds


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


def test_rail_renders_the_owner_ten_page_menu(win):
    """The owner-verified rail: Overview as the large clickable home
    title, then the Care / Defense / System groups; every row carries
    its glyph-plus-label; the bar carries the .gw-rail class."""
    assert tuple(win._tabs) == ("overview",) + RAIL_KEYS
    assert tuple(k for keys in shell.RAIL for k in keys) == RAIL_KEYS
    assert "gw-rail" in win.rail_bar.get_css_classes()
    assert rail_row_label(win._tabs["overview"]) == "Overview"
    for key, label in zip(RAIL_KEYS, RAIL_LABELS):
        assert rail_row_label(win._tabs[key]) == label, key


def test_group_headings_render_under_the_owner_names(win):
    """Group i of RAIL renders under HEADINGS[i+1]: Care, Defense,
    System; Overview is HEADINGS[0] itself — the home row, rendered as
    the large clickable title, not a plain heading label."""
    for heading in ("@Care", "@Defense", "@System"):
        head = win._rail_rows[heading]
        assert isinstance(head, Gtk.Label), heading
        assert head.get_visible()
        assert head.get_text() == heading[1:]
    # a button, not a label: the home row is clickable
    assert isinstance(win._rail_rows["overview"], Gtk.Button)
    assert "@Overview" not in win._rail_rows


def test_launch_opens_overview_with_ai(win):
    """Overview is the main screen: the assistant conversation lives on
    its right column, and the home row reads active."""
    assert win.stack.get_visible_child_name() == "overview"
    page = win.stack.get_visible_child()
    assert page is not None
    parent, found = win.overview_page._assistant.get_parent(), False
    while parent is not None and not found:
        found = parent is page
        parent = parent.get_parent()
    assert found, "the assistant conversation is not on the Overview page"
    assert "gw-active" in win._tabs["overview"].get_css_classes()


def test_care_group_row_routes_resolve(win):
    """Every menu row opens its page through the one legacy map: the
    four Care rows land on Services, logs joins the Activity Log - and
    thunter is its own page again (rebuild round 2, task 8: the Threat
    Hunter's cards returned from the fold-in)."""
    from ui.window import _LEGACY_PAGE as routes
    win._show("scans")
    pump(6)
    assert win.stack.get_visible_child_name() == "services"
    for key, page in (("protect", "services"), ("tools", "services"),
                      ("harden", "services"), ("thunter", "thunter"),
                      ("logs", "auditlog")):
        assert routes.get(key, key) == page, key
        win._show(key)
        pump(6)
        assert win.stack.get_visible_child_name() == page, key
        assert "gw-active" in win._tabs[key].get_css_classes(), key


def test_care_group_lights_as_one_group(win):
    """The Care menu rows all route to the Services page, and the active
    row styling follows the shown page, so all four read as the open
    group; rows of other groups stay dark."""
    win._show("scans")
    pump(6)
    assert win.stack.get_visible_child_name() == "services"
    for key in ("scans", "protect", "tools", "harden"):
        assert "gw-active" in win._tabs[key].get_css_classes(), key
    for key in ("defense", "thunter", "logs", "settings", "help",
                "overview"):
        assert "gw-active" not in win._tabs[key].get_css_classes(), key


def test_every_page_switches(win):
    for key in ("overview",) + RAIL_KEYS:
        win._show(key)
        pump(6)
        assert "gw-active" in win._tabs[key].get_css_classes(), key


def test_every_row_carries_a_symbol(win):
    """One drawn glyph per row - no row is text-only, nothing shares a
    DrawingArea."""
    seen = set()
    for key in ("overview",) + RAIL_KEYS:
        sym = glyph_area(win, key)
        assert sym is not None, key
        assert sym not in seen, f"{key} reuses another row's glyph"
        seen.add(sym)
    from ui.themes import gtk_css, load_themes
    css = gtk_css(load_themes()["graphite"])
    assert ".gw-rail button.gw-active" in css


def test_rail_badge_counts_unread(win):
    win.set_badge("defense", 2)
    pump(4)
    badge = win._badges["defense"]
    assert badge.get_visible() and badge.get_text() == "2"
    win.set_badge("defense", 0)
    pump(4)
    assert not badge.get_visible()


def test_footer_pages_carry_badges_too(win):
    """Every rail row obeys the same badge contract, System group
    included."""
    win.set_badge("settings", 1)
    pump(4)
    assert win._badges["settings"].get_text() == "1"
    assert win._badges["settings"].get_visible()
    win.set_badge("settings", 0)
    pump(4)
    assert not win._badges["settings"].get_visible()


def test_rail_bar_is_fixed_at_the_five_percent_law(win):
    """The rail is FIXED: the bar's minimum width follows the five
    percent law (floored, capped) and the collapse constants are gone —
    the window getting narrow never turns the rail glyph-only."""
    w, _h = win.rail_bar.get_size_request()
    assert w == shell.rail_size(win.get_allocated_width())
    assert 150 <= w <= 200
    assert not hasattr(win, "rail_collapsed")


def test_sun_moon_is_pinned_at_the_rail_footer(win):
    """The sun/moon voice toggle is the rail's last child, hugging the
    bottom-left under an expanding spacer."""
    btn = win._voice_btn
    assert btn is not None
    assert win.rail_bar.get_last_child() is btn
    assert btn.get_halign() == Gtk.Align.START
    assert "gw-voice-toggle" in btn.get_css_classes()
    spacer = btn.get_prev_sibling()
    assert spacer is not None and spacer.get_vexpand()


def test_sun_moon_click_flips_the_voice_and_persists(win, monkeypatch,
                                                     tmp_path):
    """Clicking the sun/moon flips graphite<->paper through the theme
    seam, persists the pick, and re-applies the CSS provider."""
    import json
    from ui import shell, themes
    monkeypatch.setattr(themes, "SETTINGS_PATH", tmp_path / "state.json")
    before = themes.active_theme()
    win._voice_btn.emit("clicked")
    pump(12)
    after = themes.active_theme()
    assert after != before, (before, after)
    assert after in themes.THEMES
    assert win._voice_btn.get_label() == shell._VOICE_GLYPH[after]
    assert win._voice_btn.get_tooltip_text() == shell._VOICE_TIP[after]
    saved = json.loads((tmp_path / "state.json").read_text())
    assert saved["theme"] == after
    # flip it back so later tests in this module start from the same place
    win._voice_btn.emit("clicked")
    pump(12)
    assert themes.active_theme() == before


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
