from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk    # noqa: E402


# The rail (rebuild round 2, task 2): the owner's ten-page menu restored.
# HEADINGS[0], Overview, is the large clickable home row itself and holds
# no group; group i of RAIL renders under HEADINGS[i + 1] (Care, Defense,
# System). The rows route through the window's one legacy map into the
# pane stack: the Care rows all serve the Services page, thunter shares
# the Firewall page with defense, logs lands on the Activity Log.
HEADINGS = ("Overview", "Care", "Defense", "System")
RAIL = (
    ("scans", "protect", "tools", "harden"),
    ("defense", "thunter"),
    ("logs", "settings", "help"),
)

RAIL_KEYS = tuple(key for keys in RAIL for key in keys)

RAIL_LABELS = {
    "overview": "Overview",
    "scans": "Scans", "protect": "Protections", "tools": "Tools",
    "harden": "Harden", "defense": "Firewall", "thunter": "Browser Watch",
    "logs": "Activity Log", "settings": "Settings", "help": "Help",
}

# Keys the old tab shell knew that are not rail rows: they stay openable
# (deep links, assistant words) through the pane stack, just not listed.
HIDDEN_KEYS = ("diagnostics",)

# The sun/moon footer: the button shows the voice you would switch TO.
_VOICE_GLYPH = {"graphite": "☀", "paper": "☾"}
_VOICE_TIP = {"graphite": "Switch to the paper light voice",
              "paper": "Switch to the graphite dark voice"}


def rail_size(win_width: int) -> int:
    """About five percent of the window, floored and capped: 150 so the
    labels always fit, 200 so very wide panels never balloon the rail.
    The rail is FIXED at this width - it never collapses to glyphs."""
    return max(150, min(200, round(win_width * 0.05)))


def build_rail(win):
    """The sidebar: Overview as the large clickable home title, then the
    three heading groups with their rows. Rows expose win._tabs[key]
    (the button), win._badges[key] and win._symbols[key] with the tab
    shell's per-key semantics, so the badge and activation code never
    learns the rail exists."""
    win._tabs = {}
    win._badges = {}
    win._symbols = {}
    win._rail_rows = {}
    bar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    bar.add_css_class("gw-rail")

    home = _rail_row(win, "overview")
    home.add_css_class("gw-rail-home")
    win._rail_rows["overview"] = home
    bar.append(home)

    for heading, keys in zip(HEADINGS[1:], RAIL):
        head = Gtk.Label(label=heading, xalign=0)
        head.add_css_class("gw-rail-head")
        win._rail_rows[f"@{heading}"] = head
        bar.append(head)
        for key in keys:
            row = _rail_row(win, key)
            win._rail_rows[key] = row
            bar.append(row)
    win.rail_bar = bar
    return bar


def _rail_row(win, key):
    """One rail row: glyph, label, unread badge - the same shape for the
    home title and every menu row, so one code path drives them all."""
    b = Gtk.Button()
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    sym = win_glyph(key, 18)
    sym.set_halign(Gtk.Align.CENTER)
    sym.set_valign(Gtk.Align.CENTER)
    row.append(sym)
    win._symbols[key] = sym
    lb = Gtk.Label(label=RAIL_LABELS.get(key, key))
    lb.xalign = 0.0
    lb.add_css_class("gw-rail-label")
    # No hexpand here: an expanding label makes THIS bar compute as
    # expanding, and the page stack's body then hands it half the
    # spare width ( GTK walks descendants for expansion). Rows span
    # the bar without it; the badge simply follows the name.
    row.append(lb)
    badge = Gtk.Label(label="0")
    badge.add_css_class("gw-badge")
    badge.set_visible(False)
    badge.set_valign(Gtk.Align.CENTER)
    row.append(badge)
    b.set_child(row)
    b.set_tooltip_text(RAIL_LABELS.get(key, key))
    b.connect("clicked", win._tab_pick, key)
    win._tabs[key] = b
    win._badges[key] = badge
    return b


def set_theme_toggle(win):
    """The rail footer: an expanding spacer pins the sun/moon button to
    the bar's bottom-left corner. The button itself is window-level - it
    signals window._toggle_voice(), which flips the voice through the
    theme seam and re-applies the CSS."""
    spacer = Gtk.Box()
    spacer.set_vexpand(True)
    win.rail_bar.append(spacer)
    btn = Gtk.Button()
    btn.add_css_class("gw-voice-toggle")
    btn.set_halign(Gtk.Align.START)
    btn.set_label(_voice_glyph())
    btn.set_tooltip_text(_voice_tip())
    btn.connect("clicked", lambda *_a: win._toggle_voice())
    win._voice_btn = btn
    win.rail_bar.append(btn)
    return btn


def _voice_glyph():
    from ui.themes import active_theme
    return _VOICE_GLYPH.get(active_theme(), _VOICE_GLYPH["graphite"])


def _voice_tip():
    from ui.themes import active_theme
    return _VOICE_TIP.get(active_theme(), _VOICE_TIP["graphite"])


def voice_toggle_sync(win):
    """Re-dress the sun/moon for the voice now in charge, so the button
    always shows the voice clicking it would bring."""
    btn = getattr(win, "_voice_btn", None)
    if btn is not None:
        btn.set_label(_voice_glyph())
        btn.set_tooltip_text(_voice_tip())


def win_glyph(key, size=22):
    """The rail row's drawn glyph - the tab plates' cairo glyphs, reused
    for the sidebar so one icon language covers the shell."""
    from ui.themes import tab_symbol
    return tab_symbol(key, size)
