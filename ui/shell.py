from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk    # noqa: E402

from ui import metrics


# The rail: pages grouped the way the two-system directive thinks.
# Watch is the landing, Defense holds every threat-facing desk, Care holds
# the suite the keeper runs, System holds the service's own surfaces.
RAIL = (
    ("Watch", (("home", "Home"),)),
    ("Defense", (("thunter", "Threat Hunter"), ("defense", "Defense"))),
    ("Care", (("scans", "Scans"), ("protect", "Protections"),
              ("tools", "Tools"), ("harden", "Harden"))),
    ("System", (("logs", "Activity log"), ("settings", "Settings"),
                ("help", "Help"))),
)

RAIL_KEYS = tuple(key for _g, rows in RAIL for key, _l in rows)

# Keys the old tab shell knew that are not rail rows: they stay openable
# (deep links, assistant words) through the pane stack, just not listed.
HIDDEN_KEYS = ("diagnostics",)

WIDE_RAIL = 152        # label + glyph column
NARROW_RAIL = 52       # icons only, the window got too tight


def build_rail(win):
    """The sidebar: one button per page, grouped under the two-system
    headings. Rows expose win._tabs[key] (the button), win._badges[key]
    and win._symbols[key] with the tab shell's per-key semantics, so the
    badge and activation code never learns the rail exists."""
    win._tabs = {}
    win._badges = {}
    win._symbols = {}
    bar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    bar.add_css_class("gw-rail")
    win._rail_rows = {}
    for group, rows in RAIL:
        head = Gtk.Label(label=group, xalign=0)
        head.add_css_class("gw-rail-head")
        win._rail_rows[f"@{group}"] = head
        bar.append(head)
        for key, label in rows:
            b = Gtk.Button()
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            sym = win_glyph(key)
            sym.set_halign(Gtk.Align.CENTER)
            sym.set_valign(Gtk.Align.CENTER)
            row.append(sym)
            win._symbols[key] = sym
            lb = Gtk.Label(label=label)
            lb.xalign = 0.0
            lb.add_css_class("gw-rail-label")
            lb.set_hexpand(True)
            row.append(lb)
            badge = Gtk.Label(label="0")
            badge.add_css_class("gw-badge")
            badge.set_visible(False)
            badge.set_valign(Gtk.Align.CENTER)
            row.append(badge)
            b.set_child(row)
            b.set_tooltip_text(label)
            b.connect("clicked", win._tab_pick, key)
            bar.append(b)
            win._tabs[key] = b
            win._badges[key] = badge
            win._rail_rows[key] = b
    win.rail_bar = bar
    return bar


def win_glyph(key, size=22):
    """The rail row's drawn glyph - the tab plates' cairo glyphs, reused
    for the sidebar so one icon language covers the shell."""
    from ui.themes import tab_symbol
    return tab_symbol(key, size)


def rail_pinned(win) -> bool:
    """True while the window fits the labelled rail (design rule: the
    rail collapses to glyph-only when the window goes narrow)."""
    return win.get_allocated_width() >= 1100


def collapse_rail(win, narrow: bool):
    """Flip labels out when the window went narrow; glyphs stay. Group
    headings collapse with the labels - a glyph-only column keeps its
    tooltips, and the badge still counts."""
    if narrow == getattr(win, "rail_collapsed", None):
        return
    win.rail_collapsed = narrow
    for key, row in win._rail_rows.items():
        if key.startswith("@"):
            row.set_visible(not narrow)
            continue
        child = row.get_child()
        for piece in child:
            if isinstance(piece, Gtk.Label) \
                    and piece.has_css_class("gw-rail-label"):
                piece.set_visible(not narrow)


def rail_size(win) -> int:
    return NARROW_RAIL if getattr(win, "rail_collapsed", False) \
        else WIDE_RAIL
