"""Shared widgets for the new UI: the furniture every page builds from.

The vocabulary is the app's own: an eyebrow line, an uppercase headline,
state pills in the three marks, cards, and key-value rows. Nothing here
invents data; every value arrives from the page.
"""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango

from ui import themes


def eyebrow(text: str) -> Gtk.Label:
    lab = Gtk.Label()
    # upper first, escape second: uppercasing an entity (&amp;) would
    # break the markup parse. Size and colour live in the stylesheet so
    # the wide layout can scale them.
    lab.set_markup(
        f"<span weight='bold' letter_spacing='1400' "
        f"variant='small-caps'>{esc(text.upper())}</span>")
    lab.set_xalign(0.0)
    lab.add_css_class("gw-eyebrow")
    return lab


def headline(text: str) -> Gtk.Label:
    lab = Gtk.Label()
    lab.set_markup(
        f"<span weight='ultrabold'>{esc(text.upper())}</span>")
    lab.set_xalign(0.0)
    lab.add_css_class("gw-headline")
    return lab


def sub(text: str) -> Gtk.Label:
    lab = Gtk.Label(label=text)
    lab.add_css_class("gw-subtitle")
    lab.set_xalign(0.0)
    lab.set_wrap(True)
    # a full-width page must not run the body line across the panel: the
    # character cap sets the natural measure, and START makes the label's
    # allocation equal that measure instead of the whole card width
    lab.set_max_width_chars(90)
    lab.set_halign(Gtk.Align.START)
    return lab


def meta(text: str) -> Gtk.Label:
    lab = Gtk.Label(label=text)
    lab.add_css_class("gw-meta")
    lab.set_xalign(0.0)
    lab.set_wrap(True)
    lab.set_max_width_chars(90)
    lab.set_halign(Gtk.Align.START)
    return lab


MARK_LEVELS = {"ok": "gw-ok", "warn": "gw-warn", "fail": "gw-fail",
               "mute": "dim"}


def state_pill(word: str, level: str = "mute") -> Gtk.Label:
    """The state mark: the state word inside a pill, coloured by level
    (ok/warn/fail). Every page top carries one."""
    lab = Gtk.Label(label=str(word).upper())
    lab.add_css_class("gw-pill")
    lab.set_halign(Gtk.Align.START)
    lab.set_valign(Gtk.Align.CENTER)
    if level in ("ok", "warn", "fail"):
        lab.add_css_class(f"gw-pill-{level}")
    return lab


def mark_dot(level: str, size: int = 10) -> Gtk.DrawingArea:
    """A filled square dot in the level's colour; square edges, the
    brutal way, so a row reads its mark before its words."""
    area = Gtk.DrawingArea()
    area.set_size_request(size, size)
    colours = {"ok": themes.CURRENT.get("ok", "#3ddc84"),
               "warn": themes.CURRENT.get("warn", "#ffd23f"),
               "fail": themes.CURRENT.get("fail", "#ff4d4d")}
    colour = colours.get(level, themes.CURRENT.get("mute", "#9b9884"))

    def _draw(_a, cr, w, h):
        from ui.themes import _hex_rgba
        cr.set_source_rgba(*_hex_rgba(colour))
        m = min(w, h) * 0.18          # a small margin, still square
        cr.rectangle(m, m, w - 2 * m, h - 2 * m)
        cr.fill()

    area.set_draw_func(_draw)
    return area


def card(*children, cls: str = "gw-card") -> Gtk.Frame:
    """One card: a frame over a vertical box of children."""
    inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    for c in children:
        if c is not None:
            inner.append(c)
    frame = Gtk.Frame()
    for name in str(cls or "gw-card").split():
        frame.add_css_class(name)
    frame.set_child(inner)
    return frame


def kv_row(key: str, value: str, level: str = "mute") -> Gtk.Box:
    """One key - value line: key in ink-soft, value in the level colour,
    both plain sentences short enough to read once."""
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
    k = Gtk.Label(label=key)
    k.add_css_class("dim")
    k.set_xalign(0.0)
    k.set_hexpand(True)
    v = Gtk.Label(label=value)
    v.set_xalign(1.0)
    if level in ("ok", "warn", "fail"):
        v.add_css_class(f"gw-{level}")
    box.append(k)
    box.append(v)
    return box


def cta_button(text: str, on_click) -> Gtk.Button:
    b = Gtk.Button(label=text)
    b.add_css_class("gw-cta")
    b.set_halign(Gtk.Align.START)
    b.connect("clicked", on_click)
    return b


def count_word(n: int, word: str, plural=None) -> str:
    """A counted noun in plain words, never '(s)': one row, two rows,
    one address, three addresses. The law says no parenthetical in any
    label; this is how every count keeps its plural honestly."""
    if n == 1:
        return f"{n} {word}"
    pl = plural
    if pl is None:
        pl = word + ("es" if word.endswith(("s", "x", "sh", "ch"))
                     else "s")
    return f"{n} {pl}"


def esc(text) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
