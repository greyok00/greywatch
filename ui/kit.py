"""The GreyWatch element layer: the shared widgets every screen
composes from. One table builder, state chips, level bars, progress
bars, section cards and the tool icon seam. Everything drawn or
composed here reads the applied theme's tokens and keeps the labels
law: standard terms, no parentheticals, plurals through count_word.
"""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import toolicons
from ui.widgets import count_word, esc


def icon(tool_id: str, size: int = 22) -> Gtk.Image:
    """The tool's symbolic icon from the installed user icon theme;
    symbolic icons pick up the theme's ink colour on their own."""
    image = Gtk.Image.new_from_icon_name(toolicons.icon_name(str(tool_id)))
    image.set_pixel_size(int(size))
    return image


def section_card(title: str, *rows, cls: str = "gw-card") -> Gtk.Frame:
    """One titled card: an eyebrow head plus any rows."""
    head = Gtk.Label()
    head.set_markup(
        f"<span font_size='10752' weight='bold' letter_spacing='1400' "
        f"variant='small-caps'>{esc(title.upper())}</span>")
    head.add_css_class("gw-eyebrow")
    head.set_xalign(0.0)
    inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    inner.append(head)
    for row in rows:
        if row is None or isinstance(row, str):
            lab = Gtk.Label(label=row if isinstance(row, str) else "")
            lab.set_xalign(0.0)
            lab.set_ellipsize(3)            # Pango.EllipsizeMode.END
            inner.append(lab)
        else:
            inner.append(row)
    frame = Gtk.Frame()
    for name in str(cls or "gw-card").split():
        frame.add_css_class(name)
    frame.set_child(inner)
    return frame


def table(columns, rows=(), height: int = 220,
          tool_icons: list | None = None) -> tuple:
    """The one tree builder: a fixed-column tree over a scroller. An
    optional leading icon column renders one symbolic icon per row,
    given as `tool_icons` (the tool's own id); nothing is guessed. The
    row data rides the scroller as `_gw_rows` for tests, because a tree
    cell's text is not a widget label."""
    with_icon = tool_icons is not None
    store = Gtk.ListStore(*[str] * (len(columns) + (1 if with_icon
                                                    else 0)))
    for i, row in enumerate(rows):
        values = [str(c) for c in row]
        if with_icon:
            store.append([
                toolicons.icon_name(tool_icons[i])] + values)
        else:
            store.append(values)
    tree = Gtk.TreeView(model=store, activate_on_single_click=False)
    tree.set_enable_search(True)
    if with_icon:
        cell = Gtk.CellRendererPixbuf()
        col = Gtk.TreeViewColumn("", cell)
        col.add_attribute(cell, "icon-name", 0)
        col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        col.set_fixed_width(30)
        tree.append_column(col)
    base = 1 if with_icon else 0
    for i, (title, width) in enumerate(columns):
        cell = Gtk.CellRendererText()
        col = Gtk.TreeViewColumn(title, cell, text=i + base)
        col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        col.set_fixed_width(width)
        # the last column takes the leftover width on a wide panel
        if i == len(columns) - 1:
            col.set_expand(True)
        tree.append_column(col)
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scroll.set_min_content_height(height)
    scroll.set_child(tree)
    scroll._gw_rows = [list(r) for r in rows]
    return scroll, store


def chip(text: str, level: str = "mute") -> Gtk.Label:
    """A small state chip: one word in a bordered tag."""
    lab = Gtk.Label(label=str(text))
    lab.add_css_class("gw-chip")
    if level in ("ok", "warn", "fail"):
        lab.add_css_class(f"gw-chip-{level}")
    return lab


def level_bar(value, lower_is_better: bool = False,
              width: int = 220, level: str = None) -> Gtk.LevelBar:
    """A 0-100 reading as a level bar. The bar shows the machine's
    actual state: for lower-is-better inputs the risk sits at the far
    end, so the colour mode below makes the right edge red. GTK's
    continuous mode never applies the offset classes on its own (seen
    live 2026-11-16: a worst-case CVE input painted green), so the
    caller's level is placed on the bar itself and the theme paints
    block.filled from it."""
    bar = Gtk.LevelBar(min_value=0.0, max_value=1.0)
    bar.set_value(min(1.0, max(0.0, float(value) / 100.0)))
    bar.set_size_request(width, 8)
    bar.set_mode(Gtk.LevelBarMode.CONTINUOUS)
    if level in ("ok", "warn", "fail", "mute"):
        bar.add_css_class(f"gw-{level}")
    # the offset marks: the green/yellow/red bands flip for
    # lower-is-better inputs so the bar's coloured end matches the risk
    if lower_is_better:
        # the risk climbs with the value: green at the floor, red at
        # the ceiling
        bar.add_offset_value("gw-mid", 0.21)
        bar.add_offset_value("gw-bad", 0.61)
    else:
        bar.add_offset_value("gw-mid", 0.7)
        bar.add_offset_value("gw-good", 0.8)
    return bar


def progress_bar(fraction: float | None, text: str = "",
                 width: int = 200, indeterminate: bool = False) -> Gtk.Box:
    """One progress row: a bar plus its counting text. An
    indeterminate bar shows honest motion for scanners that report no
    total yet; it pulses through the stylesheet's animation."""
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    bar = Gtk.ProgressBar()
    if indeterminate or fraction is None:
        bar.pulse()
    else:
        bar.set_fraction(min(1.0, max(0.0, float(fraction))))
    bar.set_size_request(width, 12)
    if text:
        lab = Gtk.Label(label=text)
        lab.add_css_class("dim")
        box.append(lab)
    box.append(bar)
    return box


def state_dot(level: str, size: int = 10) -> Gtk.DrawingArea:
    """The small square mark; level ok/warn/fail/mute from the current
    theme's colours."""
    from ui.widgets import mark_dot
    return mark_dot(level, size=size)


# the rail's own icons: verified against the installed theme (Xvfb
# probe, 2026-11-15); a name missing on the machine renders nothing,
# never a broken icon
RAIL_ICONS = {
    "Security Center": "badge",
    "Network": "gw-tool-arpwatch-symbolic",
    "Tools": "application-x-executable-symbolic",
    "Timeline": "appointment-soon-symbolic",
    "Assistant": "utilities-terminal-symbolic",
    "Help": "help-about-symbolic",
}


def rail_icon(label: str, size: int = 16) -> Gtk.Image | None:
    """The rail row's icon: the wolf badge for the landing screen, one
    verified symbolic icon for every other rail row. None when both
    fail; the rail row keeps its words."""
    from ui import themes as _themes
    try:
        name = RAIL_ICONS.get(str(label))
        if not name:
            return None
        if name == "badge":
            pb = _themes.avatar_for(_themes.active_theme(), size)
            if pb is None:
                return None
            image = Gtk.Image.new_from_pixbuf(pb)
            return image
        image = Gtk.Image.new_from_icon_name(name)
        image.set_pixel_size(int(size))
        return image
    except Exception:                        # noqa: BLE001
        return None