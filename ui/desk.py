"""Shared desk widgets.

 landed this shape for the Threat Hunter: a command strip, a
five-tile stat band, a coverage strip, a day-grouped feed and the
selected row's side-by-side dossier. The same treatment was then asked for
treatment on every page but Home ("THE AI IS THE DUMBED DOWN SCREEN..."),
so the shape lives here once and each page composes from it. Everything
reads only files the suite itself writes; these widgets dress the layout
and carry nothing that runs.

The CSS vocabulary is the desk block in ui/themes.py; none of these
classes may be invented at a call site.
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from ui.plain import escape as _esc  # noqa: E402
from ui.plain import ink as _ink  # noqa: E402
from ui.plain import muted as _muted  # noqa: E402

# The dossier column never squeezes below this: the mockup's side-by-side
# contract (the feed ellipsizes, the dossier reads whole).
DOSSIER_WIDTH = 440

# The widest any page's content is allowed to grow. Window width past this
# goes to the page background either side of a centered column
# (maximized on a 4K panel, the pages stretched their
# rows and paragraphs edge to edge, which read as distortion).
APERTURE_MAX = 1880


def aperture(child):
    """Cap the page's content width and center it in the wide window.

    Everything wider than APERTURE_MAX goes to background margins; below
    it the content fills the window as usual. libadwaita is imported
    lazily: a machine without it keeps the previous full-width behaviour.
    """
    try:
        gi.require_version("Adw", "1")
        from gi.repository import Adw  # noqa: E402
        clamp = Adw.Clamp(child=child)
        clamp.set_maximum_size(APERTURE_MAX)
        clamp.set_tightening_threshold(APERTURE_MAX)
        return clamp
    except (ImportError, ValueError):
        return child


def related_box(rows, on_navigate=None, heading="Related pages"):
    """A related-in-suite footer: an eyebrow over where/what/Open rows,
    the desk look the dossier's footer already uses. `rows` hand off the
    rest of the suite as (where, what, key); Open calls
    on_navigate(button, key), the dossier handler's own shape."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    box.add_css_class("gw-related")
    if heading:
        head = Gtk.Label(xalign=0)
        head.add_css_class("gw-eyebrow")
        head.set_text(heading)
        box.append(head)
    for where, what, key in rows:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        where_l = Gtk.Label(xalign=0)
        where_l.add_css_class("gw-rel-where")
        where_l.set_text(where)
        row.append(where_l)
        what_l = Gtk.Label(xalign=0)
        what_l.add_css_class("gw-rel-what")
        what_l.set_hexpand(True)
        what_l.set_wrap(True)
        what_l.set_text(what)
        row.append(what_l)
        if on_navigate is not None:
            btn = Gtk.Button(label="Open")
            btn.add_css_class("gw-mini")
            btn.connect("clicked", on_navigate, key)
            row.append(btn)
        box.append(row)
    return box


class DeskStrip(Gtk.Box):
    """A desk page's command strip: widgets added in the page's own
    order; one free-width chip carries what the page acts on; a mono
    clock rides the right edge; a feedback line lives under the strip."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.add_css_class("gw-card")
        self.add_css_class("gw-desk-cmd")
        self._meta = Gtk.Label(xalign=1)
        self._meta.add_css_class("gw-mono")
        self._meta.set_justify(Gtk.Justification.RIGHT)

    def chip(self, widget) -> None:
        """A chip takes the strip's free width and ellipsizes only when
        the page genuinely runs out of room (the hunter's contract)."""
        widget.add_css_class("gw-suite-chip")
        widget.set_hexpand(True)
        self.append(widget)

    def meta(self, text: str) -> Gtk.Label:
        """The right-edge clock; mounts at finish."""
        self._meta.set_text(str(text))
        return self._meta

    def finish(self) -> None:
        """Mounts the clock the once; later finishes keep it mounted
        (a re-append would log a Gtk critical and move nothing)."""
        if self._meta.get_parent() is None:
            self.append(self._meta)

    def say(self, text: str) -> None:
        """The strip's feedback line under it (the hunter's _say): hidden
        again on the next paint so it never reads as a stuck state."""
        self._say.set_markup(
            f"<span size='12000' font_family='Inter' "
            f"color='{_muted()}'>{_esc(text)}</span>")
        self._say.set_visible(True)

    def feedback_line(self) -> Gtk.Label:
        """Builds the feedback line after the strip; the caller appends
        it so the page order stays strip, note, band."""
        self._say = Gtk.Label(xalign=0)
        self._say.set_xalign(0)
        self._say.set_wrap(True)
        self._say.set_visible(False)
        return self._say


class DeskBand(Gtk.Box):
    """Five stat tiles. Every tile's number comes from data the desk's
    page already reads; the band itself invents nothing."""

    def __init__(self, keys):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._tiles: dict = {}
        for key, label in keys:
            self.append(self._tile(key, label))

    def _tile(self, key: str, label: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        box.add_css_class("gw-tile")
        box.set_hexpand(True)
        name = Gtk.Label(xalign=0)
        name.add_css_class("gw-tile-k")
        name.set_text(label)
        value = Gtk.Label(xalign=0)
        value.add_css_class("gw-tile-v")
        value.set_ellipsize(3)
        sub = Gtk.Label(xalign=0)
        sub.add_css_class("gw-tile-s")
        sub.set_ellipsize(3)
        box.append(name)
        box.append(value)
        box.append(sub)
        self._tiles[key] = (value, sub)
        return box

    def tiles(self) -> dict:
        return self._tiles

    def set(self, key: str, value: str, sub: str) -> None:
        value_label, sub_label = self._tiles[key]
        value_label.set_text(value)
        sub_label.set_text(sub)


class DeskCoverage(Gtk.Box):
    """The coverage strip: one channel per solid tile, an optional dashed
    gap tile at the end for the channel the page does not have."""
    # No gw-band CSS rule below the hunter's block, so the strip carries
    # its spacing exactly as the band does.
    def __init__(self, channels, gap=None):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._cover_tiles: dict = {}
        for key, label in channels:
            self.append(self._channel(key, label))
        if gap is not None:
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            box.add_css_class("gw-tile")
            box.add_css_class("gw-tile-gap")
            box.set_hexpand(True)
            name = Gtk.Label(xalign=0)
            name.add_css_class("gw-tile-k")
            name.set_text(gap[0])
            text = Gtk.Label(xalign=0)
            text.add_css_class("gw-tile-s")
            text.add_css_class("gw-mono")
            text.set_text(gap[1])
            box.append(name)
            box.append(text)
            self.append(box)

    def _channel(self, key: str, label: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        box.add_css_class("gw-tile")
        box.add_css_class("gw-cchan")
        box.set_hexpand(True)
        name = Gtk.Label(xalign=0)
        name.add_css_class("gw-tile-k")
        name.set_text(label)
        text = Gtk.Label(xalign=0)
        text.add_css_class("gw-tile-s")
        text.set_ellipsize(3)
        box.append(name)
        box.append(text)
        self._cover_tiles[key] = text
        return box

    def tiles(self) -> dict:
        return self._cover_tiles

    def set(self, key: str, text: str) -> None:
        self._cover_tiles[key].set_text(text)


class DeskFeed(Gtk.Box):
    """A page's feed column: eyebrow head, an optional right flag, the
    day-grouped rows, a plain empty-state line and a foot note. Rows are
    boxes with a dot, a line that carries the words and a meta stamp;
    a click selects, and selection is the caller's to act on."""

    def __init__(self, eyebrow: str = "FEED", on_select=None,
                 foot: str = "", chips: dict | None = None,
                 flag_label: str = ""):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add_css_class("gw-card")
        self.add_css_class("gw-feed")
        self.set_hexpand(True)
        self.on_select = on_select
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        head.add_css_class("gw-feedhead")
        self._head = head
        e = Gtk.Label(xalign=0)
        e.add_css_class("gw-eyebrow")
        e.set_text(eyebrow)
        head.append(e)
        self._chip_btns: dict = {}
        if chips:
            for label in chips:
                chip = Gtk.Button(label=label)
                chip.add_css_class("gw-chip")
                chip.connect("clicked", self._on_chip, chips[label])
                head.append(chip)
                self._chip_btns[label] = chip
            self._chip_btns[next(iter(chips))].add_css_class("gw-chip-on")
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        head.append(spacer)
        self._flag = Gtk.Label(xalign=0)
        self._flag.add_css_class("gw-mono")
        self._flag.set_visible(False)
        head.append(self._flag)
        self.append(head)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        self._list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._list.add_css_class("gw-feedbody")
        scroll.set_child(self._list)
        self.append(scroll)
        self._empty = Gtk.Label(xalign=0)
        self._empty.set_xalign(0)
        self._empty.set_wrap(True)
        # A wrapped label's GTK minimum is its single-line width: the
        # scans feed's three-sentence foot and empty-state were demanding
        # ~1200px each, which scrolled the whole desk sideways on 1320
        # and 1280 windows. The cap keeps the paint, kills the demand.
        self._empty.set_max_width_chars(96)
        self._empty.add_css_class("gw-feed-empty")
        self.append(self._empty)
        self._foot = foot
        self._foot_w = None
        if foot:
            foot_l = Gtk.Label(xalign=0)
            foot_l.add_css_class("gw-feedfoot")
            foot_l.set_wrap(True)
            foot_l.set_text(foot)
            # wrap + cap: an unwrapped foot label carried the full
            # sentence as its GTK minimum (1431px on the scans desk)
            foot_l.set_max_width_chars(96)
            self._foot_w = foot_l
            self.append(foot_l)
        # Per-row paint state: the caller paints, the feed owns nothing.
        self._row_widgets: dict = {}
        self._selected: str | None = None

    # ------------------------------------------------------------- chips
    def chips(self) -> dict:
        return self._chip_btns

    def chip_on(self, label: str) -> None:
        for name, chip in self._chip_btns.items():
            if name == label:
                chip.add_css_class("gw-chip-on")
            else:
                chip.remove_css_class("gw-chip-on")

    def set_flag(self, text: str) -> None:
        if text:
            self._flag.set_markup(
                f"<span size='10000' font_family='IBM Plex Mono' "
                f"weight='650' color='{_muted()}'>{_esc(text)}</span>")
            self._flag.set_visible(True)
        else:
            self._flag.set_text("")
            self._flag.set_visible(False)

    def headrow(self, widget):
        """A widget that rides the head's right edge (the Scans desk's
        run chips); the feed paints it, the caller owns it. The flag
        stays the head's last word."""
        if self._flag.get_parent() is self._head:
            self._head.remove(self._flag)
        self._head.append(widget)
        self._head.append(self._flag)

    def bodyrow(self, widget):
        """A persistent body row (the Scans desk's findings section): it
        survives the row paint's clear() and renders after the feed's
        rows, before the empty state and foot."""
        tail = [x for x in (self._empty, self._foot_w)
                if x is not None and x.get_parent() is self]
        for x in tail:
            self.remove(x)
        self.append(widget)
        for x in tail:
            self.append(x)

    # -------------------------------------------------------------- rows
    def clear(self) -> None:
        for child in list(self._list.observe_children()):
            self._list.remove(child)
        self._row_widgets.clear()

    def group(self, label: str) -> None:
        strip = Gtk.Label(xalign=0)
        strip.add_css_class("gw-day")
        strip.set_text(label)
        self._list.append(strip)

    def append_row(self, key: str, row: Gtk.Box) -> None:
        self._list.append(row)
        if getattr(row, "_gw_row_key", None) is not None:
            self._row_widgets[str(row._gw_row_key)] = row
        else:
            self._row_widgets[str(key)] = row

    def rows(self) -> dict:
        return self._row_widgets

    def row(self, key: str, title: str, meta: str, sub: str | None = None,
            dot_colour: str | None = None, new_flag: str = "",
            sub_width: int | None = None) -> Gtk.Box:
        """One feed row. `sub` is the state words label the old card
        carried (the fixed-width _sub, kept so pause labels have a home
        and the row-selection contract keeps working)."""
        row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        row.add_css_class("gw-frow")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        if dot_colour is None:
            dot_colour = _muted()
        dot = Gtk.Label(xalign=0)
        dot.set_markup(
            f"<span size='10000' font_family='Inter' weight='600' "
            f"color='{dot_colour}'>●</span>")
        dot.set_valign(Gtk.Align.CENTER)
        head.append(dot)
        title_l = Gtk.Label(xalign=0)
        title_l.set_xalign(0)
        title_l.set_wrap(True)
        title_l.set_hexpand(True)
        title_l.set_markup(
            f"<span size='12000' font_family='Inter' weight='600' "
            f"color='{_ink()}'>{_esc(title)}</span>")
        head.append(title_l)
        if sub is not None:
            sub_l = Gtk.Label(xalign=0)
            sub_l.add_css_class("gw-fmeta")
            sub_l.set_ellipsize(3)
            sub_l.set_hexpand(False)
            if sub_width:
                # The state column keeps its fixed width: the
                # longest phrase paints whole, Pause lines up, and the
                # row never ellipsizes its own copy.
                sub_l.set_size_request(sub_width, -1)
            sub_l.set_markup(
                f"<span size='10500' font_family='Inter' weight='600' "
                f"color='{dot_colour}'>{_esc(sub)}</span>")
            head.append(sub_l)
            row._sub = sub_l
        if new_flag:
            flag = Gtk.Label(xalign=0)
            flag.add_css_class("gw-mono")
            flag.set_markup(
                f"<span size='10000' font_family='IBM Plex Mono' "
                f"weight='650' color='{_muted()}'>" + _esc(new_flag) +
                "</span>")
            head.append(flag)
        row.append(head)
        if meta:
            meta_l = Gtk.Label(xalign=0)
            meta_l.add_css_class("gw-fmeta")
            meta_l.set_xalign(0)
            meta_l.set_wrap(True)
            meta_l.set_markup(
                f"<span size='10500' font_family='IBM Plex Mono' "
                f"color='{_muted()}'>{_esc(meta)}</span>")
            row.append(meta_l)
        row._gw_row_key = str(key)
        click = Gtk.GestureClick()
        click.connect("released", self._on_row_gesture)
        row.add_controller(click)
        return row

    def _on_row_gesture(self, gesture, _n_press, _x, _y) -> None:
        row = gesture.get_widget()
        key = getattr(row, "_gw_row_key", None)
        if key is not None:
            self.select(str(key))

    def select(self, key: str | None) -> None:
        """Paint + remember the selection (a click or the caller's own
        pick); callers needing the click's side effects get them through
        on_select, a click routes here and the caller reads .selected."""
        if key is not None:
            key = str(key)
        self._selected = key
        self._paint_row_on(key)
        if key is not None and self.on_select is not None:
            self.on_select(key)

    def mark_selected(self, key: str | None) -> None:
        """Selection without a side effect: the paint path's pick (a
        click routes through select and fires on_select instead)."""
        if key is not None:
            key = str(key)
        self._selected = key
        self._paint_row_on(key)

    def _paint_row_on(self, key: str | None) -> None:
        for row_key, row in self._row_widgets.items():
            if row_key == key:
                row.add_css_class("gw-row-on")
            else:
                row.remove_css_class("gw-row-on")

    def selected(self) -> str | None:
        return self._selected

    def set_empty(self, text: str) -> None:
        self._empty.set_markup(
            f"<span size='12000' font_family='Inter' "
            f"color='{_muted()}'>{_esc(text)}</span>")
        self._empty.set_visible(bool(text))


class DeskDossier(Gtk.Box):
    """The side-by-side dossier: eyebrow, title, pills, the body scroll,
    and the fixed related footer. Callers fill the body per selection;
    nothing here runs."""

    def __init__(self, eyebrow: str, related_footer: str = "",
                 on_navigate=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add_css_class("gw-card")
        self.add_css_class("gw-dossier")
        self.set_size_request(DOSSIER_WIDTH, -1)
        self.on_navigate = on_navigate
        head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        head.add_css_class("gw-dhead")
        e = Gtk.Label(xalign=0)
        e.add_css_class("gw-eyebrow")
        e.set_text(eyebrow)
        head.append(e)
        self._dtitle = Gtk.Label(xalign=0)
        self._dtitle.set_xalign(0)
        self._dtitle.set_wrap(True)
        self._dtitle.add_css_class("gw-dtitle")
        head.append(self._dtitle)
        self._dpills = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                               spacing=5)
        head.append(self._dpills)
        self.append(head)
        dscroll = Gtk.ScrolledWindow()
        dscroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        dscroll.set_vexpand(True)
        self._detail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                               spacing=8)
        self._detail.add_css_class("gw-dbody")
        dscroll.set_child(self._detail)
        self.append(dscroll)
        self._related = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                spacing=2)
        self._related.add_css_class("gw-related")
        self._related_rows: dict = {}
        self.append(self._related)

    def title(self) -> Gtk.Label:
        return self._dtitle

    def pills(self) -> Gtk.Box:
        return self._dpills

    def detail(self) -> Gtk.Box:
        return self._detail

    def clear(self) -> None:
        # Title, pills and body reset per fill; the related footer is the
        # dossier's fixed part (the hunter's contract, one mount).
        self._dtitle.set_text("")
        for child in list(self._dpills.observe_children()):
            self._dpills.remove(child)
        for child in list(self._detail.observe_children()):
            self._detail.remove(child)
        self._dpills.set_visible(False)

    def fill_empty(self, text: str) -> None:
        self.clear()
        self._detail.append(self.lead(text))

    def evline(self, text: str) -> Gtk.Label:
        """One mono line in the scanner's own units; set as plain text so
        it never truncates a unit mid-word. Selectable so its units can
        reach the clipboard."""
        t = Gtk.Label(xalign=0)
        t.set_xalign(0)
        t.set_wrap(True)
        t.add_css_class("gw-facts-line")
        t.set_selectable(True)
        t.set_text(text)
        return t

    def pill(self, text: str, css: str = "gw-pill-neutral",
             colour: str | None = None) -> None:
        pill = Gtk.Label(xalign=0)
        pill.set_xalign(0)
        pill.add_css_class("gw-pill")
        pill.add_css_class(css)
        if colour:
            pill.set_markup(
                f"<span size='9500' font_family='IBM Plex Mono' "
                f"weight='700' color='{colour}'>{_esc(text)}</span>")
        else:
            pill.set_text(str(text).upper())
        self._dpills.append(pill)

    def lead(self, text: str) -> Gtk.Label:
        t = Gtk.Label(xalign=0)
        t.set_xalign(0)
        t.set_wrap(True)
        # same single-line minimum as the feed's foot: the scans
        # dossier's empty sentence demanded ~1290px and overflowed the
        # dossier's own fixed width.
        t.set_max_width_chars(72)
        t.add_css_class("gw-dlead")
        t.set_text(text)
        return t

    def label(self, text: str) -> Gtk.Label:
        lab = Gtk.Label(xalign=0)
        lab.set_xalign(0)
        lab.add_css_class("gw-dlabel")
        lab.set_text(text)
        return lab

    def prose(self, text: str) -> Gtk.Label:
        t = Gtk.Label(xalign=0)
        t.set_xalign(0)
        t.set_wrap(True)
        t.set_selectable(True)
        t.add_css_class("gw-prose")
        t.set_text(text)
        return t

    def facts(self, lines) -> Gtk.Label:
        t = Gtk.Label(xalign=0)
        t.set_xalign(0)
        t.set_wrap(True)
        t.set_selectable(True)
        t.add_css_class("gw-facts")
        t.set_text("\n".join(str(x) for x in lines))
        return t

    def next_box(self, text: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.add_css_class("gw-next")
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        body.set_text(str(text))
        box.append(body)
        return box

    def related(self, rows) -> None:
        """Rows are (where, what, key) hand-offs to the rest of the
        suite; when a navigate hook is given they grow an Open button."""
        for where, what, key in rows:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            where_l = Gtk.Label(xalign=0)
            where_l.add_css_class("gw-rel-where")
            where_l.set_text(where)
            row.append(where_l)
            what_l = Gtk.Label(xalign=0)
            what_l.add_css_class("gw-rel-what")
            what_l.set_hexpand(True)
            what_l.set_wrap(True)
            what_l.set_text(what)
            row.append(what_l)
            if self.on_navigate is not None:
                btn = Gtk.Button(label="Open")
                btn.add_css_class("gw-mini")
                btn.connect("clicked", self._related_open, key)
                row.append(btn)
            self._related_rows[key] = row
            self._related.append(row)

    def _related_open(self, _btn, key: str) -> None:
        if self.on_navigate is not None:
            self.on_navigate(key)