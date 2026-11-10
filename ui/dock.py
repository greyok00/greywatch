"""The fixed right control dock (rebuild round 2, task 3).

Every page hands the dock ("Title", [widgets]) groups; the dock renders
them in its own scroller, so a control the feed needs never scrolls away
and the feed never scrolls because of the dock. The dock never
auto-collapses (its width is the window's law, ui.window.dock_width) and
flash() pulses one group's title — the accent-soft beat that says "this
control is the one the hand-off wants" without moving anything.
"""
from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

PULSE_MS = 600

_FLASH = "gw-dock-flash"


class DockHost(Gtk.Box):
    """The right pane: one scroller, one group card per page group."""

    def __init__(self, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add_css_class("gw-dock")
        self._win = win
        self.current = None
        self._titles: dict = {}
        self._pulses: list = []
        self._note: tuple | None = None   # (page key, "came from …")
        self._crumb = Gtk.Label(xalign=0)
        self._crumb.add_css_class("gw-breadcrumb")
        self._crumb.set_visible(False)
        self._scroller = Gtk.ScrolledWindow()
        self._scroller.set_policy(Gtk.PolicyType.NEVER,
                                  Gtk.PolicyType.AUTOMATIC)
        self._scroller.set_vexpand(True)
        self._page_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                 spacing=10)
        self._scroller.set_child(self._page_box)
        self.append(self._crumb)
        self.append(self._scroller)
        self.connect("destroy", self._on_destroy)

    def _on_destroy(self, *_a):
        self._stop_pulses()
        return False

    # -- the arrival breadcrumb -------------------------------------------
    def set_note(self, key, text):
        """One "came from <page>" line at the top of the dock, set by the
        guided hand-off (auto-routing only). It shows while the noted page
        is the one mounted."""
        self._note = (str(key), str(text))
        self._crumb.set_text(str(text))
        self._crumb.set_visible(str(key) == (self.current or ""))

    def clear_note(self):
        """A click arrival: the note belongs to the auto-route that just
        happened, not to the page forever."""
        self._note = None
        self._crumb.set_text("")
        self._crumb.set_visible(False)

    def _apply_crumb(self, key):
        if self._note is None or self._note[0] != str(key):
            self._crumb.set_visible(False)
            return
        self._crumb.set_text(self._note[1])
        self._crumb.set_visible(True)

    # -- page groups -------------------------------------------------------
    def set_page(self, key, groups):
        """Rebuild the dock for one page. `groups` is a list of
        ("Title", [widgets]); the widgets stay the page's own objects, so
        a control keeps its live state across page switches."""
        self._stop_pulses()
        for child in list(self._page_box):
            self._page_box.remove(child)
        self._titles = {}
        self.current = key
        self._apply_crumb(key)
        for title, widgets in (groups or []):
            section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                              spacing=8)
            section.add_css_class("gw-dock-group")
            heading = Gtk.Label(label=str(title), xalign=0)
            heading.add_css_class("gw-dock-title")
            section.append(heading)
            self._titles[str(title)] = heading
            for w in (widgets or []):
                if w is None:
                    continue
                self._claim(w)
                section.append(w)
            self._page_box.append(section)

    def _claim(self, w):
        """GTK4 never reparents on append: a widget still parented by its
        page must be unparented first, or the dock silently renders an
        empty group. Moving is the design — the control lives here while
        its page is shown."""
        parent = w.get_parent()
        if parent is not None:
            parent.remove(w)

    def group_titles(self) -> list:
        return list(self._titles)

    # -- the pulse ---------------------------------------------------------
    def flash(self, title_name) -> bool:
        """Two soft accent beats on one group's title, 600 ms apart. An
        unknown title is quiet: a hand-off never invents a target. A page
        switch mid-pulse retires it through _stop_pulses and the heading
        ownership check."""
        heading = self._titles.get(str(title_name))
        if heading is None:
            return False
        self._stop_pulses()
        heading.add_css_class(_FLASH)
        self._schedule(heading, 1)
        return True

    def _schedule(self, heading, step):
        self._pulses.append(
            GLib.timeout_add(PULSE_MS, self._beat, heading, step))

    def _beat(self, heading, step):
        # Beats land in schedule order; retire the one that just fired so
        # the id list tracks the sources actually in flight.
        if self._pulses:
            del self._pulses[0]
        if heading not in self._titles.values():
            return False                  # the page moved on mid-flash
        if heading.has_css_class(_FLASH):
            heading.remove_css_class(_FLASH)
        else:
            heading.add_css_class(_FLASH)
        if step < 3:
            self._schedule(heading, step + 1)
        return False

    def _stop_pulses(self):
        for sid in list(self._pulses):
            try:
                GLib.source_remove(sid)
            except (RuntimeError, TypeError):
                pass                      # already fired
        self._pulses.clear()
