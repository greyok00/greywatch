from __future__ import annotations

import pathlib

from gi.repository import GLib
from ui import cliapi


def signature(*names: str) -> str:
    parts = []
    for name in names:
        try:
            st = pathlib.Path(cliapi.state_path(name)).stat()
            parts.append(f"{name}:{st.st_mtime_ns}:{st.st_size}")
        except OSError:
            parts.append(f"{name}:-")
    return "|".join(parts)


def restore_scroll(scroller) -> None:
    adjustment = scroller.get_vadjustment()
    value = adjustment.get_value()

    def put():
        adjustment.set_value(value)
        return False

    GLib.idle_add(put)


def scroll_to_widget(scroller, widget, retries: int = 8) -> None:
    """Bring `widget` into view inside `scroller`. GTK4 has no
    scroll-to-child, so the offset is summed down the ancestor chain and
    applied once the widget is actually allocated (a just-built page has
    no geometry yet — the idle retries cover that, bounded so a test
    shell never spins)."""
    if scroller is None or widget is None:
        return

    def put(tries: int):
        alloc = widget.get_allocation()
        if (not widget.get_realized() or alloc.height <= 1) and tries > 0:
            # geometry not ready: requeue with one fewer try. The next
            # attempt is scheduled by hand, because idle_add would call
            # back with the SAME tries value every time and never count
            # down — an unrealized widget (a test shell) would spin
            # forever.
            GLib.idle_add(put, tries - 1)
            return False
        y = 0
        w = widget
        while w is not None and w != scroller:
            y += w.get_allocation().y
            w = w.get_parent()
        scroller.get_vadjustment().set_value(max(0, y - 48))
        return False

    GLib.idle_add(put, retries)
