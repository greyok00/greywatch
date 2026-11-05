from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib  # noqa: E402

# The last REAL pointer/keyboard X timestamp this app saw, if any.
# GreyWatch used to hand the window manager every toplevel activation with
# timestamp 0 (_NET_ACTIVE_WINDOW), which Marco logs as a buggy client and
# settles with CurrentTime for focus - each present then flipped focus on
# its own terms: the screen shook while popups
# and the setup wizard were up; .xsession-errors caught the app, its popups
# and the unrelated Server Pill racing zero-timestamp focus requests in
# exactly that window).
#
# Mouse motion and key presses are constant while a human is using the app,
# so a pair of controllers on the main window keep a fresh, honest X
# timestamp for every activation that follows.
_LAST = [0]


def _stamp(ctl: Gtk.EventController, *args) -> None:
    try:
        event = ctl.get_current_event()
        ts = event.get_time() if event is not None else 0
    except Exception:
        ts = 0
    if ts and ts > _LAST[0]:
        _LAST[0] = int(ts)


def attach(win) -> None:
    """Record real X timestamps from ordinary activity on `win`."""
    try:
        motion = Gtk.EventControllerMotion()
        motion.connect("motion", _stamp)
        motion.connect("enter", _stamp)
        win.add_controller(motion)
        key = Gtk.EventControllerKey()
        key.connect("key-pressed", _stamp)
        key.connect("key-released", _stamp)
        win.add_controller(key)
    except Exception:
        pass


def last_x_ts() -> int:
    return _LAST[0]


def present_now(win) -> None:
    """Present a toplevel with the last real X timestamp we observed.

    Falls back to a bare present() when no timestamp exists yet (fresh
    windows in tests, headless runs) or this GTK build lacks the
    present_with_time variant. Never hands the window manager CurrentTime
    when an honest stamp is available.
    """
    with_time = getattr(win, "present_with_time", None)
    ts = _LAST[0]
    if with_time is not None and ts:
        try:
            with_time(int(ts))
            return
        except (AttributeError, TypeError, GLib.Error):
            pass
    win.present()
