"""The guided-attention layer (rebuild round 2, task 4).

Three pieces, one job: when the app knows where the owner should look
next, it says so without moving anything out from under them.

- pulse(target): a soft accent beat on one element (dock group titles
  today, any widget by name with a window at hand). ONE active pulse in
  the whole window: a newer pulse replaces it and drains the timer
  sources of the pulse that came before, and a target already mid-cycle
  never re-fires.
- point(target): a small arrow over a window-level overlay, near the
  target's allocation, held about 1.5 s and faded away. The overlay never
  takes input or focus. gtk-enable-animations off (reduced motion) draws
  the arrow statically: no hold timer, no fade, it stays until the next
  point (or hand-off) reuses the slot.
- handoff(win, page_key, dock_group, row): the router behind "the app
  sends you to the right page with the correct dock open and the row
  highlighted". De-dupes per (page, item-key) through win._handoff_seen
  — the same item routes once no matter how often its source calls — and
  consults the auto_jump toggle the Settings seam persists.

PAGE_ENTRY is the greeting table: which dock group a page's arrival
pulses. A page with no row here opens quiet.
"""
from __future__ import annotations

import json
import pathlib

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from gwpaths import data_dir as _gw_data

SETTINGS_PATH = _gw_data() / "greywatch-ui-settings.json"

PULSE_MS = 600        # one beat: on, off, on, off at this spacing
POINT_MS = 1500       # how long the arrow holds before it fades
FADE_MS = 60          # per fade step
FADE_STEPS = 8
POINT_OFF = 22        # the arrow sits this far left of the target

# The greeting table (page_key -> dock group name). Activity Log greets
# its Filter group (variant 1 expanded the Task-3 Search group into
# Filter/Sources/Actions); Firewall greets Rules (fw-A's first group);
# the Threat Hunter greets Filter (th-A's first group, task 8); the
# Tools page greets Show, its all/live-only card filter (task 9); the
# Scans page greets Schedule and Protections greets Advisories (their
# first dock groups, task 10); Harden greets Profile (its honest
# profile radios, task 11); Settings greets the Search control and
# Help greets About (task 12); pages without a row here open quiet.
PAGE_ENTRY = {"auditlog": "Filter", "overview": "Snapshot",
              "defense": "Rules", "thunter": "Filter", "tools": "Show",
              "scans": "Schedule", "protect": "Advisories",
              "harden": "Profile",
              "settings": "Search", "help": "About"}

_PULSE = "gw-guided-pulse"
_POINT = "gw-guided-point"
_ROW = "gw-handoff-row"

# The one active pulse, window-wide (module law: the newest wins).
_active: dict = {}


# -- the auto_jump toggle (read once by the window; Settings writes it) --
def load_toggle(path=None, key="auto_jump", default=True) -> bool:
    """The saved pick from the UI settings file: an explicit false reads
    False, an absent key (or a dead file) reads the default."""
    p = pathlib.Path(path if path is not None else SETTINGS_PATH)
    try:
        raw = json.loads(p.read_text(encoding="utf-8")).get(key)
    except (OSError, ValueError, TypeError, AttributeError):
        return default
    return default if raw is None else bool(raw)


def persist_toggle(value, path=None, key="auto_jump") -> bool:
    """Write one toggle key through the same temp+rename seam every
    settings writer uses; nothing else in the file is touched."""
    p = pathlib.Path(path if path is not None else SETTINGS_PATH)
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cfg = {}
    cfg[key] = bool(value)
    try:
        from appfw.atomicio import write_json_atomic
        write_json_atomic(p, cfg)
        return True
    except OSError:
        return False


# -- reduced motion -----------------------------------------------------
def reduced_motion() -> bool:
    """gtk-enable-animations off says the desktop wants no beat: the
    pulse paints statically and the arrow holds without timers."""
    try:
        s = Gtk.Settings.get_default()
        return not bool(s.get_property("gtk-enable-animations"))
    except (TypeError, AttributeError):
        return True


# -- the pulse ----------------------------------------------------------
def _drain() -> None:
    """Retire the active pulse: its pending beats are removed and the
    css class comes off the target if the widget still exists."""
    act = dict(_active)
    _active.clear()
    for sid in act.get("ids") or ():
        try:
            GLib.source_remove(sid)
        except (RuntimeError, TypeError):
            pass                            # already fired or gone
    target = act.get("target")
    if target is None:
        return
    try:
        target.remove_css_class(_PULSE)
    except (RuntimeError, TypeError):
        pass                                # the widget died mid-cycle


def _beat(target, step) -> bool:
    """One 600 ms beat: toggle the css class; the third beat retires.
    A beat whose pulse was replaced mid-cycle is a ghost and moves
    nothing."""
    if _active.get("target") is not target:
        return False
    ids = _active.get("ids") or []
    if ids:
        del ids[0]
    try:
        if target.has_css_class(_PULSE):
            target.remove_css_class(_PULSE)
        else:
            target.add_css_class(_PULSE)
    except (RuntimeError, TypeError):       # the widget died mid-cycle
        _active.clear()
        return False
    if step >= 3:                           # off - on - off, then rest
        if _active.get("target") is target:
            _active.clear()
    return False


def pulse(target, win=None) -> bool:
    """Greet one element with the accent-soft beat, 600 ms x2. A target
    already mid-cycle never re-fires; a new target replaces the active
    pulse and drains its pending sources. Reduced motion paints the
    accent statically: no timers at all. False = quiet (unknown name, no
    window, dead widget)."""
    if isinstance(target, str):
        titles = getattr(getattr(win, "dock", None), "_titles", None)
        target = titles.get(str(target)) if titles else None
    if target is None:
        return False
    if _active.get("target") is target:
        return False                        # mid-cycle: never re-fire
    _drain()
    try:
        target.add_css_class(_PULSE)
    except (RuntimeError, TypeError):
        return False
    _active["target"] = target
    _active["ids"] = []
    if not reduced_motion():
        for step in (1, 2, 3):
            _active["ids"].append(
                GLib.timeout_add(PULSE_MS, _beat, target, step))
    return True


# -- the pointer arrow ---------------------------------------------------
def _unparent(child) -> None:
    """Take a float child off its host: Gtk.Overlay takes
    remove_overlay; every other parent (a Box, should the arrow ever
    migrate) answers remove."""
    parent = child.get_parent()
    if parent is None:
        return
    if hasattr(parent, "remove_overlay"):
        parent.remove_overlay(child)
    else:
        parent.remove(child)


def _arrow_for(target, win) -> Gtk.Label:
    """One input-transparent floating label over the window's overlay.
    The old arrow is retracted first: one pointer on screen at a time."""
    old = getattr(win, "_guided_point", None)
    if old is not None:
        for sid in getattr(old, "_guided_ids", ()) or ():
            try:
                GLib.source_remove(sid)
            except (RuntimeError, TypeError):
                pass
        _unparent(old)
    arrow = Gtk.Label(label="→")
    arrow.add_css_class(_POINT)
    arrow.set_halign(Gtk.Align.START)
    arrow.set_valign(Gtk.Align.START)
    arrow.set_focusable(False)
    try:
        arrow.set_can_target(False)         # floats, never blocks a click
    except AttributeError:                  # pragma: no cover - older GTK
        pass
    win._guided_point = arrow
    return arrow


def _place_and_hold(arrow, target, win) -> bool:
    """Put the arrow near the target's allocation (left of it, clamped
    into the window) and schedule its hold + fade. This is the settle
    step, not an animation: a target freshly shown may still be 0x0 until
    its first allocation, so a short idle retry is allowed in BOTH
    modes; what reduced motion skips is the hold/fade timers."""
    host = win._guided_overlay
    try:
        if target.get_allocation().width <= 0:
            return False                    # not laid out yet
        pos = target.translate_coordinates(host, 0, 0)
        if pos is None:
            return False                    # not in this window's tree
        arrow.set_margin_start(max(2, pos[0] - POINT_OFF))
        arrow.set_margin_top(max(2, pos[1]))
    except (RuntimeError, TypeError):
        return False
    return True


def point(widget, win=None) -> bool:
    """Float the pointer arrow near a widget's allocation: held ~1.5 s,
    faded, gone. The overlay never takes input. The geometry-settling
    idle below is not an animation; with reduced motion the arrow is
    drawn statically and no hold or fade timer is scheduled at all."""
    if widget is None or isinstance(widget, str):
        return False
    try:
        win = win or widget.get_root()
        host = getattr(win, "_guided_overlay", None)
    except (RuntimeError, TypeError):
        return False
    if host is None or not isinstance(widget, Gtk.Widget):
        return False
    arrow = _arrow_for(widget, win)
    host.add_overlay(arrow)

    state = {"tries": 30, "ids": []}
    arrow._guided_ids = state["ids"]

    def settle() -> bool:
        """Idle retry: read the allocation, place the arrow, stop.
        Giving up (no allocation after 30 passes, target gone) removes
        the arrow - a pointer to nothing never stays on screen."""
        if not _place_and_hold(arrow, widget, win):
            state["tries"] -= 1
            if state["tries"] <= 0:
                _retract(arrow, state)
                return False
            return True                     # try again after this pass
        if not reduced_motion():
            state["ids"].append(
                GLib.timeout_add(POINT_MS, _hold_done, arrow, state))
        return False

    def _hold_done(_arrow, st) -> bool:
        """Hold over: fade the arrow stepwise, then retire it."""
        st["ids"].clear()

        def fade() -> bool:
            st["ids"].clear()
            try:
                if arrow.get_parent() is None:
                    return False
                op = max(0.0, arrow.get_opacity() - 1.0 / FADE_STEPS)
                arrow.set_opacity(op)
            except (RuntimeError, TypeError):
                return False
            if op > 0.0:
                st["ids"].append(GLib.timeout_add(FADE_MS, fade))
                return True
            _retract(arrow, st)
            return False

        return fade()

    GLib.idle_add(settle)
    return True


def _retract(arrow, state) -> None:
    """Take one arrow off the screen and cancel its remaining timers.
    The root is read BEFORE unparenting: an unparented widget has none,
    so its window slot would never clear."""
    for sid in list(state.get("ids") or ()):
        try:
            GLib.source_remove(sid)
        except (RuntimeError, TypeError):
            pass
    state["ids"].clear()
    try:
        root = arrow.get_root()
    except (RuntimeError, TypeError):
        root = None
    try:
        _unparent(arrow)
    except (RuntimeError, TypeError):
        pass
    try:
        if root is not None and getattr(root, "_guided_point", None) is arrow:
            root._guided_point = None
    except (RuntimeError, TypeError):
        pass


# -- the entry greeting and the hand-off router ---------------------------
def entry(win) -> bool:
    """A page's arrival greeting: the entry target its dock group
    declares in PAGE_ENTRY, resolved through the live dock titles. No
    entry, no such group, nothing to pulse - the page opens quiet."""
    try:
        key = win.stack.get_visible_child_name()
    except (RuntimeError, TypeError, AttributeError):
        return False
    name = PAGE_ENTRY.get(key)
    if not name:
        return False
    target = win.dock._titles.get(name)
    if target is None:
        return False                        # a hand-off never invents one
    return pulse(target)


def navigate(win, page_key) -> None:
    """The one router hop. Its own seam: callers that test handoff()
    replace this, and every real route goes through the window's own
    _show (legacy keys, guards, dock hand-off, entry greeting)."""
    win._show(page_key)


def handoff(win, page_key, dock_group=None, row=None) -> bool:
    """Send the owner to the right place: open the page, greet the
    declared dock group (pulse + arrow) and wash the row with the
    hand-off class. auto_jump off = nothing happens at all (and nothing
    is marked seen, so a later toggle-on still routes). The same
    (page, item) routes once - the seen-set lives on the window, so
    later callers can clear it and route again."""
    if not dict(getattr(win, "_toggles", None) or {}).get("auto_jump", True):
        return False
    item = (str(page_key), str(dock_group or ""), str(row or ""))
    seen = getattr(win, "_handoff_seen", None)
    if seen is None:
        seen = set()
        win._handoff_seen = seen
    if item in seen:
        return False
    seen.add(item)
    navigate(win, page_key)
    target = None
    if dock_group:
        target = win.dock._titles.get(str(dock_group))
    if target is not None:
        pulse(target)
        try:
            point(target, win)
        except (RuntimeError, TypeError):   # the arrow is best-effort
            pass
    try:
        if isinstance(row, Gtk.Widget):
            row.add_css_class(_ROW)
    except (RuntimeError, TypeError):
        pass
    return True
