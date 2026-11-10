"""Rebuild round 2, task 4: the guided-attention layer.

pulse() greets one element with the accent-soft beat (one active pulse
window-wide, newest replaces and drains the timers that came before),
point() floats a small arrow near the target's allocation over an
input-transparent overlay, and handoff() is the router: when something
important needs a human the app opens the page, greets the right dock
group and highlights the row — routed once per (page, item).

Beats and fades are driven directly, so no pin races a wall clock (the
same shape the dock flash pins use). GUI tests run on the private Xvfb
conftest starts, never the owner's desktop.
"""
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)

import ui.guided as guided  # noqa: E402
from ui.window import MainWindow  # noqa: E402


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


def pump_settled(limit=8.0, step=0.002):
    """Pump with a wall-clock floor: showing a page whose table scrolls
    inside a ScrolledWindow (the fit law's inner containers) can leave
    GTK's own sources busy for seconds, and the guided settle idles land
    after them. Waiting beats flaking - the pins stay exactly as written."""
    import time as _time
    ctx = GLib.main_context_default()
    deadline = _time.time() + limit
    while _time.time() < deadline:
        ctx.iteration(False)
        _time.sleep(step)


@pytest.fixture(scope="module")
def win():
    w = MainWindow()
    w.present()
    pump(30)
    yield w
    w.destroy()


@pytest.fixture(autouse=True)
def clean_handoff_state(win):
    """Each test starts with an empty seen-set and the saved toggle; the
    module window is shared, so a test that flips auto_jump must not
    leak its flip into the next one."""
    win._handoff_seen.clear()
    yield
    win._handoff_seen.clear()
    win._toggles["auto_jump"] = guided.load_toggle()


# ------------------------------------------------------------- entry

def test_entry_pulses_dock_title(win, monkeypatch):
    """The owner's example: click the logs page and the right pane's
    control title flashes - the Activity Log greets its dock group."""
    calls = []
    monkeypatch.setattr(guided, "pulse",
                        lambda w, c=calls: calls.append(w))
    win._show("logs")
    assert calls == [win.dock._titles["Filter"]], \
        "page open must pulse its entry target"


def test_page_without_entry_opens_quiet(win, monkeypatch):
    """Pages that declare no entry group see no pulse: entry is a
    greeting, not a default. (Overview declares one since task 5: its
    verdict strip arrives through the Snapshot dock group; task 12 gave
    Settings/Search and Help/About rows - the Services page, which has
    no dock groups, is the quiet example now.)"""
    calls = []
    monkeypatch.setattr(guided, "pulse",
                        lambda w, c=calls: calls.append(w))
    win._show("services")
    assert calls == []


def test_entry_with_unknown_group_is_quiet(win, monkeypatch):
    monkeypatch.setattr(guided, "PAGE_ENTRY", {"overview": "Nope"})
    calls = []
    monkeypatch.setattr(guided, "pulse",
                        lambda w, c=calls: calls.append(w))
    win._show("overview")
    assert calls == []
    assert guided.entry(win) is False


# ------------------------------------------------------------- pulse

def test_pulse_beats_replaces_and_never_refires(win, monkeypatch):
    """The pulse lights at once and hands the target three beats
    (off - on - off, 600 ms apart, like the dock flash). A second pulse
    for the SAME target mid-cycle never re-fires; a pulse for another
    target replaces the active one and drains its pending timers."""
    sched = []

    def schedule(ms, fn, *a):
        sched.append((ms, fn, a))
        return len(sched)

    monkeypatch.setattr(guided.GLib, "timeout_add", schedule)
    gone = []
    monkeypatch.setattr(guided.GLib, "source_remove",
                        lambda sid: gone.append(sid) or None)
    monkeypatch.setattr(guided, "reduced_motion", lambda: False)
    # the boot entry greeting (task 5: Overview pulses its Snapshot dock
    # group) may leave its own real beats in the slot; the pin measures
    # this test's own scheduling, so start from an empty pulse slot.
    guided._active.clear()
    a, b = Gtk.Label(label="a"), Gtk.Label(label="b")
    assert guided.pulse(a) is True
    assert "gw-guided-pulse" in a.get_css_classes()
    beats = list(sched)
    assert [ms for ms, _f, _a in beats] == [guided.PULSE_MS] * 3
    # one active pulse at a time: the same target does not re-fire
    n = len(sched)
    assert guided.pulse(a) is False
    assert len(sched) == n
    # newest replaces: the prior class comes off and its timers drain
    assert guided.pulse(b) is True
    assert len(gone) == 3                 # a's three pending beats removed
    assert "gw-guided-pulse" not in a.get_css_classes()
    assert "gw-guided-pulse" in b.get_css_classes()
    assert guided._active["target"] is b
    # ghost beat: a's drained timers, driven by hand, move nothing
    for _ms, fn, args in beats:
        ret = fn(*args)
        assert ret is False
    assert "gw-guided-pulse" not in a.get_css_classes()
    # b's beats (the three after the replace) drive the cycle to its end
    for entry in sched[-3:]:
        entry[1](*entry[2])
    assert "gw-guided-pulse" not in b.get_css_classes()
    assert guided._active == {}


def test_pulse_reduced_motion_draws_statically(win, monkeypatch):
    """With animations off the pulse paints the accent and stops: no
    beat timers are ever scheduled."""
    def no_timer(ms, fn, *a):
        raise AssertionError("reduced motion must not schedule timers")

    monkeypatch.setattr(guided, "reduced_motion", lambda: True)
    monkeypatch.setattr(guided.GLib, "timeout_add", no_timer)
    w = Gtk.Label(label="still")
    assert guided.pulse(w) is True
    assert "gw-guided-pulse" in w.get_css_classes()
    assert guided._active["ids"] == []


def test_pulse_of_a_name_resolves_through_the_dock(win, monkeypatch):
    """pulse() also answers by dock-group name when a window rides
    along; an unknown name (or a name without a window) is quiet."""
    monkeypatch.setattr(guided, "reduced_motion", lambda: True)
    monkeypatch.setattr(guided, "entry", lambda w: None)  # arrival quiet
    win._show("auditlog")
    pump(5)
    title = win.dock._titles["Filter"]
    assert guided.pulse("Filter", win) is True
    assert "gw-guided-pulse" in title.get_css_classes()
    assert guided.pulse(win.dock._titles["Filter"]) is False  # still active
    assert guided.pulse("Nope", win) is False
    assert guided.pulse("Filter") is False    # name without a window


# -------------------------------------------------------------- point

def test_point_floats_an_input_transparent_arrow(win, monkeypatch):
    """The pointer arrow rides a window-level overlay near the target's
    allocation and can never eat a click or focus."""
    monkeypatch.setattr(guided, "reduced_motion", lambda: True)
    win._show("auditlog")
    pump(10)
    title = win.dock._titles["Filter"]
    # reduced motion: not a single timer, held statically until replaced
    assert guided.point(title) is True
    pump_settled()                        # the geometry settle is an idle
    arrow = win._guided_point
    assert arrow is not None
    assert "gw-guided-point" in arrow.get_css_classes()
    assert arrow.get_can_target() is False
    assert arrow.get_parent() is win._guided_overlay
    x, y = title.translate_coordinates(win._guided_overlay, 0, 0)
    assert arrow.get_margin_start() == max(2, x - guided.POINT_OFF)
    # a new point replaces the old arrow (one pointer at a time)
    assert guided.point(title) is True
    assert win._guided_point is not arrow
    assert arrow.get_parent() is None


def test_point_holds_then_fades(win, monkeypatch):
    """Animated mode: the arrow holds ~1.5 s, then fades stepwise and is
    finally removed from the overlay."""
    sched = []

    def schedule(ms, fn, *a):
        sched.append((ms, fn, a))
        return len(sched)

    monkeypatch.setattr(guided.GLib, "timeout_add", schedule)
    monkeypatch.setattr(guided.GLib, "source_remove", lambda sid: None)
    monkeypatch.setattr(guided, "reduced_motion", lambda: False)
    win._show("auditlog")
    pump(10)
    guided.point(win.dock._titles["Filter"])
    pump_settled()
    arrow = win._guided_point
    assert arrow.get_opacity() == 1.0
    holds = [e for e in sched if e[0] == guided.POINT_MS]
    assert holds, "the hold timer must be scheduled"
    holds[0][1](*holds[0][2])             # hold fires: the first fade step
    assert arrow.get_opacity() < 1.0
    # each fade step drains and re-schedules one timer; drive to the end
    for _ in range(12):
        if win._guided_point is not arrow:
            break
        pend = [e for e in sched if getattr(e[1], "__name__", "") == "fade"]
        assert pend, "the fade must keep stepping until the arrow leaves"
        pend[-1][1]()
    assert arrow.get_parent() is None
    assert win._guided_point is not arrow


def test_window_hosts_the_point_overlay(win):
    """The window's child is the overlay host: pages live inside it, so
    the arrow can float above any page surface."""
    host = win._guided_overlay
    assert isinstance(host, Gtk.Overlay)
    assert win.get_child() is host
    assert isinstance(host.get_child(), Gtk.Box)


# ----------------------------------------------------------- handoff

def test_handoff_routes_once(monkeypatch, win):
    """The router's de-dupe law: the same (page, item) hand-off routes
    exactly once, however often the source calls it."""
    win._toggles["auto_jump"] = True
    sent = []
    monkeypatch.setattr(guided, "navigate", lambda w, key: sent.append(key))
    guided.handoff(win, "defense", dock_group="Rules", row=None)  # once
    guided.handoff(win, "defense", dock_group="Rules", row=None)  # again
    assert sent == ["defense"]


def test_handoff_flash_point_and_row(win, monkeypatch):
    """A hand-off opens the page, pulses and points the declared dock
    group and washes the row with the hand-off class; a second call for
    the same item is refused by the seen-set."""
    from gi.repository import Gtk
    monkeypatch.setattr(guided, "reduced_motion", lambda: True)
    row = Gtk.Label(label="blocked.example.invalid")
    assert guided.handoff(win, "auditlog", dock_group="Filter", row=row)
    assert win.stack.get_visible_child_name() == "auditlog"
    assert "gw-guided-pulse" in win.dock._titles["Filter"].get_css_classes()
    assert "gw-guided-point" in win._guided_point.get_css_classes()
    assert "gw-handoff-row" in row.get_css_classes()
    assert ("auditlog", "Filter", str(row)) in win._handoff_seen
    assert not guided.handoff(win, "auditlog", dock_group="Filter", row=row)


def test_handoff_respects_auto_jump_off(monkeypatch, win):
    """The toggle gates the whole router: with auto_jump off nothing is
    navigated, nothing is marked seen (a later toggle-on still works)."""
    win._toggles["auto_jump"] = False
    sent = []
    monkeypatch.setattr(guided, "navigate", lambda w, key: sent.append(key))
    assert not guided.handoff(win, "defense", dock_group="Rules")
    assert sent == []
    assert win._handoff_seen == set()


def test_handoff_without_group_routes_only(win, monkeypatch):
    """A page-level hand-off (no group named) navigates and dedupes on
    the page alone; a different item on the same page routes again."""
    monkeypatch.setattr(guided, "reduced_motion", lambda: True)
    win._show("auditlog")
    pump(5)
    sent = []
    monkeypatch.setattr(guided, "navigate", lambda w, key: sent.append(key))
    assert guided.handoff(win, "auditlog")
    assert sent == ["auditlog"]
    assert guided.handoff(win, "auditlog") is False
    assert sent == ["auditlog"]
    assert guided.handoff(win, "auditlog", dock_group="Filter") is True
    assert sent == ["auditlog", "auditlog"]


def test_window_handoff_passthrough(win, monkeypatch):
    """win.handoff is the same router with the window bound, sharing the
    one seen-set."""
    monkeypatch.setattr(guided, "reduced_motion", lambda: True)
    assert win.handoff("auditlog", dock_group="Filter")
    assert ("auditlog", "Filter", "") in win._handoff_seen
    assert not win.handoff("auditlog", dock_group="Filter")


# ------------------------------------------------------------- toggle

def test_auto_jump_toggle_default_true(tmp_path, monkeypatch):
    """The seam: default True, a stored false reads False, and a window
    booted on that file consults it through win._toggles."""
    monkeypatch.setattr(guided, "SETTINGS_PATH", tmp_path / "ui.json")
    assert guided.load_toggle() is True          # default
    (tmp_path / "ui.json").write_text(json.dumps({"auto_jump": False}))
    assert guided.load_toggle() is False
    w = MainWindow()
    w.present()
    pump(10)
    assert w._toggles == {"auto_jump": False}
    w._toggles["auto_jump"] = True
    w.destroy()


def test_auto_jump_persist_keeps_the_rest_of_the_file(tmp_path):
    """persist_toggle writes the key through the same temp+rename seam
    and never drops the file's other keys."""
    p = tmp_path / "ui.json"
    p.write_text(json.dumps({"theme": "paper", "dock_width": 260}))
    guided.persist_toggle(False, path=p)
    cfg = json.loads(p.read_text())
    assert cfg["theme"] == "paper"
    assert cfg["dock_width"] == 260
    assert cfg["auto_jump"] is False
    assert guided.load_toggle(path=p) is False


def test_toggles_read_once_at_boot(win):
    """The window reads the settings file once (the seam the Settings
    desk will write through) - _toggles carries the resolved value."""
    assert set(win._toggles) == {"auto_jump"}
    assert win._toggles["auto_jump"] is guided.load_toggle()


# ------------------------------------------- breadcrumb + rail heading

def test_handoff_leaves_came_from_breadcrumb_in_the_dock(win):
    """The final-review breadcrumb: an auto-route names where the owner
    was sent FROM - one small line at the top of the target's dock."""
    win._show("overview")
    pump(5)
    assert guided.handoff(win, "tools")
    assert win.dock.current == "tools"
    assert win.dock._crumb.get_visible()
    assert win.dock._crumb.get_text() == "came from Overview"


def test_rail_click_clears_the_breadcrumb(win):
    """Nav by click does not SET the note, and it clears a stale one: the
    line belongs to the auto-route that earned it."""
    assert guided.handoff(win, "tools")
    assert win.dock._crumb.get_visible()
    win._tab_pick(None, "defense")
    pump(5)
    assert not win.dock._crumb.get_visible()


def test_handoff_pulses_the_rail_group_heading(win):
    """Spec trigger 2's pulse half: the hand-off also beats the target
    page's rail group heading (its own lane, so it never drains the dock
    title's pulse)."""
    head = win._rail_rows["@Care"]
    guided.rail_pulse(win, "tools")
    assert head.has_css_class("gw-guided-pulse")
    # newest rail pulse replaces: the Care heading is drained at once
    new = guided.handoff(win, "thunter")
    assert new is True                      # a different item, not deduped
    assert not head.has_css_class("gw-guided-pulse")
    assert win._rail_rows["@Defense"].has_css_class("gw-guided-pulse")
    guided._rail_end()
    assert not win._rail_rows["@Defense"].has_css_class("gw-guided-pulse")


def test_pages_off_the_rail_pulse_no_heading(win):
    """A page with no rail group (Overview is its own home row) greets
    quiet: a hand-off never invents a rail heading."""
    assert guided.rail_heading_of("overview") is None
    assert guided.rail_pulse(win, "overview") is False


def test_breadcrumb_never_names_an_unnameable_source(win):
    """A source the words cannot name (the waiting panel) is no guess:
    the dock stays quiet."""
    win._show("overview")
    pump(5)
    guided._set_breadcrumb(win, "tools", None)
    assert not win.dock._crumb.get_visible()
