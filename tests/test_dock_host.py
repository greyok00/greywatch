"""Rebuild round 2, task 3: the three-pane frame's DockHost + stale guard.

The dock is the FIXED right control strip. Every page hands it
("Title", [widgets]) groups; the dock never scrolls a control away with
the feed, never auto-collapses, and its width is a law the tests pin.
The stale-snapshot guard swaps the page stack for one centered waiting
panel while the daemon's digest is missing or older than the 90 s law
(the snapshot-staleness number ui/homepage already carries for the Home
verdict), and hands the stack back the moment a fresh snapshot lands.

Tests must not depend on the live daemon's heartbeat age: conftest's
autouse seam disarms the guard window-wide, and the guard pins here
re-arm it by restoring the real predicate captured at import time.
"""
import datetime as dt
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib  # noqa: E402

if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)

import ui.dock as dock  # noqa: E402
import ui.window as W  # noqa: E402
from ui.window import MainWindow  # noqa: E402

# The real staleness predicate, captured before conftest's seam fires.
REAL_STALE = W.snapshot_stale


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


@pytest.fixture(scope="module")
def win():
    w = MainWindow()
    w.present()
    pump(30)
    yield w
    w.destroy()


# ---------------------------------------------------------------- dock

def test_dock_host_sets_groups(win):
    host = dock.DockHost(win)
    host.set_page("logs", [("Filter", [Gtk.Entry()]),
                           ("Sources", [Gtk.CheckButton(label="psad")])])
    assert host.current == "logs"
    assert host.group_titles() == ["Filter", "Sources"]


def test_dock_width_law():
    assert W.dock_width(2400) == max(220, min(320, round(2400 * 0.26)))
    assert W.dock_width(2400) == 320      # the cap keeps 4K panels sane
    assert W.dock_width(700) == 220       # the floor keeps the controls
    assert W.dock_width(846) == 220       # 0.26 share below the floor


def test_dock_width_stored_pick_is_clamped():
    assert W.dock_width(1200, override=999) == 400
    assert W.dock_width(1200, override=40) == 200
    assert W.dock_width(1200, override=300) == 300


def test_dock_is_the_fixed_right_pane(win):
    """The body is rail | feed | dock: the dock is the body's last child
    and its width comes from the law, never from a collapse."""
    body = win.dock.get_parent()
    children = list(body)
    assert children[-1] is win.dock
    assert children[0] is win.rail_bar
    win._size_dock()
    want = W.dock_width(win.get_allocated_width())
    assert win.dock.get_size_request()[0] == want


def test_dock_scrolls_itself_never_the_feed(win):
    host = dock.DockHost(win)
    groups = [(f"Group {i}", [Gtk.Label(label=f"g{i}")]) for i in range(3)]
    host.set_page("services", groups)
    scroller = list(host)[0]
    assert isinstance(scroller, Gtk.ScrolledWindow)
    assert scroller.get_vscrollbar() is not None
    wrapped = scroller.get_child()
    assert isinstance(wrapped, Gtk.Viewport)
    assert wrapped.get_child() is host._page_box


def test_dock_flash_pulses_the_group_title(win, monkeypatch):
    """flash() lights the title at once, then hands it two soft beats
    (off - on - off) 600 ms apart, and retires the pulse after the final
    beat. The beats are driven directly, so the pin holds without racing
    a wall clock."""
    calls = []

    def schedule(ms, fn, *a):
        calls.append((ms, fn, a))
        return len(calls)

    monkeypatch.setattr(dock.GLib, "timeout_add", schedule)
    host = dock.DockHost(win)
    host.set_page("logs", [("Filter", [Gtk.Entry()])])
    lbl = host._titles["Filter"]
    assert host.flash("Filter") is True
    assert lbl.has_css_class("gw-dock-flash")
    assert [ms for ms, _fn, _a in calls] == [dock.PULSE_MS]
    calls[0][1](*calls[0][2])            # beat one: off, schedules beat two
    assert not lbl.has_css_class("gw-dock-flash")
    assert len(calls) == 2
    calls[1][1](*calls[1][2])            # beat two: on again
    assert lbl.has_css_class("gw-dock-flash")
    calls[2][1](*calls[2][2])            # beat three: off, pulse retires
    assert not lbl.has_css_class("gw-dock-flash")
    assert len(calls) == 3               # no further beats scheduled
    assert host._pulses == []


def test_dock_flash_of_an_unknown_title_is_quiet(win):
    host = dock.DockHost(win)
    host.set_page("logs", [("Filter", [Gtk.Entry()])])
    assert host.flash("Nope") is False


def test_activity_log_search_lives_in_the_dock(win):
    win._show("auditlog")
    pump(10)
    assert win.dock.current == "auditlog"
    assert win.dock.group_titles() == ["Search"]
    entry = win.auditlog_page._search
    # Gtk's is_ancestor misses across the scroller's internal Viewport;
    # get_ancestor answers the same question truthfully.
    assert entry.get_ancestor(dock.DockHost) is win.dock


def test_full_log_page_hands_its_controls_to_the_dock(win):
    built = win._builders["logs"]()
    content, groups = built
    titles = [t for t, _w in groups]
    assert titles == ["Filter", "Actions"]


def test_dock_groups_reset_across_pages(win):
    win._show("auditlog")
    pump(5)
    assert win.dock.group_titles() == ["Search"]
    win._show("overview")
    pump(5)
    assert win.dock.current == "overview"
    assert win.dock.group_titles() == []


# -------------------------------------------------------- stale guard

def test_stale_guard_shows_waiting_panel(win, monkeypatch):
    """While no fresh digest arrives, the stack IS the waiting panel and
    the pill says so with warn styling; a fresh snapshot hands the
    surface straight back."""
    monkeypatch.setattr(W, "snapshot_stale", REAL_STALE)
    monkeypatch.setattr(
        W.daemon_mod, "load_status",
        lambda *a, **k: {"updated": None, "tools": {}})
    win.refresh()
    pump(5)
    assert win.stack.get_visible_child_name() == W.WAITING_KEY
    assert "waiting for the daemon" in win.header_pill.get_label().lower()
    assert "warn" in win.header_pill.get_css_classes()

    fresh = dt.datetime.now(dt.timezone.utc).isoformat()
    monkeypatch.setattr(
        W.daemon_mod, "load_status",
        lambda *a, **k: {"updated": fresh,
                         "tools": {t["name"]: {"state": "GREEN"}
                                   for t in win.registry}})
    monkeypatch.setattr(W.daemon_mod, "read_events", lambda *a, **k: [])
    win.refresh()
    pump(5)
    assert win.stack.get_visible_child_name() == "overview"
    assert win.stack.get_child_by_name(W.WAITING_KEY) is None
    assert "Waiting for the daemon" != win.header_pill.get_label()
    # the pre-stale page is remembered, not just any first child
    win._show("services")
    pump(5)


def test_snapshot_stale_law():
    """The pure law, unit-shaped: no stamp or an old one waits; a fresh
    stamp and a junk-free iso never do (the same 90 s the Home verdict
    already carries)."""
    now = dt.datetime.now(dt.timezone.utc)
    assert REAL_STALE(None) is True
    assert REAL_STALE("") is True
    assert REAL_STALE("not-a-stamp") is True
    old = (now - dt.timedelta(seconds=91)).isoformat()
    fresh = (now - dt.timedelta(seconds=10)).isoformat()
    assert REAL_STALE(old) is True
    assert REAL_STALE(fresh) is False


def test_stale_guard_remembers_the_page_you_picked(win, monkeypatch):
    """Picking a rail row while stale must not swallow the choice: the
    recovery lands on the row the user clicked, not on Overview."""
    monkeypatch.setattr(W, "snapshot_stale", REAL_STALE)
    monkeypatch.setattr(
        W.daemon_mod, "load_status",
        lambda *a, **k: {"updated": None, "tools": {}})
    win._show("settings")
    pump(5)
    assert win.stack.get_visible_child_name() == W.WAITING_KEY
    fresh = dt.datetime.now(dt.timezone.utc).isoformat()
    monkeypatch.setattr(
        W.daemon_mod, "load_status",
        lambda *a, **k: {"updated": fresh,
                         "tools": {t["name"]: {"state": "GREEN"}
                                   for t in win.registry}})
    monkeypatch.setattr(W.daemon_mod, "read_events", lambda *a, **k: [])
    win.refresh()
    pump(5)
    assert win.stack.get_visible_child_name() == "settings"
    win._show("overview")
