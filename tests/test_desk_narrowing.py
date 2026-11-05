"""The desk feeds' narrowing contract (round-2 audit): the visible set
decides only what the feed MOUNTS, never what the counters or the
dossier describe, and a filter that hides the selected row opens the
empty dossier again instead of keeping a ghost record."""
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui.protectdesk import ProtectDesk
from ui.toolsdesk import ToolsDesk

_REG = ("clamav", "rkhunter", "lynis", "aide")


def _registry():
    return [{"name": n, "unit": f"{n}.service", "logs": ()} for n in _REG]


def _facts():
    facts = {}
    for n in _REG:
        facts[n] = {"name": n, "state": "GREEN", "paused": False,
                    "quiet": True, "unit": f"{n}.service",
                    "installed": True, "label": n.upper(), "event": None,
                    "last_scan": {}}
    return facts


def _day_labels(feed):
    return [w.get_text() for w in feed._list.observe_children()
            if isinstance(w, Gtk.Label) and "gw-day" in str(
                list(w.get_css_classes()))]


def test_protect_filter_hiding_every_row_mounts_no_group_banner():
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(_facts(), "2026-11-04T10:00:00+00:00", rows={}, visible=set())
    assert not desk.feed.rows()
    assert _day_labels(desk.feed) == [], "no empty group banners"
    assert desk.selected is None


def test_protect_narrowed_group_keeps_its_banner_and_only_its_rows():
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(_facts(), "2026-11-04T10:00:00+00:00",
               rows={"clamav": Gtk.Box()}, visible={"clamav"})
    assert sorted(desk.feed.rows()) == ["clamav"]
    assert _day_labels(desk.feed) == ["Runs when asked"]
    assert desk.selected is None


def test_protect_dropped_selection_reopens_the_empty_dossier():
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(_facts(), "2026-11-04T10:00:00+00:00", rows={}, visible=set())
    desk.select("clamav")
    assert desk.selected == "clamav"
    desk.paint(_facts(), "2026-11-04T10:05:00+00:00", rows={}, visible=set())
    assert desk.selected is None


def test_tools_flag_counts_the_whole_machine_while_the_feed_narrows():
    desk = ToolsDesk(_registry())
    facts = _facts()
    desk.paint(facts, [], "2026-11-04T10:00:00+00:00", visible={"lynis"})
    assert sorted(desk.feed.rows()) == ["lynis"]
    assert desk.feed._flag.get_text() == f"{len(facts)} ON FILE"


def test_tools_dropped_selection_reopens_the_empty_record():
    desk = ToolsDesk(_registry())
    desk._on_pick("rkhunter")
    assert desk.selected == "rkhunter"
    desk.paint(_facts(), [], "2026-11-04T10:00:00+00:00", visible=set())
    assert desk.selected is None