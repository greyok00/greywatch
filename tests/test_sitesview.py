import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import GLib  # noqa: E402

from ui.sitesview import SitesView  # noqa: E402


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        while ctx.pending():
            ctx.iteration(False)


class Store:
    def __init__(self):
        self.allow = set()
        self.block = set()
        self.apps_allow = set()

    def add(self, entry, verdict):
        self.allow.discard(entry)
        self.block.discard(entry)
        (self.allow if verdict == "allow" else self.block).add(entry)
        return True

    def remove(self, entry):
        self.allow.discard(entry)
        self.block.discard(entry)
        return True


def _view(tmp_path):
    store = Store()
    notes = []
    view = SitesView(lambda: store, tmp_path,
                     audit=lambda *a: notes.append(a))
    return view, store, notes


ROWS = [
    {"entry": "142.250.72.14", "name": "google.com",
     "address": "142.250.72.14", "description": "Google service",
     "program": "firefox", "port": 443,
     "last_seen": "2026-10-30T07:00:00+00:00", "count": 3, "verdict": ""},
    {"entry": "104.18.37.251", "name": "104.18.37.251",
     "address": "104.18.37.251", "description": "content delivery",
     "program": "", "port": 443, "last_seen": "", "count": 0,
     "verdict": "block"},
]


def test_rows_render_one_line_with_name_and_description(tmp_path):
    from ui.site_rows import SiteRow
    view, _store, _notes = _view(tmp_path)
    view.paint([SiteRow(**r) for r in ROWS])
    pump()
    first = view.row_text(0)
    assert "google.com (142.250.72.14)" in first
    assert "Google service" in first
    assert "142.250.72.14 — " not in first
    view.unparent()


def test_click_selects_and_actions_mutate_the_store(tmp_path):
    from ui.site_rows import SiteRow
    view, store, notes = _view(tmp_path)
    view.paint([SiteRow(**r) for r in ROWS])
    pump()
    assert not view.trust_btn.get_sensitive()
    view.select(0)
    assert view.trust_btn.get_sensitive()
    assert view.act("allow") == "Trusted google.com (142.250.72.14)."
    assert "142.250.72.14" in store.allow
    assert notes and notes[-1][0] == "trust"
    view.paint([SiteRow(**r) for r in ROWS])
    view.select(1)
    assert view.act("remove") == "Removed 104.18.37.251 from the lists."
    assert not store.block
    view.unparent()


def test_nothing_selected_explains_itself(tmp_path):
    view, _store, _notes = _view(tmp_path)
    view.paint([])
    pump()
    assert "Nothing discovered yet" in view.empty.get_text()
    assert view.visible_count() == 0
    assert view.act("allow") == "Select a site in the list first."
    view.unparent()


def test_filter_narrows_the_list(tmp_path):
    from ui.site_rows import SiteRow
    view, _store, _notes = _view(tmp_path)
    view.paint([SiteRow(**r) for r in ROWS])
    view.filter_entry.set_text("delivery")
    pump()
    assert view.visible_count() == 1
    assert "104.18.37.251" in view.row_text(0)
    view.filter_entry.set_text("")
    pump()
    assert view.visible_count() == 2
    view.unparent()


def test_a_blocked_site_says_blocked(tmp_path):
    from ui.site_rows import SiteRow
    view, _store, _notes = _view(tmp_path)
    view.paint([SiteRow(**r) for r in ROWS])
    pump()
    chip = view.listbox.get_row_at_index(1).get_child().get_last_child()
    assert "Blocked" in chip.get_text()
    view.unparent()
