"""Rebuild round 2, task 6 re-root (was: the Phase-4 three-tab page):
the Activity Log page is now ONE chronology table with the variant-1
tab strip, and the quarantine ledger stays the Findings tab's data.

What the page must keep saying: a record renders with the ledger's own
words (the ORIGINAL target path as the helper's single argument), the
three stored answers are the only offers (keep / restore / secure-wipe)
through the page's confirm pipeline, and an unreadable ledger renders
as its own honest empty state, never as nothing to say.
"""
import datetime
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def _walk(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        out.append(c)
        out.extend(_walk(c))
        c = c.get_next_sibling()
    return out


def _words(widget):
    """Text-of-the-page walker: labels read get_text, buttons get_label."""
    out = []
    for w in _walk(widget):
        if isinstance(w, Gtk.Label):
            out.append(str(w.get_text() or ""))
        elif isinstance(w, Gtk.Button):
            out.append(str(w.get_label() or ""))
    return out


def _labels(root):
    return [str(w.get_text() if isinstance(w, Gtk.Label) else
                (w.get_label() or "") if isinstance(w, Gtk.Button) else "")
            for w in _walk(root)]


class _FakeWin:
    def __init__(self, data_dir):
        self.data_dir = str(data_dir)
        self.registry = [{"name": "psad"}, {"name": "aide"},
                         {"name": "rkhunter"}, {"name": "appfw"}]


NOW = datetime.datetime(2026, 11, 10, 14, 30, tzinfo=datetime.timezone.utc)


def _page(store):
    from ui.auditlog import ActivityLogPage
    page = ActivityLogPage(win=_FakeWin(store))
    page._now = lambda: NOW        # the honest clock, pinned for tests
    return page


def _buttons(widget):
    return [w for w in _walk(widget) if isinstance(w, Gtk.Button)]


class TestFindingsTab:
    """The quarantine ledger renders as chronology rows; activation
    offers exactly the three stored answers, the ledger's words."""

    def test_rows_render_from_ledger_with_original_path(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "2026-11-09 13:31:30",
            "orig": "/home/grey/Downloads/gw-eicar-live-3.txt",
            "file": "/var/lib/greywatch/quar/gw-eicar-live-3.txt.quar",
            "sha256_16": "275a021bbfb6489e",
            "tag": "onaccess:Eicar-Test-Signature"}) + "\n")
        page = _page(store)
        page._set_tab("Findings")
        text = " | ".join(str(r[4]) for r in page._store)
        assert "gw-eicar-live-3.txt" in text
        assert "Eicar-Test-Signature" in text

    def test_three_stored_answers_only(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "2026-11-09 13:31:30", "orig": "/x/evil.bin", "file": "/q/evil.bin.quar",
            "sha256_16": "aa", "tag": "onaccess:Eicar"}) + "\n")
        page = _page(store)
        shown = []
        import ui.auditlog as A
        old = A.present_now
        A.present_now = lambda d: shown.append(d)
        try:
            page._row_card(page._quar_records[0], "quarantine")
        finally:
            A.present_now = old
        labels = [b.get_label() for b in _buttons(shown[0])]
        for want in ("Keep quarantined", "Put it back", "Secure-wipe"):
            assert want in labels, (want, labels)

    def test_wipe_routes_delete_helper_with_original_arg(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "2026-11-09 13:31:30", "orig": "/home/grey/Downloads/gw-eicar-live-3.txt",
            "file": "/q/a.quar", "sha256_16": "aa", "tag": "tag"}) + "\n")
        page = _page(store)
        seen = []
        page._confirm_and_run = lambda opt: seen.append(dict(opt))
        import ui.auditlog as A
        shown = []
        old = A.present_now
        A.present_now = lambda d: shown.append(d)
        try:
            page._row_card(page._quar_records[0], "quarantine")
        finally:
            A.present_now = old
        wipe = [b for b in _buttons(shown[0])
                if b.get_label() == "Secure-wipe"]
        assert len(wipe) == 1
        wipe[0].emit("clicked")
        assert seen == [{"id": "wipe", "label": "Secure-wipe",
                         "tone": "danger",
                         "helper": "delete-quarantine",
                         "args": ["/home/grey/Downloads/"
                                  "gw-eicar-live-3.txt"],
                         "kind": "helper"}]

    def test_restore_routes_restore_helper(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "2026-11-09 13:31:30", "orig": "/x/evil.bin", "file": "/q/a.quar",
            "sha256_16": "aa", "tag": "tag"}) + "\n")
        page = _page(store)
        seen = []
        page._confirm_and_run = lambda opt: seen.append(dict(opt))
        import ui.auditlog as A
        shown = []
        old = A.present_now
        A.present_now = lambda d: shown.append(d)
        try:
            page._row_card(page._quar_records[0], "quarantine")
        finally:
            A.present_now = old
        put = [b for b in _buttons(shown[0])
               if b.get_label() == "Put it back"]
        put[0].emit("clicked")
        assert seen[0]["helper"] == "restore-quarantine"
        keep = [b for b in _buttons(shown[0])
                if b.get_label() == "Keep quarantined"]
        keep[0].emit("clicked")
        assert seen[1]["helper"] == "keep-quarantine"

    def test_unreadable_ledger_is_honest_not_silent(self, store):
        page = _page(store)
        page._set_tab("Findings")
        assert page._store.get_iter_first() is None
        text = " ".join(_words(page)).lower()
        assert "nothing" in text


class TestDecisionsTab:
    def test_rows_render_from_answer_ledger(self, store):
        (store / "decisions.jsonl").write_text(json.dumps({
            "id": "fail2ban:ab12cd", "option": "keep",
            "ts": "2026-11-09T07:12:00+00:00"}) + "\n")
        page = _page(store)
        page._set_tab("Decisions")
        text = " ".join(str(r[4]) for r in page._store)
        # the id prefix renders through friendly_name, so fail2ban shows
        # as its human name
        assert "intrusion blocker" in text.lower()

    def test_empty_ledger_is_honest(self, store):
        page = _page(store)
        page._set_tab("Decisions")
        assert page._store.get_iter_first() is None
        text = " ".join(_words(page)).lower()
        assert "no answers" in text


class TestSearch:
    def test_search_filters_findings(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "2026-11-09 13:31:30", "orig": "/x/alpha.txt", "file": "/q/a.quar",
            "sha256_16": "aa", "tag": "tag"}) + "\n" + json.dumps({
            "ts": "2026-11-09 13:35:00", "orig": "/x/beta.txt", "file": "/q/b.quar",
            "sha256_16": "bb", "tag": "tag"}) + "\n")
        page = _page(store)
        page._search.set_text("alpha")
        page._set_tab("Findings")
        text = " ".join(str(r[4]) for r in page._store)
        assert "alpha.txt" in text and "beta.txt" not in text

    def test_search_filters_the_events_feed(self, store):
        (store / "events.jsonl").write_text(json.dumps({
            "ts": "2026-11-10T07:12:00+00:00", "from_tool": "psad",
            "severity": "HIGH",
            "text": "src: 192.0.2.7, ports: DANGER: 1"}) + "\n" + json.dumps(
            {"ts": "2026-11-10T07:13:00+00:00", "from_tool": "fail2ban",
             "severity": "MEDIUM", "text": "ban 10.1.2.3 in sshd"}) + "\n")
        page = _page(store)
        page._search.set_text("fail2ban")
        page._set_tab("Everything")
        rows = [str(r[4]) for r in page._store]
        assert rows, "the ban row matches the tool's own name"
        assert not any("192.0.2.7" in r for r in rows)
        assert all("intrusion blocker" in str(r[3]).lower()
                   for r in page._store)


class TestStrip:
    def test_four_tabs_named_and_the_feed_is_one_table(self, store):
        page = _page(store)
        labels = [str(b.get_label()) for b in page._tabs.values()]
        assert labels == ["Everything", "Decisions", "Blocks", "Findings"]
        # ONE chronology table, refilled per tab - not a stack of tabs
        from gi.repository import Gtk as G
        assert len([w for w in _walk(page)
                    if isinstance(w, G.TreeView)]) == 1
        assert not hasattr(page, "_stack")
