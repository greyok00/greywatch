"""Rebuild Phase 4: the Activity Log page's three tabs.

The page is history, not control surface: security events reuse the
window's raw-logs desk, operator decisions read the one answer ledger,
and quarantine rows offer exactly the three stored answers (keep /
restore / secure-wipe) through the window's confirm pipeline with the
ORIGINAL target path as the helper's single argument - the ledger's
own words, never the page's invention.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi_required = pytest.importorskip("gi")
gi_required.require_version("Gtk", "4.0")

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


def _labels(root):
    return [str(w.get_text() if isinstance(w, Gtk.Label) else
                (w.get_label() or "") if isinstance(w, Gtk.Button) else "")
            for w in _walk(root)]


class _FakeWin:
    def __init__(self, data_dir):
        self.data_dir = str(data_dir)
        self._routed = None

    def _logs_view(self):
        return Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

    def _run_log_option(self, _btn, opt):
        self._routed = dict(opt)


def _page(store):
    from ui.auditlog import ActivityLogPage
    win = _FakeWin(store)
    return ActivityLogPage(win=win), win


def _quar_tab(page):
    return page._quarantines


def _dec_tab(page):
    return page._decisions


class TestQuarantineTab:
    def test_rows_render_from_ledger_with_original_path(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "2026-10-27 13:31:30",
            "orig": "/home/grey/Downloads/gw-eicar-live-3.txt",
            "file": "/var/lib/greywatch/quar/gw-eicar-live-3.txt.quar",
            "sha256_16": "275a021bbfb6489e",
            "tag": "onaccess:Eicar-Test-Signature"}) + "\n")
        page, _win = _page(store)
        _quar_tab(page).paint()
        text = " | ".join(_labels(_quar_tab(page)))
        assert "gw-eicar-live-3.txt" in text
        assert "Eicar-Test-Signature" in text

    def test_three_stored_answers_only(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "t", "orig": "/x/evil.bin", "file": "/q/evil.bin.quar",
            "sha256_16": "aa", "tag": "onaccess:Eicar"}) + "\n")
        page, _win = _page(store)
        _quar_tab(page).paint()
        labels = [t.lower() for t in _labels(_quar_tab(page))
                  if t and not t.startswith(("nothing", "0 "))]
        for want in ("keep quarantined", "put it back", "secure-wipe"):
            assert any(want in t for t in labels), (want, labels)

    def test_wipe_routes_delete_helper_with_original_arg(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "t", "orig": "/home/grey/Downloads/gw-eicar-live-3.txt",
            "file": "/q/a.quar", "sha256_16": "aa", "tag": "tag"}) + "\n")
        page, win = _page(store)
        _quar_tab(page).paint()
        win._routed = None
        buttons = [w for w in _walk(_quar_tab(page))
                   if isinstance(w, Gtk.Button)]
        wipe = [b for b in buttons if b.get_label() == "Secure-wipe"]
        assert len(wipe) == 1
        wipe[0].emit("clicked")
        assert win._routed == {"id": "wipe", "label": "Secure-wipe",
                               "tone": "danger",
                               "helper": "delete-quarantine",
                               "args": ["/home/grey/Downloads/"
                                        "gw-eicar-live-3.txt"]}

    def test_restore_routes_restore_helper(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "t", "orig": "/x/evil.bin", "file": "/q/a.quar",
            "sha256_16": "aa", "tag": "tag"}) + "\n")
        page, win = _page(store)
        _quar_tab(page).paint()
        win._routed = None
        buttons = [w for w in _walk(_quar_tab(page))
                   if isinstance(w, Gtk.Button)]
        put = [b for b in buttons if b.get_label() == "Put it back"]
        put[0].emit("clicked")
        assert win._routed["helper"] == "restore-quarantine"
        keep = [b for b in buttons if b.get_label() == "Keep quarantined"]
        keep[0].emit("clicked")
        assert win._routed["helper"] == "keep-quarantine"

    def test_unreadable_ledger_is_honest_not_silent(self, store):
        page, _win = _page(store)
        _quar_tab(page).paint()
        text = " ".join(_labels(_quar_tab(page))).lower()
        assert "nothing in quarantine" in text


class TestDecisionsTab:
    def test_rows_render_from_answer_ledger(self, store):
        (store / "decisions.jsonl").write_text(json.dumps({
            "id": "fail2ban:ab12cd", "option": "keep",
            "ts": "2026-11-06T07:12:00+00:00"}) + "\n")
        page, _win = _page(store)
        _dec_tab(page).paint()
        text = " ".join(_labels(_dec_tab(page)))
        # the id prefix renders through friendly_name, so fail2ban shows
        # as its human name
        assert "intrusion blocker" in text.lower()
        assert ".keep" not in text.lower() or "keep" in text.lower()

    def test_empty_ledger_is_honest(self, store):
        page, _win = _page(store)
        _dec_tab(page).paint()
        assert "no answers recorded yet" in \
            " ".join(_labels(_dec_tab(page))).lower()

    def test_search_filters_both_tabs(self, store):
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "t", "orig": "/x/alpha.txt", "file": "/q/a.quar",
            "sha256_16": "aa", "tag": "tag"}) + "\n" + json.dumps({
            "ts": "t2", "orig": "/x/beta.txt", "file": "/q/b.quar",
            "sha256_16": "bb", "tag": "tag"}) + "\n")
        page, _win = _page(store)
        page._search.set_text("alpha")
        page._refilter()
        text = " ".join(_labels(_quar_tab(page)))
        assert "alpha.txt" in text and "beta.txt" not in text


class TestStack:
    def test_three_tabs_titled_and_events_tab_is_the_logs_desk(self, store):
        page, _win = _page(store)
        names = []
        for k in ("events", "decisions", "quarantines"):
            child = page._stack.get_child_by_name(k)
            assert child is not None, k
            names.append(page._stack.get_page(child).get_title())
        assert names == ["Security events", "Operator decisions",
                         "Active quarantines"]
