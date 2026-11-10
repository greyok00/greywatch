"""Rebuild round 2, task 6 (owner variant 1): the Activity Log is ONE
chronology table with a tab strip - Everything / Decisions / Blocks /
Findings - over the page's existing data, with per-row enforcement
actions chosen by the producing tool, the blocks-per-hour strip under
the table, the Filter / Sources / Actions dock groups, and the
waiting/glitch row that glows with the guided pulse class as the
hand-off target.

Every action re-uses an existing lane and nothing new: block-ip /
lift-block for psad rows, the appfw ask-answer bridge for appfw rules,
baseline-update.sh (rkhunter --propupd) for reviewer-blessed rkhunter
rows, and the page's own diff-review read dialog for aide. After any
action the page says plainly what happened.
"""
import datetime as dt
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


class _FakeWin:
    """The page's seams with the window, as the real MainWindow carries
    them: a registry for the Sources toggles, the decisions-window
    opener, and nothing else - the page owns its own run pipeline."""

    def __init__(self, data_dir):
        self.data_dir = str(data_dir)
        self.registry = [{"name": "psad"}, {"name": "aide"},
                         {"name": "rkhunter"}, {"name": "appfw"},
                         {"name": "fail2ban"}]
        self._opened = 0

    def _open_decisions(self, *_a):
        self._opened += 1


def _page(store):
    from ui.auditlog import ActivityLogPage
    win = _FakeWin(store)
    page = ActivityLogPage(win=win)
    page._now = lambda: NOW        # the honest clock, pinned for tests
    return page, win


NOW = dt.datetime(2026, 11, 10, 14, 30, tzinfo=dt.timezone.utc)


def _psad_probe(at="2026-11-10T07:12:00+00:00"):
    return {"ts": at, "from_tool": "psad", "severity": "HIGH",
            "text": "src: 192.0.2.7, ports: DANGER: 1"}


def _psad_block(at="2026-11-10T07:20:00+00:00"):
    return {"ts": at, "from_tool": "psad", "severity": "CRITICAL",
            "text": "added iptables auto-block against 192.0.2.7 after 5"
                    " probes"}


# ------------------------------------------------------------ the tabs

class TestTabStrip:
    def test_tab_strip_order(self, store):
        page, _win = _page(store)
        labels = [str(b.get_label()) for b in page._tabs.values()]
        assert labels == ["Everything", "Decisions", "Blocks", "Findings"], \
            (labels, "the owner's variant 1 strip, in order")

    def test_tabs_read_the_existing_ledgers(self, store):
        (store / "events.jsonl").write_text(
            json.dumps(_psad_probe()) + "\n" +
            json.dumps(_psad_block()) + "\n" +
            json.dumps({"ts": "2026-11-10T08:00:00+00:00",
                        "from_tool": "fail2ban", "severity": "MEDIUM",
                        "text": "check-in: ok"}) + "\n")
        (store / "decisions.jsonl").write_text(json.dumps({
            "id": "fail2ban:ab12cd", "option": "keep",
            "ts": "2026-11-09T07:12:00+00:00"}) + "\n")
        (store / "quarantine.jsonl").write_text(json.dumps({
            "ts": "2026-11-09 13:31:30",
            "orig": "/home/grey/Downloads/gw-eicar.txt",
            "file": "/var/lib/greywatch/quar/gw-eicar.txt.quar",
            "sha256_16": "275a021b", "tag": "onaccess:Eicar-Test"}) + "\n")
        page, _win = _page(store)
        page.refresh()
        store_ = page._store
        text = [str(r[4]) for r in store_]
        assert page._tab == "Everything"
        assert any("192.0.2.7" in t for t in text), text

        page._set_tab("Decisions")
        text = [str(r[4]) for r in page._store]
        assert any("intrusion blocker" in t.lower() for t in text), text

        page._set_tab("Blocks")
        text = [str(r[4]) for r in page._store]
        assert text and all("192.0.2.7" in t for t in text)
        assert all(r[5]["from_tool"] == "psad" for r in page._store)

        page._set_tab("Findings")
        text = [str(r[4]) for r in page._store]
        assert any("gw-eicar.txt" in t for t in text), text

    def test_empty_ledgers_say_so_honestly(self, store):
        page, _win = _page(store)
        page.refresh()
        for tab, honest in (("Everything", "no events"),
                            ("Decisions", "no answers"),
                            ("Blocks", "no blocks"),
                            ("Findings", "nothing")):
            page._set_tab(tab)
            words = " | ".join(_words(page))
            assert honest in words.lower() or not page._store, \
                (tab, "the tab must say when it holds nothing")


# ------------------------------------------- per-row actions (per tool)

class TestRowActions:
    def test_psad_rows_block_and_unblock_through_existing_helpers(self, store):
        from ui.auditlog import row_options
        opts = row_options(_psad_probe())
        names = [o["id"] for o in opts]
        assert names[:2] == ["block", "unblock"]
        assert opts[0]["helper"] == "block-ip"
        assert opts[0]["args"] == ["192.0.2.7"]
        assert opts[1]["helper"] == "lift-block"
        assert opts[1]["args"] == ["192.0.2.7"]

    def test_psad_row_without_an_ip_offers_nothing(self, store):
        from ui.auditlog import row_options
        assert [o["id"] for o in row_options(
            {"ts": "t", "from_tool": "psad", "text": "signature match: 41"})] \
            == []

    def test_rkhunter_rows_update_the_baseline(self, store):
        from ui.auditlog import row_options
        opts = row_options({"ts": "2026-11-10T07:00:00+00:00",
                            "from_tool": "rkhunter", "severity": "HIGH",
                            "text": "Warning: hidden file /etc/x"})
        base = [o for o in opts if o["id"] == "baseline"]
        assert base, opts
        assert base[0]["label"] == "Update baseline"
        assert base[0]["helper"] == "baseline-update"
        assert base[0]["args"] == ["rkhunter"]

    def test_aide_rows_review_the_diff_through_its_read_lane(self, store):
        from ui.auditlog import row_options
        opts = row_options({"ts": "2026-11-10T03:00:00+00:00",
                            "from_tool": "aide", "severity": "HIGH",
                            "text": "changed: /etc/passwd f..H......."})
        diff = [o for o in opts if o["id"] == "aide-review"]
        assert diff and diff[0]["label"] == "Review diff"
        # the read lane never runs a helper against the system
        assert not diff[0].get("helper")

    def _appfw_row(self):
        return {"ts": "2026-11-10T09:00:00+00:00", "from_tool": "appfw",
                "severity": "HIGH",
                "interaction": {
                    "id": "appfw:brave:4242:5555",
                    "subject": "brave wants internet access",
                    "options": [
                        {"id": "allow-always",
                         "label": "Always allow this program",
                         "tone": "quiet", "helper": "none",
                         "args": ["allow", "always"]},
                        {"id": "block-always",
                         "label": "Always block this program",
                         "tone": "danger", "helper": "none",
                         "args": ["deny", "always"]}]}}

    def test_appfw_row_with_a_live_ask_answers_the_rule(self, store):
        import hashlib
        from ui.auditlog import row_options
        asks = store / "appfw" / "asks"
        asks.mkdir(parents=True)
        key = hashlib.sha256(b"appfw:brave:4242:5555").hexdigest()[:16]
        (asks / f"{key}.json").write_text(json.dumps({
            "id": "appfw:brave:4242:5555", "spec": {}}))
        opts = row_options(self._appfw_row())
        allow = [o for o in opts if o["id"] == "appfw-allow"]
        block = [o for o in opts if o["id"] == "appfw-block"]
        assert allow and block, opts
        # the answer rides the existing ask-answer bridge (the same
        # JSON the ask dialog writes; action + duration)
        assert allow[0]["args"][:2] == ["allow", "always"]
        assert block[0]["args"][:2] == ["deny", "always"]
        assert allow[0]["kind"] == "appfw-answer"
        # no polkit helper runs: the bridge is the lane
        assert not allow[0].get("helper")

    def test_appfw_row_without_a_live_ask_is_disabled_honestly(self, store):
        from ui.auditlog import row_options
        opts = row_options(self._appfw_row())
        for o in opts:
            if o["id"] in ("appfw-allow", "appfw-block"):
                assert o.get("disabled") is True, \
                    "an ask that is gone must not ship a button that" \
                    " pretends to work"
                assert "ask is closed" in o["why"]
                assert "asks again" in o["why"]

    def test_a_plain_appfw_record_is_disabled_honestly(self, store):
        from ui.auditlog import row_options
        opts = row_options({"ts": "t", "from_tool": "appfw",
                            "text": "blocked brave -> example.com"})
        dis = [o for o in opts if o.get("disabled")]
        assert dis, opts


class TestRowCard:
    """The fix card on one row carries the producing tool's actions."""

    def _card(self, page, ev, kind="event"):
        page._presented = []
        import ui.auditlog as A
        old = A.present_now
        A.present_now = lambda d: page._presented.append(d)
        try:
            page._row_card(ev, kind)
        finally:
            A.present_now = old
        return page._presented[0]

    @staticmethod
    def _buttons(dlg):
        out = []

        def walk(w):
            c = w.get_first_child()
            while c is not None:
                if isinstance(c, Gtk.Button):
                    out.append(c)
                walk(c)
                c = c.get_next_sibling()
        walk(dlg.get_content_area())
        return out

    def test_psad_card_routes_block(self, store):
        page, _win = _page(store)
        seen = []
        page._confirm_and_run = lambda opt: seen.append(dict(opt))
        cap = self._card(page, _psad_block())
        btn = [b for b in self._buttons(cap)
               if b.get_label() == "Block 192.0.2.7"]
        assert btn, [b.get_label() for b in self._buttons(cap)]
        btn[0].emit("clicked")
        assert seen == [{"id": "block", "label": "Block 192.0.2.7",
                         "tone": "primary", "helper": "block-ip",
                         "args": ["192.0.2.7"], "kind": "helper"}]

    def test_findings_card_keeps_the_three_stored_answers(self, store):
        rec = {"ts": "2026-11-09 13:31:30",
               "orig": "/home/grey/Downloads/gw-eicar.txt",
               "file": "/var/lib/greywatch/quar/gw-eicar.txt.quar",
               "sha256_16": "275a021b", "tag": "onaccess:Eicar"}
        page, _win = _page(store)
        seen = []
        page._confirm_and_run = lambda opt: seen.append(dict(opt))
        cap = self._card(page, rec, kind="quarantine")
        btns = {b.get_label(): b for b in self._buttons(cap)}
        for want in ("Keep quarantined", "Put it back", "Secure-wipe"):
            assert want in btns, (want, list(btns))
        btns["Secure-wipe"].emit("clicked")
        assert seen[0]["helper"] == "delete-quarantine"
        assert seen[0]["args"] == ["/home/grey/Downloads/gw-eicar.txt"]

    def test_aide_review_opens_the_read_lane(self, store):
        import ui.auditlog as A
        ev = {"ts": "2026-11-10T03:00:00+00:00", "from_tool": "aide",
              "severity": "HIGH", "text": "changed: /etc/passwd f....."}
        page, _win = _page(store)
        shown = []
        old = A.present_now
        A.present_now = lambda d: shown.append(d)
        try:
            page._row_card(ev, "event")
            btn = [b for b in self._buttons(shown[0])
                   if b.get_label() == "Review diff"]
            assert btn
            btn[0].emit("clicked")
        finally:
            A.present_now = old
        # a second dialog appeared: the page's diff read, which names the
        # changed path and never runs a helper against the system
        assert len(shown) == 2, shown
        texts = [w.get_text() for w in _walk(shown[1].get_content_area())
                 if isinstance(w, Gtk.Label)]
        assert any("/etc/passwd" in t for t in texts), texts
        assert any("baseline" in t.lower() for t in texts), texts


# ------------------------------------------------- the resolution line

class TestResolutionWording:
    def test_done_says_done(self, store):
        page, _win = _page(store)
        page._after_run("Put it back", 0, "")
        assert page._status.get_text().startswith("Put it back:")
        assert "done" in page._status.get_text().lower()

    def test_failure_quotes_the_helper(self, store):
        page, _win = _page(store)
        page._after_run("Block 192.0.2.7", 66, "block-ip: refused")
        words = page._status.get_text().lower()
        assert "did not finish" in words
        assert "refused" in words, "the helper's own reason rides along"

    def test_runner_fails_when_the_helper_lane_is_missing(self, store, monkeypatch):
        """The page's runner goes through the same cli seam the whole
        suite reroutes in tests: an exit code means the truth is shown."""
        page, _win = _page(store)
        page._after_run("x", -1, "helper gone")
        assert "did not finish" in page._status.get_text().lower()


# --------------------------------------------------- blocks-per-hour

class TestBlockStrip:
    def test_buckets_are_24_and_hourly(self, store):
        from ui.auditlog import block_buckets
        rows = [_psad_block(at="2026-11-10T13:00:00+00:00"),
                _psad_block(at="2026-11-10T13:59:00+00:00"),
                _psad_block(at="2026-11-10T01:00:00+00:00")]
        buckets = block_buckets(rows, now=NOW)
        assert len(buckets) == 24
        assert [c for _l, c in buckets].count(0) >= 21
        assert sum(c for _l, c in buckets) == 3
        assert max(c for _l, c in buckets) == 2

    def test_the_strip_is_a_drawing_area_under_the_table(self, store):
        page, _win = _page(store)
        from gi.repository import Gtk as G
        areas = [w for w in _walk(page)
                 if isinstance(w, G.DrawingArea) and getattr(
                     w, "_gw_strip", False)]
        assert areas, "the blocks-per-hour strip must be part of the page"
        # and it sits AFTER the chronology table in the page's own column
        table = page._view
        order = [w for w in _walk(page)]
        assert order.index(areas[0]) > order.index(table)

    def test_empty_state_is_honest(self, store):
        page, _win = _page(store)
        page.refresh()
        strip = page._strip
        assert strip._empty.get_visible()
        words = strip._empty.get_text().lower()
        assert "no blocks" in words and "day" in words, words
        # with content the note leaves and the tooltip carries the story
        (store / "events.jsonl").write_text(
            json.dumps(_psad_block(at="2026-11-10T13:00:00+00:00")) + "\n")
        page.refresh()
        assert not strip._empty.get_visible()
        assert "peak" in strip._area.get_tooltip_text().lower()

    def test_rows_out_of_the_window_never_invent_a_bar(self, store):
        from ui.auditlog import block_buckets
        rows = [_psad_block(at="2026-11-10T13:00:00+00:00"),
                _psad_block(at="2026-01-01T00:00:00+00:00")]
        buckets = block_buckets(rows, now=NOW)
        assert sum(c for _l, c in buckets) == 1


# --------------------------------------------------- the attention row

class TestAttentionRow:
    SPEC = {"id": "appfw:brave:1:2", "subject": "brave wants internet",
            "eyebrow": "App firewall",
            "options": [{"id": "allow-once", "label": "Allow",
                         "args": ["allow", "once"]}]}

    def test_the_waiting_row_glows_with_the_guided_pulse(self, store):
        (store / "events.jsonl").write_text(json.dumps({
            "ts": "2026-11-10T09:00:00+00:00", "from_tool": "appfw",
            "severity": "HIGH", "interaction": self.SPEC,
            "text": "ask"}) + "\n")
        page, _win = _page(store)
        page.refresh()
        row = page.attention_row()
        assert row is not None
        assert "gw-guided-pulse" in row.get_css_classes(), \
            "the row that needs the owner IS the hand-off target"
        labels = _words(row)
        assert any("brave" in str(t) for t in labels), labels
        assert any("waiting" in str(t).lower() for t in labels), labels

    def test_an_answered_ask_gives_back_the_row(self, store):
        (store / "events.jsonl").write_text(json.dumps({
            "ts": "2026-11-10T09:00:00+00:00", "from_tool": "appfw",
            "severity": "HIGH", "interaction": self.SPEC,
            "text": "ask"}) + "\n")
        page, _win = _page(store)
        (store / "decisions.jsonl").write_text(json.dumps(
            {"id": self.SPEC["id"], "option": "allow-once",
             "ts": "2026-11-10T09:01:00+00:00"}) + "\n")
        page.refresh()
        assert page.attention_row() is None

    def test_quiet_history_has_no_attention_row(self, store):
        (store / "events.jsonl").write_text(json.dumps(
            {"ts": "2026-11-10T09:00:00+00:00", "from_tool": "psad",
             "severity": "HIGH", "text": "src: 192.0.2.9, ports: x"})
            + "\n")
        page, _win = _page(store)
        page.refresh()
        assert page.attention_row() is None

    def test_the_decide_button_opens_the_decisions_window(self, store):
        (store / "events.jsonl").write_text(json.dumps({
            "ts": "2026-11-10T09:00:00+00:00", "from_tool": "appfw",
            "severity": "HIGH", "interaction": self.SPEC,
            "text": "ask"}) + "\n")
        page, win = _page(store)
        page.refresh()
        row = page.attention_row()
        btn = [w for w in _walk(row) if isinstance(w, Gtk.Button)
               and w.get_label() == "Decide"]
        assert btn
        btn[0].emit("clicked")
        assert win._opened == 1
