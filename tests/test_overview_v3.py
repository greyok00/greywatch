"""Rebuild round 2, task 5: the Overview page is variant 3.

One verdict strip (is this box OK right now), one health card per rail
group (Care / Defense / System) that hands off through the guided
router, the 7-day trend bars, and a Needs-you list that shows ONLY the
decisions that carry buttons - the whole section vanishes when nothing
waits (the bug-9 law, pinned here for the rebuilt page).
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


def _iso(hours_ago=0.0):
    when = (dt.datetime.now(dt.timezone.utc)
            - dt.timedelta(hours=hours_ago))
    return when.isoformat()


def _day(hours_ago):
    return "{0:%b} {0.day}".format(
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours_ago))


class _FakeWin:
    """A window seam: handoff and _show record; refresh counts."""

    def __init__(self):
        self.handoffs = []
        self.shows = []
        self.refreshes = 0
        self.registry = []
        self.chat_llm = None

    def handoff(self, page_key, dock_group=None, row=None):
        self.handoffs.append((page_key, dock_group, row))
        return True

    def _show(self, key):
        self.shows.append(key)

    def refresh(self):
        self.refreshes += 1

    def _get_status(self):
        return {}

    def _get_recent(self):
        return []

    def _assistant_intent(self, *_a, **_k):
        pass


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def _page(win=None):
    from ui.console import OverviewPage
    win = win or _FakeWin()
    return OverviewPage(win=win), win


def _page_of(content):
    """The builder returns the page whole since the fit law (2026-11-10)
    removed the whole-page scroller; the unwrap only survives for an
    aperture-clamped content."""
    if isinstance(content, Gtk.Viewport):
        return content.get_child()
    try:
        import gi
        gi.require_version("Adw", "1")
        from gi.repository import Adw
        if isinstance(content, Adw.Clamp):
            return content.get_child()
    except (ImportError, ValueError):
        pass
    return content


def _snap(**over):
    tools = {f"tool{i}": {"state": "GREEN" if i % 2 else "YELLOW",
                          "installed": True} for i in range(10)}
    snap = {"updated": _iso(0),
            "tools": tools,
            "defense": {"blocked": [{"ip": "203.0.113.9", "ts": ""}]},
            "pending_decisions": 2,
            "recent": [
                {"ts": _iso(1), "from_tool": "ufw",
                 "severity": "HIGH", "text": "BLOCK"}]}
    snap.update(over)
    return snap


# ------------------------------------------------------------- verdict strip

def test_verdict_strip_counts_the_published_digest(store):
    page, _w = _page()
    page.refresh(_snap())
    texts = [str(chip.get_text() or "") for chip in page._chips]
    assert "tools 5 / 10" in texts
    assert "decisions 2" in texts
    assert "blocked 1" in texts
    assert "findings 1 HIGH" in texts


def test_ok_box_says_so_and_warns_by_counts(store):
    page, _w = _page()
    snap = _snap()
    snap["tools"] = {t: {"state": "GREEN", "installed": True}
                     for t in snap["tools"]}
    snap["defense"] = {"blocked": []}
    snap["pending_decisions"] = 0
    snap["recent"] = []
    page.refresh(snap)
    assert page.verdict_head.get_text() == "This box is OK right now"
    assert page.status_glyph.has_css_class("ok")

    page.refresh(_snap())          # a yellow tool + 2 waiting = attention
    assert "things need you" in page.verdict_head.get_text()
    assert page.status_glyph.has_css_class("warn")


def test_snapshot_age_is_stated(store):
    page, _w = _page()
    page.refresh(_snap())
    assert "s ago" in page.age_label.get_text()
    page.refresh(_snap(updated=_iso(24 * 40)))
    assert "waiting for the daemon" in page.age_label.get_text()


# -------------------------------------------------------------- group cards

def test_group_cards_handoff_through_stable_string_keys(store):
    page, win = _page()
    for key in ("care", "defense", "system"):
        page.group_cards[key].emit("clicked")
    assert [(p, r) for p, _g, r in win.handoffs] == [
        ("tools", "care"), ("defense", "defense"), ("logs", "system")]
    assert win.shows == []         # the guided hop landed; no fallback ran


def test_group_card_click_falls_back_when_handoff_is_idle(store):
    """auto_jump off (or the item already routed once) may silence the
    guided hop, but a click always works: the card falls through to the
    window's own _show."""
    page, win = _page()

    def no_route(_key, dock_group=None, row=None):
        return False
    win.handoff = no_route
    page.group_cards["defense"].emit("clicked")
    assert win.shows == ["defense"]


def test_group_cards_carry_two_status_lines(store):
    page, _w = _page()
    page.refresh(_snap())
    lines = " ".join(str(line.get_text() or "") for line in
                     page._group_lines["defense"])
    assert "2 decisions waiting" in lines
    assert "1" in lines and "blocked" in lines
    care = " ".join(str(line.get_text() or "") for line in
                    page._group_lines["care"])
    assert "5 / 10" in care
    syslines = " ".join(str(line.get_text() or "") for line in
                        page._group_lines["system"])
    assert "checked in" in syslines


# ------------------------------------------------------------------- trend

def test_trend_buckets_from_the_published_recent_list(store):
    page, _w = _page()
    rows = [{"ts": _iso(26), "from_tool": "ufw"},
            {"ts": _iso(27), "from_tool": "ufw"},
            {"ts": _iso(2), "from_tool": "clamav"}]
    page.refresh(_snap(recent=rows))
    buckets = page.trend_buckets()
    assert len(buckets) == 7
    counts = [c for _label, c in buckets]
    assert counts[-1] == 1
    assert counts[-2] == 2


def test_trend_radio_switches_to_24_hours(store):
    page, _w = _page()
    page.refresh(_snap())
    page._set_range("24h")
    assert page._trend_range == "24h"
    assert len(page.trend_buckets()) == 24


def test_trend_is_honest_when_the_source_is_empty(store):
    page, _w = _page()
    page.refresh(_snap(recent=[]))
    assert page.trend_buckets() == []
    assert page._trend_empty.get_visible()


def test_peak_bar_is_named_in_the_tooltip(store):
    page, _w = _page()
    rows = [{"ts": _iso(26), "from_tool": "ufw"}]
    page.refresh(_snap(recent=rows))
    tip = str(page._trend.get_tooltip_text() or "")
    assert "1 event" in tip and _day(26) in tip


# ---------------------------------------------------------------- needs you

_QUESTION = {"id": "responderd:q1", "source": "responderd",
             "kind": "question", "title": "quarantine ask", "detail": "",
             "ts": _iso(3),
             "options": [{"id": "keep", "label": "Keep",
                          "helper": "keep-quarantine"}],
             "spec": {"id": "responderd:q1", "eyebrow": "Threat found",
                      "subject": "'evil.bin' was quarantined",
                      "question": "Keep it locked away?",
                      "options": [{"id": "keep", "label": "Keep",
                                   "helper": "keep-quarantine"}]}}


def _publish(store, items):
    (store / "status.json").write_text(json.dumps(
        {"updated": _iso(0), "pending_list": items}))


def test_needs_you_lists_only_items_with_buttons(store):
    page, _w = _page()
    _publish(store, [
        _QUESTION,
        {"id": "hunter:adv", "source": "browser-watch", "kind": "advisory",
         "title": "scan finished", "detail": "", "ts": "",
         "options": [{"id": "note", "label": "Noted"}],
         "spec": {"id": "hunter:adv", "subject": "scan finished",
                  "options": [{"id": "note", "label": "Noted"}]}},
    ])
    page.refresh(_snap())
    assert page.needs_you_box.get_visible()
    buttons = page.action_buttons()
    assert len(buttons) == 1
    assert str(buttons[0].get_label() or "") == "Keep"


def test_needs_you_hides_card_and_title_when_empty(store):
    """The bug-9 law on the rebuilt page: nothing waiting means the
    section AND its title are gone, not an empty-looking card."""
    page, _w = _page()
    page.refresh(_snap())
    assert not page.needs_you_box.get_visible()
    page.refresh(_snap())          # still nothing on disk
    assert not page.needs_you_box.get_visible()


def test_needs_you_row_click_hands_off_with_the_decision_id(store):
    page, win = _page()
    _publish(store, [_QUESTION])
    page.refresh(_snap())
    page.needs_you_row_open("responderd:q1")
    assert win.handoffs == [("defense", None, "responderd:q1")]


def test_needs_you_buttons_run_through_the_answer_pipeline(
        store, monkeypatch):
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    page, _w = _page()
    _publish(store, [_QUESTION])
    page.refresh(_snap())
    btn = page.action_buttons()[0]
    runs = []
    monkeypatch.setattr(
        "ui.console._helper_exec",
        lambda helper, args: (runs.append(helper) or 0, ""))
    recorded = []
    monkeypatch.setattr(
        "ui.decisionlist.answer_record",
        lambda *a, **_k: recorded.append(a) or True)
    btn.emit("clicked")
    for _ in range(40):
        ctx.iteration(False)
    assert runs == ["keep-quarantine"]
    assert recorded[-1][1] == "responderd:q1"


# ------------------------------------------------------------------- dock

def test_build_overview_hands_the_three_dock_groups(store):
    from ui.console import build_overview
    win = _FakeWin()
    _content, groups = build_overview(win)
    assert [t for t, _ws in groups] == ["Snapshot", "Trend", "Ask about"]
    widgets = [w for _t, ws in groups for w in ws]
    assert any(isinstance(w, Gtk.Button) and
               "Refresh now" in str(w.get_label() or "") for w in widgets)


def test_dock_refresh_button_calls_window_refresh(store):
    from ui.console import build_overview
    win = _FakeWin()
    _content, groups = build_overview(win)
    snap_group = dict(groups)["Snapshot"]
    btn = next(w for w in snap_group if isinstance(w, Gtk.Button))
    btn.emit("clicked")
    assert win.refreshes == 1


def test_dock_trend_radios_re_render_the_chart(store):
    from ui.console import build_overview
    win = _FakeWin()
    content, groups = build_overview(win)
    page = _page_of(content)
    page.refresh(_snap())
    trend_group = dict(groups)["Trend"]
    radios = [w for w in trend_group if isinstance(w, Gtk.CheckButton)]
    assert len(radios) == 2
    radios[1].set_active(True)
    assert page._trend_range == "24h"
    assert len(page.trend_buckets()) == 24


def test_dock_ask_button_focuses_the_assistant(store, monkeypatch):
    from ui.console import build_overview
    win = _FakeWin()
    content, groups = build_overview(win)
    page = _page_of(content)
    asks = dict(groups)["Ask about"]
    btn = next(w for w in asks if isinstance(w, Gtk.Button))
    focused = []
    monkeypatch.setattr(page, "focus_assistant", lambda: focused.append(1))
    btn.emit("clicked")
    assert focused == [1]


# --------------------------------------------- the trend card's table

def test_trend_table_toggle_swaps_chart_for_table(store):
    """The dataviz table law, on the Overview trend card: the toggle in
    the card swaps the bars for a date/count table of the same buckets,
    in the same card."""
    page, _ = _page()
    page.refresh({"recent": [{"ts": _iso(2)}, {"ts": _iso(26)}]})
    buckets = page.trend_buckets()
    assert buckets
    card = page._trend
    assert card._area.get_visible()
    assert not card._table_scroll.get_visible()
    page._trend_toggle.set_active(True)
    assert not card._area.get_visible()
    assert card._table_scroll.get_visible()
    rows = list(card._table)
    assert len(rows) == len(buckets)
    # the rows carry the buckets' own label and count
    labels = [row.get_first_child().get_text() for row in rows]
    counts = [row.get_first_child().get_next_sibling().get_text()
              for row in rows]
    assert labels == [b[0] for b in buckets]
    assert counts == [str(b[1]) for b in buckets]
    # and back: the bars return
    page._trend_toggle.set_active(False)
    assert card._area.get_visible()
    assert not card._table_scroll.get_visible()


def test_trend_table_empty_state_is_honest(store):
    """No events = no fake table rows, in either view: the empty copy
    the chart already shows is the same one the table view shows."""
    page, _ = _page()
    page._trend_evs = []
    page.refresh({})
    page._trend_toggle.set_active(True)
    card = page._trend
    assert not list(card._table)
    assert card._empty.get_visible()
