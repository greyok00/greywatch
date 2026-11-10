"""GW215 (fix-wave bug 8, re-pinned on the rebuilt UI): ONE pending list,
ONE count. The old test file was lost with the retired UI; this is the
law pinned against the rebuilt pages.

The old failure mode: a count surface walked the newest event lines and
counted every ask line, so a repeated decision inflated the pill one row
per repeat ("93 vs 44"). Now the daemon publishes the pending list once
(status.json's pending_list) and every surface that displays a pending
count reads that list's length, never a raw event-line walk:

- the tray pill (ui.tray.Tray.refresh_badge),
- the broker badge (ui.decisions.DecisionBroker.badge),
- the dashboard pill (ui.window.MainWindow._refresh),
- the Home verdict line (ui.homepage.suite_summary),
- the Overview decisions chip (ui.console.OverviewPage),
- the CLI status badge (cli.cmd_status),
- the mini tile (ui.minitile.build_rows).

The rail badges are not pinned here: the Firewall rail badge counts the
watchlist's HIGH findings and the Threat Hunter rail badge the hunter's
unread notes (ui.window._refresh) - neither displays a pending-decision
count, so the bug-8 surface list does not reach them.

Every surface is pinned twice:
  published  - a list of 1 plus an event log carrying 5 duplicate ask
               lines (one id repeated 3x, one repeated 2x) and one stale
               scalar: every count reads 1, never the line count, never
               the scalar;
  unpublished - no published list (older daemon): each surface states
               its fallback honestly - tray and broker fall back to the
               whole-file dedupe scan (2 unique unanswered ids, not the
               5 lines), snapshot-fed surfaces to the scalar.
"""
import datetime as dt
import inspect
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")


@pytest.fixture
def store(tmp_path, monkeypatch):
    """The desktop-side readers steer here via GREYWATCH_DATA_DIR; the
    module-level DATA_DIR seams are patched per surface below."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def _ask(spec_id="psad:aa01", ts="2026-11-06T09:00:00+00:00"):
    return {"from_tool": "psad", "severity": "INFO",
            "text": f"auto-block ({spec_id})", "ts": ts,
            "interaction": {"id": spec_id,
                            "subject": f"{spec_id} was locked out",
                            "question": "Keep blocking, or lift it?",
                            "options": [{"id": "keep", "label": "Keep",
                                         "helper": "block-review"}]}}


def _item(spec_id="psad:aa01"):
    """A published-list item the way the daemon enriches it (gw206)."""
    spec = _ask(spec_id)["interaction"]
    return {"id": spec_id, "source": "psad", "kind": "question",
            "title": spec["subject"], "detail": "", "ts": "2026-11-06",
            "options": spec["options"], "spec": spec}


def _dup_events():
    """Five ask lines, two unique ids: the line walk's fuel."""
    return [_ask("psad:aa01", "2026-11-06T09:00:00+00:00"),
            _ask("psad:aa01", "2026-11-06T09:01:00+00:00"),
            _ask("psad:aa01", "2026-11-06T09:02:00+00:00"),
            _ask("psad:bb02", "2026-11-06T09:03:00+00:00"),
            _ask("psad:bb02", "2026-11-06T09:04:00+00:00")]


def _write_events(store, asks):
    (store / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in asks) + "\n")


def _answered(store, spec_id):
    with (store / "decisions.jsonl").open("a") as f:
        f.write(json.dumps({"id": spec_id, "answer": "keep"}) + "\n")


def _published(store, items, **extra):
    snap = {"updated": dt.datetime.now(dt.timezone.utc).isoformat(),
            "pending_list": items}
    snap.update(extra)
    (store / "status.json").write_text(json.dumps(snap))


def _published_conflict(store, wrong=93):
    """The list of 1 next to a stale scalar 93, over the duplicate-line
    event log with one id answered: every count must read 1."""
    _write_events(store, _dup_events())
    _answered(store, "psad:bb02")
    _published(store, [_item("psad:aa01")], pending_decisions=wrong,
               tools={}, recent=[])
    return {"updated": dt.datetime.now(dt.timezone.utc).isoformat(),
            "pending_decisions": wrong,
            "pending_list": [_item("psad:aa01")],
            "tools": {}, "recent": []}


# ---- the shared rule ---------------------------------------------------------

def test_snapshot_pending_reads_the_published_list_first():
    """The pure rule every snapshot-fed surface runs: the published
    list's length wins; the scalar is only the older daemon's fallback."""
    from decisions_factory import snapshot_pending
    items = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
    assert snapshot_pending({"pending_list": items,
                             "pending_decisions": 93}) == 3
    assert snapshot_pending({"pending_decisions": 4}) == 4
    assert snapshot_pending({}) == 0
    assert snapshot_pending(None) == 0


def test_pending_count_published_and_fallback(store):
    """The count for tray/broker surfaces that hold no snapshot: the
    published list's length, else the whole-file dedupe scan."""
    from decisions_factory import pending_count
    _write_events(store, _dup_events())
    assert pending_count(store) == 2        # deduped, never 5 lines
    _answered(store, "psad:bb02")
    assert pending_count(store) == 1
    _published(store, [_item("psad:aa01")])
    assert pending_count(store) == 1        # the list's row, not the
    # five lines; an old scalar planted beside it could not move it


# ---- the tray pill -----------------------------------------------------------

def _tray(monkeypatch, store):
    """A Tray without its subprocess helper: refresh_badge is what the
    law pins; the helper only mirrors the numbers it is handed."""
    import greywatch_daemon as gd
    from ui.tray import Tray
    monkeypatch.setattr(gd, "DATA_DIR", store)
    t = Tray.__new__(Tray)          # __init__ would start the helper
    t.badge_cb = None
    t.icon = "greywatch"
    t.item_id = "greywatch"
    t.on_show = t.on_quit = None
    t._proc = None
    return t


def test_tray_counts_the_published_list_not_ask_lines(store, monkeypatch):
    _write_events(store, _dup_events())
    _answered(store, "psad:bb02")
    _published_conflict(store)
    t = _tray(monkeypatch, store)
    try:
        t.refresh_badge()
        assert t._pending == 1     # the list: one row, never 5 lines
    finally:
        t.stop()


def test_tray_unpublished_falls_back_to_whole_file_scan(
        store, monkeypatch):
    _write_events(store, _dup_events())
    t = _tray(monkeypatch, store)   # no status.json at all
    try:
        t.refresh_badge()
        assert t._pending == 2     # deduped: aa01 + bb02, not 5 lines
    finally:
        t.stop()


# ---- the broker badge --------------------------------------------------------

def test_broker_badge_counts_the_published_list(store, monkeypatch):
    import greywatch_daemon as gd
    from ui.decisions import DecisionBroker
    monkeypatch.setattr(gd, "DATA_DIR", store)
    _write_events(store, _dup_events())
    _answered(store, "psad:bb02")
    _published_conflict(store)
    assert DecisionBroker().badge() == 1   # the list; the replayed cli
    # walk is gone from the count path (the old second count source)


def test_broker_badge_unpublished_falls_back_to_whole_file_scan(
        store, monkeypatch):
    import greywatch_daemon as gd
    from ui.decisions import DecisionBroker
    monkeypatch.setattr(gd, "DATA_DIR", store)
    _write_events(store, _dup_events())
    assert DecisionBroker().badge() == 2   # deduped, answered gone


# ---- the dashboard pill ------------------------------------------------------

def test_window_pill_uses_the_one_rule():
    """ui.window.MainWindow._refresh feeds the verdict machinery through
    the shared snapshot rule: the pill counts the published list the
    pages render, and no scalar walk of its own survives."""
    import ui.window as window
    src = inspect.getsource(window.MainWindow.refresh)
    assert "snapshot_pending" in src
    assert "pending_decisions" not in src.split("snapshot_pending", 1)[1]


def test_window_pill_counts_the_published_list(store):
    from decisions_factory import snapshot_pending
    snap = _published_conflict(store)
    assert snapshot_pending(snap) == 1    # list over the stale scalar


def test_window_pill_falls_back_to_the_scalar():
    from decisions_factory import snapshot_pending
    snap = {"updated": "2026-11-06T09:00:00+00:00",
            "pending_decisions": 93, "tools": {}}
    assert snapshot_pending(snap) == 93   # the older daemon's
    # scalar fallback stands behind the unpublished state


# ---- the Home verdict line ---------------------------------------------------

def test_home_verdict_counts_the_published_list(store):
    from ui.homepage import suite_summary
    _published_conflict(store)
    verdict, ctx = suite_summary(store)
    assert "1 decision waiting" in ctx
    assert "93" not in ctx                 # the stale scalar never shows


def test_home_verdict_unpublished_keeps_the_scalar(store):
    from ui.homepage import suite_summary
    (store / "status.json").write_text(json.dumps(
        {"updated": dt.datetime.now(dt.timezone.utc).isoformat(),
         "tools": {}, "pending_decisions": 2}))
    verdict, ctx = suite_summary(store)
    assert "2 decisions waiting" in ctx


# ---- the Overview decisions chip ---------------------------------------------

class _StubWin:
    registry = []
    chat_llm = None

    def _get_status(self):
        return {}

    def _get_recent(self):
        return []

    def _assistant_intent(self, *_a, **_k):
        pass


def _overview(store):
    import ui.console as console_mod
    return console_mod.OverviewPage(win=_StubWin())


def _chip_text(page):
    texts = [str(c.get_text() or "") for c in page._chips]
    return next(t for t in texts if t.startswith("decisions"))


def test_overview_chip_counts_the_published_list(store):
    page = _overview(store)
    snap = {"updated": "2026-11-06T09:00:00+00:00", "recent": [],
            "tools": {}, "pending_decisions": 93,
            "pending_list": [_item("psad:aa01")]
            + [{"id": f"note{i}", "source": "psad", "kind": "advisory",
                "title": "observed", "detail": "", "ts": "",
                "options": [{"id": "note", "label": "Noted"}],
                "spec": {"id": f"note{i}", "subject": "observed",
                         "options": [{"id": "note", "label": "Noted"}]}}
               for i in range(2)]}
    page.refresh(snap)
    assert _chip_text(page) == "decisions 3"    # the list, not 93
    # the advisory rows carry no helper, so the needs-you section stays
    # hidden (the chip counts the gate's list, the section filters it)
    assert not page.needs_you_box.get_visible()


def test_overview_chip_unpublished_keeps_the_scalar(store):
    page = _overview(store)
    page.refresh({"updated": "2026-11-06T09:00:00+00:00", "recent": [],
                  "tools": {}, "pending_decisions": 5})
    assert _chip_text(page) == "decisions 5"


# ---- the CLI status badge ----------------------------------------------------

def test_cli_status_badge_counts_the_published_list(store, monkeypatch,
                                                    capsys):
    import cli
    monkeypatch.setattr(cli, "DATA_DIR", store)
    from registry import load_registry
    snap = {"updated": dt.datetime.now(dt.timezone.utc).isoformat(),
            "dropped": 0, "pending_decisions": 93,
            "pending_list": [_item("psad:aa01")],
            "tools": {t["name"]: {"label": t["label"], "state": "GREEN",
                                  "last_event": None}
                      for t in load_registry()}}
    (store / "status.json").write_text(json.dumps(snap))
    monkeypatch.setattr(cli, "load_status", lambda _p: snap)
    rc = cli.main(["status"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 pending decision(s)" in out
    assert "93" not in out


# ---- the mini tile -----------------------------------------------------------

def test_mini_tile_counts_the_published_list(store):
    from ui.minitile import build_rows
    rows = build_rows({"pending_list": [_item("psad:aa01"),
                                        _item("psad:bb02"),
                                        _item("psad:cc03")],
                       "pending_decisions": 93})
    assert any("3 decision(s) waiting" in r for r in rows)
    assert not any("93 decision" in r for r in rows)


def test_mini_tile_unpublished_keeps_the_scalar(store):
    from ui.minitile import build_rows
    rows = build_rows({"pending_decisions": 4})
    assert any("4 decision(s) waiting" in r for r in rows)
