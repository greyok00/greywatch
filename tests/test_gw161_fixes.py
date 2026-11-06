"""GW-161..163 fix wave pins (reports of 2026-11-04).

GW-161: the pill said "29 decisions waiting" and nothing was clickable.
GW-162: an appfw ask dialog survived the daemon's own 30 s answer window;
        phantom answers could be written for asks nobody would read.
GW-163: every toplevel activation was handed to the window manager with
        timestamp 0 (owner-visible focus races under marco).
Also: the hunter clock said "NEXT ~1 SEC" forever on a dead runner, and
the event note claimed "answered: deny" when nobody was watching.
"""
import datetime as _dt
import json

import gi
import pytest

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib  # noqa: E402

import greywatch_daemon as dm

ASK_SPEC = {
    "id": "appfw:brave:4242:55555",
    "eyebrow": "App firewall",
    "subject": "brave wants internet access",
    "detail": "/usr/bin/brave → example.com:443 (TCP) · pid 4242",
    "host": "example.com",
    "options": [
        {"id": "deny-once", "label": "Block", "tone": "primary",
         "helper": "keep-quarantine", "args": ["x"]},
        {"id": "allow-once", "label": "Allow", "tone": "danger",
         "helper": "restore-quarantine", "args": ["y"]},
    ],
}


def _spec(sid, subject="a file was quarantined"):
    return {"id": sid, "eyebrow": "Threat found", "subject": subject,
            "detail": "sig · /tmp/x", "question": "Keep it?",
            "options": [{"id": "keep", "label": "Keep quarantined",
                         "tone": "primary", "helper": "keep-quarantine",
                         "args": ["/tmp/x"]}]}


def _event(ts, sid, subject="a file"):
    return {"ts": ts, "from_tool": "responderd", "severity": "INFO",
            "text": "quarantine: /tmp/x", "interaction": _spec(sid, subject=subject)}


def _iso(when):
    return when.isoformat()


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "DATA_DIR", tmp_path)
    # GW-166: the overlay resolves the store from the env at call time, so
    # the test steers it the way the runtime does.
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def _pump(context=None):
    context = context or GLib.main_context_default()
    while context.pending():
        context.iteration(False)


# -- GW-161: the list ----------------------------------------------------

def test_pending_rows_scan_the_whole_file(store):
    # Put the live ask far before the file's tail: a capped read would
    # miss it and the pill's count would disagree with the list.
    lines = ['{"ts":"2026-11-01T00:00:00+00:00","from_tool":"x","text":"n"}']
    lines.append(json.dumps(_event("2026-11-01T01:00:00+00:00",
                                   "responderd:abc")))
    lines += [json.dumps({"ts": f"2026-11-0{d}T02:00:00+00:00",
                          "from_tool": "noise", "text": "n"})
              for d in range(2, 5)]
    (store / "events.jsonl").write_text("\n".join(lines) + "\n")
    from ui.decisionlist import pending_rows
    rows = pending_rows(store)
    assert [r[0]["id"] for r in rows] == ["responderd:abc"]


def test_pending_rows_dedupe_and_answered_filter(store):
    answered_id = "responderd:dup"
    (store / "events.jsonl").write_text("\n".join([
        json.dumps(_event("2026-11-01T01:00:00+00:00", answered_id)),
        json.dumps(_event("2026-11-01T05:00:00+00:00", answered_id)),
        json.dumps(_event("2026-11-01T02:00:00+00:00", "responderd:live")),
    ]) + "\n")
    (store / "decisions.jsonl").write_text(
        json.dumps({"id": answered_id, "option": "keep"}) + "\n")
    from ui.decisionlist import pending_rows
    rows = pending_rows(store)
    assert [r[0]["id"] for r in rows] == ["responderd:live"]


def test_pending_rows_newest_encounter_wins_for_age(store):
    (store / "events.jsonl").write_text("\n".join([
        json.dumps(_event("2026-11-01T01:00:00+00:00", "responderd:dup")),
        json.dumps(_event("2026-11-01T09:00:00+00:00", "responderd:dup")),
    ]) + "\n")
    from ui.decisionlist import pending_rows
    rows = pending_rows(store)
    assert len(rows) == 1 and rows[0][1] == "2026-11-01T09:00:00+00:00"


def test_status_json_fallback_when_events_unreadable(store):
    snap = {"recent": [_event("2026-11-01T01:00:00+00:00", "responderd:abc")]}
    (store / "status.json").write_text(json.dumps(snap))
    from ui.decisionlist import pending_rows
    assert [r[0]["id"] for r in pending_rows(store)] == ["responderd:abc"]


@pytest.mark.gtk
def test_decisions_window_renders_pending(store):
    (store / "events.jsonl").write_text(
        json.dumps(_event("2026-11-01T01:00:00+00:00", "responderd:abc")) + "\n")
    from ui.decisionlist import DecisionsWindow
    w = DecisionsWindow()
    assert w._headline.get_text() == "1 decision waiting"
    rows = list(w._list)
    assert len(rows) == 1
    w.destroy()


@pytest.mark.gtk
def test_decisions_window_empty_state(store):
    from ui.decisionlist import DecisionsWindow
    w = DecisionsWindow()
    assert w._headline.get_text() == "No decisions waiting"
    w.destroy()


def _exit_script(tmp_path, code):
    helper = tmp_path / "fake-helper.sh"
    helper.write_text(f"#!/bin/sh\nexit {code}\n")
    helper.chmod(0o755)
    return helper


@pytest.mark.gtk
def test_decisions_window_answer_records_and_clears(store, monkeypatch,
                                                    tmp_path):
    helper = _exit_script(tmp_path, 0)
    monkeypatch.setenv("GREYWATCH_HELPER_CMD", str(helper))
    (store / "events.jsonl").write_text(
        json.dumps(_event("2026-11-01T01:00:00+00:00", "responderd:abc")) + "\n")
    calls = []
    from ui.decisionlist import DecisionsWindow
    w = DecisionsWindow(on_change=lambda: calls.append(1))
    row = w._list.get_first_child()
    btn = row._gw_first_button() if hasattr(row, "_gw_first_button") \
        else _first_button(row)
    btn.emit("clicked")
    # the answer runs on a worker thread; the record lands through
    # idle_add only once its subprocess has finished, so wait for it the
    # way test_decisions_window_failed_helper_keeps_row_open already does
    _wait_for(lambda: (store / "decisions.jsonl").exists(), 2.0)
    assert (store / "decisions.jsonl").exists()
    rec = json.loads((store / "decisions.jsonl").read_text().splitlines()[0])
    assert rec["id"] == "responderd:abc" and rec["option"] == "keep"
    assert calls == [1]
    w.destroy()


@pytest.mark.gtk
def test_decisions_window_failed_helper_keeps_row_open(store, monkeypatch,
                                                       tmp_path):
    helper = _exit_script(tmp_path, 3)
    monkeypatch.setenv("GREYWATCH_HELPER_CMD", str(helper))
    (store / "events.jsonl").write_text(
        json.dumps(_event("2026-11-01T01:00:00+00:00", "responderd:abc")) + "\n")
    from ui.decisionlist import DecisionsWindow, pending_rows
    w = DecisionsWindow()
    row = w._list.get_first_child()
    btn = _first_button(row)
    btn.emit("clicked")
    _wait_for(lambda: w._list.get_first_child() is not None
              and any("exit code 3" in str(
                  _state_text(row)) for _ in (1,)), 2.0)
    assert pending_rows(store)  # nothing recorded, decision stays open
    assert btn.get_sensitive()
    w.destroy()


def _first_button(widget):
    from gi.repository import Gtk as _G
    stack = [widget]
    while stack:
        w = stack.pop(0)
        if isinstance(w, _G.Button):
            return w
        k = w.get_first_child()
        while k is not None:
            stack.append(k)
            k = k.get_next_sibling()
    return None


def _state_text(widget):
    from gi.repository import Gtk as _G
    stack = [widget]
    while stack:
        w = stack.pop(0)
        if isinstance(w, _G.Label) and w.get_visible() and w.get_text():
            return w.get_text()
        k = w.get_first_child()
        while k is not None:
            stack.append(k)
            k = k.get_next_sibling()
    return ""


def _wait_for(fn, timeout):
    ctx = GLib.main_context_default()
    waited = 0.0
    while not fn() and waited < timeout:
        ctx.iteration(False)
        waited += 0.02
        _sleep(0.02)
    return fn()


def _sleep(s):
    import time
    time.sleep(s)


def test_age_text_shapes(store):
    from ui.decisionlist import _age_text
    now = _dt.datetime.now(_dt.timezone.utc)
    assert _age_text(None) is None
    assert _age_text("nope") is None
    assert _age_text(_iso(now)) == "asked just now"
    assert _age_text(_iso(now - _dt.timedelta(minutes=38))) \
        == "asked 38 min ago"
    assert _age_text(_iso(now - _dt.timedelta(hours=5))) == "asked 5 h ago"
    assert _age_text(_iso(now - _dt.timedelta(days=3))) == "asked 3 d ago"


# -- GW-162: retraction + phantom answers --------------------------------

def test_write_answer_skips_when_the_ask_is_gone(tmp_path):
    from ui.decisions import DecisionBroker
    b = DecisionBroker()
    answers = tmp_path / "appfw" / "answers"
    answers.mkdir(parents=True)
    b._asks_dir = tmp_path / "appfw" / "asks"
    b._asks_dir.mkdir(parents=True)
    b._answers_dir = answers
    gone = tmp_path / "appfw" / "asks" / "abc.json"   # never created
    b._write_answer(gone, "deny", "once", None)
    assert not list(answers.iterdir())


def test_retraction_destroys_dialog_when_daemon_ate_the_ask(tmp_path,
                                                            monkeypatch):
    from ui.decisions import DecisionBroker
    asks = tmp_path / "appfw" / "asks"
    answers = tmp_path / "appfw" / "answers"
    asks.mkdir(parents=True)
    answers.mkdir(parents=True)
    (asks / "abc123.json").write_text(json.dumps({
        "id": ASK_SPEC["id"],
        "ts": _dt.datetime.now(_dt.timezone.utc)
              .isoformat(timespec="seconds"),
        "spec": ASK_SPEC}))
    b = DecisionBroker()
    b._asks_dir, b._answers_dir = asks, answers
    b._asked_files = set()
    got = []
    monkeypatch.setattr(b, "_show_dialog", _recording_show(b, got))
    b._poll_appfw_asks()
    assert got and got[0] == "appfw:brave:4242:55555"
    assert b._tagged, "the ask must be tagged for retraction"
    dlg = b._tagged[list(b._tagged)[0]]
    (asks / "abc123.json").unlink()          # daemon consumed / timed out
    b._poll_appfw_asks()
    assert dlg.destroyed == 1                # the popup went down
    assert b._active is None and b._active_tag is None
    assert not list(answers.iterdir())       # no phantom answer
    assert b._queue == []


class _FakeDialog:
    """A stand-in popup: GTK's "destroy" signal fires on final dispose,
    not on destroy(), so a real widget cannot be asserted on directly."""

    def __init__(self, spec):
        self.spec = spec
        self.destroyed = 0

    def destroy(self):
        self.destroyed += 1


def _recording_show(b, got):
    """Mimic the real _show_dialog's tagging with a fake popup."""
    def show(spec, eyebrow="Protection", resolve=None, tag=None):
        got.append(spec["id"])
        dlg = _FakeDialog(spec)
        if tag is not None:
            b._tagged[tag] = dlg
    return show


# -- GW-163: no-dashboard fast path ---------------------------------------

def test_ui_alive_states(tmp_path):
    d = dm.Daemon(data_dir=tmp_path, registry=[])
    assert d._ui_alive() is False            # lock file never created
    lock = tmp_path / "gui.lock"
    lock.write_text("")
    assert d._ui_alive() is False            # file exists but is free
    import fcntl
    f = open(lock, "w")
    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert d._ui_alive() is True             # a dashboard holds the lock
    fcntl.flock(f, fcntl.LOCK_UN)
    f.close()


def test_ask_skipped_and_answered_headless_when_nobody_watch(tmp_path):
    d = dm.Daemon(data_dir=tmp_path, registry=[])
    d._ask_policy = "deny-once"
    started = _dt.datetime.now()
    got = d._appfw_ask_user(ASK_SPEC)
    took = (_dt.datetime.now() - started).total_seconds()
    assert got == ("deny", "once", None, "headless: deny (no dashboard open)")
    assert took < 1.0                        # instant, not a 30 s stall
    asks = list((tmp_path / "appfw" / "asks").glob("*.json")) \
        if (tmp_path / "appfw" / "asks").exists() else []
    assert asks == []                        # no ask left dangling


def test_headless_note_reaches_the_event_note(tmp_path):
    import tests.test_appfw as fixture
    from appfw.policy import Policy, decide
    from appfw.rules import RuleStore

    conn = fixture._conn(dst_host="example.net", dst_port=443)
    store = RuleStore(tmp_path / "rules")
    policy = Policy(tmp_path, trust_list=fixture.FakeTrust(),
                    blocklist=fixture.FakeBlock(False))

    def ask(spec):
        return ("deny", "once", None, "headless: deny (no dashboard open)")

    act, dur, note, op = decide(conn, policy, store=store, ask=ask)
    assert note == "headless: deny (no dashboard open)"
    assert act == "deny"


# -- hunter clock honesty (GW-155 face off the dead lane) -----------------

def test_hunter_clock_says_not_responding_when_stale():
    from ui.hunterview import _next_hunt_text
    now = _dt.datetime.now(_dt.timezone.utc)
    stale = now - _dt.timedelta(seconds=300 * 2.6)
    text = _next_hunt_text({"ts": _iso(stale), "interval_s": 300})
    assert "NOT RESPONDING" in text and "LAST" in text
    fresh = _next_hunt_text(
        {"ts": _iso(now - _dt.timedelta(seconds=10)), "interval_s": 300})
    assert "NEXT IN" in fresh


def test_hunter_clock_still_counts_a_live_run():
    from ui.hunterview import _next_hunt_text
    now = _dt.datetime.now(_dt.timezone.utc)
    soon = _next_hunt_text(
        {"ts": _iso(now - _dt.timedelta(seconds=90)), "interval_s": 300})
    assert "NEXT IN" in soon and "LAST" in soon


# -- assistant wording (headless rows read as denies) ----------------------

def test_assistant_matches_headless_deny_rows():
    from ui.assistant import _kind_rows
    row = {"text": "appfw /usr/bin/curl → 203.0.113.9:443 deny "
                   "[headless: deny (no dashboard open)]",
           "from_tool": "appfw", "ts": _iso(_dt.datetime.now(
               _dt.timezone.utc))}
    got = _kind_rows("denied", {"history": [], "recent": [row]})
    assert got == [row]


# -- GW-163: the timestamp clock ------------------------------------------

def test_present_now_uses_recorded_x_timestamp():
    from ui import eventclock as ec

    class FakeWin:
        def __init__(self):
            self.with_time = []
            self.bare = []

        def present_with_time(self, ts):
            self.with_time.append(ts)

        def present(self):
            self.bare.append(1)

    fake = FakeWin()
    ec._LAST[0] = 90001
    ec.present_now(fake)
    assert fake.with_time == [90001] and fake.bare == []

    ec._LAST[0] = 0                     # nothing seen yet → bare present
    ec.present_now(fake)
    assert fake.bare == [1] and fake.with_time == [90001]


@pytest.mark.gtk
def test_eventclock_attach_is_harmless_on_any_window():
    from ui import eventclock as ec
    win = Gtk.Window()
    ec.attach(win)
    win.destroy()
