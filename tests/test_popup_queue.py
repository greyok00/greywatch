"""One popup at a time: the broker must never open a stack of dialogs.

Regression for the owner report "it's still spamming windows ... 5+ windows
at once" (2026-10-27).
"""
import datetime as dt

import ui.decisions as D


def _spec(i):
    return {"id": f"responderd:{i}", "question": "Keep or restore?",
            "options": [{"id": "keep", "label": "Keep", "helper": "none",
                         "args": []}]}


def _ev(i, ts=None):
    return {"from_tool": "responderd", "ts": ts or _now(), "text": "x",
            "interaction": _spec(i)}


def _now(offset=0):
    return (dt.datetime.now(dt.timezone.utc) +
            dt.timedelta(seconds=offset)).isoformat(timespec="seconds")


class Broker(D.DecisionBroker):

    def __init__(self):
        super().__init__()
        self.shown = []

    def _show_dialog(self, spec, eyebrow="Protection", resolve=None):
        self.shown.append(spec["id"])

    def _notify_denies(self, events):
        pass

    def _notify_critical(self, events):
        pass


def test_five_pending_events_open_exactly_one_popup():
    b = Broker()
    b.pump([_ev(i) for i in range(5)])
    # newest first: the freshest ask is the one worth interrupting for
    assert b.shown == ["responderd:4"]
    assert len(b._queue) == 4


def test_next_popup_only_after_the_current_one_closes():
    b = Broker()
    b.pump([_ev(i) for i in range(3)])
    b._active = None
    b._pump_next()
    assert b.shown == ["responderd:2", "responderd:1"]
    b._active = None
    b._pump_next()
    assert b.shown == ["responderd:2", "responderd:1", "responderd:0"]


def test_repeated_pump_does_not_requeue_the_same_spec():
    b = Broker()
    events = [_ev(0)]
    for _ in range(5):
        b.pump(events)
        assert len(b._queue) == 0
    assert b.shown == ["responderd:0"]


def test_stale_backlog_is_not_shown():
    b = Broker()
    b.pump([_ev(1, ts=_now(-3600))])
    assert b.shown == []


def test_appfw_specs_do_not_use_this_path():
    b = Broker()
    ev = _ev(2)
    ev["interaction"]["id"] = "appfw:abc"
    b.pump([ev])
    assert b.shown == [] and b._queue == []


def test_appfw_ask_uses_the_same_single_slot(monkeypatch):
    b = Broker()
    b.ask_timeout = 0.1
    b.pump([_ev(0)])                 # a protection popup is already up
    calls = []

    def fake_idle(fn, *a):
        fn(*a)
        return 0

    monkeypatch.setattr(D.GLib, "idle_add", fake_idle)
    monkeypatch.setattr(D.GLib, "timeout_add", lambda *_a: 0)
    b.ask_appfw({"id": "appfw:1", "question": "Allow?",
                 "options": [{"id": "allow", "label": "Allow",
                              "helper": "none", "args": ["allow", "once"]}]})
    # the queued ask must NOT have opened a second window
    assert len(b.shown) == 1
    assert b._queue and b._queue[0]["eyebrow"] == "App firewall"


def test_identical_appfw_ask_within_two_seconds_reuses_answer(monkeypatch):
    """OpenSnitch's rule: an identical connection repeated immediately reuses
    the previous answer. A browser opening parallel sockets must not queue a
    popup per socket."""
    b = Broker()
    b.ask_timeout = 0.05

    def fake_idle(fn, *a):
        fn(*a)
        return 0

    monkeypatch.setattr(D.GLib, "idle_add", fake_idle)
    spec = {"id": "appfw:1", "subject": "firefox wants internet access",
            "host": "example.org", "question": "Allow?",
            "options": [{"id": "allow", "label": "Allow",
                         "helper": "none", "args": ["allow", "once"]}]}
    first = b.ask_appfw(dict(spec))
    queued = len(b._queue)
    second = b.ask_appfw(dict(spec, id="appfw:2"))
    assert second == first == ("allow", "once")
    assert len(b._queue) == queued          # no second popup queued


def test_different_site_is_still_asked(monkeypatch):
    b = Broker()
    b.ask_timeout = 0.05

    def fake_idle(fn, *a):
        fn(*a)
        return 0

    monkeypatch.setattr(D.GLib, "idle_add", fake_idle)
    spec = {"id": "appfw:1", "subject": "firefox wants internet access",
            "host": "example.org", "question": "Allow?",
            "options": [{"id": "allow", "label": "Allow",
                         "helper": "none", "args": ["allow", "once"]}]}
    b.ask_appfw(dict(spec))
    queued = len(b._queue)
    b.ask_appfw(dict(spec, id="appfw:2", host="other.org"))
    assert len(b._queue) == queued + 1
