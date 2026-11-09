"""GW-193 — the critical lane stopped treating this machine's own tools
like outside threats.

Owner findings live, right after the 0.1.21 install (2026-11-05):
- the first popup after launch replayed a forty-minute-old rkhunter alarm
  from the events file, because the critical filter never looked at age;
- a tool-down popup offered Block address / Block program, which are
  connections words and did nothing about a local scanner;
- the popup should have been able to START the tool it was complaining
  about.
"""
import datetime as _dt
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui import notify_alert as na
from ui.notify_alert import (CriticalSquare, CriticalEvents,
                             critical_filter, start_tool)


UTC = _dt.timezone.utc


class _FakeNotification:
    instances = []

    def __init__(self, summary=None, body=None):
        self.summary, self.body = summary, body
        self.updates = []
        self.shown = 0
        self.actions = []

    @classmethod
    def new(cls, summary, body):
        inst = cls(summary, body)
        cls.instances.append(inst)
        return inst

    def set_timeout(self, t):
        pass

    def update(self, s, b):
        self.updates.append((s, b))

    def add_action(self, *a):
        self.actions.append(a)

    def show(self):
        self.shown += 1


class _FakeNotify:
    Notification = _FakeNotification


def _aged(seconds: float, now) -> str:
    return (now - _dt.timedelta(seconds=seconds)).isoformat()


def test_critical_filter_drops_old_events():
    """The newest HIGH in the file is not news an hour later: a popup is
    for what just happened, so the filter reads the event's own stamp."""
    now = _dt.datetime.now(UTC)
    events = [
        {"from_tool": "rkhunter", "severity": "HIGH",
         "text": "RKHunter is down", "ts": _aged(4000.0, now)},
        {"from_tool": "rkhunter", "severity": "HIGH",
         "text": "RKHunter is down NOW", "ts": _aged(30.0, now)},
    ]
    assert critical_filter(events, now=now) == \
        [{"lane": "tool", "tool": "rkhunter",
          "text": "RKHunter is down NOW"}]
    # an event with no readable stamp fails OPEN: silence must be a
    # chosen state, never a parsing accident. Fail2ban's own ban lines
    # speak about the outside, so GW-197 sorts them into the threat lane;
    # only this synthetic "Ban" wording's lane changed, not the
    # fail-open rule it pins.
    assert critical_filter([{"from_tool": "fail2ban", "severity": "HIGH",
                             "text": "Ban", "ts": "not a stamp"}],
                           now=now) == [{"lane": "threat",
                                         "tool": "fail2ban",
                                         "text": "Ban"}]


def test_critical_square_starts_the_tool(tmp_path, monkeypatch):
    """A critical event about rkhunter is a local tool statement, not an
    outside threat: its popup carries Start tool instead of the deny
    lane's block actions."""
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)
    _FakeNotification.instances.clear()

    sq = CriticalSquare(CriticalEvents(), notifier=_FakeNotify)
    sq.show(sq.blocked.add("rkhunter", "rkhunter is down and could not "
                           "be repaired automatically (unknown)"))
    square = _FakeNotification.instances[-1]
    names = [a[0] for a in square.actions]
    assert names == ["start-tool", "snooze", "review"]

    # pressing it starts the TOOL the event was about
    calls = []
    monkeypatch.setattr(na, "_run", lambda cmd, timeout=45:
                        (calls.append(cmd), 0)[1])
    ok = sq._on_start_tool()
    assert ok is True
    assert calls[0][1].endswith("scan-now.sh") and calls[0][2] == "rkhunter"


def test_critical_square_start_refusal_is_honest(tmp_path, monkeypatch):
    """An unnamed or foreign tool gets an honest NO, never a silent
    nothing."""
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)
    _FakeNotification.instances.clear()

    sq = CriticalSquare(CriticalEvents(), notifier=_FakeNotify)
    blocked = CriticalEvents()
    sq.blocked = blocked
    monkeypatch.setattr(na, "_run", lambda cmd, timeout=45: 0)

    ok = sq._on_start_tool()          # no critical event seen yet
    assert ok is False
    assert "not a managed tool" in _FakeNotification.instances[-1].body \
        or "Nothing to start" in _FakeNotification.instances[-1].body


def test_start_tool_maps_every_shape_of_tool(monkeypatch):
    calls = []

    def fake_run(cmd, timeout=45):
        calls.append(cmd)
        return 0

    # unit-less scanner: the scan itself is the start lever
    ok, words = start_tool("rkhunter", run=fake_run)
    assert ok and calls[-1][1].endswith("scan-now.sh") \
        and calls[-1][2] == "rkhunter"
    assert "scan" in words.lower()

    # root unit: through the tool-control helper
    ok, words = start_tool("fail2ban", run=fake_run)
    assert ok and calls[-1] == ["pkexec", str(ROOT / "apply" /
                                              "tool-control.sh"),
                                "start", "fail2ban.service"]

    # user unit: the user bus, no pkexec prompt at all
    ok, _words = start_tool("yara-watch", run=fake_run)
    assert ok and calls[-1] == ["systemctl", "--user", "start",
                                "yara-watch.service"]

    # GreyWatch's own unit: refuse honestly
    ok, words = start_tool("appfw", run=fake_run)
    assert not ok and "own unit" in words

    # foreign name: honest refusal, no command at all
    before = len(calls)
    ok, words = start_tool("not-a-real-tool", run=fake_run)
    assert not ok and len(calls) == before


def test_deny_lane_keeps_its_block_actions(tmp_path, monkeypatch):
    """Only the critical lane changed: firewall popups still offer the
    address and program levers."""
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)
    _FakeNotification.instances.clear()

    q = na.BlockedQueue(tmp_path)
    sq = na.NotifyAlert(q, notifier=_FakeNotify)
    sq.handle_deny("/usr/bin/curl", "bad.example", now=1000.0)
    square = _FakeNotification.instances[-1]
    names = [a[0] for a in square.actions]
    assert names[:2] == ["block-site", "block-app"]
    assert "start-tool" not in names
