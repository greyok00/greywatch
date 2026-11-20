"""A cold start must never pop the backlog as popups.

Regression for the owner report "greywatch launches and has like 50 popup
notifications all at once" (2026-11-10): at UI start the deny/critical
replay consumed every historical event as fresh, because the shown-memory
lives only in the process. The first pump after startup now drains the
backlog silently - popups are for what happens AFTER the window exists -
and every later pump pops normally.
"""
import datetime as dt
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import ui.decisions as D
import ui.notify_alert as NA


def _now(offset=0):
    return (dt.datetime.now(dt.timezone.utc) +
            dt.timedelta(seconds=offset)).isoformat(timespec="seconds")


def _deny(offset, tool="curl", host="192.0.2.10:443"):
    return {"from_tool": "appfw", "ts": _now(offset),
            "text": f"appfw {tool} → {host} deny"}


def _crit(offset, tool="fail2ban", text="Ban 1.2.3.4"):
    return {"from_tool": tool, "severity": "HIGH", "ts": _now(offset),
            "text": text}


class _RecAlert:
    """Mirrors NotifyAlert: a popup fires exactly when BlockedQueue emits
    text (fresh pair or the 120 s repeat), without touching a bus."""

    def __init__(self, blocked, notifier=None):
        self.blocked = blocked
        self.shown = []

    def handle_deny(self, app, host):
        text, _kind, _rec = self.blocked.add_deny(app, host)
        if text:
            self.shown.append(text)


class _RecSquare:
    def __init__(self, blocked):
        self.blocked = blocked
        self.shown = []

    def show(self, text, gate=True, lane="tool"):
        self.shown.append((text, lane))


class Broker(D.DecisionBroker):

    def __init__(self):
        super().__init__()
        self.shown_dialogs = []

    def _show_dialog(self, spec, eyebrow="Protection", resolve=None,
                     tag=None):
        self.shown_dialogs.append(spec.get("id"))


@pytest.fixture()
def broker(monkeypatch):
    b = Broker()
    monkeypatch.setattr(NA, "NotifyAlert", _RecAlert)
    monkeypatch.setattr(NA, "CriticalSquare", _RecSquare)
    return b


def test_cold_start_drains_deny_backlog_silently(broker):
    backlog = [_deny(-60 * i, host=f"192.0.2.{i}:443") for i in range(1, 21)]
    broker.pump(backlog)
    assert broker._alert.shown == []


def test_denies_after_start_still_pop(broker):
    broker.pump([_deny(-120)])
    broker.pump([_deny(-30, host="198.51.100.7:443")])
    assert len(broker._alert.shown) == 1
    assert "198.51.100.7" in broker._alert.shown[0]


def test_cold_start_drains_critical_backlog_silently(broker):
    backlog = [_crit(-60 * i, text=f"Ban 1.2.3.{i}") for i in range(1, 6)]
    broker.pump(backlog)
    assert broker._crit_square.shown == []
    # the drain still remembers what was consumed - the next different
    # critical pops, the same one does not
    broker.pump([_crit(0, text="Ban 5.6.7.8")])
    assert len(broker._crit_square.shown) == 1
    broker.pump([_crit(5, text="Ban 5.6.7.8")])
    assert len(broker._crit_square.shown) == 1


def test_drained_pairs_do_not_double_count_the_badge(broker):
    broker.pump([_deny(-60 * i, host=f"192.0.2.{i}:443") for i in range(1, 6)])
    assert broker._alert.blocked.pending() == 0
    broker.pump([_deny(0, host="198.51.100.7:443")])
    assert broker._alert.blocked.pending() == 1
