# GW-191: the popup itself gets the working actions (owner 2026-11-05:
# "still just has unblock all or review. no pause notifications, no block
# all from this ip or app") and the drawn tiles read on a notification
# bubble (light card, dark mark - a dark tile was a shapeless blob).
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

from ui import notify_alert as na   # noqa: E402


@pytest.fixture(autouse=True)
def _settings(tmp_path, monkeypatch):
    """No test touches the live settings file; the popup gates read a
    default-open sandbox copy instead."""
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)
    return settings


def _alert(tmp_path, host_store):
    return na.NotifyAlert(na.BlockedQueue(host_store), notifier=_FakeNotify)


class _FakeNote:
    instances: list = []

    def __init__(self, summary=None, body=None):
        self.summary, self.body = summary, body
        self.shown = 0
        self.actions: list = []
        _FakeNote.instances.append(self)

    @classmethod
    def new(cls, summary, body):
        return cls(summary, body)

    def set_timeout(self, t):
        pass

    def update(self, s, b):
        self.body = b

    def add_action(self, *a):
        self.actions.append(a)

    def show(self):
        self.shown += 1


class _FakeNotify:
    Notification = _FakeNote
    initted = True

    @staticmethod
    def is_initted():
        return True

    @staticmethod
    def init(_app):
        pass


def test_the_popup_offers_block_address_block_program_and_snooze(tmp_path):
    _FakeNote.instances.clear()
    alert = _alert(tmp_path, tmp_path)
    alert.handle_deny("chrome", "203.0.113.9:443")
    note = _FakeNote.instances[-1]
    acts = [a[0] for a in note.actions]
    assert acts[:5] == ["block-site", "block-app", "snooze",
                        "unblock-all", "review"]


def test_block_address_writes_a_dst_ip_rule_and_says_so(tmp_path):
    _FakeNote.instances.clear()
    alert = _alert(tmp_path, tmp_path)
    alert.handle_deny("chrome", "203.0.113.9:443")
    done = alert._on_block_site()
    assert done == ["203.0.113.9"]           # the port was stripped off
    rules = (tmp_path / "appfw" / "rules" / "deny-always.json").read_text()
    assert "203.0.113.9" in rules


def test_block_program_needs_a_name_but_writes_process_path(tmp_path):
    _FakeNote.instances.clear()
    alert = _alert(tmp_path, tmp_path)
    alert.handle_deny("<unknown>", "203.0.113.9:443")
    assert alert._on_block_app() == []        # nothing named, nothing done
    alert.handle_deny("/usr/bin/curl", "203.0.113.9:443")
    done = alert._on_block_app()
    assert done == ["/usr/bin/curl"]
    text = (tmp_path / "appfw" / "rules" / "deny-always.json").read_text()
    assert "/usr/bin/curl" in text


def test_snooze_from_the_popup_stamps_and_confirms(tmp_path):
    import time
    _FakeNote.instances.clear()
    alert = _alert(tmp_path, tmp_path)
    alert.handle_deny("chrome", "203.0.113.9:443")
    assert alert._on_snooze() is True
    prefs = na.read_alert_prefs(na.ALERTS_SETTING_PATH)
    assert prefs["alerts_snooze_until"] > time.time() + 1700
