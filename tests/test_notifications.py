"""tests/test_notifications.py — the critical-events square + engine cycles."""
import json
import socket
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui import notify_alert
from ui.notify_alert import (NotifyAlert, CriticalSquare, CriticalEvents,
                             critical_filter, parse_deny)
from appfw.engine import Engine, read_enabled, write_enabled
from appfw import rules as R


class _SubStub:
    DEVNULL = -3
    STDOUT = -2
    @staticmethod
    def run(*a, **k):
        return type("R", (), {"returncode": 0})()

    @staticmethod
    def Popen(argv, env=None, **k):
        import subprocess as _real
        return _real.Popen([sys.executable,
                            str(pathlib.Path(ROOT) / "tests" /
                                "fake_worker.py"), "1"], env=env)


# ── critical filter: newest wins, only the named classes ────────────────
def test_critical_filter_picks_only_named_classes():
    events = [
        {"from_tool": "fail2ban", "severity": "HIGH", "text": "Ban 1.2.3.4"},
        {"from_tool": "yara-watch", "severity": "MEDIUM", "text": "no"},
        {"from_tool": "ufw", "severity": "HIGH", "text": "not a class"},
        {"from_tool": "rkhunter", "severity": "CRITICAL", "text": "RTKT"},
    ]
    picked = critical_filter(events)
    assert picked == [("rkhunter", "RTKT")]      # newest of matched classes
    assert critical_filter([]) == []
    assert critical_filter([None, {}]) == []


def test_critical_events_coalesce_without_stacking():
    c = CriticalEvents()
    assert "fail2ban" in c.add("fail2ban", "Ban 1.2.3.4")
    assert c.count == 1
    text = c.add("yara-watch", "hit: eicar")
    assert "2 critical" in text and "yara-watch" in text
    assert c.latest == ("yara-watch", "hit: eicar")
    assert not c.stale()                          # fresh
    c._stamped -= 700                             # aged beyond the window
    assert c.stale()


def test_critical_square_replaces_itself(tmp_path, monkeypatch):
    # popups-off default (owner order 2026-10-25): flip alerts ON in an
    # ISOLATED settings file.
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(notify_alert, "ALERTS_SETTING_PATH", settings)

    class FakeNotification:
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

    class FakeNotify:
        Notification = FakeNotification

    sq = CriticalSquare(CriticalEvents(), notifier=FakeNotify)
    sq.show(sq.blocked.add("fail2ban", "Ban 5.6.7.8"))
    sq.show(sq.blocked.add("rkhunter", "RTKT found"))
    assert len(FakeNotification.instances) == 1   # ONE square, replaced
    first = FakeNotification.instances[0]
    assert first.shown >= 2
    assert first.updates and "rkhunter" in first.updates[-1][1]
    assert first.summary == "Security: critical event"


def test_deny_parse_still_shapes_the_blocked_square():
    assert parse_deny("appfw curl → bad.example:80 deny [n]") == \
        {"app": "curl", "host": "bad.example:80", "action": "deny"}


# ── engine lifecycle: repeated stop/start cycles stay clean (P0 invariant)
def test_engine_repeated_rearm_cycles(tmp_path, monkeypatch):
    write_enabled(tmp_path, True)
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "enable.json").write_text(
        json.dumps({"enabled": True}) + "\n")
    (ROOT / "tests" / "fake_worker.py").chmod(0o755)
    events = []
    monkeypatch.setattr("appfw.engine.ENGINE_BIN",
                        ROOT / "tests" / "fake_worker.py")
    monkeypatch.setattr("appfw.engine.subprocess", _SubStub())
    eng = Engine(tmp_path, on_event=events.append, socket_dir=str(tmp_path),
                 proc_root="/proc")
    for _ in range(3):                            # stop→start stays honest
        assert eng.start() and eng.running, "arm refused: %r / %r" % (
            events, eng.store.load_errors)
        eng.stop()
        assert not eng.running
    # the switch is untouched by engine cycles (owner-gated truth)
    assert read_enabled(tmp_path)


def test_engine_denies_by_ip_rule(tmp_path, monkeypatch):
    """A saved deny rule denies the matching connection in the queue. Engine
    v1 sees IP-only connections (no reverse DNS — the incident rule), so an
    IP rule is what matches."""
    write_enabled(tmp_path, True)
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "enable.json").write_text(
        json.dumps({"enabled": True}) + "\n")
    (ROOT / "tests" / "fake_worker.py").chmod(0o755)
    monkeypatch.setattr("appfw.engine.ENGINE_BIN",
                        ROOT / "tests" / "fake_worker.py")
    monkeypatch.setattr("appfw.engine.subprocess",
                        type("S", (), {"DEVNULL": -3, "STDOUT": -2, "run": staticmethod(
                            lambda *a, **k: type("R", (), {
                                "returncode": 0})()),
                            "Popen": staticmethod(lambda argv, env=None, **k:
                                subprocess.Popen(
                                    [sys.executable, str(ROOT / "tests" /
                                                         "fake_worker.py"),
                                     "1"], env=env))}))
    events = []
    eng = Engine(tmp_path, on_event=events.append, socket_dir=str(tmp_path))
    eng.start()
    eng.store.add(R.validate("site", "deny", "always", "dst.ip",
                             "203.0.113.99"))
    # worker lane: a PKT line for the denied IP → DROP verdict on ctl
    ctl = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    ctl.bind(str(tmp_path / "probe.sock"))
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    pathlib.Path(str(tmp_path / "nfq_worker.sock")).unlink(missing_ok=True)
    listener.bind(str(tmp_path / "nfq_worker.sock"))   # steady dst
    listener.settimeout(3)
    eng._decide_line("PKT 777 tcp 127.0.0.1 50000 203.0.113.99 443", ctl)
    # the engine answers on the WORKER control path — read there, not on ctl
    verb, _ = listener.recvfrom(64)
    assert verb.decode() == "DROP 777"
    assert any("deny" in e and "203.0.113.99" in e for e in events)
    eng.stop()