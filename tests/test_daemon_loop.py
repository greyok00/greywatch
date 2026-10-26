

import greywatch_daemon as gd
from decisions_factory import interaction_for, sanitize
from events import Event
from greywatch_daemon import Daemon, read_events
from registry import load_registry
from status import classify, log_state_of, snapshot


def _reg():
    return load_registry()


def fake_unit(state_by_name):
    def check(tool):
        return state_by_name.get(tool["name"], "inactive" if tool.get("unit") else "no-unit")
    return check


def mk_daemon(tmp_path, **kw):
    return Daemon(data_dir=tmp_path / "data", registry=_reg(), **kw)



def test_consume_emits_enriched_event(tmp_path):
    d = mk_daemon(tmp_path)
    ev = d.consume("yara-watch", "eicar /tmp/eicar-rt2.txt (realtime sha256:275a021bbfb6489e)")
    assert ev is not None and ev.severity == "HIGH"
    assert ev.nist_func == "DETECT" and "SI-3" in ev.nist_control
    d.flush_outbox()
    stored = read_events(d.events_path)
    assert len(stored) == 1 and stored[0]["from_tool"] == "yara-watch"


def test_consume_survives_malformed_and_never_writes(tmp_path):
    d = mk_daemon(tmp_path)
    for junk in ["", "  ", "\x00", "}{{{{", "a" * 5000, '{"partial":']:
        assert d.consume("yara-watch", junk) is None
    d.flush_outbox()
    assert read_events(d.events_path) == []


def test_consume_attaches_decision_spec_to_quarantine(tmp_path):
    d = mk_daemon(tmp_path)
    ev = d.consume("responderd", '{"ts": "2026-10-22 18:40:11", "action": "quarantine", "detail": "eicar /tmp/yara-responder-test.txt moved to quarantine"}')
    assert ev.interaction is not None
    assert ev.interaction["options"][0]["helper"] in ("keep-quarantine", "restore-quarantine")



def test_status_classify_matrix():
    assert classify("active", "ok", True, True) == "GREEN"
    assert classify("active", "missing", True, True) == "YELLOW"
    assert classify("failed", "ok", True, True) == "RED"
    assert classify("failed", "missing", True, True) == "RED"
    assert classify("inactive", "missing", True, True) == "RED"
    assert classify("inactive", "ok", True, True) == "RED"
    assert classify("no-unit", "missing", False, True) == "YELLOW"
    assert classify("no-unit", "unreadable", False, True) == "YELLOW"
    assert classify("no-unit", "ok", False, True) == "GREEN"
    assert classify("no-unit", "ok", False, False) == "GREEN"


def test_log_state_of_real_and_missing(tmp_path):
    staged = tmp_path / "responderd.log"
    staged.write_text("probe\n")
    assert log_state_of(str(staged)) == "ok"
    assert log_state_of("/does/not/exist.log") == "missing"
    assert log_state_of("journal:kern") == "ok"


def test_snapshot_full_registry_state_transitions(tmp_path):
    reg = _reg()
    states = {t["name"]: ("active" if t.get("unit") else "no-unit") for t in reg}
    snap = snapshot(reg, fake_unit(states))
    assert snap["tools"]["responderd"]["state"] == "GREEN"
    states["responderd"] = "failed"
    snap = snapshot(reg, fake_unit(states))
    assert snap["tools"]["responderd"]["state"] == "RED"
    states["yara-watch"] = "active"
    snap = snapshot(reg, fake_unit(states))
    assert snap["tools"]["yara-watch"]["state"] in ("GREEN", "YELLOW")


def test_status_roundtrip_json_and_atomic(tmp_path):
    d = mk_daemon(tmp_path)
    d.write_status()
    from status import load_status
    loaded = load_status(str(d.status_path))
    assert set(loaded["tools"]) == {t["name"] for t in _reg()}
    assert "pending_decisions" in loaded and "updated" in loaded
    assert not (tmp_path / "data" / "status.json.tmp").exists()



def test_interaction_specs_generated_and_sanitized():
    cases = [
        Event(from_tool="responderd", severity="HIGH",
              text="quarantine: eicar /tmp/x.txt", ts="t"),
        Event(from_tool="fail2ban", severity="HIGH",
              text="Ban in jail [sshd] — 1.2.3.4 (near-ignoreip: 3 re-bans in 300s)", ts="t"),
        Event(from_tool="yara-watch", severity="HIGH",
              text="quarantine rule eicar matched /tmp/x", ts="t"),
        Event(from_tool="secops-mcp", severity="HIGH", text="ban requested", ts="t"),
    ]
    for ev in cases:
        spec = sanitize(interaction_for(ev))
        assert spec is not None, ev.from_tool
        for o in spec["options"]:
            assert o["helper"] in ("drop-listener", "allow-listener",
                                   "restore-quarantine", "keep-quarantine",
                                   "unban-ip", "keep-scan-ban", "widen-scan-ban", "none")


def test_interaction_none_for_plain_events():
    ev = Event(from_tool="yara-watch", severity="HIGH",
               text="rule eicar matched /tmp/x", ts="t")
    assert interaction_for(ev) is None
    lone = Event(from_tool="fail2ban", severity="HIGH",
                 text="Ban in jail [sshd] — 1.2.3.4", ts="t")
    assert interaction_for(lone) is None     # single ban: no near-ignoreip


def test_fail2ban_ban_heuristic_three_rebans(tmp_path):
    d = mk_daemon(tmp_path)
    for _ in range(3):
        ev = d.consume("fail2ban",
                       "2026-10-22 18:00:32,110 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.9")
    assert ev is not None and "near-ignoreip" in ev.text
    assert ev.interaction is not None
    assert any(o["helper"] == "unban-ip" for o in ev.interaction["options"])
    ev4 = d.consume("fail2ban",
                    "2026-10-22 18:01:32,110 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.9")
    assert ev4.interaction is None


def test_answer_once_enforced(tmp_path):
    from decisions_factory import record_answer, pending_ids
    d = mk_daemon(tmp_path)
    dp = d.decisions_path
    spec = sanitize(interaction_for(Event(
        from_tool="responderd", severity="HIGH", text="quarantine: x", ts="t")))
    i = spec["id"]
    assert record_answer(dp, i, "keep") is True
    assert record_answer(dp, i, "restore") is False      # answered already
    assert i in pending_ids(dp)
    snap = d.write_status()
    assert snap["pending_decisions"] == 0



def test_trim_cap(tmp_path):
    d = mk_daemon(tmp_path, max_events=20)
    for i in range(30):
        d.consume("ufw", f"[ 1{i}.1] [UFW BLOCK] IN=wlan0 SRC=1.2.3.{i % 250} DST=1.1.1.1 PROTO=TCP")
    d.flush_outbox()
    assert len(read_events(d.events_path)) == 30
    removed = d.trim_events()
    assert removed == 10
    assert len(read_events(d.events_path)) == 20
    assert d.trim_events() == 0


def test_queue_overflow_flag_in_status(tmp_path):
    from collectors import BoundedQueue
    q = BoundedQueue(max_items=2)
    for i in range(5):
        q.put_nowait(i)
    d = mk_daemon(tmp_path)
    d.queue = q
    snap = d.write_status()
    assert snap["dropped"] == 3          # 5 puts into 2 slots → 3 dropped



class FakeTailer:
    def __init__(self, items):
        self.items = items

    def start(self):
        pass

    def stop(self):
        pass

    def drain_self(self):
        pass


def test_run_once_with_fake_collectors(tmp_path):
    d = mk_daemon(tmp_path)
    items = [("yara-watch", "eicar /tmp/x (realtime sha256:abc)"),
             ("fail2ban", "2026-10-22 18:00:32,110 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.9"),
             ("responderd", '{"ts": "2026-10-22 18:40:11", "action": "quarantine", "detail": "moved to quarantine"}')]
    d = type(d)(data_dir=tmp_path / "data", registry=_reg(),
                unit_checker=d.unit_checker, max_events=20)
    from unittest.mock import patch
    with patch.object(d, "collect_burst", return_value=items):
        snap = d.run_once(tailers=[])
    evs = read_events(d.events_path)
    assert len(evs) == 3
    assert {e["from_tool"] for e in evs} == {"yara-watch", "fail2ban", "responderd"}
    assert snap["pending_decisions"] == 1


def test_unit_checker_factory_shapes():
    checker = gd.unit_checker_factory()
    reg = _reg()
    rd = [t for t in reg if t["name"] == "responderd"][0]
    out = checker(rd)
    assert out in ("active", "inactive", "failed", "no-unit", "unknown")
    yw = [t for t in reg if t["name"] == "yara-watch"][0]
    out2 = checker(yw)                       # user scope → systemctl --user
    assert out2 in ("active", "inactive", "failed", "no-unit", "unknown")

def test_routine_noise_not_recorded(tmp_path):
    d = mk_daemon(tmp_path)
    d.consume("auditd", 'type=SYSCALL msg=audit(1758532800.001:221): arch=c000003e syscall=59 success=yes')
    d.consume("responderd", '{"ts": "2026-10-22 18:46:52", "action": "tetragon_watch", "detail": "routine"}')
    d.consume("tetragon", '{"ts": "2026-10-22 18:46:52", "binary": "/bin/ls", "pid": 5}')
    d.flush_outbox()
    assert len(read_events(d.events_path)) == 0        # all routine → none kept
    d.consume("clamav", "Infected files: 0")           # scan finished → kept
    d.consume("responderd", '{"ts": "2026-10-22 18:40:11", "action": "quarantine", "detail": "x"}')
    d.flush_outbox()
    kept = read_events(d.events_path)
    assert [e["from_tool"] for e in kept] == ["clamav", "responderd"]
    assert kept[1]["interaction"] is not None          # the ask survived

def test_heartbeat_reports_the_real_state(tmp_path):
    d = mk_daemon(tmp_path)
    d._last_snap = {"tools": {
        "appfw": {"state": "RED", "installed": True},
        "ufw": {"state": "GREEN", "installed": True},
        "lynis": {"state": "YELLOW", "installed": False},
        "yara-watch": {"state": "GREEN", "installed": True, "paused": True},
    }}
    d.heartbeat()
    d.flush_outbox()
    evs = {e["from_tool"]: e for e in read_events(d.events_path)}

    assert evs["ufw"]["text"].endswith("alive, running normally")
    assert evs["ufw"]["severity"] == "INFO"
    assert "NOT RUNNING" in evs["appfw"]["text"]
    assert evs["appfw"]["severity"] == "HIGH"
    assert "not installed" in evs["lynis"]["text"]
    assert evs["lynis"]["severity"] == "MEDIUM"
    assert "paused in the app" in evs["yara-watch"]["text"]
    assert "not available" in evs["responderd"]["text"]


def test_heartbeat_cannot_flood_the_activity_feeds():
    from ui.models import feed_worthy, recent_rows
    high_ping = {"from_tool": "appfw", "severity": "HIGH", "ts":
                 "2026-10-23T14:00:00+00:00", "text":
                 "check-in: NOT RUNNING — needs attention"}
    assert not feed_worthy(high_ping)
    assert recent_rows([high_ping], 6) == []
