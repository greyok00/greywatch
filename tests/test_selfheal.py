import types

import pytest

import selfheal
import triage


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _tool(name="fail2ban", unit="fail2ban.service", scope="root", **kw):
    return {"name": name, "unit": unit, "scope": scope,
            "label": name.title(), **kw}


class Recorder:
    def __init__(self, journal="", enabled="enabled", heal_works=True):
        self.calls = []
        self.journal = journal
        self.enabled = enabled
        self.heal_works = heal_works
        self.was_actioned = False

    def systemctl(self, tool, *args):
        self.calls.append(list(args))
        if args[0] == "is-active":
            state = "active" if self.was_actioned else "failed"
            return types.SimpleNamespace(stdout=state + "\n", stderr="")
        if args[0] == "is-enabled":
            return types.SimpleNamespace(stdout=self.enabled + "\n", stderr="")
        if args[0] in ("restart", "start", "reload-or-restart"):
            if self.heal_works:
                self.was_actioned = True
        if args[0] == "status":
            return types.SimpleNamespace(stdout=self.journal, stderr="")
        return types.SimpleNamespace(stdout="", stderr="")


def _healer(rec, registry=None, **kw):
    logs, alerts = [], []
    h = selfheal.SelfHealer(
        "/tmp/nope", registry or [_tool()],
        log=lambda tool, text: logs.append((tool, text)),
        alert=lambda tool, text: alerts.append((tool, text)),
        clock=kw.pop("clock", Clock()),
        **kw)
    h._systemctl = rec.systemctl
    h._journal = lambda tool, lines=20: rec.journal
    h._active = lambda tool: rec.was_actioned
    h.logs, h.alerts = logs, alerts
    return h


def test_classify_known_causes():
    assert selfheal.classify("main process exited, code=dumped, signal=SEGV") \
        == ("crashed", "restart")
    assert selfheal.classify("No space left on device") == ("disk-full", None)
    assert selfheal.classify("Permission denied") == ("permissions", None)
    assert selfheal.classify("address already in use") \
        == ("port-conflict", None)
    assert selfheal.classify("everything is fine") == ("unknown", None)


def test_repair_restarts_crashed_unit():
    rec = Recorder(journal="code=dumped, signal=SEGV")
    h = _healer(rec)
    res = h.repair("fail2ban")
    assert res["action"] == "restart" and res["ok"] is True
    assert ["restart"] in rec.calls
    assert any("repaired: restart after crashed" in t for _n, t in h.logs)


def test_paused_tool_is_never_touched():
    rec = Recorder()
    h = _healer(rec)
    h.tick({"fail2ban": {"paused": True, "state": "RED",
                         "unit_state": "failed"}})
    assert rec.calls == []


def test_healthy_and_state_only_are_skipped():
    rec = Recorder()
    h = _healer(rec)
    h.tick({"fail2ban": {"state": "GREEN", "unit_state": "active"}})
    assert rec.calls == []
    # the timer is state_only in registry terms
    h2 = _healer(Recorder(), registry=[_tool("timer", unit="x.timer",
                                             state_only=True)])
    h2.tick({"timer": {"state": "RED", "unit_state": "inactive"}})
    assert h2.attempts == {}


def test_unknown_cause_escalates_without_restart():
    rec = Recorder(journal="something strange happened")
    h = _healer(rec)
    res = h.repair("fail2ban")
    assert res["action"] == "none"
    assert h.alerts and "could not be repaired" in h.alerts[0][1]
    assert not any(c and c[0] == "restart" for c in rec.calls)


def test_triage_can_supply_a_restart():
    rec = Recorder(journal="weird failure text")
    h = _healer(rec, triage=lambda lines: {
        "cause": "state-corrupt", "action": "restart", "confidence": 0.9})
    res = h.repair("fail2ban")
    assert res["action"] == "restart"


def test_attempt_budget_escalates_once():
    rec = Recorder(journal="code=dumped, signal=SEGV", heal_works=False)
    clk = Clock()
    h = _healer(rec, clock=clk)
    for _ in range(5):
        h.repair("fail2ban")
        clk.t += selfheal.COOLDOWN + 1
    assert len([a for a in h.alerts]) == 1
    assert len(h.attempts["fail2ban"]) == selfheal.MAX_ATTEMPTS


def test_cooldown_blocks_back_to_back_repairs():
    rec = Recorder(journal="code=dumped")
    h = _healer(rec)
    assert h.repair("fail2ban") is not None
    assert h.repair("fail2ban") is None


def test_disabled_unit_is_started_not_restarted():
    rec = Recorder(journal="not running", enabled="disabled")
    h = _healer(rec)
    res = h.repair("fail2ban")
    assert res["action"] == "start"
    assert ["start"] in rec.calls


def test_user_scope_uses_runuser(monkeypatch):
    seen = []

    def fake_run(cmd, timeout=15, env=None):
        seen.append(cmd)
        return types.SimpleNamespace(stdout="active\n", stderr="", returncode=0)

    monkeypatch.setattr(selfheal, "_run", fake_run)
    h = selfheal.SelfHealer("/tmp", [_tool("yara", unit="yara.service",
                                           scope="user")],
                            log=lambda *a: None, user="grey",
                            runtime_dir="/run/user/1000")
    h._systemctl(_tool("yara", unit="yara.service", scope="user"),
                 "is-active")
    assert seen and seen[0][0] == "runuser"
    assert "--user" in seen[0]


def test_triage_parse_reply_contract():
    ok = triage.parse_reply('{"cause":"oom","action":"restart",'
                            '"confidence":0.8,"explain":"x"}')
    assert ok["action"] == "restart"
    assert triage.parse_reply('{"action":"rm -rf","confidence":0.9}') is None
    assert triage.parse_reply('{"action":"restart","confidence":0.2}') is None
    assert triage.parse_reply("no json here") is None


def test_triage_scrubs_home_paths():
    out = triage.scrub("error in /home/alice/.ssh/id_rsa " + "a" * 40)
    assert "/home/alice" not in out
    assert "<hex>" in out


def test_triage_disabled_by_default(tmp_path):
    assert triage.make(tmp_path) is None
    (tmp_path / "ai-triage.json").write_text('{"enabled": true}')
    assert callable(triage.make(tmp_path))
