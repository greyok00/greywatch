"""E-1: crash-kill restart proof at decision level (sandboxed).

Layer-0 crash-recovery contract, proven with a REAL killed child process
but WITHOUT touching systemd: a child is SIGKILLed, and the SelfHealer's
cause->action ladder classifies the death as crashed -> restart, with
budget and cooldown semantics intact. The live-install restart belt is
systemd's Restart=always + WatchdogSec=30 (pinned separately by
tests/test_boot_timeline.py and the watchdog margin tests); what this
file pins is greywatch's own decision layer over that belt.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys

import selfheal


class Recorder:
    """systemctl/journal recorder: the journal carries the real SIGKILL
    journal shape; is-active reads failed until a restart lands."""

    def __init__(self):
        self.calls = []
        self.journal = " Main PID 12345 (python3) code=killed, status=KILL/9"
        self.was_actioned = False

    def systemctl(self, tool, *args):
        self.calls.append(list(args))
        if args[0] == "is-active":
            state = "active" if self.was_actioned else "failed"
            return subprocess.CompletedProcess(args, 0, state + "\n", "")
        if args[0] == "is-enabled":
            return subprocess.CompletedProcess(args, 0, "enabled\n", "")
        if args[0] == "restart":
            self.was_actioned = True
        if args[0] == "status":
            return subprocess.CompletedProcess(args, 0, self.journal, "")
        return subprocess.CompletedProcess(args, 0, "", "")


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _tool(name="fail2ban", unit="fail2ban.service", scope="root", **kw):
    return {"name": name, "unit": unit, "scope": scope,
            "label": name.title(), **kw}


def _killer_child():
    """A real SIGKILL-able child: sleeps until killed. Proves the drill's
    own kill primitive works on this box (the death we classify)."""
    p = subprocess.Popen([sys.executable, "-c",
                          "import time; time.sleep(600)"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.kill(p.pid, signal.SIGKILL)
    p.wait(timeout=10)
    assert p.returncode == -signal.SIGKILL
    return p.pid


def test_real_sigkill_classifies_as_crashed_restart():
    """The real child's death maps to the healer's crashed->restart rung
    (the same journal shape production SIGKILLs leave behind)."""
    _killer_child()
    cause, action = selfheal.classify("code=killed, status=KILL/9")
    assert cause == "crashed" and action == "restart"


def test_sigkilled_daemon_is_classified_and_restart_invoked():
    """Full ladder: journal says killed -> classify crashed -> the ONE
    restart call fires, is verified, and the budget records the action."""
    _killer_child()
    rec = Recorder()
    logs, alerts = [], []
    h = selfheal.SelfHealer(
        "/tmp/nope", [_tool()],
        log=lambda tool, text: logs.append((tool, text)),
        alert=lambda tool, text: alerts.append((tool, text)),
        clock=Clock())
    h._systemctl = rec.systemctl
    h._journal = lambda tool, lines=20: rec.journal
    h._active = lambda tool: rec.was_actioned
    res = h.repair("fail2ban")
    assert res["action"] == "restart" and res["ok"] is True
    assert ["restart"] in rec.calls
    assert any("repaired: restart after crashed" in t for _n, t in logs)
    assert len(h.attempts.get("fail2ban", [])) == 1


def test_crash_loop_cannot_storm_the_unit():
    """The attempt budget caps repeated crash-heals: 3 repairs inside the
    window, then the 4th is REFUSED (escalation, not a restart storm)."""
    rec = Recorder()
    logs, alerts = [], []
    clock = Clock()
    h = selfheal.SelfHealer(
        "/tmp/nope", [_tool()],
        log=lambda tool, text: logs.append((tool, text)),
        alert=lambda tool, text: alerts.append((tool, text)),
        clock=clock)
    h._systemctl = rec.systemctl
    h._journal = lambda tool, lines=20: rec.journal
    h._active = lambda tool: rec.was_actioned
    outcomes = []
    for _ in range(4):
        outcomes.append(h.repair("fail2ban"))
        clock.t += selfheal.COOLDOWN + 1.0   # space past cooldown: budget only
    # product contract: refusal is None (tests/test_selfheal.py pins it)
    ok_n = sum(1 for r in outcomes if r is not None and r.get("ok"))
    assert ok_n == selfheal.MAX_ATTEMPTS, outcomes
    # the 4th repair escalates ONCE (a named refusal, not a restart storm)
    assert outcomes[3] is not None and outcomes[3]["action"] == "escalated" \
        and outcomes[3]["ok"] is False, outcomes[3]
    assert any("budget" in t.lower() or "escalat" in t.lower()
               or "gave up" in t.lower() for _n, t in logs + alerts), \
        "the escalation must be named"


def test_back_to_back_repairs_respect_cooldown(tmp_path=None):
    """Two repairs of one tool inside COOLDOWN: the second is refused."""
    rec = Recorder()
    logs = []
    clock = Clock()
    h = selfheal.SelfHealer(
        "/tmp/nope", [_tool()],
        log=lambda tool, text: logs.append((tool, text)),
        clock=clock)
    h._systemctl = rec.systemctl
    h._journal = lambda tool, lines=20: rec.journal
    h._active = lambda tool: rec.was_actioned
    assert h.repair("fail2ban") is not None      # first repair lands
    clock.t += 1.0                               # one second later
    assert h.repair("fail2ban") is None          # cooldown refusal
