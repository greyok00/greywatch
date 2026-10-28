"""Self-healing for protection services.

A protection tool that is installed and not paused but is not actually
running is a bug, not a state to display. This module closes that loop:
ask the service why it stopped, apply the least invasive fix that fits the
answer, verify the fix, and only then report. When the safe fixes are
exhausted it escalates ONCE with the evidence instead of silently showing a
red row forever (owner report 2026-10-27: "it shouldn't just fail to report
or not do anything").

The healer never touches a paused tool, never touches a tool that is not
installed, never restarts timers, and keeps a per-tool attempt budget so a
crash loop cannot turn into a restart storm.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import time

MAX_ATTEMPTS = 3          # per tool, per window
WINDOW = 1800.0           # attempt budget window, seconds
COOLDOWN = 45.0           # minimum seconds between two repairs of one tool
VERIFY_WAIT = 2.0

# Recognisable failure causes, in priority order. Each maps to the action we
# are willing to take without the owner's input.
CAUSES = (
    (re.compile(r"could not be found|not found|no such file", re.I),
     "unit-missing", None),
    (re.compile(r"no space left|disk full", re.I), "disk-full", None),
    (re.compile(r"permission denied|access denied", re.I), "permissions", None),
    (re.compile(r"address already in use|bind.*in use", re.I),
     "port-conflict", None),
    (re.compile(r"out of memory|oom-kill|killed process", re.I),
     "out-of-memory", None),
    (re.compile(r"failed to load|cannot load|module.*not found", re.I),
     "dependency", None),
    (re.compile(r"exec format error|bad interpreter", re.I),
     "binary", None),
    (re.compile(r"timed out|timeout", re.I), "hung", "restart"),
    (re.compile(r"signal[= ]*(segv|abrt|kill)|sig(segv|abrt|kill)|core dumped"
                r"|segmentation", re.I), "crashed", "restart"),
    (re.compile(r"exit(ed)? (code|status) [1-9]", re.I), "failed", "restart"),
)

# Actions the healer may run by itself, all idempotent.
SAFE_ACTIONS = frozenset({"restart", "start", "reload"})


def _run(cmd, timeout=15, env=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None


def classify(text: str) -> tuple[str, str | None]:
    """Map raw service output to (cause, safe action or None)."""
    for rx, cause, action in CAUSES:
        if rx.search(text or ""):
            return cause, action
    return "unknown", None


class SelfHealer:

    def __init__(self, data_dir, registry, log, alert=None, triage=None,
                 user="", runtime_dir="", clock=time.monotonic):
        self.data_dir = pathlib.Path(data_dir)
        self.registry = list(registry or [])
        self.log = log                       # (tool, text) → event
        self.alert = alert                   # (tool, text) → severity event
        self.triage = triage                 # callable(lines) → dict | None
        self.user = user
        self.runtime_dir = runtime_dir
        self.clock = clock
        self.attempts: dict[str, list[float]] = {}
        self.last_at: dict[str, float] = {}
        self.escalated: set[str] = set()
        self.history: list[dict] = []

    # ---- service addressing -------------------------------------------------
    def _tool(self, name):
        for t in self.registry:
            if t.get("name") == name:
                return t
        return {}

    def _is_user(self, tool) -> bool:
        return tool.get("scope") == "user"

    def _systemctl(self, tool, *args):
        unit = tool.get("unit") or ""
        if self._is_user(tool):
            if self.runtime_dir and self.user:
                return _run(["runuser", "-u", self.user, "--", "env",
                             f"XDG_RUNTIME_DIR={self.runtime_dir}",
                             f"DBUS_SESSION_BUS_ADDRESS=unix:path="
                             f"{self.runtime_dir}/bus",
                             "systemctl", "--user", *args, unit])
            return _run(["systemctl", "--user", *args, unit])
        return _run(["systemctl", *args, unit])

    def _journal(self, tool, lines=20) -> str:
        unit = tool.get("unit") or ""
        if self._is_user(tool):
            out = self._systemctl(tool, "status", "--no-pager", "-n", "20")
        else:
            out = _run(["journalctl", "-u", unit, "-n", str(lines),
                        "--no-pager", "-o", "cat"])
            out = out or self._systemctl(tool, "status", "--no-pager", "-n",
                                         str(lines))
        if out is None:
            return ""
        return (out.stdout or "") + (out.stderr or "")

    def _active(self, tool) -> bool:
        out = self._systemctl(tool, "is-active")
        return bool(out and (out.stdout or "").strip() == "active")

    def _enabled_state(self, tool) -> str:
        out = self._systemctl(tool, "is-enabled")
        return (out.stdout or "").strip() if out else ""

    # ---- public loop --------------------------------------------------------
    def tick(self, tools_snapshot: dict) -> list[dict]:
        """One repair pass over the status snapshot. Returns what was done."""
        done = []
        now = self.clock()
        for tool in self.registry:
            name = tool.get("name") or ""
            snap = (tools_snapshot or {}).get(name) or {}
            if not snap or snap.get("paused"):
                continue
            if snap.get("installed") is False or tool.get("state_only"):
                continue
            unit_state = str(snap.get("unit_state") or "")
            state = str(snap.get("state") or "").upper()
            if unit_state == "active" and state in ("GREEN", "YELLOW"):
                self.escalated.discard(name)
                continue
            if unit_state in ("", "unknown") and state != "RED":
                continue
            res = self.repair(name, now)
            if res:
                done.append(res)
        if done:
            self.history = (self.history + done)[-200:]
        return done

    def repair(self, name, now=None) -> dict | None:
        now = self.clock() if now is None else now
        tool = self._tool(name)
        if not tool or tool.get("state_only"):
            return None
        stamps = [t for t in self.attempts.get(name, []) if now - t < WINDOW]
        self.attempts[name] = stamps
        if now - self.last_at.get(name, -COOLDOWN) < COOLDOWN:
            return None
        if len(stamps) >= MAX_ATTEMPTS:
            if name not in self.escalated:
                self.escalated.add(name)
                self._escalate(tool, "gave up after "
                               f"{MAX_ATTEMPTS} attempts")
                return {"tool": name, "action": "escalated", "ok": False}
            return None

        self.last_at[name] = now
        stamps.append(now)
        evidence = self._journal(tool)
        cause, action = classify(evidence)
        enabled = self._enabled_state(tool)
        if enabled in ("disabled", "masked", "not-found", ""):
            action = "start" if enabled == "disabled" else action
        if cause == "unknown" and self.triage:
            verdict = self._ai(evidence)
            if verdict:
                cause = verdict.get("cause") or cause
                act = verdict.get("action")
                if act in SAFE_ACTIONS:
                    action = act
                self.log(name, f"ai triage: {cause} → {act or 'no action'} "
                               f"({verdict.get('confidence', 0):.2f})")
        if action is None:
            if name not in self.escalated:
                self.escalated.add(name)
                self._escalate(tool, cause)
            return {"tool": name, "action": "none", "cause": cause,
                    "ok": False}
        ok, detail = self._apply(tool, action)
        self.log(name, ("repaired" if ok else "repair failed") +
                 f": {action} after {cause} ({detail})")
        if not ok and len(stamps) >= MAX_ATTEMPTS:
            self.escalated.add(name)
            self._escalate(tool, f"{cause}; {detail}")
        return {"tool": name, "action": action, "cause": cause,
                "ok": ok, "detail": detail}

    def _apply(self, tool, action) -> tuple[bool, str]:
        if action == "reload":
            self._systemctl(tool, "reload-or-restart")
        elif action == "start":
            self._systemctl(tool, "start")
        else:
            self._systemctl(tool, "restart")
        deadline = time.monotonic() + VERIFY_WAIT + 3.0
        while time.monotonic() < deadline:
            if self._active(tool):
                return True, "active"
            time.sleep(0.5)
        out = self._systemctl(tool, "status", "--no-pager", "-n", "5")
        tail = ((out.stdout or out.stderr or "").strip().splitlines()
                if out else [])
        return False, "still inactive" + (
            f": {tail[0]}" if tail else "")

    def _ai(self, evidence) -> dict | None:
        if not evidence.strip():
            return None
        try:
            return self.triage(evidence)
        except Exception:
            return None

    def _escalate(self, tool, reason) -> None:
        name = tool.get("name") or "?"
        label = tool.get("label") or name
        text = (f"{label} is down and could not be repaired automatically "
                f"({reason}). Open the tool's row for details or start it "
                f"manually.")
        if self.alert:
            self.alert(name, text)
        else:
            self.log(name, text)
