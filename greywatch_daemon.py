#!/usr/bin/env python3
"""greywatch_daemon — L1, the ONE root-privileged monitor (Task 5, plan 105).

Loop (real run): one collector per registry read-source → parse → enrich →
events.jsonl → atomic status.json; hourly trim of events.jsonl to 20 000;
60 s unit-state check (RED on failed unit, YELLOW on unreadable/missing log).
Decision specs are attached daemon-side by decisions_factory; answers land in
decisions.jsonl and are executed ONLY through allowlisted pkexec helpers.

Test surface: every unit (registry/checker/collectors) is injectable; the
same state machine runs with fake collectors in tests and real journalctl +
inotify tailers in production. `--once` makes a single bounded pass.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
from collections import deque
import pathlib
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from collectors import BoundedQueue, FileTailer, JournalTailer
from supervisor import Supervisor
from decisions_factory import interaction_for, sanitize
from enrichment import enrich
from events import normalize_event
from parsers import PARSERS
from registry import load_registry, tool_names
from status import (GREEN, YELLOW, RED, classify, log_state_of, snapshot,
                    write_status, load_status)

ROOT = pathlib.Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
EVENTS_PATH = DATA_DIR / "events.jsonl"

# The desktop user whose user-scope units this daemon reports on. The daemon
# runs as root, and root may NOT connect to a user's session bus directly
# ("Failed to connect to user scope bus ... Operation not permitted"), so the
# query is run through runuser as that user. Overridable for tests/other hosts.
UI_USER = os.environ.get("GREYWATCH_UI_USER", "grey")
try:
    import pwd as _pwd
    _UI_UID = _pwd.getpwnam(UI_USER).pw_uid
except (KeyError, ImportError):
    _UI_UID = 1000
UI_RUNTIME_DIR = f"/run/user/{_UI_UID}"
STATUS_PATH = DATA_DIR / "status.json"
MAX_EVENTS = 20_000
TRIM_KEEP = 20_000


def unit_checker_factory(command_ok=True):
    """BATCHED production unit checker: ONE `systemctl is-active u1 u2...`
    per scope (a per-tool subprocess each makes status writes take ~10 s,
    which starved the queue into overflow churn)."""
    from registry import load_registry
    units_by_scope = {"root": [], "user": []}
    states = {"active": "active", "inactive": "inactive", "failed": "failed",
              "unknown": "unknown"}

    def refresh(scope):
        units = units_by_scope[scope]
        if not units:
            return {}
        env = None
        if scope == "user":
            if os.geteuid() == 0:
                # root cannot reach the user bus directly; runuser can
                cmd = ["runuser", "-u", UI_USER, "--", "env",
                       f"XDG_RUNTIME_DIR={UI_RUNTIME_DIR}",
                       f"DBUS_SESSION_BUS_ADDRESS=unix:path={UI_RUNTIME_DIR}/bus",
                       "systemctl", "--user", "is-active"] + list(units)
            else:
                cmd = ["systemctl", "--user", "is-active"] + list(units)
                env = dict(os.environ, XDG_RUNTIME_DIR=UI_RUNTIME_DIR,
                           DBUS_SESSION_BUS_ADDRESS=(
                               f"unix:path={UI_RUNTIME_DIR}/bus"))
        else:
            cmd = ["systemctl", "is-active"] + list(units)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=10, env=env)
        except (OSError, subprocess.SubprocessError):
            return {u: "unknown" for u in units}
        if proc.returncode != 0 and not (proc.stdout or "").strip():
            return {u: "unknown" for u in units}
        out = (proc.stdout or "").split("\n")
        return dict(zip(units, [l.strip() for l in out if l.strip()]))

    cache = {}

    def check(tool) -> str:
        unit = tool.get("unit")
        if not unit:
            return "no-unit"
        scope = tool.get("scope", "root")
        if unit not in units_by_scope.get(scope, []):
            units_by_scope.setdefault(scope, []).append(unit)
        key = (scope, unit)
        if key not in cache:
            cache[key] = refresh(scope)
        out = cache[key].get(unit)
        if out is None:                       # cache stale after batch grows
            cache[key] = refresh(scope)       # one batched re-query
            out = cache[key].get(unit)
        return out if out in states.values() else "no-unit"

    def invalidate():
        cache.clear()
    check.invalidate = invalidate
    return check


BAN_WINDOW_S = 300
BAN_TRIGGER = 3


class Daemon:
    """State machine only — collectors are injectable (real or fake)."""

    def __init__(self, data_dir=DATA_DIR, registry=None, unit_checker=None,
                 max_events=MAX_EVENTS):
        self.data_dir = pathlib.Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.registry = registry or load_registry()
        self.unit_checker = unit_checker or unit_checker_factory()
        self.max_events = max_events
        self.events_path = self.data_dir / "events.jsonl"
        self.status_path = self.data_dir / "status.json"
        self.decisions_path = self.data_dir / "decisions.jsonl"
        # net-watch's own log must EXIST from startup: the state machine
        # reads "log missing" as YELLOW/needs-attention, and this log is
        # only written on the first IDS finding — a quiet network reads
        # as a fault forever otherwise (found 2026-10-25).
        (self.data_dir / "netwatch-events.jsonl").touch(exist_ok=True)
        self.queue = BoundedQueue(5000)
        self._ban_windows = {}      # ip → deque of epoch timestamps
        self._lock = threading.Lock()
        self._outbox = []           # batched events.jsonl writes
        self._malformed = []        # batched malformed.log lines
        self.forever_mode = False   # run_forever(): skip each log's history
        self._last_snap = None      # last write_status() result (heartbeats)
        # main-loop liveness stamp (2026-10-25 lockup): the systemd
        # WATCHDOG=1 ping is GATED on this, so a wedged main loop gets the
        # unit restarted instead of being petted to death by a separate
        # thread that knows nothing about the loop's health.
        self._beat = 0.0

    # ── the single path a line travels ──────────────────────────────────
    def consume(self, tool: str, line: str):
        """parse → enrich → interaction spec → events.jsonl. Never raises.
        The shared kernel lane (ufw) reroutes apparmor lines by content."""
        if tool == "ufw" and "apparmor=" in line:
            tool = "apparmor"
        if tool == "suricata" and '"event_type"' in line \
                and '"event_type":"alert"' not in line:
            return None                      # eve flow records: not alert signal
        ev = None
        try:
            ev = normalize_event(tool, line)
        except Exception:
            ev = None
        if ev is None:
            self._log_malformed(tool, line)
            return None
        try:
            self._ban_heuristic(ev)
            enrich(ev)
            # passive light-IDS lanes (port scan / burst / denial cluster):
            # analyzer ingests EVERY parsed event; its findings come back
            # through the mirror — never blocks, never raises
            try:
                if getattr(self, "netwatch", None) is None:
                    from netwatch import NetWatch
                    self.netwatch = NetWatch(self._netwatch_event)
                self.netwatch.ingest(ev)
            except Exception:
                pass
            ev.interaction = sanitize(interaction_for(ev))
            keep = ev.interaction is not None
            if not keep:
                from ui.models import feed_worthy
                keep = feed_worthy(ev.__dict__)
            if not keep:
                return None          # routine: seen, parsed, NOT logged
            with self._lock:
                self._outbox.append(json.dumps(ev.to_dict(), separators=(",", ":")))
        except Exception:
            return None
        return ev

    def flush_outbox(self) -> int:
        """ONE append+close per flush cycle (batched; per-line open/close was
        the throughput killer under steady traffic)."""
        with self._lock:
            if not self._outbox:
                return 0
            batch, self._outbox = self._outbox, []
        try:
            with self.events_path.open("a") as f:
                f.write("\n".join(batch) + "\n")
        except OSError:
            # re-queue on transient failure (bounded by trim)
            with self._lock:
                self._outbox = batch + self._outbox[:2000]
            return 0
        return len(batch)

    def heartbeat(self):
        """ALL tools report at least once every 15 min (owner order): a
        check-in per tool, visible in Logs, hidden from the highlight feeds.

        The words must match the tool's REAL state. The old fixed
        "alive, running normally" said the same thing for a dead service as
        for a live one — the Logs screen showed green while Security showed
        red (Pass 1 defect, 2026-10-23). Severity follows the state so the
        Logs dot agrees with the Security lights; check-ins stay out of the
        activity feeds (feed_worthy() knows them by their prefix)."""
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        tools = (self._last_snap or {}).get("tools", {})
        lines = []
        for t in self.registry:
            info = tools.get(t["name"], {})
            state = info.get("state")
            if info.get("paused"):
                text, sev = "check-in: paused by you", "INFO"
            elif state == "GREEN":
                text, sev = "check-in: alive, running normally", "INFO"
            elif state == "RED":
                text, sev = "check-in: NOT RUNNING — needs attention", "HIGH"
            elif state == "YELLOW" and info.get("installed") is False:
                text, sev = "check-in: not installed on this computer", "MEDIUM"
            elif state == "YELLOW":
                text, sev = "check-in: needs attention", "MEDIUM"
            else:
                # No snapshot (or the probe could not answer): never claim
                # "running normally" on a guess.
                text, sev = "check-in: status not available yet", "MEDIUM"
            ev = {"from_tool": t["name"], "severity": sev,
                  "text": text,
                  "ts": now, "nist_func": "IDENTIFY", "nist_control": [],
                  "cves": [], "interaction": None, "heartbeat": True}
            lines.append(json.dumps(ev, separators=(",", ":")))
        with self._lock:
            self._outbox.extend(lines)

    def _ban_heuristic(self, ev):
        """fail2ban: 3+ re-bans of one IP inside the window → near-ignoreip
        decision candidate (plan: fail2ban near-ignoreip → unban/keep)."""
        if ev.from_tool != "fail2ban" or not ev.text.startswith("Ban"):
            return
        ip = ev.text.rsplit("— ", 1)[-1].strip()
        dq = self._ban_windows.setdefault(ip, deque())
        now = time.time()
        dq.append(now)
        while dq and now - dq[0] > BAN_WINDOW_S:
            dq.popleft()
        if len(dq) >= BAN_TRIGGER:
            ev.text += f" (near-ignoreip: {len(dq)} re-bans in {BAN_WINDOW_S}s)"
            dq.clear()

    def _log_malformed(self, tool: str, line: str):
        self._malformed.append(f"{tool}\t{line[:300]}")

    def flush_malformed(self) -> int:
        """Batched + capped malformed log (per-line open/close was a burn;
        unbounded growth a leak)."""
        with self._lock:
            if not self._malformed:
                return 0
            batch, self._malformed = self._malformed, []
        try:
            with (self.data_dir / "malformed.log").open("a") as f:
                f.write("\n".join(batch) + "\n")
            log = self.data_dir / "malformed.log"
            if log.stat().st_size > 1_000_000:     # cap ≈1 MB
                lines = log.read_text().splitlines()
                tmp = str(log) + ".tmp"
                with open(tmp, "w") as f:
                    f.write("\n".join(lines[-2000:]) + "\n")
                os.replace(tmp, str(log))
        except OSError:
            return 0
        return len(batch)

    TOOL_BINARIES = {"lynis": "/usr/sbin/lynis", "rkhunter": "/usr/bin/rkhunter",
                     "secops-mcp": None}     # process-detected only

    @staticmethod
    def tool_installed(tool) -> bool | None:
        """Real probe: True = the unit is listed, False = the command
        succeeded and it is NOT listed, None = the probe could not answer.
        The old version passed an empty argv element for root units and
        treated empty output as "installed", so a fake unit returned True."""
        unit = tool.get("unit")
        if unit:
            probe = unit
            if "@" in unit:                 # arpwatch@iface.service → template
                base, rest = unit.split("@", 1)
                suffix = rest.split(".", 1)[1] if "." in rest else "service"
                probe = f"{base}@.{suffix}"
            env = None
            if tool.get("scope") == "user":
                if os.geteuid() == 0:
                    cmd = ["runuser", "-u", UI_USER, "--", "env",
                           f"XDG_RUNTIME_DIR={UI_RUNTIME_DIR}",
                           f"DBUS_SESSION_BUS_ADDRESS=unix:path={UI_RUNTIME_DIR}/bus",
                           "systemctl", "--user", "list-unit-files", probe]
                else:
                    cmd = ["systemctl", "--user", "list-unit-files", probe]
                    env = dict(os.environ, XDG_RUNTIME_DIR=UI_RUNTIME_DIR,
                               DBUS_SESSION_BUS_ADDRESS=(
                                   f"unix:path={UI_RUNTIME_DIR}/bus"))
            else:
                cmd = ["systemctl", "list-unit-files", probe]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=10, env=env)
            except (OSError, subprocess.SubprocessError):
                return None
            if proc.returncode != 0:
                return None
            return probe in (proc.stdout or "")
        b = Daemon.TOOL_BINARIES.get(tool["name"], "")
        if b:
            return os.path.exists(b)
        if tool["name"] == "secops-mcp":
            out = subprocess.run(["pgrep", "-f", "secops"], capture_output=True,
                                 text=True, timeout=5)
            if out.stdout.strip():
                return True
        return None

    # ── status ───────────────────────────────────────────────────────────
    def write_status(self):
        if hasattr(self.unit_checker, "invalidate"):
            self.unit_checker.invalidate()      # fresh batched unit query
        # the owner's installed/not-installed truth (no guessing)
        for t in self.registry:
            t["_installed"] = self.tool_installed(t)
        snap = snapshot(self.registry, self.unit_checker)
        # deliberate pauses are a state the owner chose, not a fault
        try:
            paused = set(json.loads(
                (DATA_DIR / "paused.json").read_text()).get("paused") or [])
        except (OSError, ValueError):
            paused = set()
        for name in paused:
            if name in snap["tools"]:
                snap["tools"][name]["paused"] = True
        # appfw engine = ours alone (owner 2026-10-23: rebuilt in-suite);
        # state text is informational, never a RED state.
        try:
            eng = getattr(self, "appfw_engine", None)
            snap["appfw_engine"] = ("running" if eng is not None and
                                    eng.running else
                                    "off (owner switch in data/appfw)")
        except Exception:
            pass
        # P0-e component honesty: supervised tailers + engine supervision
        try:
            snap["components"] = {
                **(self.supervisor.snapshot()
                   if getattr(self, "supervisor", None) else {}),
                "appfw-engine": ({"state": "running",
                                  "restarts": 0}
                                 if getattr(self, "appfw_engine", None)
                                 and self.appfw_engine.running else
                                 {"state": "off/failed", "restarts": 0})}
        except Exception:
            pass
        try:
            answered = _answered_ids(self.decisions_path)
            evs = read_events(self.events_path, 2000)
        except OSError:
            evs = []
        pend = 0
        for ev in reversed(evs):
            info = snap["tools"].get(ev["from_tool"])
            if info is None:
                continue
            # "check-in: alive" heartbeats are liveness, not activity — they
            # made every row say "5 min ago" and hid the real last event
            if info["last_event"] is None and not str(
                    ev.get("text", "")).startswith("check-in:"):
                info["last_event"] = ev["ts"]
            if ev.get("interaction") and ev["interaction"]["id"] not in answered:
                pend += 1
        snap["pending_decisions"] = pend
        snap["dropped"] = self.queue.dropped
        self._last_snap = snap          # heartbeats report THIS truth
        write_status(str(self.status_path), snap)
        return snap

    # ── trim (hourly in prod; capped here for tests) ────────────────────
    def trim_events(self):
        try:
            lines = self.events_path.read_text().splitlines()
        except OSError:
            return 0
        if len(lines) <= self.max_events:
            return 0
        keep = lines[-self.max_events:]
        tmp = str(self.events_path) + ".tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(keep) + "\n")
        os.replace(tmp, self.events_path)
        return len(lines) - len(keep)

    # ── appfw engine: HEADLESS (owner 2026-10-23: "i need it running
    # headless, not with the gui. we should be controlling it inside of
    # this"). Answers instantly — never blocks a connection:
    #   trust-list hit → allow/deny ALWAYS (rule saved by the engine)
    #   otherwise      → allow ONCE (fail-open default) + the ask is
    #                    emitted as a NON-BLOCKING decision event; making
    #                    it permanent = trust list / CLI rule.
    def start_appfw(self):
        from appfw.engine import Engine, read_enabled
        if not read_enabled(self.data_dir):
            self.appfw_engine = None
            return False
        from ui.settings import TrustList
        from ui.blocklist import BlockList
        eng = Engine(self.data_dir, on_event=self._appfw_event,
                     trust_list=TrustList(), blocklist=BlockList(),
                     ask=self._appfw_default_ask)
        if not eng.start():
            self.appfw_engine = None
            return False
        self.appfw_engine = eng
        return True

    def stop_appfw(self):
        eng = getattr(self, "appfw_engine", None)
        if eng is not None:
            eng.stop()
            self.appfw_engine = None

    def _appfw_event(self, text: str):
        """Mirror an intercept as an event (tool=appfw) — non-blocking; a
        plain copy also lands in data/appfw/events.jsonl (the tool's own
        log source, registry-driven like every other tool)."""
        try:
            from events import Event
            from enrichment import enrich
            now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
            ev = Event(from_tool="appfw", severity="MEDIUM", text=text[:500],
                       ts=now)
            enrich(ev)
            with self._lock:
                self._outbox.append(json.dumps(ev.to_dict(), separators=(",", ":")))
            log = self.data_dir / "appfw" / "events.jsonl"
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a") as f:
                f.write(text[:500] + "\n")
        except Exception as e:
            # never silent: stderr lands in the systemd journal even when a
            # structured write is impossible
            print("appfw mirror write failed:", e, flush=True)

    def _netwatch_event(self, severity: str, text: str):
        """Mirror an IDS finding (tool=net-watch) — non-blocking; the plain
        copy lands in data/netwatch-events.jsonl (the tool's own log)."""
        try:
            from events import Event
            from enrichment import enrich
            now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
            ev = Event(from_tool="net-watch", severity=severity, text=text[:500],
                       ts=now)
            enrich(ev)
            with self._lock:
                self._outbox.append(json.dumps(ev.to_dict(), separators=(",", ":")))
            log = self.data_dir / "netwatch-events.jsonl"
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a") as f:
                f.write(f"netwatch {severity} {text[:400]}\n")
        except Exception as e:
            print("net-watch mirror write failed:", e, flush=True)

    @staticmethod
    def _appfw_default_ask(spec):
        """Instant headless answer; the decision event carries the trust
        options so the UI/CLI can make it permanent without any modal."""
        return ("allow", "once")

    # ── learning mode (owner 2026-10-23) — the switches live in
    # appfw.policy.Policy, built by the engine itself from data_dir; the
    # daemon holds no separate copy of that logic.

    # ── update schedule self-heal (root) ────────────────────────────────
    def ensure_updates(self):
        """An enabled but inactive timer NEVER fires — the weekly security
        list silently stopped that way (owner 2026-10-23: "don't leave the
        update here as paused"). Start it, and refresh a stale cache now.
        Offline is a valid outcome; nothing here can hurt."""
        for t in self.registry:
            unit = str(t.get("unit") or "")
            if not unit.endswith(".timer"):
                continue
            try:
                en = subprocess.run(["systemctl", "is-enabled", unit],
                                    capture_output=True, text=True,
                                    timeout=10).stdout.strip()
                ac = subprocess.run(["systemctl", "is-active", unit],
                                    capture_output=True, text=True,
                                    timeout=10).stdout.strip()
                if en == "enabled" and ac != "active":
                    subprocess.run(["systemctl", "start", unit],
                                   capture_output=True, timeout=20)
            except (OSError, subprocess.SubprocessError):
                continue
        cache = self.data_dir / "cve-cache.json"
        try:
            fresh = time.time() - cache.stat().st_mtime < 8 * 86400
        except OSError:
            fresh = False
        if not fresh:
            try:
                subprocess.run([sys.executable, str(ROOT / "cve-refresh.py")],
                               capture_output=True, timeout=300)
            except (OSError, subprocess.SubprocessError):
                return
            try:                       # the GUI (not root) also writes it
                st = self.data_dir.stat()
                os.chown(cache, st.st_uid, st.st_gid)
            except OSError:
                pass

    # ── real collectors ─────────────────────────────────────────────────
    def build_collectors(self):
        """One collector per unique journal/log source from the registry.

        Shared logs are claimed by the first tool with them (yara-tmp-scan
        is state_only); journal sources become JournalTailer instances.
        """
        out, claimed = [], set()
        for t in self.registry:
            for src in t.get("logs", []):
                if src in claimed:
                    continue
                claimed.add(src)
                if str(src).startswith("journal:"):
                    arg = self.KERNEL_LANE.get(str(src))
                    if arg:
                        if self.forever_mode:
                            arg += " -n 0"    # follow-only: no history replay
                        # kernel lane pre-gate keeps [UFW + apparmor; auditd
                        # noise (1000+/s on a busy box) dies at the tailer
                        flt = ["[UFW", "apparmor="]
                        out.append(JournalTailer(t["name"], arg,
                                                 self.queue.put_nowait,
                                                 line_filter=flt))
                else:
                    out.append(FileTailer(src, t["name"], self.queue.put_nowait,
                                          start_at_end=self.forever_mode))
            for jf in [t] if t.get("journal") else []:
                arg = t["journal"]["filter"]
                if "-f" not in arg.split():
                    arg += " -f"              # follow: never a print-then-die
                if self.forever_mode:
                    arg += " -n 0"
                out.append(JournalTailer(t["name"], arg, self.queue.put_nowait))
        return out

    KERNEL_LANE = {"journal:kern": "-k -f -o cat"}

    def make_collector_args(self, tool_name: str, path):
        for t in self.registry:
            if t["name"] == tool_name and str(path).startswith("journal"):
                return [t]
        return []

    # ── lifecycle ────────────────────────────────────────────────────────
    def collect_burst(self, tailers, settle=1.5):
        """Start tailers, let them land on the queue, stop them (test/once)."""
        for t in tailers:
            t.start()
        time.sleep(settle)
        items = self.queue.drain()
        for t in tailers:
            t.stop()
        return items

    def run_once(self, tailers=None, settle=1.5) -> dict:
        items = self.collect_burst(tailers or self.build_collectors(), settle)
        for tool, line in items:
            self.consume(tool, line)
        self.flush_outbox()
        return self.write_status()

    def run_forever(self, tailers=None, unit_interval=60, trim_interval=3600,
                    stop=None):
        """Real mode. The queue drains CONTINUOUSLY (0.5 s cadence so it never
        overflows during normal traffic); write_status runs on the 60 s unit
        check; trim hourly. Never exits except on stop."""
        self.forever_mode = True
        stop = stop or threading.Event()
        self._beat = time.monotonic()
        try:
            served = self.start_appfw()
            print("greywatch appfw engine:",
                  "running (headless)" if served else
                  "off — enable switch is data/appfw/enable.json")
        except Exception as e:
            served = False
            print("appfw engine unavailable:", e)
        # Keep the update schedule alive without a person remembering it.
        try:
            threading.Thread(target=self.ensure_updates, daemon=True).start()
        except Exception:
            pass
        from appfw.sd_notify import notify as _sd
        _sd('READY=1')
        live = tailers or self.build_collectors()
        self.supervisor = Supervisor()
        for t in live:
            t.start()
            # supervised launcher: health = the tailer's own thread; a dead
            # inotify/journal tailer re-spawns within one loop cycle
            self.supervisor.register(
                f"tail:{getattr(t, 'tool', 'journal')}", target=t.start,
                health=lambda t=t: getattr(t, "_thread", None) is not None
                and t._thread.is_alive(), latched_target=False)
        # systemd-native watchdog (owner decision 2026-10-25): ping
        # WATCHDOG=1 every 10 s; the manager restarts beyond WatchdogSec=30
        threading.Thread(target=self._watchdog_ping_loop, args=(stop,),
                         daemon=True, name="watchdog-ping").start()
        status_at = time.monotonic() + unit_interval
        trim_at = time.monotonic() + trim_interval
        heartbeat_at = time.monotonic() + 900      # every tool: 15-min check-in
        # P0-e engine supervision (≤10 s detect): rearm when enabled+dead;
        # breaker parks after 3 failures/60 s (quiet reset 300 s); switch-off
        # stops the engine whenever seen.
        engine_check_at = time.monotonic() + 10
        engine_fails: list[float] = []
        while not stop.is_set():
            self._beat = time.monotonic()
            try:
                # drain until empty (never a churned backlog between cycles)
                for _ in range(10):
                    got = self.queue.drain(2000)
                    if not got:
                        break
                    for tool, line in got:
                        self.consume(tool, line)
                self.flush_outbox()
                self.flush_malformed()
                self.supervisor.check_all()
                now = time.monotonic()
                if now >= status_at:
                    self.write_status()
                    status_at = now + unit_interval
                if now >= engine_check_at:
                    engine_check_at = now + 10
                    eng = getattr(self, "appfw_engine", None)
                    # a Settings config.json change re-arms (ruleset + lane
                    # options land without a daemon restart)
                    if eng is not None and eng.running and eng.config_changed():
                        self.stop_appfw()
                        eng = None
                        print("greywatch appfw engine: config changed — re-arming")
                    armed_now = appfw_enabled(str(self.data_dir))
                    if armed_now and (eng is None or not eng.running):
                        now_t = time.monotonic()
                        engine_fails = [t for t in engine_fails
                                        if now_t - t < 60.0]
                        if len(engine_fails) < 3:          # breaker open?
                            try:
                                served = self.start_appfw()
                                if served:
                                    engine_fails = []
                                    print("greywatch appfw engine: running "
                                          "(owner switch enabled)")
                                else:
                                    engine_fails.append(now_t)
                            except Exception as e:
                                # never silent: the owner reads the ledger
                                engine_fails.append(now_t)
                                try:
                                    self._appfw_event(
                                        f"appfw engine arm failed: {e}")
                                except Exception:
                                    pass
                        # breakered: parked; surfaced in the snapshot —
                        # NEVER fake-green
                    elif not armed_now and eng is not None and eng.running:
                        self.stop_appfw()
                        print("greywatch appfw engine: stopped (switch off)")
                if now >= trim_at:
                    self.trim_events()
                    trim_at = now + trim_interval
                if now >= heartbeat_at:
                    self.heartbeat()
                    heartbeat_at = now + 900
            except Exception:
                pass                       # one loop-iteration survival rule
            stop.wait(0.5)
        # clean stop: tear the engine down so nothing is left queued; a
        # SIGKILL leaves the table behind — 'bypass' keeps traffic flowing
        # and the next install is delete-then-add idempotent
        self.stop_appfw()

    def _watchdog_ping_loop(self, stop) -> None:
        """Type=notify watchdog: WATCHDOG=1 every 10 s (WatchdogSec=30).
        Also the boot READY comes from main(). The old heartbeat file +
        greywatch-watchdog.timer are RETIRED (owner decision).

        GATED on main-loop liveness (2026-10-25 lockup): this thread must
        never pet the watchdog on behalf of a main loop that is wedged.
        A beat older than 8 s means the loop has not completed an
        iteration — stop pinging and let systemd restart the unit."""
        from appfw.sd_notify import notify
        while not stop.is_set():
            try:
                if time.monotonic() - self._beat < 8.0:
                    notify("WATCHDOG=1")
                else:
                    print("greywatch: main loop stale — watchdog NOT petted")
            except Exception:
                pass
            stop.wait(10.0)


def read_events(events_path, limit=None):
    """Last `limit` events, oldest→newest. TAIL-READ (bounded): reads from
    the END of the file in chunks — the old full-file parse made every GUI
    refresh re-read 28 MB (the 'super slow' app). Missing → []; malformed
    lines skipped."""
    try:
        f = open(events_path, "rb")
    except OSError:
        return []
    with f:
        try:
            f.seek(0, 2)
            size = f.tell()
        except OSError:
            return []
        if size == 0:
            return []
        chunk = max(65536, limit * 1100 if limit else 131072)   # ~1kB/line est.
        tail = b""
        pos = size
        while len(tail) < (limit * 1200 if limit else size):
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            tail = f.read(step) + tail
            if pos == 0 or tail.count(b"\n") >= (limit or 10**9):
                break
        lines = [l.strip() for l in tail.split(b"\n") if l.strip()]
        if limit:
            lines = lines[-limit:]
    out = []
    for raw in lines:
        try:
            out.append(json.loads(raw.decode("utf-8", "replace")))
        except ValueError:
            continue
    return out


def appfw_enabled(data_dir=None) -> bool:
    """The owner's engine switch, mirrored here for tests and the CLI."""
    from appfw.engine import read_enabled
    return read_enabled(data_dir or str(DATA_DIR))


def _answered_ids(decisions_path):
    from decisions_factory import pending_ids
    try:
        return pending_ids(decisions_path)
    except OSError:
        return set()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="greywatch")
    ap.add_argument("--once", action="store_true", help="single bounded pass")
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--settle", type=float, default=1.5,
                    help="--once: seconds to let collectors burst")
    ap.add_argument("--data-dir", default=str(DATA_DIR))
    ap.add_argument("--max-events", type=int, default=MAX_EVENTS)
    args = ap.parse_args(argv)

    d = Daemon(args.data_dir, max_events=args.max_events)
    if args.once:
        once = d.run_once(settle=args.settle)
        print(json.dumps(once))
        return 0
    # battery 2026-10-24: no signal handler existed — systemd's stops hung
    # out the full TimeoutStopSec (and with WatchdogSec=30 the restart
    # cycles compounded). Wire SIGTERM/SIGINT/CLEANUP to the run's stop
    # Event so every exit path is the CLEAN teardown (engine off + nft
    # table removed), never a dangling stop job.
    import signal, threading
    _stop = threading.Event()

    def _on_term(signum, frame):
        _stop.set()
    for _sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(_sig, _on_term)
    import atexit
    atexit.register(lambda: _stop.set())
    d.run_forever(stop=_stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())