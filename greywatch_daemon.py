from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
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
from registry import load_registry
from gwpaths import data_dir as _default_data_dir
from status import (snapshot,
                    write_status,
                    atomic_replace,
                    append_checked,
                    load_status)  # noqa: F401

ROOT = pathlib.Path(__file__).resolve().parent
DATA_DIR = _default_data_dir()
EVENTS_PATH = DATA_DIR / "events.jsonl"

UI_USER = os.environ.get("GREYWATCH_UI_USER", "grey")
try:
    import pwd as _pwd
except ImportError:
    _pwd = None

STATUS_PATH = DATA_DIR / "status.json"
MAX_EVENTS = 20_000
TRIM_KEEP = 20_000


def ui_uid():
    """The desktop user's uid — or None when that identity cannot be
    resolved. GW-02: an unresolved UI identity is never guessed (the old
    code invented 1000); the user-session probes and the GUI relaunch
    degrade honestly instead of acting on the wrong account."""
    if _pwd is None:
        return None
    try:
        return _pwd.getpwnam(UI_USER).pw_uid
    except KeyError:
        return None


def ui_runtime_dir():
    uid = ui_uid()
    return f"/run/user/{uid}" if uid is not None else None


def unit_checker_factory(command_ok=True):
    units_by_scope = {"root": [], "user": []}
    states = {"active": "active", "inactive": "inactive", "failed": "failed",
              "unknown": "unknown"}

    def refresh(scope):
        units = units_by_scope[scope]
        if not units:
            return {}
        env = None
        if scope == "user":
            rt = ui_runtime_dir()
            if os.geteuid() == 0:
                if rt is None:          # unresolved desktop user: probe honestly
                    return {u: "unknown" for u in units}
                cmd = ["runuser", "-u", UI_USER, "--", "env",
                       f"XDG_RUNTIME_DIR={rt}",
                       f"DBUS_SESSION_BUS_ADDRESS=unix:path={rt}/bus",
                       "systemctl", "--user", "is-active"] + list(units)
            else:
                cmd = ["systemctl", "--user", "is-active"] + list(units)
                env = dict(os.environ, XDG_RUNTIME_DIR=rt,
                           DBUS_SESSION_BUS_ADDRESS=f"unix:path={rt}/bus"
                           ) if rt else None
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
        (self.data_dir / "netwatch-events.jsonl").touch(exist_ok=True)
        self.queue = BoundedQueue(5000)
        self._ban_windows = {}      # ip → deque of epoch timestamps
        self._lock = threading.Lock()
        self._outbox = []           # batched events.jsonl writes
        self._malformed = []        # batched malformed.log lines
        self.forever_mode = False   # run_forever(): skip each log's history
        self._last_snap = None      # last write_status() result (heartbeats)
        self._beat = 0.0
        self.ui_gid = self._ui_gid()
        self._share_with_ui(self.events_path)
        # Same failure class as status.json: written by root 0600, so the
        # dashboard silently shows "nothing fetched yet" while the cache is
        # right there. The CVE list is public data; 0640 root:grey is enough.
        self._share_with_ui(self.data_dir / "cve-cache.json")
        self._fail_counts = {}      # category → {"count": int, "last": str}
        self._fail_log_at = {}      # category → monotonic of last log line
        self._ask_policy = "deny-once"    # re-read at start_appfw()
        self._ask_policy_label = ("deny-once — no approval dialog wired "
                                  "(headless fallback, NOT user-approved)")
        self.healer = None       # built in run_forever (needs log/alert)
        self._notice_at = {}     # generic notice dedupe table
        # Scans belong to the daemon: it spawns them, parses their output
        # and writes the live/findings/summary files the GUI reads. The GUI
        # holds no scan state, so a GUI crash loses nothing.
        self.scans = None        # built when run_forever starts

    def _share_with_ui(self, path) -> None:
        """Let the desktop GUI read an existing root-owned file.

        The daemon runs as root and the GUI as the desktop user. Files
        created before the 0640 fix are root:root 0600, so the GUI reads
        nothing — no feed, no prompts — and the failure is silent. Called
        at startup so the next restart repairs the live file in place.
        """
        if self.ui_gid is None or os.geteuid() != 0:
            return
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return
        try:
            st = os.fstat(fd)
            if st.st_uid == os.geteuid() and (st.st_mode & 0o170000) == 0o100000:
                os.fchown(fd, -1, self.ui_gid)
                os.fchmod(fd, 0o640)
        except OSError:
            pass
        finally:
            os.close(fd)

    @staticmethod
    def _ui_gid():
        try:
            import pwd as _pwd
            return _pwd.getpwnam(UI_USER).pw_gid
        except (KeyError, ImportError):
            return None

    FAIL_LOG_INTERVAL_S = 30.0

    def count_failure(self, category: str, where: str,
                      error: BaseException) -> None:
        """Record a swallowed exception per category; rate-limit the log."""
        rec = self._fail_counts.setdefault(
            category, {"count": 0, "last": ""})
        rec["count"] += 1
        rec["last"] = f"{where}: {type(error).__name__}"
        now = time.monotonic()
        if now - self._fail_log_at.get(
                category, -self.FAIL_LOG_INTERVAL_S) >= self.FAIL_LOG_INTERVAL_S:
            self._fail_log_at[category] = now
            print(f"greywatch: {category} errors — {rec['count']} total "
                  f"(last: {rec['last']})", flush=True)

    def consume(self, tool: str, line: str):
        if tool == "ufw" and "apparmor=" in line:
            tool = "apparmor"
        ev = None
        try:
            ev = normalize_event(tool, line)
        except Exception as e:
            self.count_failure("parse", "normalize_event", e)
            ev = None
        if ev is None:
            self._log_malformed(tool, line)
            return None
        try:
            self._ban_heuristic(ev)
            enrich(ev)
            try:
                if getattr(self, "netwatch", None) is None:
                    from netwatch import NetWatch
                    self.netwatch = NetWatch(self._netwatch_event)
                self.netwatch.ingest(ev)
            except Exception as e:
                self.count_failure("netwatch", "ingest", e)
            ev.interaction = sanitize(interaction_for(ev))
            keep = ev.interaction is not None
            if not keep:
                from ui.models import feed_worthy
                keep = feed_worthy(ev.__dict__)
            if not keep:
                return None          # routine: seen, parsed, NOT logged
            with self._lock:
                self._outbox.append(json.dumps(ev.to_dict(), separators=(",", ":")))
        except Exception as e:
            self.count_failure("process", "consume", e)
            return None
        return ev

    def flush_outbox(self) -> int:
        with self._lock:
            if not self._outbox:
                return 0
            batch, self._outbox = self._outbox, []
        try:
            append_checked(str(self.events_path), "\n".join(batch) + "\n",
                           create_mode=0o640, gid=self.ui_gid)
        except OSError as e:
            self.count_failure("write", "events.jsonl", e)
            with self._lock:
                self._outbox = batch + self._outbox[:2000]
            return 0
        return len(batch)

    def heartbeat(self):
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        tools = (self._last_snap or {}).get("tools", {})
        lines = []
        for t in self.registry:
            info = tools.get(t["name"], {})
            state = info.get("state")
            if info.get("paused"):
                text, sev = "check-in: paused in the app", "INFO"
            elif state == "GREEN":
                text, sev = "check-in: alive, running normally", "INFO"
            elif state == "RED":
                text, sev = "check-in: NOT RUNNING — needs attention", "HIGH"
            elif state == "YELLOW" and info.get("installed") is False:
                text, sev = "check-in: not installed on this computer", "MEDIUM"
            elif state == "YELLOW":
                text, sev = "check-in: needs attention", "MEDIUM"
            else:
                text, sev = "check-in: status not available yet", "MEDIUM"
            ev = {"from_tool": t["name"], "severity": sev,
                  "text": text,
                  "ts": now, "nist_func": "IDENTIFY", "nist_control": [],
                  "cves": [], "interaction": None, "heartbeat": True}
            lines.append(json.dumps(ev, separators=(",", ":")))
        with self._lock:
            self._outbox.extend(lines)

    def _ban_heuristic(self, ev):
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
        with self._lock:
            if not self._malformed:
                return 0
            batch, self._malformed = self._malformed, []
        try:
            log = self.data_dir / "malformed.log"
            append_checked(str(log), "\n".join(batch) + "\n")
            if log.stat().st_size > 1_000_000:     # cap ≈1 MB
                lines = log.read_text().splitlines()
                atomic_replace(str(log), "\n".join(lines[-2000:]) + "\n")
        except OSError as e:
            self.count_failure("write", "malformed.log", e)
            return 0
        return len(batch)

    TOOL_BINARIES = {"lynis": "/usr/sbin/lynis", "rkhunter": "/usr/bin/rkhunter",
                     "secops-mcp": None}     # process-detected only

    @staticmethod
    def tool_installed(tool) -> bool | None:
        unit = tool.get("unit")
        if unit:
            probe = unit
            if "@" in unit:                 # arpwatch@iface.service → template
                base, rest = unit.split("@", 1)
                suffix = rest.split(".", 1)[1] if "." in rest else "service"
                probe = f"{base}@.{suffix}"
            env = None
            if tool.get("scope") == "user":
                rt = ui_runtime_dir()
                if os.geteuid() == 0:
                    if rt is None:      # unresolved desktop user: probe honestly
                        return None
                    cmd = ["runuser", "-u", UI_USER, "--", "env",
                           f"XDG_RUNTIME_DIR={rt}",
                           f"DBUS_SESSION_BUS_ADDRESS=unix:path={rt}/bus",
                           "systemctl", "--user", "list-unit-files", probe]
                else:
                    cmd = ["systemctl", "--user", "list-unit-files", probe]
                    env = dict(os.environ, XDG_RUNTIME_DIR=rt,
                               DBUS_SESSION_BUS_ADDRESS=(
                                   f"unix:path={rt}/bus")) if rt else None
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

    def write_status(self):
        if hasattr(self.unit_checker, "invalidate"):
            self.unit_checker.invalidate()      # fresh batched unit query
        for t in self.registry:
            t["_installed"] = self.tool_installed(t)
        snap = snapshot(self.registry, self.unit_checker)
        try:
            paused = set(json.loads(
                (self.data_dir / "paused.json").read_text()).get("paused") or [])
        except (OSError, ValueError):
            paused = set()
        for name in paused:
            if name in snap["tools"]:
                snap["tools"][name]["paused"] = True
        eng = getattr(self, "appfw_engine", None)
        try:
            running = eng is not None and eng.running
            enabled = True
            try:
                from appfw.engine import read_enabled
                enabled = read_enabled(self.data_dir)
            except Exception:
                pass
            snap["appfw_engine"] = (
                "running" if running else
                ("off (owner switch in data/appfw)" if not enabled
                 else "off (engine failed to start — see the event log)"))
        except Exception as e:
            self.count_failure("status", "appfw summary", e)
        try:
            eng_state = ({"state": "running", "restarts": 0,
                          "ask_policy": self._ask_policy_label,
                          "backlog_fails": getattr(eng, "_backlog_fails", 0),
                          "last_backlog": getattr(eng, "_last_backlog", None)}
                         if eng is not None and eng.running else
                         {"state": "off/failed", "restarts": 0})
            snap["components"] = {
                **(self.supervisor.snapshot()
                   if getattr(self, "supervisor", None) else {}),
                "appfw-engine": eng_state}
        except Exception as e:
            self.count_failure("status", "component snapshot", e)
        snap["appfw_ask_policy"] = self._ask_policy_label
        evs = []
        try:
            answered = _answered_ids(self.decisions_path)
            evs = read_events(self.events_path, 2000)
            snap["recent"] = recent_digest(evs)
        except OSError:
            evs = []
        pend = 0
        for ev in reversed(evs):
            info = snap["tools"].get(ev["from_tool"])
            if info is None:
                continue
            if info["last_event"] is None and not str(
                    ev.get("text", "")).startswith("check-in:"):
                info["last_event"] = ev["ts"]
            if ev.get("interaction") and ev["interaction"]["id"] not in answered:
                pend += 1
        snap["pending_decisions"] = pend
        snap["dropped"] = self.queue.dropped
        snap["failures"] = {k: v["count"]
                            for k, v in self._fail_counts.items()}
        snap["degraded"] = sorted(snap["failures"])
        self._last_snap = snap          # heartbeats report THIS truth
        try:
            write_status(str(self.status_path), snap, gid=self.ui_gid)
        except OSError as e:
            self.count_failure("status", "status.json", e)
        return snap

    def trim_events(self):
        try:
            lines = self.events_path.read_text().splitlines()
            if len(lines) <= self.max_events:
                return 0
            keep = lines[-self.max_events:]
            atomic_replace(str(self.events_path), "\n".join(keep) + "\n")
            return len(lines) - len(keep)
        except OSError as e:
            self.count_failure("write", "events trim", e)
            return 0

    def _headless_ask(self):
        """Which verdict to answer with when NO approval dialog is wired:
        read from data/appfw/config.json ({"headless_ask": ...})."""
        from appfw.config import load as cfg_load
        mode = str(cfg_load(self.data_dir).get("headless_ask") or "")
        return "deny-once" if mode == "deny-once" else "allow-once"

    def start_appfw(self):
        from appfw.engine import Engine, read_enabled
        if not read_enabled(self.data_dir):
            self.appfw_engine = None
            return False
        self._ask_policy = self._headless_ask()
        self._ask_policy_label = (f"ask the dashboard popup; "
                                  f"{self._ask_policy} when it is closed "
                                  f"(headless fallback)")
        from ui.settings import TrustList
        from ui.blocklist import BlockList
        eng = Engine(self.data_dir, on_event=self._appfw_event,
                     trust_list=TrustList(), blocklist=BlockList(),
                     ask=self._appfw_ask_user)
        if not eng.start():
            self.appfw_engine = None
            return False
        self.appfw_engine = eng
        self._appfw_event(f"appfw engine armed — {self._ask_policy_label}")
        return True

    def stop_appfw(self):
        eng = getattr(self, "appfw_engine", None)
        if eng is not None:
            eng.stop()
            self.appfw_engine = None

    _appfw_notice_at: dict[str, float] = {}   # dedupe identical notices

    def _appfw_event(self, text: str, dedupe_window_s: float = 300.0):
        """Appfw notices are deduplicated: an identical message within the
        dedupe window is dropped. Without this, a persistently failing engine
        (nft install, worker spawn) retries every 10 s and floods the event
        feed and the UI with thousands of identical MEDIUM rows — the exact
        flood that pinned the daemon at its memory cap. Event-path failures
        still reach the mirror log via count_failure; this only shapes the
        feed the user reads."""
        key = text[:500]
        now = time.monotonic()
        prev = self._appfw_notice_at.get(key)
        if prev is not None and now - prev < dedupe_window_s:
            return
        self._appfw_notice_at[key] = now
        if len(self._appfw_notice_at) > 256:      # bound the dedupe table
            self._appfw_notice_at = dict(
                sorted(self._appfw_notice_at.items(),
                       key=lambda kv: kv[1], reverse=True)[:256])
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
            append_checked(str(log), text[:500] + "\n")
        except Exception as e:
            self.count_failure("write", "appfw mirror", e)
            print("appfw mirror write failed:", e, flush=True)

    def _netwatch_event(self, severity: str, text: str):
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
            append_checked(str(log), f"netwatch {severity} {text[:400]}\n")
        except Exception as e:
            self.count_failure("write", "net-watch mirror", e)
            print("net-watch mirror write failed:", e, flush=True)

    def _notice(self, tool: str, severity: str, text: str,
                dedupe_window_s: float = 600.0) -> None:
        """One feed row for something the daemon itself decided (repairs,
        escalations). Deduplicated like the appfw notices so a crash loop
        cannot flood the feed."""
        key = f"{tool}|{severity}|{text[:400]}"
        now = time.monotonic()
        prev = self._notice_at.get(key)
        if prev is not None and now - prev < dedupe_window_s:
            return
        self._notice_at[key] = now
        if len(self._notice_at) > 256:
            self._notice_at = dict(sorted(
                self._notice_at.items(), key=lambda kv: kv[1],
                reverse=True)[:256])
        try:
            from events import Event
            ev = Event(from_tool=tool, severity=severity, text=text[:500],
                       ts=_dt.datetime.now(_dt.timezone.utc)
                       .isoformat(timespec="seconds"))
            enrich(ev)
            with self._lock:
                self._outbox.append(json.dumps(ev.to_dict(),
                                               separators=(",", ":")))
        except Exception as e:
            self.count_failure("write", "self-heal notice", e)

    @staticmethod
    def _appfw_ask_allow(spec):
        # HEADLESS fallback, not approval: nothing here is user-verified.
        # The engine's policy label in status.json says so explicitly.
        return ("allow", "once")

    @staticmethod
    def _appfw_ask_deny(spec):
        # Headless fail-closed: no dialog wired and the operator asked for
        # unknown programs to be denied rather than let through.
        return ("deny", "once")

    ASK_TIMEOUT_S = 15.0

    def _ask_paths(self, spec):
        """Request/answer file pair for one ask, keyed by the spec id.

        The id contains the app name, pid and source port, so hashing it
        keeps the filename safe and lets the GUI correlate the answer.
        """
        import hashlib
        key = hashlib.sha256(
            str(spec.get("id") or "").encode()).hexdigest()[:16]
        base = self.data_dir / "appfw"
        return (base / "asks" / f"{key}.json",
                base / "answers" / f"{key}.json")

    def _share_dir_with_ui(self, path) -> None:
        """Create a directory the desktop GUI (a different user) can use.

        Group-write is set explicitly: the daemon's umask decides the mode
        otherwise, and a 0755 directory silently makes every ask time out
        because the GUI cannot write its answer.
        """
        path.mkdir(parents=True, exist_ok=True)
        try:
            if self.ui_gid is not None and os.geteuid() == 0:
                os.chown(path, -1, self.ui_gid)
            os.chmod(path, 0o775)
        except OSError:
            pass

    @staticmethod
    def _host_op(value):
        """What the operator chose to remember.

        The dashboard sends either a mode ("trust", "block-host", …) or the
        destination it resolved. The old whitelist accepted only two of the
        four modes, so "Always allow/block this site" reached the engine as
        "nothing to remember" and the prompt came back forever (owner
        report 2026-10-28). Validate instead of enumerating.
        """
        if not isinstance(value, str):
            return None
        value = value.strip()[:200]
        if value in ("host", "block-host", "trust", "trust-block"):
            return value
        if re.fullmatch(r"[A-Za-z0-9*._:/-]{1,120}", value or ""):
            return value
        return None

    def _appfw_ask_user(self, spec):
        """Ask the running GUI instead of guessing.

        The daemon is root with no display; the GUI polls this ask
        directory every half second and writes the operator's answer into
        the matching file. The engine's decision loop is serial, so at
        most one ask is ever outstanding — which is what lets the GUI keep
        its single-popup promise.

        If no GUI answers in time (it may not be running at all) the
        configured headless verdict is used, so behaviour degrades to
        exactly what shipped before — never to an unasked allow.
        """
        fallback = (("deny", "once") if self._ask_policy == "deny-once"
                    else ("allow", "once"))
        req = ans = None
        try:
            req, ans = self._ask_paths(spec)
            self._share_dir_with_ui(req.parent)
            self._share_dir_with_ui(ans.parent)
            for p in (req, ans):
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
            payload = {"id": spec.get("id"),
                       "ts": _dt.datetime.now(_dt.timezone.utc)
                       .isoformat(timespec="seconds"),
                       "spec": spec}
            atomic_replace(str(req), json.dumps(payload))
            try:
                os.chmod(req, 0o644)
            except OSError:
                pass
            deadline = time.monotonic() + self.ASK_TIMEOUT_S
            while time.monotonic() < deadline:
                if ans.exists():
                    doc = json.loads(ans.read_text())
                    action = str(doc.get("action") or "")
                    if action not in ("allow", "deny"):
                        break                 # malformed → fallback
                    duration = str(doc.get("duration") or "once")
                    host_op = self._host_op(doc.get("host_op"))
                    return (action,
                            duration if duration in ("once", "always")
                            else "once",
                            host_op)
                time.sleep(0.1)
        except (OSError, ValueError) as e:
            self.count_failure("appfw", "ask bridge", e)
        finally:
            for p in (req, ans):
                if p is None:
                    continue
                try:
                    p.unlink()
                except OSError:
                    pass
        return fallback


    def ensure_updates(self):
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

    def build_collectors(self):
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

    def _arm_scans(self, live) -> None:
        """Build the scan service and hand it the log tailers it must mute."""
        by_tool = {}
        for t in live:
            if isinstance(t, FileTailer) and getattr(t, "tool", None):
                by_tool.setdefault(t.tool, []).append(t)
        try:
            svc = self.make_scan_service()

            def pause(tool):
                for t in by_tool.get(tool, []):
                    t.pause()        # thread stays up: no supervisor restart

            def resume(tool):
                for t in by_tool.get(tool, []):
                    t.resume()

            svc.set_tailer_hooks(pause, resume)
            svc.recover_interrupted()
            self.scans = svc
        except Exception as e:
            self.scans = None
            self.count_failure("scan", "init", e)

    def make_scan_service(self):
        """The scan owner for this data dir, wired to this daemon's sink."""
        from scan_session import ScanService
        return ScanService(
            self.data_dir, consume=self.consume, gid=self.ui_gid,
            ui_user=UI_USER, home=os.path.expanduser(f"~{UI_USER}"),
            log=lambda m: print(f"greywatch scan: {m}", flush=True))

    def make_collector_args(self, tool_name: str, path):
        for t in self.registry:
            if t["name"] == tool_name and str(path).startswith("journal"):
                return [t]
        return []

    def collect_burst(self, tailers, settle=1.5):
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
        try:
            threading.Thread(target=self.ensure_updates, daemon=True).start()
        except Exception as e:
            self.count_failure("loop", "updates thread", e)
        from appfw.sd_notify import notify as _sd
        _sd('READY=1')
        live = tailers or self.build_collectors()
        try:
            from selfheal import SelfHealer
            import triage as _triage
            self.healer = SelfHealer(
                self.data_dir, self.registry,
                log=lambda n, t: self._notice(n, "MEDIUM", t),
                alert=lambda n, t: self._notice(n, "HIGH", t,
                                                dedupe_window_s=3600.0),
                triage=_triage.make(self.data_dir),
                user=UI_USER, runtime_dir=ui_runtime_dir() or "")
            print("greywatch self-heal: on"
                  + ("" if _triage.make(self.data_dir) is None
                     else " (ai triage on)"), flush=True)
        except Exception as e:
            self.healer = None
            self.count_failure("heal", "init", e)
        self.supervisor = Supervisor()
        for t in live:
            t.start()
            self.supervisor.register(
                f"tail:{getattr(t, 'tool', 'journal')}", target=t.start,
                health=lambda t=t: getattr(t, "_thread", None) is not None
                and t._thread.is_alive(), latched_target=False)
        threading.Thread(target=self._watchdog_ping_loop, args=(stop,),
                         daemon=True, name="watchdog-ping").start()
        self._arm_scans(live)
        status_at = time.monotonic() + unit_interval
        trim_at = time.monotonic() + trim_interval
        heartbeat_at = time.monotonic() + 900      # every tool: 15-min check-in
        engine_check_at = time.monotonic() + 10
        engine_fails: list[float] = []
        while not stop.is_set():
            self._beat = time.monotonic()
            try:
                for _ in range(10):
                    got = self.queue.drain(2000)
                    if not got:
                        break
                    for tool, line in got:
                        self.consume(tool, line)
                self.flush_outbox()
                self.flush_malformed()
                if self.scans is not None:
                    try:
                        self.scans.tick()
                    except Exception as e:
                        self.count_failure("scan", "tick", e)
                self.supervisor.check_all()
                now = time.monotonic()
                if now >= status_at:
                    snap = self.write_status()
                    status_at = now + unit_interval
                    if self.healer is not None:
                        try:
                            self.healer.tick(snap.get("tools") or {})
                        except Exception as e:
                            self.count_failure("heal", "tick", e)
                if now >= engine_check_at:
                    engine_check_at = now + 10
                    eng = getattr(self, "appfw_engine", None)
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
                                engine_fails.append(now_t)
                                try:
                                    self._appfw_event(
                                        f"appfw engine arm failed: {e}")
                                except Exception as e2:
                                    self.count_failure(
                                        "appfw", "arm-failure notice", e2)
                    elif not armed_now and eng is not None and eng.running:
                        self.stop_appfw()
                        print("greywatch appfw engine: stopped (switch off)")
                if now >= trim_at:
                    self.trim_events()
                    trim_at = now + trim_interval
                if now >= heartbeat_at:
                    self.heartbeat()
                    heartbeat_at = now + 900
            except Exception as e:
                self.count_failure("loop", "run_forever", e)
            stop.wait(0.5)
        self.stop_appfw()

    def _watchdog_ping_loop(self, stop) -> None:
        from appfw.sd_notify import notify
        while not stop.is_set():
            try:
                if time.monotonic() - self._beat < 8.0:
                    notify("WATCHDOG=1")
                else:
                    print("greywatch: main loop stale — watchdog NOT petted")
            except Exception as e:
                self.count_failure("watchdog", "ping loop", e)
            stop.wait(10.0)


def read_events(events_path, limit=None):
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


def recent_digest(events, cap=40):
    """Bounded tail of recent events, published inside status.json: the
    raw event store is root-owned (0600) and the user-run GUI cannot
    read it, so this digest rides on the status file — which is written
    0640 root:<UI user group> so the desktop session can read it but
    unrelated local accounts cannot."""
    return list(events[-cap:])


def appfw_enabled(data_dir=None) -> bool:
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
