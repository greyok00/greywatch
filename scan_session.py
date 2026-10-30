"""Scan sessions — the daemon owns every scan.

The GUI writes ``scan-request.json``; this module validates it, spawns the
scanners as root, parses their output into progress and findings, and writes
three files the GUI only ever reads:

  ``scan-live.json``       atomic rewrite, at most once a second
  ``scan-findings.jsonl``  append-only, one JSON object per finding
  ``scans/<id>.json``      finished summary, newest 20 kept

No GTK here. The service is ticked from the daemon's main loop; reading a
child never blocks. Only the six fixed keys can run — text from the request
file is never executed.

Empirically verified on this machine (2026-10-30): ``clamscan --stdout
--log=…`` streams one ``path: OK|FOUND`` line per file to stdout while the
log file receives only the summary, which is why the live counter is fed
from stdout and not from the log.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import time

SCAN_KEYS = ("scan-all", "yara-tmp-scan", "clamav", "rkhunter", "lynis",
             "aide")
SCAN_ALL = ("clamav", "rkhunter", "lynis", "aide", "yara-tmp-scan")
KEEP_SUMMARIES = 20
LIVE_INTERVAL_S = 1.0

SCANNERS = {
    "clamav": {"counter": "files scanned", "timeout_s": 6 * 3600},
    "rkhunter": {"counter": "checks completed", "timeout_s": 45 * 60},
    "lynis": {"counter": "tests completed", "timeout_s": 45 * 60},
    "aide": {"counter": "differences listed", "timeout_s": 45 * 60},
    "yara-tmp-scan": {"counter": "temp folders swept", "timeout_s": 10 * 60},
}

_ID_RE = re.compile(r"^\d{8}T\d{6}-[a-f0-9]{4}$")


def request_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "scan-request.json"


def live_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "scan-live.json"


def findings_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "scan-findings.jsonl"


def scans_dir(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "scans"


def validate_request(doc) -> tuple[str, str] | None:
    """(id, key) for a well-formed request; None for anything else."""
    if not isinstance(doc, dict):
        return None
    rid, key = doc.get("id"), doc.get("key")
    if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
        return None
    if key not in SCAN_KEYS:
        return None
    return rid, key


def commands_for(key, home, ui_user) -> list[list[str]]:
    """The exact argv for a key. Never built from request text."""
    home = str(home)
    table = {
        "clamav": ["/usr/bin/clamscan", "-r", "--stdout",
                   f"--log={home}/security-hardening/clam-scan.log",
                   home, "/tmp", "/var/tmp", "/etc", "/usr/local"],
        "rkhunter": ["/usr/bin/rkhunter", "--check", "--sk"],
        "lynis": ["/usr/sbin/lynis", "audit", "system", "--quick"],
        "aide": ["/usr/bin/aide", "--config=/etc/aide/aide-scoped.conf",
                 "--check"],
        "yara-tmp-scan": ["/usr/sbin/runuser", "-u", str(ui_user), "--",
                          "/bin/bash",
                          f"{home}/security-hardening/yara-tmp-scan.sh"],
    }
    if key == "scan-all":
        return [table[k] for k in SCAN_ALL]
    one = table.get(key)
    return [one] if one else []


# clamscan prints "path: OK", "path: Empty file", "path: Symbolic link" and,
# on a hit, "path: <Signature-Name> FOUND". The signature name is part of the
# verdict, so a plain (OK|FOUND) alternation missed every infected file.
_CLAM = re.compile(r"^(?P<path>.+?): (?P<verdict>OK|Empty file|"
                   r"Symbolic link|FOUND|.+? FOUND)$")
_RKH_CHECK = re.compile(r"^\[?[0-9:]{0,8}\]?\s*Checking\s+(?P<what>.*?)"
                        r"(?:\.\.\.|\s*\])?\s*$")
_RKH_WARN = re.compile(r"Warning:\s*(?P<what>.+)$")
_LYNIS_TEST = re.compile(r"^\s*Performing test\s+(?P<what>.*)$")
_LYNIS_WARN = re.compile(r"^\s*Warning\s*[:\[]\s*(?P<what>.+?)\s*\]?\s*$")
_YARA = re.compile(r"^(?P<rule>[A-Za-z0-9_:+.-]{2,64})\s+(?P<path>/\S.*)$")
_AIDE_DIFF = re.compile(r"^[dfmn][+\-]{6,}\s*:|^[dfmn]{9}\s|"
                         r"^(?:added|removed|changed):\s")

_BLANK = {"counted": False, "current": "", "finding": None}


def parse_progress(tool: str, line: str):
    """One scanner stdout line -> counter/current/finding. None when blank.

    Returns ``{"counted": bool, "current": str, "finding": dict | None}``
    where finding is ``{"severity": str, "text": str}``.
    """
    text = line.rstrip("\n")
    if not text.strip():
        return None
    if tool == "clamav":
        m = _CLAM.match(text)
        if not m:
            return dict(_BLANK)
        path, verdict = m.group("path"), m.group("verdict")
        finding = None
        if verdict.endswith("FOUND"):
            sig = verdict[:-len("FOUND")].strip()
            finding = {"severity": "HIGH",
                       "text": f"Infected file: {path}"
                               + (f" ({sig})" if sig else "")}
        return {"counted": True, "current": path, "finding": finding}
    if tool == "rkhunter":
        m = _RKH_CHECK.match(text)
        if m and not _RKH_WARN.search(text):
            return {"counted": True, "current": m.group("what"),
                    "finding": None}
        m = _RKH_WARN.search(text)
        if m:
            return {"counted": False, "current": "",
                    "finding": {"severity": "HIGH",
                                "text": "Warning: " + m.group("what").strip()}}
        return dict(_BLANK)
    if tool == "lynis":
        m = _LYNIS_TEST.match(text)
        if m:
            return {"counted": True, "current": m.group("what").strip(),
                    "finding": None}
        if _LYNIS_WARN.match(text):
            return {"counted": False, "current": "",
                    "finding": {"severity": "MEDIUM",
                                "text": text.strip()[:300]}}
        return dict(_BLANK)
    if tool == "aide":
        stripped = text.strip()
        if _AIDE_DIFF.match(stripped):
            return {"counted": True, "current": stripped[:120],
                    "finding": {"severity": "HIGH", "text": stripped[:300]}}
        return dict(_BLANK)
    if tool == "yara-tmp-scan":
        stripped = text.strip()
        if _YARA.match(stripped):
            return {"counted": True, "current": stripped[:120],
                    "finding": {"severity": "HIGH",
                                "text": stripped[:300]}}
        return dict(_BLANK)
    return dict(_BLANK)


# Hidden files under these roots are normal package-manager debris, not
# evidence of compromise. Everything else stays real.
_ROUTINE_ROOTS = ("/etc/", "/dev/", "/proc/", "/sys/", "/var/cache/",
                  "/usr/share/man/", "/usr/lib/", "/run/")


def is_routine(tool: str, text: str) -> bool:
    """Presentation-only fold. Everything is still recorded; unknown = real."""
    low = (text or "").strip().lower()
    if tool == "rkhunter":
        if "hidden file" in low or "hidden directory" in low:
            return any(root in low for root in _ROUTINE_ROOTS)
        if "man page" in low and "symlink" in low:
            return True
        return False
    if tool == "lynis":
        return "suggestion" in low or "hardening index" in low
    if tool == "aide":
        return "/var/cache" in low or "/var/tmp" in low or "/tmp/" in low
    if tool == "yara-tmp-scan":
        return "test-fixture" in low
    return False


def exit_verdict(tool: str, rc: int) -> tuple[str, str]:
    """(state, detail). State is "done" or "failed"."""
    if tool == "clamav":
        return ("done", "") if rc in (0, 1) else \
            ("failed", f"clamscan exited {rc}")
    if tool == "rkhunter":
        return ("done", "") if rc in (0, 1) else \
            ("failed", f"rkhunter exited {rc}")
    if tool == "lynis":
        return ("done", "") if rc == 0 else ("failed", f"lynis exited {rc}")
    if tool == "aide":
        return ("done", "") if 0 <= rc <= 7 else \
            ("failed", f"aide exited {rc}")
    if tool == "yara-tmp-scan":
        return ("done", "") if rc == 0 else \
            ("failed", f"the temp scan exited {rc}")
    return ("failed", f"scan exited {rc}")


def event_line(tool: str, line: str, when: _dt.datetime) -> str:
    """Give raw stdout the shape the existing log parsers already accept."""
    stripped = line.strip()
    if tool == "rkhunter" and _RKH_WARN.search(stripped) \
            and not stripped.startswith("["):
        return f"[{when.strftime('%H:%M:%S')}] {stripped}"
    if tool == "lynis" and _LYNIS_WARN.match(stripped) \
            and not re.match(r"^\d{4}-\d{2}-\d{2} ", stripped):
        return f"{when.strftime('%Y-%m-%d %H:%M:%S')} {stripped}"
    if tool == "aide" and _AIDE_DIFF.match(stripped) \
            and "differences found" not in stripped.lower():
        return f"differences found: {stripped}"
    return line


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- service

class ProcessHandle:
    """A scanner child with a non-blocking stdout reader."""

    def __init__(self, argv):
        self.argv = list(argv)
        self.proc = subprocess.Popen(
            self.argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=0, close_fds=True)
        self.path = self.argv[0]
        os.set_blocking(self.proc.stdout.fileno(), False)
        self._buf = b""
        self._last = ""

    def lines(self) -> list[str]:
        while True:
            try:
                chunk = self.proc.stdout.read(65536)
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            self._buf += chunk
        out = []
        while b"\n" in self._buf:
            raw, self._buf = self._buf.split(b"\n", 1)
            out.append(raw.decode("utf-8", "replace").rstrip("\r"))
        if out:
            self._last = out[-1]
        return out

    def poll(self):
        return self.proc.poll()

    def terminate(self):
        try:
            self.proc.terminate()
        except OSError:
            pass


def subprocess_spawner(argv):
    return ProcessHandle(argv)


class ScanService:
    """Owns at most one scan session. Ticked from the daemon's main loop."""

    def __init__(self, data_dir, *, consume=None, gid=None, ui_user="grey",
                 home=None, spawn=subprocess_spawner, clock=time.monotonic,
                 log=None):
        self.dir = pathlib.Path(data_dir)
        self.consume = consume
        self.gid = gid
        self.ui_user = ui_user
        self.home = home or os.path.expanduser("~" + ui_user)
        self.spawn = spawn
        self.clock = clock
        self.log = log or (lambda _m: None)
        self.session = None            # dict while running
        self.children = {}             # tool -> runtime state
        self.last_live = None
        self._pause = lambda _t: None
        self._resume = lambda _t: None
        self._finding_rows = []
        self._last_write = -1e9
        self._aid_noted = False
        self._missing = set()

    # ---- hooks -----------------------------------------------------
    def set_tailer_hooks(self, pause, resume):
        self._pause = pause
        self._resume = resume

    def running(self) -> bool:
        return self.session is not None

    # ---- request channel -------------------------------------------
    def _take_request(self):
        path = request_path(self.dir)
        try:
            raw = path.read_text()
        except OSError:
            return None
        try:
            path.unlink()
        except OSError:
            pass
        try:
            doc = json.loads(raw)
        except ValueError:
            self.log("rejected a request that was not JSON")
            return None
        got = validate_request(doc)
        if got is None:
            self.log("rejected a request with an unknown key or bad id")
        return got

    # ---- lifecycle -------------------------------------------------
    def tick(self):
        got = self._take_request()
        if got is not None:
            if self.session is not None:
                self.session["note"] = "a scan is already running"
                self._write_live(force=True)
            else:
                self.start(*got)
        if self.session is None:
            return
        for key in list(self.children):
            self._drain(key)
        self._check_timeouts()
        if all(c["state"] not in ("queued", "running")
               for c in self.children.values()):
            self._finish_session()
        else:
            self._write_live()

    def start(self, scan_id: str, key: str):
        keys = list(SCAN_ALL) if key == "scan-all" else [key]
        self.children = {}
        self._finding_rows = []
        self._aid_noted = False
        started = []
        for k in keys:
            child = {"state": "queued", "count": 0, "current": "",
                     "findings": 0, "detail": "", "started_at": _now_iso(),
                     "ended_at": None, "exit_code": None, "handle": None,
                     "started": self.clock(), "last_line": ""}
            self.children[k] = child
            argv = (commands_for(k, self.home, self.ui_user) or [None])[0]
            if argv is None or k in self._missing or not shutil.which(
                    argv[0]):
                child.update(state="failed", detail="not installed",
                             ended_at=_now_iso())
                continue
            try:
                child["handle"] = self.spawn(argv)
            except (OSError, ValueError) as e:
                child.update(state="failed", ended_at=_now_iso(),
                             detail=f"could not start: {type(e).__name__}")
                continue
            self._pause(k)
            child["state"] = "running"
            started.append(k)
        self.session = {"scan_id": scan_id, "key": key, "state": "running",
                        "started_at": _now_iso(), "ended_at": None,
                        "note": ""}
        if started:
            self._write_live(force=True)
        else:
            self._finish_session()

    # ---- parsing ----------------------------------------------------
    def _drain(self, key: str):
        child = self.children[key]
        handle = child.get("handle")
        if handle is None or child["state"] != "running":
            return
        # Local time with an offset: the finding row sorts with its
        # neighbours and the clock matches what the scanner printed.
        when = _dt.datetime.now().astimezone()
        for line in handle.lines():
            child["last_line"] = line.strip()[:200]
            prog = parse_progress(key, line)
            self._consume_event(key, line, when)
            if prog is None:
                continue
            if prog["counted"]:
                child["count"] += 1
            if prog["current"]:
                child["current"] = prog["current"][:160]
            if prog["finding"]:
                self._record_finding(key, prog["finding"], when)
        rc = handle.poll()
        if rc is not None:
            state, detail = exit_verdict(key, rc)
            if state == "failed" and not detail:
                detail = "scan failed"
            if state == "failed" and child["last_line"]:
                detail = f"{detail}: {child['last_line']}"
            child.update(state=state, detail=detail, exit_code=rc,
                         ended_at=_now_iso(), current="")
            handle.terminate()
            self._resume(key)

    def _consume_event(self, key: str, line: str, when):
        if self.consume is None:
            return
        if key == "aide":
            first = parse_progress("aide", line)
            if not first or first["finding"] is None:
                return
            if self._aid_noted:
                return
            self._aid_noted = True
        try:
            self.consume(key, event_line(key, line, when))
        except Exception as e:      # a scanner must never kill the daemon
            self.log(f"consume failed for {key}: {type(e).__name__}")

    def _record_finding(self, key: str, finding: dict, when):
        routine = is_routine(key, finding["text"])
        self.children[key]["findings"] += 1
        row = {"scan_id": (self.session or {}).get("scan_id"), "tool": key,
               "ts": when.isoformat(timespec="seconds"),
               "severity": finding["severity"], "text": finding["text"][:400],
               "routine": routine}
        self._finding_rows.append(row)
        try:
            import status
            status.append_checked(str(findings_path(self.dir)),
                                  json.dumps(row, separators=(",", ":"))
                                  + "\n", create_mode=0o640, gid=self.gid)
        except (OSError, ValueError) as e:
            self.log(f"could not append a finding: {type(e).__name__}")

    # ---- completion -------------------------------------------------
    def _check_timeouts(self):
        now = self.clock()
        for key, child in self.children.items():
            if child["state"] != "running":
                continue
            limit = SCANNERS.get(key, {"timeout_s": 3600})["timeout_s"]
            if now - child["started"] > limit:
                child["handle"].terminate()
                child.update(state="failed", ended_at=_now_iso(), current="",
                             detail=f"timed out after {limit // 60} minutes")
                self._resume(key)

    def _finish_session(self):
        states = [c["state"] for c in self.children.values()]
        state = "done" if any(s == "done" for s in states) else "failed"
        self.session.update(state=state, ended_at=_now_iso())
        self._write_live(force=True)
        self._write_summary(state)
        self.session = None
        self.children = {}
        self._keep_recent()

    # ---- writers ----------------------------------------------------
    def _document(self) -> dict:
        s = self.session or {}
        scanners = {}
        for key, c in self.children.items():
            duration = None
            if c.get("started") is not None and self.session is not None:
                duration = round(self.clock() - c["started"], 1)
            current = c["current"]
            if key == "aide" and c["state"] == "running" and not current:
                current = "comparing the file database (reports at the end)"
            scanners[key] = {
                "state": c["state"],
                "counter_label": SCANNERS.get(key, {}).get("counter", "checks"),
                "count": c["count"], "current": current,
                "findings": c["findings"], "started_at": c["started_at"],
                "ended_at": c["ended_at"], "detail": c["detail"],
                "exit_code": c.get("exit_code"), "duration_s": duration}
        real = sum(1 for r in self._finding_rows if not r["routine"])
        routine = sum(1 for r in self._finding_rows if r["routine"])
        return {"scan_id": s.get("scan_id"), "key": s.get("key"),
                "state": s.get("state", "done"),
                "started_at": s.get("started_at"),
                "ended_at": s.get("ended_at"), "note": s.get("note", ""),
                "scanners": scanners, "real_findings": real,
                "routine_findings": routine}

    def _write_live(self, force=False):
        doc = self._document()
        self.last_live = doc
        now = self.clock()
        if not force and now - self._last_write < LIVE_INTERVAL_S:
            return
        self._last_write = now
        try:
            import status
            status.atomic_replace(str(live_path(self.dir)),
                                  json.dumps(doc), gid=self.gid)
        except (OSError, ValueError) as e:
            self.log(f"could not write scan-live.json: {type(e).__name__}")

    def _write_summary(self, state: str):
        doc = self._document()
        doc["state"] = state
        target = scans_dir(self.dir) / f"{doc['scan_id']}.json"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            import status
            status.atomic_replace(str(target), json.dumps(doc),
                                  gid=self.gid)
        except (OSError, ValueError) as e:
            self.log(f"could not write the scan summary: {type(e).__name__}")

    def _keep_recent(self):
        d = scans_dir(self.dir)
        try:
            files = sorted(d.glob("*.json"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            return
        for old in files[KEEP_SUMMARIES:]:
            try:
                old.unlink()
            except OSError:
                pass
        keep = {p.stem for p in files[:KEEP_SUMMARIES]}
        try:
            lines = findings_path(self.dir).read_text(
                errors="replace").splitlines()
        except OSError:
            return
        kept = []
        for ln in lines:
            try:
                if json.loads(ln).get("scan_id") in keep:
                    kept.append(ln)
            except ValueError:
                continue
        if len(kept) == len(lines):
            return
        try:
            import status
            status.atomic_replace(str(findings_path(self.dir)),
                                  "".join(l + "\n" for l in kept),
                                  gid=self.gid)
        except (OSError, ValueError):
            pass

    def recover_interrupted(self):
        try:
            live = json.loads(live_path(self.dir).read_text())
        except (OSError, ValueError):
            return
        if live.get("state") != "running":
            return
        live["state"] = "interrupted"
        live["ended_at"] = _now_iso()
        live["note"] = "the daemon restarted while this scan was running"
        for sc in (live.get("scanners") or {}).values():
            if sc.get("state") in ("queued", "running"):
                sc["state"] = "interrupted"
                sc["detail"] = "the daemon restarted"
        try:
            import status
            status.atomic_replace(str(live_path(self.dir)),
                                  json.dumps(live), gid=self.gid)
        except (OSError, ValueError):
            pass
