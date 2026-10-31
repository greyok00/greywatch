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
import signal
import subprocess
import time

SCAN_KEYS = ("scan-all", "yara-tmp-scan", "clamav", "rkhunter", "lynis",
             "aide")
SCAN_ALL = ("clamav", "rkhunter", "lynis", "aide", "yara-tmp-scan")
KEEP_SUMMARIES = 20
LIVE_INTERVAL_S = 1.0

SCANNER_NAMES = {"clamav": "Antivirus", "rkhunter": "Rootkit scan",
                 "lynis": "Security audit", "aide": "File integrity",
                 "yara-tmp-scan": "Quick scan"}

SCANNERS = {
    "clamav": {"counter": "files scanned", "timeout_s": 6 * 3600},
    "rkhunter": {"counter": "checks completed", "timeout_s": 45 * 60},
    "lynis": {"counter": "tests completed", "timeout_s": 45 * 60},
    "aide": {"counter": "differences listed", "timeout_s": 45 * 60},
    "yara-tmp-scan": {"counter": "temp folders swept", "timeout_s": 10 * 60},
}

_ID_RE = re.compile(r"^\d{8}T\d{6}-[a-f0-9]{4}$")

# Every scanner writes its own log file and a tiny shell wrapper appends this
# marker when the process exits. A restarted daemon can then tell "still
# running" from "finished with rc" without owning the pipe, which is what
# used to make every scan die with the service.
_END_RE = re.compile(r"^@@END rc=(-?\d+)\s*$")
_WRAP = '"$@" 2>&1; rc=$?; printf "\\n@@END rc=%s\\n" "$rc"'
# A scan that loses its process without a marker is reported, never guessed.
_LOST_RC = 137


def scan_log_dir(data_dir, scan_id) -> pathlib.Path:
    return pathlib.Path(data_dir) / "scan-logs" / str(scan_id)


def scan_log_path(data_dir, scan_id, tool) -> pathlib.Path:
    return scan_log_dir(data_dir, scan_id) / f"{tool}.log"


def unit_name(scan_id, tool) -> str:
    """The transient unit that keeps one scanner outside the daemon's cgroup."""
    return f"gw-scan-{scan_id}-{tool}"


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


APPLY_DIR = pathlib.Path(__file__).resolve().parent / "apply"


def commands_for(key, home, ui_user) -> list[list[str]]:
    """The exact argv for a key. Never built from request text."""
    home = str(home)
    # The temp sweep ships with the app: the old user-side script printed
    # only hits, so "folders swept" stayed at 0 and the scan looked instant.
    # A shipped copy can report its own progress; the user script stays a
    # fallback for installs that predate this file.
    yara_script = APPLY_DIR / "yara-tmp-scan.sh"
    if yara_script.is_file():
        yara = ["/usr/sbin/runuser", "-u", str(ui_user), "--", "/bin/bash",
                str(yara_script),
                f"{home}/security-hardening/yara-rules/index.yar",
                "/tmp", "/var/tmp", f"{home}/Downloads"]
    else:
        yara = ["/usr/sbin/runuser", "-u", str(ui_user), "--", "/bin/bash",
                f"{home}/security-hardening/yara-tmp-scan.sh"]
    table = {
        "clamav": ["/usr/bin/clamscan", "-r", "--stdout",
                   f"--log={home}/security-hardening/clam-scan.log",
                   home, "/tmp", "/var/tmp", "/etc", "/usr/local"],
        "rkhunter": ["/usr/bin/rkhunter", "--check", "--sk"],
        "lynis": ["/usr/sbin/lynis", "audit", "system", "--quick"],
        "aide": ["/usr/bin/aide", "--config=/etc/aide/aide-scoped.conf",
                 "--check"],
        "yara-tmp-scan": yara,
    }
    if key == "scan-all":
        return [table[k] for k in SCAN_ALL]
    one = table.get(key)
    return [one] if one else []


# These three write their progress in blocks when stdout is a file or pipe,
# so a live counter sat at 0 for minutes. `stdbuf -oL` forces one line at a
# time. ClamAV is added too: its per-file lines are the live counter.
_BUFFERED = ("clamav", "rkhunter", "lynis", "aide")


def line_buffered(tool: str, argv: list[str]) -> list[str]:
    if tool not in _BUFFERED or not shutil.which("/usr/bin/stdbuf"):
        return list(argv)
    return ["/usr/bin/stdbuf", "-oL", "-eL"] + list(argv)


# clamscan prints "path: OK", "path: Empty file", "path: Symbolic link" and,
# on a hit, "path: <Signature-Name> FOUND". The signature name is part of the
# verdict, so a plain (OK|FOUND) alternation missed every infected file.
_CLAM = re.compile(r"^(?P<path>.+?): (?P<verdict>OK|Empty file|"
                   r"Symbolic link|FOUND|.+? FOUND)$")
_RKH_CHECK = re.compile(r"^\[?[0-9:]{0,8}\]?\s*Checking\s+(?P<what>.*?)"
                        r"(?:\.\.\.|\s*\])?\s*$")
_RKH_WARN = re.compile(r"Warning:\s*(?P<what>.+)$")
# rkhunter closes with this summary whenever anything failed a check, and
# some of those failures never print a "Warning:" line the parser can read.
# Without it a finished scan was described as "clean" over a log that said
# warnings were found (owner, 2026-10-31).
_RKH_SUMMARY = re.compile(r"warnings? (?:have|has) been found", re.I)
_LYNIS_TEST = re.compile(r"^\s*Performing test\s+(?P<what>.*)$")
_LYNIS_WARN = re.compile(r"^\s*Warning\s*[:\[]\s*(?P<what>.+?)\s*\]?\s*$")
_YARA = re.compile(r"^(?P<rule>[A-Za-z0-9_:+.-]{2,64})\s+(?P<path>/\S.*)$")
# The shipped temp sweep reports how much of the tree it has walked, so the
# counter moves while YARA is still reading files.
_YARA_DIRS = re.compile(r"^@@DIRS\s+(?P<n>\d+)(?:\s+(?P<path>\S.*))?$")
# AIDE prints the change string, then the path: `f+++++++++ : /path` for an
# entry the database does not know, `f..H...... : /path` for a known file
# whose attributes or content moved. The string mixes '+', '-' and '.'
# with letters, so the old '+'/'-'-only pattern never matched a real change.
_AIDE_DIFF = re.compile(r"^[dfmn][+\-.A-Za-z]{6,}\s*:|^[dfmn]{9}\s|"
                         r"^(?:added|removed|changed):\s")
# All-plus is "not in the baseline, present now"; all-minus is "in the
# baseline, gone now". Either way the database predates the file, which is
# drift to refresh, not an edit to a file the check knows.
_AIDE_ADDED = re.compile(r"^[fdmn]\+{3,}\s*:")
_AIDE_REMOVED = re.compile(r"^[fdmn]-{3,}\s*:")

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
        if _RKH_SUMMARY.search(text):
            # A flag, not a finding: the individual warnings are recorded
            # above, and counting the summary too would double them.
            return {"counted": False, "current": "", "finding": None,
                    "warned": True}
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
        if not _AIDE_DIFF.match(stripped):
            return dict(_BLANK)
        # A change string of nothing but '+' means the file is there now and
        # was not in the database; all '-' means it is gone. That is baseline
        # drift, and a stale database reports it for every file installed
        # after it was built (owner saw 128 rows of it on 2026-10-30 and read
        # them as errors). A real change carries a letter flag (`f..H......`,
        # content or attributes moved), and only that is an integrity
        # finding. The reader gets a sentence, not AIDE's change string.
        added = bool(_AIDE_ADDED.match(stripped)) or \
            stripped.startswith("added:")
        removed = bool(_AIDE_REMOVED.match(stripped)) or \
            stripped.startswith("removed:")
        path = stripped.split(":", 1)[1].strip() if ":" in stripped \
            else stripped
        if added:
            return {"counted": True, "current": stripped[:120],
                    "finding": {"severity": "LOW", "routine": True,
                                "text": f"New since the file-integrity "
                                        f"baseline: {path}"[:300]}}
        if removed:
            return {"counted": True, "current": stripped[:120],
                    "finding": {"severity": "LOW", "routine": True,
                                "text": f"Gone since the file-integrity "
                                        f"baseline: {path}"[:300]}}
        return {"counted": True, "current": stripped[:120],
                "finding": {"severity": "HIGH",
                            "text": f"Changed since the file-integrity "
                                    f"baseline: {path}"[:300]}}
    if tool == "yara-tmp-scan":
        stripped = text.strip()
        m = _YARA_DIRS.match(stripped)
        if m:
            n = int(m.group("n"))
            return {"counted": False, "count": n,
                    "current": (m.group("path") or "")[:160],
                    "finding": None}
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
        if "/var/cache" in low or "/var/tmp" in low or "/tmp/" in low:
            return True
        # Baseline drift, wherever the file lives: an entry the database
        # does not know is a refresh task, not an intrusion. The row is
        # still recorded, and the expander still counts it.
        return bool(_AIDE_ADDED.match(low) or _AIDE_REMOVED.match(low)
                    or low.startswith("added:") or low.startswith("removed:"))
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

def systemd_available() -> bool:
    return (os.path.isdir("/run/systemd/system") and os.geteuid() == 0
            and shutil.which("systemd-run") is not None)


class DetachedHandle:
    """One scanner whose lifetime is independent of the daemon.

    Output goes to a log file in the state directory; a shell wrapper
    appends ``@@END rc=N`` when the scanner exits. The daemon only ever
    tails the file, so a service restart no longer kills a running scan.

    When systemd is available the scanner also runs as a transient unit
    (``systemd-run``), which puts it in its own cgroup — otherwise
    ``systemctl restart greywatch`` would still SIGTERM the whole tree.
    """

    def __init__(self, argv, log_path, *, unit=None, runtime_max=None,
                 start_offset=0, attach_only=False):
        self.argv = list(argv)
        self.log_path = pathlib.Path(log_path)
        self.unit = unit
        self.lost = False
        self._rc = None
        self._offset = int(start_offset or 0)
        self._partial = b""
        self.proc = None
        if attach_only:
            return
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        if unit and self._start_unit(unit, runtime_max):
            return
        self.proc = self._start_popen()

    # ---- start ------------------------------------------------------
    def _start_unit(self, unit, runtime_max) -> bool:
        argv = ["/usr/bin/systemd-run", f"--unit={unit}", "--collect",
                "--quiet"]
        if runtime_max:
            argv.append(f"--property=RuntimeMaxSec={int(runtime_max)}")
        argv += [
            f"--property=StandardOutput=append:{self.log_path}",
            f"--property=StandardError=append:{self.log_path}",
            "/bin/sh", "-c", _WRAP, "sh", *self.argv]
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=15)
        except (OSError, subprocess.SubprocessError):
            self.unit = None
            return False
        if done.returncode != 0:
            self.unit = None
            return False
        return True

    def _start_popen(self):
        try:
            fh = open(self.log_path, "ab", buffering=0)
        except OSError:
            fh = subprocess.DEVNULL
        try:
            return subprocess.Popen(
                ["/bin/sh", "-c", _WRAP, "sh", *self.argv],
                stdout=fh, stderr=subprocess.STDOUT, start_new_session=True,
                close_fds=True)
        finally:
            if fh is not subprocess.DEVNULL:
                fh.close()

    # ---- reading ----------------------------------------------------
    def lines(self) -> list[str]:
        try:
            with open(self.log_path, "rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
        except OSError:
            return []
        if not chunk:
            return []
        self._offset += len(chunk)
        buf = self._partial + chunk
        parts = buf.split(b"\n")
        self._partial = parts.pop()
        out = []
        for raw in parts:
            text = raw.decode("utf-8", "replace").rstrip("\r")
            m = _END_RE.match(text.strip())
            if m is not None:
                self._rc = int(m.group(1))
                continue
            out.append(text)
        return out

    def poll(self):
        if self._rc is not None:
            return self._rc
        if self.proc is not None:
            return self.proc.poll()
        if self.unit:
            try:
                state = subprocess.run(
                    ["/usr/bin/systemctl", "is-active", "--quiet", self.unit],
                    capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                return None
            if state.returncode != 0:
                if self._rc is not None:
                    return self._rc
                self.lost = True
                return _LOST_RC
        return None

    def terminate(self):
        if self.unit:
            try:
                subprocess.run(["/usr/bin/systemctl", "stop", self.unit],
                               capture_output=True, timeout=20)
            except (OSError, subprocess.SubprocessError):
                pass
        if self.proc is not None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                try:
                    self.proc.terminate()
                except OSError:
                    pass


def subprocess_spawner(argv, log_path=None, *, unit=None, runtime_max=None,
                       attach_only=False, start_offset=0):
    return DetachedHandle(argv, log_path, unit=unit, runtime_max=runtime_max,
                          attach_only=attach_only,
                          start_offset=start_offset)


def _absolute_home(home, ui_user):
    """A real scan root, never a literal "~name".

    ``os.path.expanduser`` leaves the tilde in place when the account does
    not exist here, and scanners were then asked to scan a directory named
    ``~grey`` relative to the daemon's working directory.
    """
    for candidate in (home, "~" + ui_user if ui_user else None, "~"):
        if not candidate:
            continue
        got = os.path.expanduser(candidate)
        if os.path.isabs(got):
            return got
    return "/"


class ScanService:
    """Owns at most one scan session. Ticked from the daemon's main loop."""

    def __init__(self, data_dir, *, consume=None, gid=None, ui_user="grey",
                 home=None, spawn=subprocess_spawner, clock=time.monotonic,
                 log=None, use_systemd=None, which=shutil.which):
        self.dir = pathlib.Path(data_dir)
        self.consume = consume
        self.gid = gid
        self.ui_user = ui_user
        # ``~user`` only expands for an account this machine has; a daemon
        # told about a user that is not here (a container, CI) would hand
        # the scanners a literal "~grey" as a scan root.
        self.home = _absolute_home(home, ui_user)
        self.spawn = spawn
        self.which = which
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
        self._order = list(SCAN_ALL)
        self._systemd = systemd_available() if use_systemd is None \
            else bool(use_systemd)

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
        # One scanner at a time. Each finish starts the next in order, so the
        # page can say exactly which one is waiting on which.
        self._advance()
        if self.session is None:
            return
        if all(c["state"] not in ("queued", "running")
               for c in self.children.values()):
            self._finish_session()
        else:
            self._write_live()

    def start(self, scan_id: str, key: str):
        keys = list(SCAN_ALL) if key == "scan-all" else [key]
        self._order = keys
        self.children = {}
        self._finding_rows = []
        self._aid_noted = False
        for k in keys:
            self.children[k] = {
                "state": "queued", "count": 0, "current": "",
                "findings": 0, "warned": False, "detail": "",
                "started_at": None,
                "ended_at": None, "exit_code": None, "handle": None,
                "started": self.clock(), "last_line": "", "log": [],
                "log_offset": 0, "unit": None}
        self.session = {"scan_id": scan_id, "key": key, "state": "running",
                        "started_at": _now_iso(), "ended_at": None,
                        "note": ""}
        self._advance()
        if self.session is None:            # nothing could start
            return
        self._write_live(force=True)

    def _advance(self):
        """Start the next queued scanner, or finish when none remain."""
        if self.session is None:
            return
        if any(c["state"] == "running" for c in self.children.values()):
            return
        for k in self._order:
            child = self.children.get(k)
            if child is None or child["state"] != "queued":
                continue
            if self._launch(k):
                return
        if all(c["state"] not in ("queued", "running")
               for c in self.children.values()):
            self._finish_session()

    def _launch(self, key: str) -> bool:
        child = self.children[key]
        argv = (commands_for(key, self.home, self.ui_user) or [None])[0]
        if argv is None or key in self._missing or not self.which(argv[0]):
            child.update(state="failed", detail="not installed",
                         ended_at=_now_iso())
            return False
        argv = line_buffered(key, argv)
        scan_id = (self.session or {}).get("scan_id") or "scan"
        log = scan_log_path(self.dir, scan_id, key)
        unit = unit_name(scan_id, key) if self._systemd else None
        limit = SCANNERS.get(key, {"timeout_s": 3600})["timeout_s"]
        try:
            child["handle"] = self.spawn(
                argv, log, unit=unit, runtime_max=limit)
        except (OSError, ValueError) as e:
            child.update(state="failed", ended_at=_now_iso(),
                         detail=f"could not start: {type(e).__name__}")
            return False
        child.update(state="running", started=self.clock(),
                     started_at=_now_iso(), unit=unit)
        self._pause(key)
        return True

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
            stripped = line.strip()
            if stripped:
                child["last_line"] = stripped[:200]
                child["log"] = (child["log"] + [stripped[:200]])[-4:]
            prog = parse_progress(key, line)
            self._consume_event(key, line, when)
            if prog is None:
                continue
            if prog["counted"]:
                child["count"] += 1
            if prog.get("count") is not None:
                # Absolute counters (the temp sweep reports its own total)
                # replace the tally instead of adding to it.
                child["count"] = int(prog["count"])
            if prog["current"]:
                child["current"] = prog["current"][:160]
            if prog["finding"]:
                self._record_finding(key, prog["finding"], when)
            if prog.get("warned"):
                child["warned"] = True
        child["log_offset"] = getattr(handle, "_offset", child["log_offset"])
        rc = handle.poll()
        if rc is not None:
            state, detail = exit_verdict(key, rc)
            if getattr(handle, "lost", False):
                state = "failed"
                detail = ("the scan stopped without reporting a result; "
                          "its log is kept under scan-logs")
            if state == "failed" and not detail:
                detail = "scan failed"
            if state == "failed" and child["last_line"] \
                    and "stopped without" not in detail:
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
        # A parser that already knows the row is drift says so, because its
        # text is a rewritten sentence and the classifier works on the raw
        # line. Everything else still goes through the shared rules.
        routine = finding.get("routine")
        if routine is None:
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
        running = next((k for k, c in self.children.items()
                        if c["state"] == "running"), None)
        scanners = {}
        for i, (key, c) in enumerate(self.children.items(), start=1):
            duration = None
            if c["state"] != "queued" and c.get("started") is not None \
                    and self.session is not None:
                duration = round(self.clock() - c["started"], 1)
            current = c["current"]
            if key == "aide" and c["state"] == "running" and not current:
                current = "comparing the file database (reports at the end)"
            waiting = ""
            if c["state"] == "queued" and running:
                waiting = SCANNER_NAMES.get(running, running)
            scanners[key] = {
                "state": c["state"], "order": i,
                "counter_label": SCANNERS.get(key, {}).get("counter", "checks"),
                "count": c["count"], "current": current,
                "waiting_for": waiting,
                "findings": c["findings"], "warned": bool(c.get("warned")),
                "started_at": c["started_at"],
                "ended_at": c["ended_at"], "detail": c["detail"],
                "exit_code": c.get("exit_code"), "duration_s": duration,
                "log": list(c.get("log") or [])[-4:],
                "log_offset": int(c.get("log_offset") or 0),
                "unit": c.get("unit")}
        real = sum(1 for r in self._finding_rows if not r["routine"])
        routine = sum(1 for r in self._finding_rows if r["routine"])
        return {"scan_id": s.get("scan_id"), "key": s.get("key"),
                "state": s.get("state", "done"),
                "started_at": s.get("started_at"),
                "ended_at": s.get("ended_at"), "note": s.get("note", ""),
                "scanners": scanners, "real_findings": real,
                "routine_findings": routine,
                "sequence": list(self._order)}

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
        active = (self.session or {}).get("scan_id")
        logs_root = pathlib.Path(self.dir) / "scan-logs"
        try:
            dirs = [d for d in logs_root.iterdir() if d.is_dir()]
        except OSError:
            dirs = []
        for d in dirs:
            if d.name in keep or d.name == active:
                continue
            shutil.rmtree(d, ignore_errors=True)
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
        """Pick a running scan back up instead of declaring it dead.

        The daemon used to mark every in-flight scan "interrupted" on start,
        which is what the owner saw as the service killing scans. Scanners
        now run as transient units and write their own logs, so a restart
        only loses the reader: this rebuilds it and carries on where the
        queue stopped.
        """
        try:
            live = json.loads(live_path(self.dir).read_text())
        except (OSError, ValueError):
            return
        if live.get("state") != "running":
            return
        scan_id = live.get("scan_id")
        if not isinstance(scan_id, str) or not _ID_RE.fullmatch(scan_id):
            self._mark_interrupted(live, "the scan file had no usable id")
            return
        scanners = live.get("scanners") or {}
        self.children = {}
        self._finding_rows = []
        self._aid_noted = False
        order = [k for k in (live.get("sequence") or [])
                 if k in scanners] or list(scanners)
        self._order = order
        attached = 0
        for key in order:
            sc = scanners.get(key) or {}
            state = sc.get("state") or "queued"
            child = {
                "state": state if state in ("queued", "running", "done",
                                            "failed") else "queued",
                "count": int(sc.get("count") or 0),
                "current": sc.get("current") or "",
                "findings": int(sc.get("findings") or 0),
                "detail": sc.get("detail") or "",
                "started_at": sc.get("started_at"),
                "ended_at": sc.get("ended_at"),
                "exit_code": sc.get("exit_code"),
                "handle": None, "last_line": "", "log": list(sc.get("log")
                                                              or []),
                "log_offset": int(sc.get("log_offset") or 0),
                "unit": sc.get("unit"),
                "started": self.clock() - float(sc.get("duration_s") or 0.0)}
            self.children[key] = child
            if child["state"] != "running":
                continue
            unit = sc.get("unit")
            if not unit:
                # A process started without a transient unit dies with the
                # service cgroup; there is nothing left to follow.
                child.update(state="failed", ended_at=_now_iso(),
                             detail="the daemon restarted and this scanner "
                                    "had no unit of its own")
                continue
            log = scan_log_path(self.dir, scan_id, key)
            try:
                child["handle"] = self.spawn(
                    [], log, unit=unit, attach_only=True,
                    start_offset=child["log_offset"])
            except (OSError, ValueError) as e:
                child.update(state="failed", ended_at=_now_iso(),
                             detail=f"could not re-attach: "
                                    f"{type(e).__name__}")
                continue
            attached += 1
            self._pause(key)
        self.session = {"scan_id": scan_id, "key": live.get("key"),
                        "state": "running",
                        "started_at": live.get("started_at"),
                        "ended_at": None,
                        "note": "the service restarted; the scan kept running"}
        self._load_findings(scan_id)
        self._write_live(force=True)
        # _advance either starts the next queued scanner or finishes the
        # session, and _finish_session writes the final live document. A
        # write after it would print "done" over the real state.
        self._advance()

    def _load_findings(self, scan_id):
        try:
            lines = findings_path(self.dir).read_text(
                errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("scan_id") == scan_id:
                self._finding_rows.append(row)

    def _mark_interrupted(self, live, why):
        live["state"] = "interrupted"
        live["ended_at"] = _now_iso()
        live["note"] = why
        for sc in (live.get("scanners") or {}).values():
            if sc.get("state") in ("queued", "running"):
                sc["state"] = "interrupted"
                sc["detail"] = why
        try:
            import status
            status.atomic_replace(str(live_path(self.dir)),
                                  json.dumps(live), gid=self.gid)
        except (OSError, ValueError):
            pass
