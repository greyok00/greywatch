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

Empirically verified on this machine: ``clamscan --stdout
--log=…`` streams one ``path: OK|FOUND`` line per file to stdout while the
log file receives only the summary, which is why the live counter is fed
from stdout and not from the log.
"""
from __future__ import annotations

import datetime as _dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import threading
import time

SCAN_KEYS = ("full", "max-speed", "yara-tmp-scan", "clamav",
             "clamav-frequent", "clamav-home", "rkhunter", "lynis",
             "aide", "scan-all")
SCAN_ALL = ("clamav", "rkhunter", "lynis", "aide", "yara-tmp-scan")
KEEP_SUMMARIES = 20
LIVE_INTERVAL_S = 1.0

# One scan owner, one lock. Every producer that could start a scanner is
# routed through the service, and a second start is refused rather than run
# beside the first.
LOCK_NAME = "scan.lock"
CONTROL_NAME = "scan-control.json"
TOTALS_NAME = "scan-total.json"
CONTROL_ACTIONS = ("pause", "resume", "cancel")
TOTALS_TTL_S = 6 * 3600

# Rebuildable trees are excluded from the scan. The same list feeds
# ClamAV's --exclude-dir and the progress counter, so the bar's denominator
# matches the work actually done.
CLAM_EXCLUDES = (
    r"/\.cache(/|$)",
    r"/Trash(/|$)",
    r"/node_modules(/|$)",
    r"/__pycache__(/|$)",
    r"/\.venv(/|$)",
    r"/venv(/|$)",
    r"/\.git(/|$)",
    r"/build(/|$)",
    r"/dist(/|$)",
)
EXCLUDE_NAMES = {".cache", "Trash", "node_modules", "__pycache__",
                 ".venv", "venv", ".git", "build", "dist"}

# Mode key -> (scanner order, throttled). "full" is the everyday run
# and keeps every scanner capped; every key stays capped (owner
# 2026-11-17: the uncapped "max-speed" run sat at full CPU for hours and
# made the desktop "impossibly slow" - no run gives up the desktop, the
# machine works while it scans). "scan-all" is the retired button's
# key, kept so a request written by an older release can never orphan
# on the upgrade.
MODES = {
    "full": (SCAN_ALL, True),
    "max-speed": (SCAN_ALL, True),
    "scan-all": (SCAN_ALL, True),
    "clamav": (("clamav",), True),
    "clamav-frequent": (("clamav",), True),
    "clamav-home": (("clamav",), True),
    "rkhunter": (("rkhunter",), True),
    "lynis": (("lynis",), True),
    "aide": (("aide",), True),
    "yara-tmp-scan": (("yara-tmp-scan",), True),
}

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

# The everyday caps. ClamAV is the heaviest by far, so it is throttled
# hardest. Max speed runs with none of these — only its time limit survives.
THROTTLE = {
    # ClamAV gets three cores on a twenty-core machine; the desktop keeps
    # the rest, and the scan still yields on disk.
    "clamav": {"nice": 10, "io_class": "idle", "cpu_quota": "300%",
               "weight": 20, "mem": "1536M"},
    "rkhunter": {"nice": 10, "io_class": "idle", "cpu_quota": "150%",
                 "weight": 50},
    "lynis": {"nice": 10, "io_class": "idle", "cpu_quota": "150%",
              "weight": 50},
    "aide": {"nice": 10, "io_class": "idle", "cpu_quota": "150%",
             "weight": 50},
    "yara-tmp-scan": {"nice": 10, "io_class": "idle", "cpu_quota": "100%",
                      "weight": 50},
}
_UNIT_PROPS = {"nice": "Nice", "io_class": "IOSchedulingClass",
               "cpu_quota": "CPUQuota", "weight": "CPUWeight",
               "mem": "MemoryMax"}


def unit_properties_for(tool: str, throttled: bool) -> list[str]:
    """systemd transient-unit properties for one scanner this run.

    Empty for Max speed: the run is uncapped and says so in the UI."""
    if throttled:
        caps = THROTTLE.get(tool)
        if caps:
            return [f"--property={_UNIT_PROPS[k]}={v}"
                    for k, v in caps.items()]
    return []

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


def new_request_id() -> str:
    """An id in the scan service's own id shape."""
    import datetime as _dt
    import secrets as _secrets
    now = _dt.datetime.now()
    return f"{now:%Y%m%dT%H%M%S}-{_secrets.token_hex(2)}"


def write_request(data_dir, key: str) -> tuple[bool, str]:
    """File one scan request (the GUI's press, the chat's intent, the
    CLI's run). Atomic; refused with an honest note for a key the desk
    does not start; max-speed rides as an alias to the full throttled
    run (owner 2026-11-17: no scan gives up the desktop)."""
    key = "full" if key == "max-speed" else key
    if key not in SCAN_KEYS:
        return False, f"'{key}' is not a scan this desk starts."
    path = request_path(data_dir)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"id": new_request_id(), "key": key}))
    tmp.replace(path)
    return True, f"The {key} scan was requested; the desk shows progress."


def lock_path(data_dir) -> pathlib.Path:
    """The one lock every scan producer takes before launching anything."""
    return pathlib.Path(data_dir) / LOCK_NAME


def control_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / CONTROL_NAME


def totals_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / TOTALS_NAME


def validate_control(doc) -> tuple[str, str | None] | None:
    """(action, scan_id) for a well-formed control; None otherwise."""
    if not isinstance(doc, dict) or "scan_id" not in doc:
        return None
    action, scan_id = doc.get("action"), doc.get("scan_id")
    if action not in CONTROL_ACTIONS:
        return None
    if scan_id is not None and (not isinstance(scan_id, str)
                                or not _ID_RE.fullmatch(scan_id)):
        return None
    return action, scan_id


def write_control(data_dir, action: str,
                  scan_id: str | None = None) -> tuple[bool, str]:
    """Ask the owner of the one scan to pause, resume or cancel it.

    Atomic, like the request channel. The GUI and the CLI file the same
    file, so neither can drift from the other."""
    if action not in CONTROL_ACTIONS:
        return False, f"'{action}' is not a scan control."
    path = control_path(data_dir)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"action": action, "scan_id": scan_id}))
    tmp.replace(path)
    return True, f"The scan was asked to {action}."


# Scanner binaries the daemon must notice even when it did not start them.
# The realtime YARA watcher is not in this map: it scans one new file at a
# time and never holds a session.
_SCANNER_COMM = {"clamscan": "clamav", "clamdscan": "clamav",
                 "rkhunter": "rkhunter", "lynis": "lynis", "aide": "aide"}


def _boot_time(proc_root) -> float | None:
    try:
        for line in pathlib.Path(proc_root, "stat").read_text(
                errors="replace").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def scanner_processes(proc_root="/proc", *, exclude_cgroups=(),
                      exclude_pids=(), exclude_pgids=()) -> list[dict]:
    """Every scanner process on the box that the caller does not own.

    Pure /proc reading: no subprocess, no shell. ``exclude_cgroups``
    carries the transient units of the live session; ``exclude_pids`` and
    ``exclude_pgids`` cover the fallback that could not get a unit.
    """
    root = pathlib.Path(proc_root)
    try:
        entries = list(root.iterdir())
    except OSError:
        return []
    btime = _boot_time(root)
    hz = os.sysconf("SC_CLK_TCK")
    out = []
    for d in entries:
        if not d.name.isdigit():
            continue
        pid = int(d.name)
        if pid in exclude_pids:
            continue
        try:
            comm = (d / "comm").read_text(errors="replace").strip()
        except OSError:
            continue
        tool = _SCANNER_COMM.get(comm)
        if tool is None:
            continue
        try:
            cgroup = (d / "cgroup").read_text(errors="replace").strip()
        except OSError:
            cgroup = ""
        if any(tag and tag in cgroup for tag in exclude_cgroups):
            continue
        started_at = None
        age_s = None
        try:
            stat = (d / "stat").read_text(errors="replace")
            rest = stat[stat.rfind(")") + 1:].split()
            pgrp = int(rest[2])
            if pgrp in exclude_pgids:
                continue
            if btime is not None:
                started = btime + int(rest[19]) / hz
                started_at = _dt.datetime.fromtimestamp(
                    started, _dt.timezone.utc).isoformat(timespec="seconds")
                age_s = round(time.time() - started, 1)
        except (OSError, ValueError, IndexError):
            pass
        try:
            cmdline = (d / "cmdline").read_bytes().replace(
                b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            cmdline = comm
        out.append({"pid": pid, "tool": tool, "cmdline": cmdline[:300],
                    "cgroup": cgroup, "started_at": started_at,
                    "age_s": age_s})
    return out


def _read_clam_progress(home):
    """The live count an already-running ClamAV wrote for its launcher.

    Two lines: the file count and the last path. Read-only; a scanner this
    daemon did not start cannot report more than its launcher published."""
    path = pathlib.Path(home) / "security-hardening" / "clam-progress.txt"
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return None, ""
    if not lines:
        return None, ""
    try:
        count = int(lines[0].strip())
    except ValueError:
        count = None
    current = lines[1].strip() if len(lines) > 1 else ""
    return (count if count else None), current


def count_scan_tree(roots, exclude_names=EXCLUDE_NAMES):
    """(files, bytes) under the scan roots, minus the rebuildable trees.

    The denominator the progress bar needs. It walks with ``scandir``,
    never follows a symlink, and survives a directory that vanishes
    under it — the same way ClamAV does."""
    files = 0
    total = 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        stack = [str(root)]
        while stack:
            current = stack.pop()
            try:
                it = os.scandir(current)
            except OSError:
                continue
            with it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in exclude_names:
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            files += 1
                            total += entry.stat(
                                follow_symlinks=False).st_size
                    except OSError:
                        continue
    return files, total


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
AIDE_DB = pathlib.Path("/var/lib/aide/aide.db")


def existing_roots(roots) -> list:
    """Only the roots that exist as directories. clamscan exits 2 on a
    missing path, so one absent Downloads folder failed the whole quick
    scan (review I10)."""
    out = []
    for root in roots or ():
        try:
            if os.path.isdir(str(root)):
                out.append(str(root))
        except OSError:
            continue
    return out


def commands_for(key, home, ui_user, *, throttle=True):
    """The exact argv for a key. Never built from request text.

    ``throttle`` applies ClamAV's own breadth flags: the scans cap file
    size and scan size and refuse to cross into mounted file systems —
    the breadth limits that keep the antivirus from spending hours
    inside a mounted archive. Every mode runs throttled (owner
    2026-11-17: no run gives up the desktop for speed).
    """
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
    # Superseded (owner 2026-11-17): D1-a's resident engine is retired.
    # The standalone throttled scanner IS the antivirus; the daemon is
    # masked and nothing consults its socket any more.
    #
    # The app's own scratch trees are never findings: the test suite's
    # fixtures and live-file scratch live under these names (owner
    # confirmed 2026-11-14: "those are test dummies").
    excl = ["--exclude-dir=pytest-of-grey", "--exclude=gw-eicar",
            "--exclude=gw-live", "--exclude-dir=unicornscan"]
    # The counter that feeds the progress bar walks the same exclusion
    # list, so the denominator is the work.
    excl += [f"--exclude-dir={pattern}" for pattern in CLAM_EXCLUDES]
    clam = ["/usr/bin/clamscan", "-r", "--stdout", *excl,
            f"--log={home}/security-hardening/clam-scan.log"]
    if throttle:
        clam += ["--cross-fs=no", "--max-filesize=512M", "--max-scansize=2G"]
    # The scoped keys narrow the everyday roots: the frequent sweep walks
    # the places downloads and edits land, the home sweep stays in the
    # account. The legacy "clamav" key keeps the wider roots it always had.
    frequent = [f"{home}/Downloads", f"{home}/Desktop", f"{home}/Documents"]
    scopes = {
        "clamav-frequent": ["/tmp", "/var/tmp", *frequent],
        "clamav-home": [home],
    }
    clam += scopes.get(key, [home, "/tmp", "/var/tmp", "/etc", "/usr/local"])
    table = {
        "clamav": clam,
        "clamav-frequent": clam,
        "clamav-home": clam,
        "rkhunter": ["/usr/bin/rkhunter", "--check", "--sk"],
        "lynis": ["/usr/sbin/lynis", "audit", "system", "--quick"],
        "aide": ["/usr/bin/aide", "--config=/etc/aide/aide-scoped.conf",
                 "--check"],
        "yara-tmp-scan": yara,
    }
    if key in ("scan-all", "full", "max-speed"):
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
# warnings were found.
_RKH_SUMMARY = re.compile(r"warnings? (?:have|has) been found", re.I)
_LYNIS_TEST = re.compile(r"^\s*Performing test\s+(?P<what>.*)$")
_LYNIS_WARN = re.compile(r"^\s*Warning\s*[:\[]\s*(?P<what>.+?)\s*\]?\s*$")
_YARA = re.compile(r"^(?P<rule>[A-Za-z0-9_:+.-]{2,64})\s+(?P<path>/\S.*)$")
# The shipped temp sweep reports how much of the tree it has walked, so the
# counter moves while YARA is still reading files.
_YARA_DIRS = re.compile(r"^@@DIRS\s+(?P<n>\d+)(?:\s+(?P<path>\S.*))?$")
# The walk prints its final folder count, which is the temp sweep's
# honest denominator for the progress bar.
_YARA_TOTAL = re.compile(r"^@@TOTAL\s+(?P<n>\d+)$")
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
        # after it was built, which reads as a wall of errors. A real change carries a letter flag (`f..H......`,
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
        m = _YARA_TOTAL.match(stripped)
        if m:
            return {"counted": False, "total": int(m.group("n")),
                    "current": "", "finding": None}
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
        if 0 <= rc <= 7:
            return ("done", "")
        # : on this host the baseline was never built (aideinit
        # never ran), so the check exits quickly with an rc the row
        # reported as bare "aide exited N" - a phrase that names the
        # cause without telling the user what to do. A missing database
        # is a setup step, said in one sentence.
        if not AIDE_DB.is_file():
            return ("failed", "no baseline: run 'sudo aideinit' once, "
                    "then scan again")
        return ("failed", f"aide exited {rc}")
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


class ScanLock:
    """The one scan slot on the machine.

    An advisory ``flock`` held for a session's whole life. Root, the
    desktop user and every helper open the same file, so a timer, the
    boot sweep and a button press cannot start together."""

    def __init__(self, path, gid=None):
        self.path = pathlib.Path(path)
        self.gid = gid
        self.fd = None
        self.held = False

    def acquire(self) -> bool:
        if self.held:
            return True
        try:
            self.fd = os.open(str(self.path),
                              os.O_RDWR | os.O_CREAT, 0o660)
        except OSError:
            return False
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
            return False
        self.held = True
        try:
            # The service runs with a restrictive umask; the lock must be
            # readable and writable by the desktop group so any helper
            # sharing the slot can open it.
            os.fchmod(self.fd, 0o660)
            if self.gid is not None:
                os.fchown(self.fd, -1, self.gid)
            os.ftruncate(self.fd, 0)
            os.write(self.fd, f"pid={os.getpid()}\n".encode())
        except OSError:
            pass
        return True

    def release(self) -> None:
        if self.fd is None:
            self.held = False
            return
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.fd = None
        self.held = False


def _process_tree(proc_root, pid) -> list[int]:
    """A pid and its descendants, read from /proc (no subprocess)."""
    out = []
    stack = [int(pid)]
    while stack:
        current = stack.pop()
        out.append(current)
        try:
            kids = pathlib.Path(proc_root, str(current), "task",
                                str(current), "children").read_text().split()
        except OSError:
            continue
        stack.extend(int(k) for k in kids if k.isdigit())
    return out


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
                 start_offset=0, attach_only=False, properties=None):
        self.argv = list(argv)
        self.log_path = pathlib.Path(log_path)
        self.unit = unit
        # Extra systemd unit properties (CPUQuota, Nice, IOSchedulingClass
        # ...). Also marks the non-systemd fallback as throttled, so a run
        # that cannot get a transient unit still gives way to the desktop.
        self.properties = list(properties or [])
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
        argv += self.properties
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
        argv = list(self.argv)
        if self.properties:
            # Systemd could not take this scan, so the caps are approximated
            # with the two classic schedulers instead: lowest CPU priority,
            # idle-class IO.
            prefix = [p for p in ("/usr/bin/nice", "/usr/bin/ionice")
                      if pathlib.Path(p).exists()]
            if "/usr/bin/ionice" in prefix:
                argv = ["/usr/bin/nice", "-n", "19", "/usr/bin/ionice",
                        "-c3"] + argv
            elif "/usr/bin/nice" in prefix:
                argv = ["/usr/bin/nice", "-n", "19"] + argv
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

    def pause(self):
        """Freeze the scanner without losing its place."""
        self._signal(signal.SIGSTOP)

    def resume(self):
        self._signal(signal.SIGCONT)

    def _signal(self, sig):
        if self.unit:
            try:
                subprocess.run(
                    ["/usr/bin/systemctl", "kill", f"--signal={sig.name}",
                     "--kill-whom=all", self.unit],
                    capture_output=True, timeout=20)
            except (OSError, subprocess.SubprocessError):
                pass
            return
        if self.proc is None:
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), sig)
        except (OSError, ProcessLookupError):
            try:
                self.proc.send_signal(sig)
            except OSError:
                pass


def subprocess_spawner(argv, log_path=None, *, unit=None, runtime_max=None,
                       attach_only=False, start_offset=0, properties=None):
    return DetachedHandle(argv, log_path, unit=unit, runtime_max=runtime_max,
                          attach_only=attach_only,
                          start_offset=start_offset, properties=properties)


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
                 log=None, use_systemd=None, which=shutil.which,
                 proc_root="/proc", counter=None, count_totals=True):
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
        self.proc_root = proc_root
        self.counter = counter or (lambda roots: count_scan_tree(roots))
        self.count_totals = bool(count_totals)
        self.session = None            # dict while running
        self.children = {}             # tool -> runtime state
        self.external = []             # scanners this daemon did not start
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
        # One owner, one lock. The request is only consumed after the
        # slot is ours, so a request filed while an outside scan runs is
        # never silently lost.
        self.lock = ScanLock(lock_path(self.dir), gid=self.gid)
        self._totals = self._load_totals()
        self._totals_started = False
        # A count is a denominator only for the roots it walked. The cached
        # file was validated against the legacy roots, so that is its key.
        self._totals_key = "clamav" if self._totals else ""
        self._lynis_total = None
        self._last_session_doc = None
        self._stop_reason = ""
        self._external_key = None
        self._next_sweep = 0.0
        self._external_kill_at = 0.0

    # ---- hooks -----------------------------------------------------
    def set_tailer_hooks(self, pause, resume):
        self._pause = pause
        self._resume = resume

    def running(self) -> bool:
        return self.session is not None

    # ---- progress denominators -------------------------------------
    def _scope_for(self, key: str) -> str:
        """The scan key whose roots and count this child belongs to.

        The antivirus row is always keyed "clamav"; the requested key
        ("clamav-frequent", "clamav-home") decides the roots walked."""
        if key != "clamav":
            return key
        session_key = (self.session or {}).get("key")
        return session_key if session_key in (
            "clamav", "clamav-frequent", "clamav-home") else "clamav"

    def _totals_for(self, key: str) -> dict:
        """The cached count, only when it was walked for this key.

        A count from another scope is not a denominator: using it divides
        one tree's files by another tree's total."""
        return self._totals if self._totals_key == self._scope_for(key) \
            else {}

    def _clam_roots(self, key="clamav"):
        frequent = [f"{self.home}/Downloads", f"{self.home}/Desktop",
                    f"{self.home}/Documents"]
        scopes = {
            "clamav-frequent": ["/tmp", "/var/tmp", *frequent],
            "clamav-home": [self.home],
        }
        return scopes.get(key, [self.home, "/tmp", "/var/tmp", "/etc",
                                "/usr/local"])

    def _run_roots(self, key="clamav") -> list:
        """The roots this key will actually hand the scanner."""
        return existing_roots(self._clam_roots(key))

    def _roots_sig(self, key="clamav") -> str:
        text = "\n".join(self._clam_roots(key)) + "\n" + \
            "\n".join(CLAM_EXCLUDES)
        return hashlib.sha1(text.encode()).hexdigest()

    def _load_totals(self) -> dict:
        try:
            doc = json.loads(totals_path(self.dir).read_text())
        except (OSError, ValueError):
            return {}
        if doc.get("roots_sig") != self._roots_sig():
            return {}
        try:
            return {"files": int(doc.get("files") or 0),
                    "bytes": int(doc.get("bytes") or 0),
                    "ts": float(doc.get("ts") or 0.0)}
        except (TypeError, ValueError):
            return {}

    def _maybe_count_totals(self, key="clamav") -> None:
        """Teach the antivirus bar its denominator, in the background.

        The walk costs seconds; the scan costs minutes. A cached count is
        used at once and refreshed behind the running scan, so the bar
        never waits on the counter. The count is kept per scan key: one
        scope's tree is not another scope's denominator."""
        if not self.count_totals:
            return
        if key != self._totals_key:
            self._totals = {}
            self._totals_started = False
            self._totals_key = key
        if self._totals_started:
            return
        self._totals_started = True
        stale = (time.time() - float((self._totals or {}).get("ts") or 0)
                 > TOTALS_TTL_S)
        if self._totals and not stale:
            return

        def work():
            try:
                files, total = self.counter(self._run_roots(key))
            except Exception as e:            # noqa: BLE001
                self.log(f"scan counter failed: {type(e).__name__}")
                return
            # The walk outlives a scope change: a legacy walk still running
            # when a scoped session takes over must not publish its wide
            # count under the new key. The key it walked decides whether it
            # still counts.
            if key != self._totals_key:
                return
            self._totals = {"files": files, "bytes": total,
                            "ts": time.time()}
            try:
                import status
                status.atomic_replace(
                    str(totals_path(self.dir)),
                    json.dumps({"roots_sig": self._roots_sig(key),
                                "files": files, "bytes": total,
                                "ts": self._totals["ts"]}))
            except (OSError, ValueError) as e:
                self.log(f"scan total not cached: {type(e).__name__}")

        threading.Thread(target=work, daemon=True,
                         name="gw-scan-count").start()

    def _lynis_tests(self) -> int | None:
        if self._lynis_total is not None:
            return self._lynis_total or None
        try:
            done = subprocess.run(["/usr/sbin/lynis", "show", "tests"],
                                  capture_output=True, text=True, timeout=10)
            out = done.stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        self._lynis_total = sum(1 for line in out.splitlines()
                                if " Linux " in line)
        return self._lynis_total or None

    def _percent(self, key: str, child: dict):
        if child["state"] == "done":
            return 1.0
        total_bytes = int(self._totals_for(key).get("bytes") or 0)
        done_bytes = int(child.get("done_bytes") or 0)
        if total_bytes and done_bytes:
            return min(1.0, done_bytes / float(total_bytes))
        total = child.get("total")
        if total and child.get("count") is not None:
            return min(1.0, child["count"] / float(total))
        return None

    # ---- request channel -------------------------------------------
    def _read_request(self):
        """Peek: the request is only consumed once the slot is ours."""
        path = request_path(self.dir)
        try:
            raw = path.read_text()
        except OSError:
            return None
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        got = None if doc is None else validate_request(doc)
        if got is None:
            # Validate BEFORE consuming (recovery audit A9): a read that
            # races the writer's mid-write state parses as garbage, and
            # deleting here would destroy a request the user actually
            # filed. Invalid bytes are moved aside instead - the channel
            # is empty afterwards (no repeated tick spam) but nothing is
            # silently lost.
            self.log("rejected a malformed request file - moved to "
                     ".rejected")
            try:
                os.replace(str(path), str(path) + ".rejected")
            except OSError:
                pass
            return None
        return got, path

    def _consume_request(self, path) -> None:
        try:
            path.unlink()
        except OSError:
            pass

    # ---- control channel -------------------------------------------
    def _take_control(self):
        path = control_path(self.dir)
        try:
            raw = path.read_text()
        except OSError:
            return None
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        try:
            path.unlink()
        except OSError:
            pass
        got = validate_control(doc)
        if got is None:
            self.log("rejected a malformed scan control")
        return got

    def _apply_control(self) -> None:
        got = self._take_control()
        if got is None:
            return
        action, scan_id = got
        if self.session is not None and scan_id \
                and self.session.get("scan_id") != scan_id:
            return                      # a stale control for an older run
        if action == "pause":
            self.pause()
        elif action == "resume":
            self.resume()
        else:
            self.cancel()

    # ---- lifecycle -------------------------------------------------
    def tick(self):
        self._apply_control()
        got = self._read_request()
        if got is not None:
            (rid, key), path = got
            if self.session is not None:
                self.session["note"] = "a scan is already running"
                self._write_live(force=True)
                self._consume_request(path)
            elif self.lock.acquire():
                self._consume_request(path)
                self.start(rid, key)
            # else: an outside scan holds the one slot; the request waits
            # on file and starts the moment the slot frees.
        if self.session is None:
            self._sweep_external()
            return
        changed = False
        for key in list(self.children):
            changed = self._drain(key) or changed
        self._check_timeouts()
        # One scanner at a time. Each finish starts the next in order, so the
        # page can say exactly which one is waiting on which.
        self._advance()
        if self.session is None:
            self._sweep_external()
            return
        if all(c["state"] not in ("queued", "running")
               for c in self.children.values()):
            self._finish_session()
        else:
            # New output moves the bar now; an idle tick keeps to the
            # once-a-second write limit.
            self._write_live(force=changed)
        self._sweep_external()

    def start(self, scan_id: str, key: str) -> bool:
        if not self.lock.held and not self.lock.acquire():
            return False                    # another scan owns the slot
        scanners, throttled = MODES.get(key, (None, True))
        keys = list(scanners) if scanners else [key]
        self._order = keys
        self.children = {}
        self._finding_rows = []
        self._aid_noted = False
        self._stop_reason = ""
        self._totals_started = False
        for k in keys:
            self.children[k] = {
                "state": "queued", "count": 0, "current": "",
                "findings": 0, "warned": False, "detail": "",
                "started_at": None,
                "ended_at": None, "exit_code": None, "handle": None,
                "started": self.clock(), "last_line": "", "log": [],
                "log_offset": 0, "unit": None,
                "paused": False, "paused_at": None, "paused_s": 0.0,
                "done_bytes": 0, "total": None}
        self.session = {"scan_id": scan_id, "key": key, "state": "running",
                        "started_at": _now_iso(), "ended_at": None,
                        "note": "", "throttle": throttled,
                        "paused": False}
        self._shared_dir(self.dir / "scan-logs")
        self._shared_dir(scans_dir(self.dir))
        self._advance()
        if self.session is None:            # nothing could start
            return False
        self._write_live(force=True)
        return True

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
        # The row is keyed "clamav" while the requested key decides the
        # roots, so the scope is resolved before the command is built.
        scope = self._scope_for(key)
        # Max speed must be uncapped end to end: the session's throttle
        # decision drives both the unit caps and ClamAV's breadth flags.
        argv = (commands_for(
            scope, self.home, self.ui_user,
            throttle=bool((self.session or {}).get("throttle", True))
        ) or [None])[0]
        if argv is None or key in self._missing or not self.which(argv[0]):
            child.update(state="failed", detail="not installed",
                         ended_at=_now_iso())
            return False
        # One absent root used to fail the whole scan (clamscan exits 2 on
        # a missing path): hand the scanner only what exists.
        if scope in ("clamav", "clamav-frequent", "clamav-home"):
            wanted = self._clam_roots(scope)
            roots = self._run_roots(scope)
            if len(wanted) and argv[-len(wanted):] == wanted:
                argv = argv[:-len(wanted)] + roots
            if not roots:
                child.update(state="failed", ended_at=_now_iso(),
                             detail="no scan root exists")
                return False
        argv = line_buffered(key, argv)
        if scope in ("clamav", "clamav-frequent", "clamav-home"):
            self._maybe_count_totals(scope)
            child["total"] = int(
                self._totals_for(key).get("files") or 0) or None
        elif key == "lynis":
            child["total"] = self._lynis_tests()
        scan_id = (self.session or {}).get("scan_id") or "scan"
        log = scan_log_path(self.dir, scan_id, key)
        self._shared_dir(log.parent)
        unit = unit_name(scan_id, key) if self._systemd else None
        limit = SCANNERS.get(key, {"timeout_s": 3600})["timeout_s"]
        props = unit_properties_for(
            key, (self.session or {}).get("throttle", True))
        try:
            child["handle"] = self.spawn(
                argv, log, unit=unit, runtime_max=limit, properties=props)
        except (OSError, ValueError) as e:
            child.update(state="failed", ended_at=_now_iso(),
                         detail=f"could not start: {type(e).__name__}")
            return False
        child.update(state="running", started=self.clock(),
                     started_at=_now_iso(), unit=unit)
        self._pause(key)
        return True

    # ---- parsing ----------------------------------------------------
    def _drain(self, key: str) -> bool:
        child = self.children[key]
        handle = child.get("handle")
        if handle is None or child["state"] != "running":
            return False
        # Local time with an offset: the finding row sorts with its
        # neighbours and the clock matches what the scanner printed.
        when = _dt.datetime.now().astimezone()
        saw = False
        for line in handle.lines():
            saw = True
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
            if prog.get("total") is not None:
                child["total"] = int(prog["total"])
            if key == "clamav" and prog["counted"]:
                # Byte-weighted progress: a few large files are most of the
                # work, so the bar follows the bytes the scanner just read.
                try:
                    child["done_bytes"] = int(child.get("done_bytes") or 0) \
                        + os.stat(prog["current"],
                                  follow_symlinks=False).st_size
                except OSError:
                    pass
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
            return True
        return saw

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

    # Auto-action (owner 2026-11-14: "quarantine or delete, high alert"):
    # a malware FIND is moved to quarantine through the app's own
    # validated helper the moment its row records, by the daemon context,
    # not by the owner's hand. The app's own test-fixture paths are
    # exempt: they are the suite's scratch, and the app says so instead.
    _AUTOPATHS = ("file-action.sh",)
    _EXEMPT_SEGMENTS = ("/pytest-of-grey/", "/pytest-tmp/",
                        "gw-eicar", "gw-live-files", "gw-live",
                        "/etc/unicornscan/")

    def _auto_quarantine(self, key: str, finding: dict) -> None:
        if key not in ("clamav", "yara-watch", "yara-tmp-scan"):
            return
        if finding.get("severity") not in ("HIGH", "CRITICAL"):
            return
        import pathlib
        parts = str(finding.get("text", "")).split(": ", 1)
        target = parts[0].strip() if len(parts) == 2 else ""
        if not target.startswith("/") or "FOUND" not in finding.get("text", ""):
            return
        if any(seg in target for seg in self._EXEMPT_SEGMENTS):
            self.log(f"test-scratch finding left in place: {target}")
            return
        try:
            from core import scan_whitelist
            if scan_whitelist.match(target):
                self.log(f"whitelisted finding left in place: {target}")
                return
        except Exception:
            pass
        tp = pathlib.Path(target)
        if not tp.is_file():
            return
        self._run_file_action("quarantine", target)

    def _run_file_action(self, action: str, target: str) -> None:
        """The daemon context is root: run the validated helper directly
        (no polkit round trip), with a test seam for the suite."""
        script = os.environ.get("GREYWATCH_TEST_FILE_ACTION")
        if not script:
            here = pathlib.Path(__file__).resolve().parents[1] / "apply" \
                / "file-action.sh"
            lib = pathlib.Path(os.environ.get("GREYWATCH_LIB_DIR")
                               or "/usr/lib/greywatch") / "apply" \
                / "file-action.sh"
            script = str(lib if lib.exists() else here)
        import subprocess
        run = subprocess.run(["/bin/bash", script, action, target],
                             capture_output=True, text=True, timeout=60)
        self.log(f"auto-quarantine {action} {target} -> "
                 f"rc={run.returncode}")

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
        try:
            self._auto_quarantine(key, finding)
        except Exception as e:
            self.log(f"auto-quarantine failed: {type(e).__name__}: {e}")

    # ---- completion -------------------------------------------------
    def _check_timeouts(self):
        if self.session is not None and self.session.get("state") == "paused":
            return                          # a pause is not a slow scan
        now = self.clock()
        for key, child in self.children.items():
            if child["state"] != "running" or child.get("paused"):
                continue
            limit = SCANNERS.get(key, {"timeout_s": 3600})["timeout_s"]
            elapsed = now - child["started"] - float(
                child.get("paused_s") or 0.0)
            if elapsed > limit:
                child["handle"].terminate()
                child.update(state="failed", ended_at=_now_iso(), current="",
                             detail=f"timed out after {limit // 60} minutes")
                self._resume(key)

    def _finish_session(self):
        # A session is only done when every child is done. One child that
        # failed, timed out or lost its process makes the session failed,
        # and a cancel is cancelled - never quietly reported as done over
        # a scanner that did not finish.
        states = [c["state"] for c in self.children.values()]
        if self._stop_reason == "cancelled":
            state = "cancelled"
        elif any(s == "failed" for s in states):
            state = "failed"
        elif states and all(s == "done" for s in states):
            state = "done"
        else:
            state = "failed"
        # : a refusal note ("a scan is already running") describes
        # a request that could not start WHILE a scan was running; once
        # this session reaches a final state that reason is not true
        # anymore (another scan can start), so the note must not
        # outlive the state it explained - "Full scan: finished · a
        # scan is already running" was three claims in one headline.
        if self.session.get("note"):
            self.session["note"] = ""
        self.session.update(state=state, ended_at=_now_iso(), paused=False)
        self._write_live(force=True)
        self._write_summary(state)
        # every lane journals its exit in ONE place the doctor reads:
        # the daemon session's clam scan is the AV's own completion
        # record (owner 2026-11-15: "still DEGRADED" came from the two
        # lanes writing journals the other one never read). A cancelled
        # run is not a completion and says nothing here.
        if state == "done":
            try:
                home = str(getattr(self, "home", "") or "")
                if home:
                    journal = pathlib.Path(home) / "security-hardening" \
                        / "clam-run.log"
                    stamp = _dt.datetime.now(_dt.timezone.utc).isoformat(
                        timespec="seconds")
                    with journal.open("a", encoding="utf-8") as fh:
                        fh.write(f"{stamp} session "
                                 f"{self.session['scan_id']} exit rc=0\n")
            except (OSError, AttributeError, KeyError) as e:
                self.log(f"session journal not written: {type(e).__name__}")
        self.session = None
        self.children = {}
        self._stop_reason = ""
        self.lock.release()
        self._keep_recent()

    # ---- writers ----------------------------------------------------
    def _external_document(self) -> dict:
        return {"scan_id": None, "key": None, "state": "running",
                "started_at": None, "ended_at": None,
                "note": "a scan started outside the app is running",
                "throttle": True, "scanners": {},
                "external": [dict(row) for row in self.external],
                "real_findings": 0, "routine_findings": 0,
                "sequence": [],
                "paused": any(row.get("paused") for row in self.external),
                "config": {}, "updated": _now_iso()}

    def _document(self) -> dict:
        if self.session is None:
            return self._external_document()
        s = self.session
        now = self.clock()
        running = next((k for k, c in self.children.items()
                        if c["state"] == "running"), None)
        scanners = {}
        for i, (key, c) in enumerate(self.children.items(), start=1):
            duration = None
            if c["state"] != "queued" and c.get("started") is not None:
                elapsed = now - c["started"] - float(
                    c.get("paused_s") or 0.0)
                if c.get("paused") and c.get("paused_at") is not None:
                    elapsed -= now - c["paused_at"]
                duration = round(max(0.0, elapsed), 1)
            current = c["current"]
            if key == "aide" and c["state"] == "running" and not current:
                current = "comparing the file database (reports at the end)"
            waiting = ""
            if c["state"] == "queued" and running:
                waiting = SCANNER_NAMES.get(running, running)
            total = c.get("total")
            totals = self._totals_for(key)
            if key == "clamav" and totals.get("files"):
                total = int(totals["files"])
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
                "unit": c.get("unit"),
                "total": total, "percent": self._percent(key, c),
                "paused": bool(c.get("paused"))}
        real = sum(1 for r in self._finding_rows if not r["routine"])
        routine = sum(1 for r in self._finding_rows if r["routine"])
        config = {}
        if "clamav" in self.children:
            caps = THROTTLE["clamav"]
            config = {"scanner": "clamav",
                      "cpu_quota": caps["cpu_quota"],
                      "nice": caps["nice"],
                      "excludes": list(CLAM_EXCLUDES)}
        return {"scan_id": s.get("scan_id"), "key": s.get("key"),
                "state": s.get("state", "done"),
                "started_at": s.get("started_at"),
                "ended_at": s.get("ended_at"), "note": s.get("note", ""),
                "throttle": bool(s.get("throttle", True)),
                "scanners": scanners, "real_findings": real,
                "routine_findings": routine,
                "sequence": list(self._order),
                "paused": bool(s.get("paused")),
                "external": list(self.external),
                "config": config,
                # The reader-side staleness gate (audit SM3) reads this;
                # "Scanning:…" must not survive a dead writer.
                "updated": _now_iso()}

    def _write_doc(self, doc) -> None:
        try:
            import status
            status.atomic_replace(str(live_path(self.dir)),
                                  json.dumps(doc), gid=self.gid)
        except (OSError, ValueError) as e:
            self.log(f"could not write scan-live.json: {type(e).__name__}")

    def _write_live(self, force=False):
        doc = self._document()
        self.last_live = doc
        if self.session is not None:
            self._last_session_doc = doc
        now = self.clock()
        if not force and now - self._last_write < LIVE_INTERVAL_S:
            return
        self._last_write = now
        self._write_doc(doc)

    # ---- pause, resume, cancel -------------------------------------
    def pause(self) -> None:
        if self.session is not None:
            if self.session.get("state") != "running":
                return
            self.session["state"] = "paused"
            self.session["paused"] = True
            now = self.clock()
            for key, child in self.children.items():
                if child["state"] != "running":
                    continue
                child["paused"] = True
                child["paused_at"] = now
                handle = child.get("handle")
                if handle is not None and hasattr(handle, "pause"):
                    try:
                        handle.pause()
                    except OSError as e:
                        self.log(f"could not pause {key}: "
                                 f"{type(e).__name__}")
            self._write_live(force=True)
            return
        if self.external:
            self._signal_external(signal.SIGSTOP)
            for row in self.external:
                row["paused"] = True
            self._write_live(force=True)

    def resume(self) -> None:
        if self.session is not None:
            if self.session.get("state") != "paused":
                return
            now = self.clock()
            for key, child in self.children.items():
                if not child.get("paused"):
                    continue
                child["paused"] = False
                if child.get("paused_at") is not None:
                    child["paused_s"] = float(child.get("paused_s") or 0.0) \
                        + (now - child["paused_at"])
                    child["paused_at"] = None
                handle = child.get("handle")
                if handle is not None and hasattr(handle, "resume"):
                    try:
                        handle.resume()
                    except OSError as e:
                        self.log(f"could not resume {key}: "
                                 f"{type(e).__name__}")
            self.session["state"] = "running"
            self.session["paused"] = False
            self._write_live(force=True)
            return
        if self.external:
            self._signal_external(signal.SIGCONT)
            for row in self.external:
                row["paused"] = False
            self._external_kill_at = 0.0
            self._write_live(force=True)

    def cancel(self) -> None:
        if self.session is not None:
            self._stop_reason = "cancelled"
            self.session["state"] = "cancelled"
            self.session["paused"] = False
            for key, child in self.children.items():
                if child["state"] not in ("queued", "running"):
                    continue
                child.update(state="cancelled", detail="cancelled by you",
                             ended_at=_now_iso(), current="", paused=False)
                handle = child.get("handle")
                if handle is not None:
                    try:
                        handle.terminate()
                    except OSError:
                        pass
                    self._resume(key)
            self._finish_session()
            return
        if self.external:
            self._signal_external(signal.SIGTERM)
            for row in self.external:
                row["state"] = "cancelled"
            self._external_kill_at = self.clock() + 5.0
            self._write_live(force=True)

    def _signal_external(self, sig) -> None:
        for row in self.external:
            pid = row.get("pid")
            if not pid:
                continue
            for target in _process_tree(self.proc_root, pid):
                try:
                    os.kill(target, sig)
                except OSError:
                    pass

    def _sweep_external(self) -> None:
        """Find scanners the daemon did not start, and never start beside
        them. Published into the live document so the window can show,
        pause or cancel them."""
        now = self.clock()
        if self._external_kill_at and now >= self._external_kill_at:
            self._signal_external(signal.SIGKILL)
            self._external_kill_at = 0.0
        if now < self._next_sweep:
            return
        self._next_sweep = now + 2.0
        cgroups, pids, pgids = [], set(), set()
        for child in self.children.values():
            if child.get("unit"):
                cgroups.append(child["unit"])
            proc = getattr(child.get("handle"), "proc", None)
            if proc is not None:
                pids.add(proc.pid)
                pgids.add(proc.pid)
        found = scanner_processes(self.proc_root, exclude_cgroups=cgroups,
                                  exclude_pids=pids, exclude_pgids=pgids)
        for row in found:
            row["paused"] = False
            if row["tool"] == "clamav":
                count, current = _read_clam_progress(self.home)
                if count is not None:
                    row["count"] = count
                    row["counter_label"] = "files scanned"
                if current:
                    row["current"] = current
        key = tuple(sorted((row["pid"], row["tool"]) for row in found))
        was = self._external_key
        self._external_key = key
        self.external = found
        if key == was:
            if found and self.session is None:
                self._write_live()
            return
        if found:
            self._write_live(force=True)
        elif self.session is None:
            # The outside scan ended: hand the desk back its last run.
            if self._last_session_doc is not None:
                self._write_doc(self._last_session_doc)
            else:
                self._write_doc({"scan_id": None, "key": None,
                                 "state": "done", "note": "", "scanners": {},
                                 "external": [], "sequence": [],
                                 "real_findings": 0,
                                 "routine_findings": 0,
                                 "paused": False, "config": {},
                                 "updated": _now_iso()})

    def _shared_dir(self, path) -> None:
        """Create a scan directory the desktop user can actually read.

        Scans run as root, so a plain mkdir produced root-only ``0700``
        directories: the window runs as the desktop user, and RECENT SCANS
        stayed empty, "Show in folder" had nothing to open, and a scanner's
        own log could not be read. The data directory's
        pattern — ``0770``, root plus the desktop group — is the fix, and
        applying it on every scan repairs directories made by older builds.
        """
        try:
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o770)
            if self.gid is not None:
                os.chown(path, -1, self.gid)
        except OSError as e:
            self.log(f"could not prepare {path.name}: {type(e).__name__}")

    def _write_summary(self, state: str):
        doc = self._document()
        doc["state"] = state
        target = scans_dir(self.dir) / f"{doc['scan_id']}.json"
        self._shared_dir(target.parent)
        try:
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
        which looked like the service killing scans. Scanners
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
        if not self.lock.held and not self.lock.acquire():
            self.log("a scan is already running outside the app; not "
                     "re-attaching")
            return
        scan_id = live.get("scan_id")
        if not isinstance(scan_id, str) or not _ID_RE.fullmatch(scan_id):
            self._mark_interrupted(live, "the scan file had no usable id")
            self.lock.release()
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
