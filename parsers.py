"""Per-tool log-line parsers — Task 2 of the greywatch build.

Contract (plan lines 90-92, G2.1-G2.2):
- Every parser is pure: (line:str) -> Event|None and NEVER raises;
  malformed input (empty, NUL-briddled, braces, 5000-char noise) -> None.
- Fixed severity map from the build plan (owner-approved), see SEV below.
- `ts` on the Event is ISO-8601 UTC; when a line carries a timestamp in a
  parseable format it is converted; otherwise UTC now is used.

Fixtures in tests/fixtures/ hold REAL lines sampled on 2026-10-22 from the
grey-readable files, and canonical-format lines (flagged in-file) for
root-only sources — canonical fixtures are re-validated against the live
logs at G2.4 before trust.
"""
from __future__ import annotations

import datetime as _dt
import json as _json
import re as _re
from typing import Optional

from events import Event

# ── fixed severity map (plan line 90) ────────────────────────────────────
RESPONDERD_HIGH = {"kill", "delete", "firewall_drop", "quarantine"}

_ANSI = _re.compile(r"(?:\x1b)?\[[0-9;]{1,6}m")

# fail2ban canonical: 2026-10-22 18:00:32,110 fail2ban.actions [4247]: NOTICE [sshd] Ban 10.0.0.1
_F2B = _re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ fail2ban\.actions\s*\[\d+\]: "
    r"(?P<lvl>NOTICE|WARNING|INFO)\s*\[(?P<jail>[A-Za-z0-9_-]+)\] (?P<act>Ban|Unban|Restore Ban|Found) (?P<ip>\S+)$")
# ufw kernel-journal (journalctl -k -o cat): [ 1234.567] [UFW BLOCK] IN=... SRC=... DST=...
_UFW = _re.compile(r"^\[\s*[0-9.]+\s*\] \[UFW (?P<act>[A-Z_]+)\] (?P<rest>.*)$")
# suricata fast.log canonical: 10/22/2026-18:00:00.000000  [1:2200002:1] ET ... [Priority: 2] {TCP} 1.2.3.4 -> 5.6.7.8
_SURI = _re.compile(
    r"^(?P<date>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\d+:\d+:\d+\]\s+(?P<msg>.+?)\s+"
    r"\[Priority: (?P<prio>\d+)\] \{(?P<proto>[A-Z]+)\} (?P<src>\S+) -> (?P<dst>\S+)$")
# arpwatch journal canonical: Oct 22 18:00:01 host arpwatch[247]: new station 10.0.0.5 (0:1:2:3:4:5)
_ARPW = _re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+\d{2}:\d{2}:\d{2}\s+\S+\s+arpwatch\[\d+\]: (?P<msg>.*)$")
# auditd canonical: type=SYSCALL msg=audit(1690000000.000:111): arch=c000003e ...
_AUDIT = _re.compile(r"^type=(?P<type>\S+) msg=audit\((?P<raw>[0-9:.]+):\d+\): (?P<rest>.*)$")
# rkhunter canonical: [18:00:00]   Warning: <text>
_RKH = _re.compile(r"^\[[0-9:]{6,8}\]\s+(?P<what>.*Warning:.*|.*No warnings were found.*|.*Susp.*)$")
# lynis canonical (lynis.log): 2026-10-22 18:00:00 Warning: <text>  /  Lynis version/heading lines
_LYNIS_TS = _re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<what>.*)$")


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _to_utc_iso(raw: str, year: int = 2026) -> Optional[str]:
    """Best-effort parse of a raw timestamp to ISO-8601 UTC; None -> fallback."""
    raw = raw.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y:%m:%d %H:%M:%S"):
        try:
            return _dt.datetime.strptime(raw, fmt).replace(tzinfo=_dt.timezone.utc).isoformat()
        except ValueError:
            pass
    # syslog month-day form: "Oct 22 18:00:01"
    try:
        parsed = _dt.datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=_dt.timezone.utc).isoformat()
    except (ValueError, IndexError):
        pass
    # epoch float (auditd)
    try:
        return _dt.datetime.fromtimestamp(float(raw), _dt.timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        pass
    return None


def _ev(tool: str, severity: str, text: str, ts: Optional[str],
        **kw) -> Event:
    return Event(from_tool=tool, severity=severity, text=text,
                 ts=ts or _utcnow_iso(), **kw)


# ── responders / JSON-line family ───────────────────────────────────────

def _jsonl(tool: str, line: str, high: set, default: str) -> Optional[Event]:
    try:
        d = _json.loads(line)
        if not isinstance(d, dict):
            return None
    except (_json.JSONDecodeError, TypeError, UnicodeDecodeError):
        return None
    action = d.get("action")
    if not action or not isinstance(action, str):
        return None
    # *_watch = the responder merely echoing a watcher observation — routine
    # noise (owner 2026-10-23: never displayed); the real watcher's own lane
    # already carries the substance.
    sev = "HIGH" if action in high else default
    detail = str(d.get("detail", ""))[:500]
    return _ev(tool, sev, f"{action}: {detail}".strip(": "), _to_utc_iso(str(d.get("ts", ""))))


def parse_responderd(line: str) -> Optional[Event]:
    return _jsonl("responderd", line, RESPONDERD_HIGH, "INFO")


def parse_secops_mcp(line: str) -> Optional[Event]:
    return _jsonl("secops-mcp", line, set(), "INFO")


_FRESHCLAM_UPD = _re.compile(r"(?:ClamAV\s+)?updated.*?(?:version\s+(\d+)|database .* is up-to-date)", _re.I)


def parse_freshclam(line: str) -> Optional[Event]:
    """freshclam's real log lines (root-readable only; the daemon tails)."""
    if not line or "up-to-date" not in line.lower() and "updated" not in line.lower():
        return None
    m = _re.search(r"ClamAV (\S+)", line)
    text = (f"Virus definitions updated to "
            f"{m.group(1) if m else 'the latest database'}" if "updated" in line.lower()
            else "Virus definitions are up to date.")
    return _ev("freshclam", "INFO", text, None)


def parse_tetragon(line: str) -> Optional[Event]:
    """tetra-relay tail: {"ts","raw_time","binary","pid","uid","parent","args"}."""
    try:
        d = _json.loads(line)
        if not isinstance(d, dict):
            return None
    except (_json.JSONDecodeError, TypeError, UnicodeDecodeError):
        return None
    binary = d.get("binary")
    if not binary or not isinstance(binary, str):
        return None
    args = str(d.get("args", ""))[:160]
    return _ev("tetragon", "INFO", f"exec {binary} pid={d.get('pid')} {args}".rstrip(),
               _to_utc_iso(str(d.get("ts", ""))))


# ── yara / clamav ────────────────────────────────────────────────────────

def _parse_yara(tool: str, line: str) -> Optional[Event]:
    """REAL: `eicar /tmp/eicar-rt2.txt (realtime sha256:275a021bbfb6489e)`."""
    line = line.strip()
    if not line:
        return None
    parts = line.split(None, 1)
    if len(parts) != 2:
        return None
    rule, rest = parts
    if not _re.fullmatch(r"[A-Za-z0-9_:+.-]{2,64}", rule) or not rest.startswith("/"):
        return None
    return _ev(tool, "HIGH", f"rule {rule} matched {rest.strip()}", None)


def parse_yara_watch(line: str) -> Optional[Event]:
    return _parse_yara("yara-watch", line)


def parse_yara_tmp_scan(line: str) -> Optional[Event]:
    return _parse_yara("yara-tmp-scan", line)


def parse_clamav(line: str) -> Optional[Event]:
    """REAL: summary block `Infected files: 0`; also clamdscan `path FOUND`."""
    line = line.strip()
    if line.endswith("FOUND"):
        path = line[:-len("FOUND")].strip() or "<unknown>"
        return _ev("clamav", "HIGH", f"FOUND {path}", None)
    m = _re.match(r"^Infected files: (?P<n>\d+)$", line)
    if m:
        n = int(m.group("n"))
        return _ev("clamav", "HIGH" if n > 0 else "INFO",
                   f"scan summary: infected files {n}", None)
    return None


# ── fail2ban / ufw / suricata ────────────────────────────────────────────

def parse_fail2ban(line: str) -> Optional[Event]:
    m = _F2B.match(line.strip())
    if not m:
        return None
    act, jail, ip = m.group("act"), m.group("jail"), m.group("ip")
    sev = "HIGH" if act in ("Ban", "Restore Ban") else ("INFO" if act == "Unban" else "MEDIUM")
    return _ev("fail2ban", sev, f"{act} in jail [{jail}] — {ip}",
               _to_utc_iso(m.group("date")))


def parse_ufw(line: str) -> Optional[Event]:
    line = line.strip()
    if "[UFW" not in line:
        return None
    m = _UFW.match(line)
    if not m:
        return None
    act, rest = m.group("act"), m.group("rest")
    sev = "MEDIUM" if act == "BLOCK" else ("HIGH" if act == "BLOCK_UNKNOWN" else "INFO")
    src = _re.search(r"SRC=(\S+)", rest)
    dst = _re.search(r"DST=(\S+)", rest)
    text = f"UFW {act.removeprefix('UFW ')} {'-> '.join(p for p in (src.group(1) if src else None, dst.group(1) if dst else None) if p) or rest[:120]}"
    return _ev("ufw", sev, text, None)


def parse_suricata(line: str) -> Optional[Event]:
    m = _SURI.match(line.strip())
    if not m:
        return None
    prio = int(m.group("prio"))
    sev = "HIGH" if prio <= 2 else "MEDIUM"
    try:
        ts = _dt.datetime.strptime(m.group("date"), "%m/%d/%Y-%H:%M:%S.%f") \
            .replace(tzinfo=_dt.timezone.utc).isoformat()
    except ValueError:
        ts = None
    return _ev("suricata", sev, f"{m.group('msg')} {m.group('src')} -> {m.group('dst')}", ts)


# ── appfw ────────────────────────────────────────────────────────────────

_APPFW_LINE = _re.compile(
    r"appfw (?P<prog>\S+) → (?P<dst>\S+) (?P<act>allow|deny) \[(?P<note>.*)\]")


def parse_appfw(line: str) -> Optional[Event]:
    """REAL data/appfw/events.jsonl lines written by the engine mirror."""
    clean = _ANSI.sub("", line).strip()
    m = _APPFW_LINE.search(clean)
    if not m:
        return None
    act = m.group("act").lower()
    sev = "INFO" if act == "allow" else "MEDIUM"
    return _ev("appfw", sev,
               f"{act} {m.group('prog')} → {m.group('dst')} "
               f"({m.group('note').strip()})", None)


# ── net-watch (the in-daemon light IDS) ──────────────────────────────────

_NETWATCH_LINE = _re.compile(r"^netwatch (\w+) (.*)")


def parse_netwatch(line: str) -> Optional[Event]:
    """REAL data/netwatch-events.jsonl lines written by the daemon mirror."""
    m = _NETWATCH_LINE.match(line.strip())
    if not m:
        return None
    sev = m.group(1) if m.group(1) in ("HIGH", "MEDIUM", "CRITICAL") \
        else "INFO"
    return _ev("net-watch", sev, f"{m.group(2).strip()}", None)


# ── arpwatch / aide / apparmor / lynis / rkhunter / auditd ───────────────

_ARPW_HIGH_MEDIUM = ("flip flop", "flipped", "changed ethernet address", "bogon")


def parse_arpwatch(line: str) -> Optional[Event]:
    m = _ARPW.match(line.strip())
    if not m:
        return None
    msg = m.group("msg")
    low = msg.lower()
    if "new station" in low:
        sev = "INFO"
    elif any(k in low for k in _ARPW_HIGH_MEDIUM):
        sev = "MEDIUM"
    else:
        return None  # heartbeat/noise lines are not events
    ts_raw = f"{m.group('mon')} {m.group('day')} "
    ts = _to_utc_iso(ts_raw + "00:00:00")
    return _ev("arpwatch", sev, msg, None if not ts else ts)


def parse_aide(line: str) -> Optional[Event]:
    low = line.strip().lower()
    if "no differences" in low:
        return _ev("aide", "INFO", "AIDE: no differences", None)
    if "differences found" in low:
        return _ev("aide", "HIGH", line.strip()[:200], None)
    if "no differences" in low or low.endswith("checked"):
        return _ev("aide", "INFO", "AIDE: no differences", None)
    return None


_APPARMOR_AVC = _re.compile(r"apparmor=\"(?P<status>DENIED|ALLOWED)\".*?(?P<profile>profile=\"[^\"]*\")?.*?(?P<comm>comm=\"[^\"]*\")?")


def parse_apparmor(line: str) -> Optional[Event]:
    m = _APPARMOR_AVC.search(line)
    if not m or m.group("status") != "DENIED":
        return None
    ts = _AUDIT.search(line)
    return _ev("apparmor", "MEDIUM",
               f"AppArmor DENIED {m.group('profile') or ''} {m.group('comm') or ''}".strip(),
               None)


def parse_lynis(line: str) -> Optional[Event]:
    m = _LYNIS_TS.match(line.strip())
    if not m:
        return None
    what = m.group("what")
    if what.startswith("Warning"):
        return _ev("lynis", "MEDIUM", what[:200], _to_utc_iso(m.group("date")))
    return None


def parse_rkhunter(line: str) -> Optional[Event]:
    line = line.strip()
    m = _RKH.match(line)
    if not m:
        return None
    what = m.group("what").strip()
    if what.startswith("Warning"):
        return _ev("rkhunter", "HIGH", what[:200], None)
    if "Susp" in what:
        return _ev("rkhunter", "HIGH", what[:200], None)
    return _ev("rkhunter", "INFO", what[:200], None)


def parse_auditd(line: str) -> Optional[Event]:
    """Canonical audit.log. grey cannot read live — canonical fixture, G2.4."""
    m = _AUDIT.match(line.strip())
    if not m:
        return None
    ts = _to_utc_iso(m.group("raw").split(":")[0])
    rtype = m.group("type")
    sev = "MEDIUM" if ("DENIED" in m.group("rest") or rtype == "ANOM_ABEND") else "INFO"
    return _ev("auditd", sev, f"{rtype} {m.group('rest')[:160]}", ts)


PARSERS = {
    "net-watch": None,          # synthetic: the daemon's own analyzer
    "cve-updater": None,        # synthetic: mirrored from the cache
    "freshclam": parse_freshclam,
    "responderd": parse_responderd,
    "tetragon": parse_tetragon,
    "yara-watch": parse_yara_watch,
    "yara-tmp-scan": parse_yara_tmp_scan,
    "clamav": parse_clamav,
    "fail2ban": parse_fail2ban,
    "ufw": parse_ufw,
    "auditd": parse_auditd,
    "appfw": parse_appfw,
    "net-watch": parse_netwatch,
    "arpwatch": parse_arpwatch,
    "aide": parse_aide,
    "apparmor": parse_apparmor,
    "freshclam": parse_freshclam,
    "lynis": parse_lynis,
    "rkhunter": parse_rkhunter,
}


def _safe(fn):
    """The never-raise backstop (G2.2): any input type, any bug → None."""
    def wrapped(line):
        if not isinstance(line, str):
            return None
        try:
            return fn(line)
        except Exception:
            return None
    return wrapped


PARSERS = {name: _safe(fn) for name, fn in PARSERS.items()}