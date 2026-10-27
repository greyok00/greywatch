from __future__ import annotations

import datetime as _dt
import json as _json
import re as _re
from typing import Optional

from events import Event

RESPONDERD_HIGH = {"kill", "delete", "firewall_drop", "quarantine"}

_ANSI = _re.compile(r"(?:\x1b)?\[[0-9;]{1,6}m")

_F2B = _re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ fail2ban\.actions\s*\[\d+\]: "
    r"(?P<lvl>NOTICE|WARNING|INFO)\s*\[(?P<jail>[A-Za-z0-9_-]+)\] (?P<act>Ban|Unban|Restore Ban|Found) (?P<ip>\S+)$")
_UFW = _re.compile(r"^\[\s*[0-9.]+\s*\] \[UFW (?P<act>[A-Z_]+)\] (?P<rest>.*)$")
_ARPW = _re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+\d{2}:\d{2}:\d{2}\s+\S+\s+arpwatch\[\d+\]: (?P<msg>.*)$")
_AUDIT = _re.compile(r"^type=(?P<type>\S+) msg=audit\((?P<raw>[0-9:.]+):\d+\): (?P<rest>.*)$")
_RKH = _re.compile(r"^\[[0-9:]{6,8}\]\s+(?P<what>.*Warning:.*|.*No warnings were found.*|.*Susp.*)$")
_LYNIS_TS = _re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<what>.*)$")


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _to_utc_iso(raw: str, year: int = 2026) -> Optional[str]:
    raw = raw.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y:%m:%d %H:%M:%S"):
        try:
            return _dt.datetime.strptime(raw, fmt).replace(tzinfo=_dt.timezone.utc).isoformat()
        except ValueError:
            pass
    try:
        parsed = _dt.datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=_dt.timezone.utc).isoformat()
    except (ValueError, IndexError):
        pass
    try:
        return _dt.datetime.fromtimestamp(float(raw), _dt.timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        pass
    return None


def _ev(tool: str, severity: str, text: str, ts: Optional[str],
        **kw) -> Event:
    return Event(from_tool=tool, severity=severity, text=text,
                 ts=ts or _utcnow_iso(), **kw)



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
    sev = "HIGH" if action in high else default
    detail = str(d.get("detail", ""))[:500]
    return _ev(tool, sev, f"{action}: {detail}".strip(": "), _to_utc_iso(str(d.get("ts", ""))))


def parse_responderd(line: str) -> Optional[Event]:
    return _jsonl("responderd", line, RESPONDERD_HIGH, "INFO")


def parse_secops_mcp(line: str) -> Optional[Event]:
    return _jsonl("secops-mcp", line, set(), "INFO")


_FRESHCLAM_UPD = _re.compile(r"(?:ClamAV\s+)?updated.*?(?:version\s+(\d+)|database .* is up-to-date)", _re.I)


def parse_freshclam(line: str) -> Optional[Event]:
    if not line or "up-to-date" not in line.lower() and "updated" not in line.lower():
        return None
    m = _re.search(r"ClamAV (\S+)", line)
    text = (f"Virus definitions updated to "
            f"{m.group(1) if m else 'the latest database'}" if "updated" in line.lower()
            else "Virus definitions are up to date.")
    return _ev("freshclam", "INFO", text, None)


def parse_tetragon(line: str) -> Optional[Event]:
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



def _parse_yara(tool: str, line: str) -> Optional[Event]:
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



_APPFW_LINE = _re.compile(
    r"appfw (?P<prog>\S+) → (?P<dst>\S+) (?P<act>allow|deny) \[(?P<note>.*)\]")


def parse_appfw(line: str) -> Optional[Event]:
    clean = _ANSI.sub("", line).strip()
    m = _APPFW_LINE.search(clean)
    if not m:
        return None
    act = m.group("act").lower()
    sev = "INFO" if act == "allow" else "MEDIUM"
    return _ev("appfw", sev,
               f"{act} {m.group('prog')} → {m.group('dst')} "
               f"({m.group('note').strip()})", None)



_NETWATCH_LINE = _re.compile(r"^netwatch (\w+) (.*)")


def parse_netwatch(line: str) -> Optional[Event]:
    m = _NETWATCH_LINE.match(line.strip())
    if not m:
        return None
    sev = m.group(1) if m.group(1) in ("HIGH", "MEDIUM", "CRITICAL") \
        else "INFO"
    return _ev("net-watch", sev, f"{m.group(2).strip()}", None)



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
    m = _AUDIT.match(line.strip())
    if not m:
        return None
    ts = _to_utc_iso(m.group("raw").split(":")[0])
    rtype = m.group("type")
    sev = "MEDIUM" if ("DENIED" in m.group("rest") or rtype == "ANOM_ABEND") else "INFO"
    return _ev("auditd", sev, f"{rtype} {m.group('rest')[:160]}", ts)


PARSERS = {
    "cve-updater": None,        # synthetic: mirrored from the cache
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
    def wrapped(line):
        if not isinstance(line, str):
            return None
        try:
            return fn(line)
        except Exception:
            return None
    return wrapped


PARSERS = {name: _safe(fn) for name, fn in PARSERS.items()}
