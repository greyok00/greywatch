from __future__ import annotations

import datetime as _dt
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CVE_CACHE = ROOT / "data" / "cve-cache.json"
CLAM_DIR = pathlib.Path("/var/lib/clamav")
STALE_DAYS = 8            # the CVE list is refreshed weekly


def clamav_definitions() -> dict | None:
    newest = None
    try:
        for p in CLAM_DIR.glob("*.c[dl]d"):
            try:
                m = p.stat().st_mtime
            except OSError:
                continue
            if newest is None or m > newest[0]:
                newest = (m, p.name)
    except OSError:
        return None
    if newest is None:
        return None
    return {"ts": _dt.datetime.fromtimestamp(
                newest[0], _dt.timezone.utc).isoformat(timespec="seconds"),
            "file": newest[1]}


def cve_list() -> dict | None:
    try:
        data = json.loads(CVE_CACHE.read_text())
    except (OSError, ValueError):
        return None
    entries = data.get("entries") or []
    return {"ts": data.get("fetched_utc"), "count": len(entries),
            "reason": data.get("reason")}


def summary() -> dict:
    return {"clamav": clamav_definitions(), "cve": cve_list()}


def _age(iso) -> _dt.timedelta | None:
    try:
        when = _dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    return _dt.datetime.now(_dt.timezone.utc) - when


def cve_is_fresh() -> bool:
    info = cve_list()
    age = _age(info.get("ts")) if info else None
    return age is not None and age.days < STALE_DAYS


def human_stamp(iso) -> str:
    try:
        when = _dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    local = when.astimezone()
    today = _dt.datetime.now().astimezone().date()
    if local.date() == today:
        return "today " + local.strftime("%H:%M")
    return local.strftime("%b %d %H:%M")


def refresh_cve(timeout=240) -> tuple:
    try:
        out = subprocess.run(
            [sys.executable, str(ROOT / "cve-refresh.py")],
            capture_output=True, text=True, timeout=timeout)
        msg = (out.stdout or out.stderr or "").strip().splitlines()
        return out.returncode, (msg[-1] if msg else "")
    except (OSError, subprocess.SubprocessError) as e:
        return -1, str(e)
