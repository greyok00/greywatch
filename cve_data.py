"""Package-aware CVE matching against the Debian Security Tracker.

The old feed was five NVD keyword searches, so it could not say which
installed package was affected or what version fixed it. This module
reads the tracker's package-keyed JSON, compares the installed dpkg
version with the suite's fixed version, and returns only rows that are
still open on this machine.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
DEFAULT_SUITE = "trixie"

_URGENCY = {
    "emergency": ("CRITICAL", 9.5),
    "high": ("HIGH", 8.0),
    "medium": ("MEDIUM", 5.0),
    "low": ("LOW", 2.0),
    "unimportant": ("LOW", 1.0),
}

_TOOL_PREFIX = (
    (("linux",), "kernel"),
    (("clamav",), "clamav"),
    (("fail2ban",), "fail2ban"),
    (("psad",), "psad"),
    (("nftables", "iptables", "netfilter"), "appfw"),
)


def _apt():
    try:
        import apt_pkg
        try:
            apt_pkg.init_system()
        except Exception:                 # noqa: BLE001
            pass
        return apt_pkg
    except Exception:                     # noqa: BLE001
        return None


def version_compare(a, b):
    """Debian version order: <0, 0, >0; None when no comparator."""
    apt = _apt()
    if apt is not None:
        try:
            return apt.version_compare(str(a), str(b))
        except Exception:                 # noqa: BLE001
            pass
    return None


def version_ge(a, b) -> bool:
    result = version_compare(a, b)
    return result is not None and result >= 0


def installed_packages(query: str | None = None) -> dict:
    """binary package -> {version, source}; source names are unwrapped."""
    if query is not None:
        out = query
    else:
        cmd = [os.environ.get("DPKG_QUERY_BIN", "/usr/bin/dpkg-query"),
               "-W", "-f=${Package}\t${Version}\t${Source}\n"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=60).stdout
        except (OSError, subprocess.SubprocessError):
            return {}
    found = {}
    for line in str(out or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        package, version = parts[0], parts[1]
        source = parts[2] if len(parts) > 2 and parts[2] else package
        source = re.sub(r"\s*\(.*\)$", "", source).strip() or package
        found[package] = {"version": version, "source": source}
    return found


def fixed_for(release, suite: str):
    """The suite's fixed version; tracker uses "0" when the repo carries it."""
    if not isinstance(release, dict):
        return None
    fixed = release.get("fixed_version")
    if fixed in (None, "", "0"):
        fixed = (release.get("repositories") or {}).get(suite)
    return str(fixed).strip() if fixed else None


def severity_for(release) -> tuple[str, float]:
    urgency = str((release or {}).get("urgency") or "").lower()
    return _URGENCY.get(urgency, ("MEDIUM", 5.0))


def tool_for(source: str) -> str:
    name = str(source or "")
    for prefixes, tool in _TOOL_PREFIX:
        if any(name.startswith(prefix) for prefix in prefixes):
            return tool
    return name or "package"


def open_rows(tracker, installed: dict, suite: str) -> list:
    """Only installed packages whose version is below the suite fix."""
    rows = []
    for package, info in installed.items():
        source = info.get("source") or package
        cves = tracker.get(source) if isinstance(tracker, dict) else None
        if not isinstance(cves, dict):
            continue
        for cve_id, record in cves.items():
            if not isinstance(record, dict):
                continue
            release = (record.get("releases") or {}).get(suite)
            if not isinstance(release, dict):
                continue
            status = str(release.get("status") or "").lower()
            if status in ("not-affected", "undetermined"):
                continue
            fixed = fixed_for(release, suite)
            if fixed and version_ge(info.get("version", ""), fixed):
                continue                  # installed at or above the fix
            severity, score = severity_for(release)
            rows.append({
                "id": str(cve_id),
                "package": package,
                "source": source,
                "installed": str(info.get("version") or ""),
                "fixed": fixed or "",
                "severity": severity,
                "score": score,
                "tool": tool_for(source),
                "summary": str(record.get("description") or "")[:220],
                "status": status or "open",
            })
    return rows


def tracker_from_text(text: str):
    import json
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def tracker_from_file(path):
    try:
        return tracker_from_text(pathlib.Path(path).read_text())
    except OSError:
        return None
