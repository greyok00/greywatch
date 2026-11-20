# ui/labels.py
from __future__ import annotations

import re

_PARENTHETICAL = re.compile(r"\s*\([^)]*\)")
_TOOL = {
    "GREEN": ("Live", "ok"),
    "YELLOW": ("Attention", "warn"),
    "RED": ("Down", "fail"),
    "ON_DEMAND": ("On demand", "ok"),
}
# The Baseline verifier writes its verdicts as tokens too; a row that
# carries a probe result such as "active=inactive enabled=disabled"
# must read as a sentence, never as the probe's own string.
_BASELINE = {
    "ENABLED": ("Enabled", "ok"),
    "PRESENT": ("Present", "ok"),
    "ARMED": ("Armed", "ok"),
    "FRESH": ("Fresh", "ok"),
    "OFF-BY-DESIGN": ("Off by design", "mute"),
    "GAP": ("Gap", "fail"),
    "CANT-CHECK": ("Cannot check", "warn"),
}
_SCAN = {
    "idle": ("Idle", "mute"),
    "starting": ("Starting", "warn"),
    "running": ("Running", "warn"),
    "paused": ("Paused", "warn"),
    "cancelling": ("Cancelling", "warn"),
    "cancelled": ("Cancelled", "fail"),
    "failed": ("Failed", "fail"),
    "done": ("Finished", "ok"),
}
_NAMES = {
    "yara-watch": "YARA Watch",
    "yara-tmp-scan": "YARA Sweep",
    "clamav": "Antivirus",
    "freshclam": "Signatures",
    "cve-updater": "Intel",
    "net-watch": "Net Watch",
    "psad": "Port Scan Watch",
    "appfw": "App Firewall",
}


def posture(score) -> tuple[str, str]:
    if score is None:
        return "Withheld", "warn"
    if score >= 80:
        return "Secure", "ok"
    if score >= 60:
        return "Needs attention", "warn"
    return "At risk", "fail"


def tool_state(token) -> tuple[str, str]:
    return _TOOL.get(str(token or "").upper(), ("Unknown", "mute"))


def scan_state(token) -> tuple[str, str]:
    return _SCAN.get(str(token or "").lower(), ("Idle", "mute"))


def baseline_state(token) -> tuple[str, str]:
    """A baseline verdict as a word. The verifier's raw probe shape
    ("active=inactive enabled=disabled") becomes a sentence."""
    text = str(token or "").strip()
    if text in _BASELINE:
        return _BASELINE[text]
    active = re.search(r"active=(\S+)", text)
    enabled = re.search(r"enabled=(\S+)", text)
    if active or enabled:
        parts = []
        if active:
            parts.append({"active": "Running",
                          "inactive": "Not running",
                          "failed": "Failed"}.get(
                              active.group(1), active.group(1)))
        if enabled:
            parts.append({"enabled": "starts at boot",
                          "disabled": "does not start at boot",
                          "masked": "masked"}.get(
                              enabled.group(1), enabled.group(1)))
        running = active and active.group(1) == "active"
        return "; ".join(parts), ("ok" if running else "warn")
    return (text or "Unknown", "mute")


def span_words(seconds) -> str:
    """A duration in whole words, never a raw number of seconds."""
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return "an unknown time"
    if value < 60:
        return "under a minute"
    if value < 3600:
        minutes = int(round(value / 60))
        return f"{minutes} minute" + ("" if minutes == 1 else "s")
    hours = int(value // 3600)
    minutes = int(round((value % 3600) / 60))
    text = f"{hours} hour" + ("" if hours == 1 else "s")
    if minutes:
        text += f" {minutes} minute" + ("" if minutes == 1 else "s")
    return text


def clean_tool_label(text) -> str:
    return _PARENTHETICAL.sub("", str(text or "")).strip()


def display_name(text) -> str:
    key = str(text or "")
    return _NAMES.get(key, clean_tool_label(key).replace("-", " ").title())
