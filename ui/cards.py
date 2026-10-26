"""Card models + the manual-scan runner (2026-10-23 rebuild).

Reference: ~/Desktop/SECIMAGES (Total Defense / Avira) — icon rail, big
status card, big action buttons, progress circles. This module holds the
TESTABLE half: card specs per tool, scan-runner state (real systemd unit
starts + log-follow + elapsed + plain-English result), and the
plain-sentence card subtitle. No GTK here.
"""
from __future__ import annotations

import subprocess
import threading
import time

CARD_ICONS = {
    "responderd": "🛡", "tetragon": "👁", "yara-watch": "🧪",
    "yara-tmp-scan": "🧪", "clamav": "🦠", "fail2ban": "🚫", "ufw": "🔒",
    "auditd": "📜", "suricata": "📣", "appfw": "🌐", "arpwatch": "📶",
    "aide": "🔏", "apparmor": "🚧", "lynis": "📋", "rkhunter": "🔍",
    "net-watch": "🛰", "cve-updater": "🔄", "freshclam": "⬇",
    "secops-mcp": "🤝",
}

# the manual scan modes: (tool, unit to start, scope, what it does in words)
SCAN_MODES = [
    {"key": "yara-tmp-scan", "unit": "yara-tmp-scan.service", "scope": "user",
     "icon": "🧪", "title": "Quick scan",
     "about": "Scans the temporary folder for threats. Takes seconds."},
    {"key": "clamav", "scope": "root", "proc": "clamscan",
     "icon": "🦠", "title": "Full antivirus scan",
     "about": "Deep scan of the home and temporary folders."},
    {"key": "rkhunter", "unit": "rkhunter-scan.service", "scope": "root",
     "proc": "rkhunter",
     "icon": "🔍", "title": "Rootkit scan",
     "about": "Checks system internals for hidden rootkits."},
    {"key": "lynis", "unit": "lynis-audit.service", "scope": "root",
     "proc": "lynis",
     "icon": "📋", "title": "Security audit",
     "about": "Scores security and lists what to improve."},
    {"key": "aide", "unit": "aide-check.service", "scope": "root",
     "icon": "🔏", "title": "File-integrity check",
     "about": "Detects changes to system files."},
]


SEV_WORDS = {"HIGH": "At risk", "CRITICAL": "Critical",
             "MEDIUM": "Worth knowing", "INFO": "Protected"}
SEV_COLORS = {"HIGH": "#ff5a52", "CRITICAL": "#ff5a52",
              "MEDIUM": "#ffc940", "INFO": "#4dd07a"}


# schedule truth (verified 2026-10-23): what silence is NORMAL per tool
NORMAL_QUIET = {
    "clamav": "a full scan daily (evenings)", "aide": "a check daily",
    "yara-watch": "continuous; finds appear only when something matches",
    "yara-tmp-scan": "every 15 minutes",
    "lynis": "an audit nightly", "rkhunter": "manual only: press Scan now",
    "arpwatch": "events only when devices change",
}


def quiet_note(tool: str, minutes_since_activity: int | None) -> str:
    """The honest quiet line, capped at the dictionary's short form."""
    if minutes_since_activity is None:
        return "No events yet."
    if minutes_since_activity <= 15:
        return ""
    if tool == "rkhunter" and minutes_since_activity > 1440:
        return "Never scanned. Use Scan now."
    return f"Last activity {minutes_since_activity} min ago"


def card_subtitle(state: str, plain_event: str, quiet: str = "") -> str:
    """The one line a card shows: the status word + the latest plain event."""
    if state == "GREEN":
        return plain_event or "Protected"
    if state == "YELLOW":
        return plain_event or "At risk"
    if state == "RED":
        return plain_event or "Critical"
    if state == "UNKNOWN":
        return plain_event or "Status not reported"
    return "Not run yet"