from __future__ import annotations


# Tool icons live in ui/toolicons.py and assets/icons/tools/ — one drawn
# symbolic per protection, no emoji.

SCAN_MODES = [
    {"key": "scan-all", "scope": "root", "helper": "tool-control",
     "icon": "system-run-symbolic", "title": "Scan everything",
     "about": "Runs every scanner at once: antivirus, rootkit, audit, integrity, and a temp-folder sweep. One click, one password."},
    {"key": "yara-tmp-scan", "unit": "yara-tmp-scan.service", "scope": "user",
     "icon": "gw-tool-yara-tmp-scan-symbolic", "title": "Quick scan",
     "about": "Scans the temporary folder for threats. Takes seconds."},
    {"key": "clamav", "scope": "root", "proc": "clamscan",
     "icon": "gw-tool-clamav-symbolic", "title": "Full antivirus scan",
     "about": "Deep scan of the home and temporary folders."},
    {"key": "rkhunter", "unit": "rkhunter-scan.service", "scope": "root",
     "proc": "rkhunter",
     "icon": "gw-tool-rkhunter-symbolic", "title": "Rootkit scan",
     "about": "Checks system internals for hidden rootkits."},
    {"key": "lynis", "unit": "lynis-audit.service", "scope": "root",
     "proc": "lynis",
     "icon": "gw-tool-lynis-symbolic", "title": "Security audit",
     "about": "Scores security and lists what to improve."},
    {"key": "aide", "unit": "aide-check.service", "scope": "root",
     "icon": "gw-tool-aide-symbolic", "title": "File-integrity check",
     "about": "Detects changes to system files."},
]


SEV_WORDS = {"HIGH": "At risk", "CRITICAL": "Critical",
             "MEDIUM": "Worth knowing", "INFO": "Protected"}
SEV_COLORS = {"HIGH": "#ff5a52", "CRITICAL": "#ff5a52",
              "MEDIUM": "#ffc940", "INFO": "#4dd07a"}


NORMAL_QUIET = {
    "clamav": "a full scan daily (evenings)", "aide": "a check daily",
    "yara-watch": "continuous; finds appear only when something matches",
    "yara-tmp-scan": "every 15 minutes",
    "lynis": "an audit nightly", "rkhunter": "manual only: press Scan now",
    "arpwatch": "events only when devices change",
}


def quiet_note(tool: str, minutes_since_activity: int | None) -> str:
    if minutes_since_activity is None:
        return "No events yet."
    if minutes_since_activity <= 15:
        return ""
    if tool == "rkhunter" and minutes_since_activity > 1440:
        return "Never scanned. Use Scan now."
    return f"Last activity {minutes_since_activity} min ago"


def card_subtitle(state: str, plain_event: str, quiet: str = "") -> str:
    if state == "GREEN":
        return plain_event or "Protected"
    if state == "YELLOW":
        return plain_event or "At risk"
    if state == "RED":
        return plain_event or "Critical"
    if state == "UNKNOWN":
        return plain_event or "Status not reported"
    return "Not run yet"
