from __future__ import annotations


# Tool icons live in ui/toolicons.py and assets/icons/tools/ — one drawn
# symbolic per protection, no emoji.

SCAN_MODES = [
    {"key": "full", "scope": "root", "icon": "system-run-symbolic",
     "title": "Full scan", "short": "Full scan",
     "run_note": "running throttled - CPU and memory are capped so you can "
                 "keep working",
     "about": "Runs every scanner in turn: antivirus, rootkit, audit, integrity, then a temp-folder sweep. Throttled by default - CPU and memory are capped so the desktop stays usable."},
    {"key": "max-speed", "scope": "root", "icon": "system-run-symbolic",
     "title": "Full scan at max speed", "short": "Max speed",
     "run_note": "running at full speed - the desktop may lag while it scans",
     "about": "The same scan with the CPU and memory caps removed for this one run. The desktop may lag while it scans; best when you are away from the desk. Asks before it starts."},
    {"key": "yara-tmp-scan", "unit": "yara-tmp-scan.service", "scope": "user",
     "icon": "gw-tool-yara-tmp-scan-symbolic", "title": "Quick scan", "short": "Quick scan",
     "run_note": "running throttled",
     "about": "Scans the temporary folder for threats. Takes seconds."},
    {"key": "clamav", "scope": "root", "proc": "clamscan", "hidden": True,
     "icon": "gw-tool-clamav-symbolic", "title": "Deep antivirus scan", "short": "Antivirus",
     "run_note": "running throttled - CPU and memory are capped so you can keep working",
     "about": "Deep antivirus scan of the home and temporary folders, throttled by default."},
    {"key": "rkhunter", "unit": "rkhunter-scan.service", "scope": "root",
     "proc": "rkhunter",
     "icon": "gw-tool-rkhunter-symbolic", "title": "Rootkit scan", "short": "Rootkit",
     "run_note": "running throttled",
     "about": "Checks system internals for hidden rootkits."},
    {"key": "lynis", "unit": "lynis-audit.service", "scope": "root",
     "proc": "lynis",
     "icon": "gw-tool-lynis-symbolic", "title": "Security audit", "short": "Audit",
     "run_note": "running throttled",
     "about": "Scores security and lists what to improve."},
    {"key": "aide", "unit": "aide-check.service", "scope": "root",
     "icon": "gw-tool-aide-symbolic", "title": "File-integrity check", "short": "Integrity",
     "run_note": "running throttled",
     "about": "Detects changes to system files."},
    # The scan-all legacy key stays VALID — chat phrasing like "scan my
    # computer" has mapped to it for ages, and upgrade-installed clients
    # may still send it. It is hidden: it means the
    # same throttled run Full scan already offers.
    {"key": "scan-all", "scope": "root", "hidden": True,
     "icon": "system-run-symbolic", "title": "Full scan", "short": "Full scan",
     "run_note": "running throttled - CPU and memory are capped so you can "
                 "keep working",
     "about": "Every scanner in turn, throttled - the same run Full scan "
              "starts."},
]

# The strip shows the three customer choices; per-tool and legacy keys
# stay resolvable for the protection rows, chat, and upgrades.
STRIP_MODES = [m for m in SCAN_MODES if not m.get("hidden")]


def quiet_note(tool: str, minutes_since_activity: int | None) -> str:
    if minutes_since_activity is None:
        return "No events yet."
    if minutes_since_activity <= 15:
        return ""
    if tool == "rkhunter" and minutes_since_activity > 1440:
        return "Never scanned. Use Scan now."
    return f"Last activity {minutes_since_activity} min ago"
