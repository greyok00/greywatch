"""One icon language for every protection.

The dashboard used emoji per tool (🦠 for the antivirus, 🌐 for the app
firewall). Emoji render differently on every machine, ignore the theme's
ink colour, and read as decoration rather than status. These are drawn
symbols instead: 24x24, one stroke weight, no fill, tinted by the theme's
text colour because they are installed as *-symbolic icons.

The mapping is name -> icon name. Anything unmapped falls back to a plain
shield so a new registry entry never renders a blank cell.
"""
from __future__ import annotations

FALLBACK = "gw-tool-responderd-symbolic"

ICONS = {
    "responderd": "gw-tool-responderd-symbolic",
    "tetragon": "gw-tool-tetragon-symbolic",
    "yara-watch": "gw-tool-yara-watch-symbolic",
    "yara-tmp-scan": "gw-tool-yara-tmp-scan-symbolic",
    "clamav": "gw-tool-clamav-symbolic",
    "fail2ban": "gw-tool-fail2ban-symbolic",
    "ufw": "gw-tool-ufw-symbolic",
    "auditd": "gw-tool-auditd-symbolic",
    "appfw": "gw-tool-appfw-symbolic",
    "arpwatch": "gw-tool-arpwatch-symbolic",
    "aide": "gw-tool-aide-symbolic",
    "apparmor": "gw-tool-apparmor-symbolic",
    "lynis": "gw-tool-lynis-symbolic",
    "rkhunter": "gw-tool-rkhunter-symbolic",
    "net-watch": "gw-tool-net-watch-symbolic",
    "cve-updater": "gw-tool-cve-updater-symbolic",
    "freshclam": "gw-tool-freshclam-symbolic",
    "secops-mcp": "gw-tool-secops-mcp-symbolic",
}


def icon_name(tool: str) -> str:
    return ICONS.get(tool, FALLBACK)


def has_icon(tool: str) -> bool:
    return tool in ICONS
