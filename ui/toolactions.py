from __future__ import annotations

SERVICE = {
    "responderd": "responderd.service",
    "tetragon": "tetragon.service",
    "fail2ban": "fail2ban.service",
    "ufw": "ufw.service",
    "auditd": "auditd.service",
    "apparmor": "apparmor.service",
    "arpwatch": "arpwatch@{iface}.service",
    "psad": "psad.service",
    "yara-watch": "yara-watch.service",
    "freshclam": "clamav-freshclam.service",
}
SCAN = {"rkhunter": "rkhunter", "lynis": "lynis", "aide": "aide",
        "yara-tmp-scan": "yara-tmp-scan"}
SHARED = {"appfw", "net-watch"}
SPECIAL = {"cve-updater": "greywatch-cve.service"}


def actions_for(tool_ids):
    out = []
    for tid in tool_ids:
        if tid in SCAN:
            out.append({"label": "Run check", "kind": "check",
                        "scan_key": SCAN[tid]})
        elif tid in SHARED:
            out.append({"label": "Restart GreyWatch", "kind": "restart",
                        "unit": "greywatch.service"})
        elif tid in SPECIAL:
            out.append({"label": "Refresh now", "kind": "restart",
                        "unit": SPECIAL[tid]})
        elif tid in SERVICE:
            unit = SERVICE[tid]
            out.extend([
                {"label": "Start", "kind": "start", "unit": unit},
                {"label": "Stop", "kind": "stop", "unit": unit},
                {"label": "Restart", "kind": "restart", "unit": unit},
            ])
        if tid == "freshclam":
            out.append({"label": "Update now", "kind": "restart",
                        "unit": "clamav-freshclam.service"})
    return out


def helper_args(action):
    return [action["kind"], action["unit"]]
