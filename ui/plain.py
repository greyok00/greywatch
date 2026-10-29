from __future__ import annotations

import re
from xml.sax.saxutils import escape as _xml_escape

FRIENDLY = {
    "responderd": ("Auto-responder", "Reacts automatically when something dangerous appears."),
    "tetragon": ("Program watcher", "Sees every program start, in the kernel."),
    "yara-watch": ("Malware scanner (live)", "Continuously scans files for malware fingerprints."),
    "yara-tmp-scan": ("Malware scanner (scheduled)", "Scans the temporary folder for malware every 15 minutes."),
    "clamav": ("Antivirus", "The classic antivirus engine; runs a full scan once a day."),
    "fail2ban": ("Intrusion blocker", "Locks out computers that hammer you with failed logins."),
    "ufw": ("Firewall", "Decides which network connections may pass at all."),
    "auditd": ("System event log", "The kernel's detailed record of what happened on the system."),
    "appfw": ("App firewall", "Asks before a program connects to the internet (and enforces your answer)."),
    "arpwatch": ("WiFi device watcher", "Tells you about every device that appears on your network."),
    "aide": ("File integrity", "Alerts when system files changed: a tampering tripwire."),
    "apparmor": ("Program jail", "Confines programs so they can only access what they need."),
    "lynis": ("Security auditor", "Periodically grades your security and lists improvements."),
    "rkhunter": ("Rootkit scanner", "Hunts for hidden malware (rootkits) in system internals."),
    "net-watch": ("Network watcher", "Notes new network connections as they happen."),
    "cve-updater": ("Update checker", "Fetches the weekly list of known security flaws."),
    "freshclam": ("Virus definitions", "Keeps the antivirus's malware list current."),
    "secops-mcp": ("Security helper", "The assistant's security-ops bridge."),
}


def escape(text) -> str:
    return _xml_escape(str(text or ""))




def _token(name: str, fallback: str) -> str:
    try:
        from ui import themes
        return themes.CURRENT.get(name, fallback)
    except ImportError:
        return fallback


def ink() -> str:
    return _token("ink", "#dde5f2")


def soft() -> str:
    return _token("ink_soft", "#8b9bb0")


def muted() -> str:
    return _token("mute", "#8b9bb0")


def warn() -> str:
    return _token("warn", "#ffc940")


def ok() -> str:
    return _token("ok", "#4dd07a")


def fail() -> str:
    return _token("fail", "#ff5a52")


def state_colour(state: str, paused: bool = False) -> str:
    """One place that turns a protection state into ink.

    The dashboard had this mapping spelled out with hex literals in three
    views, so a theme change (console green -> obsidian sage) only reached
    whichever copy someone remembered. Paused is a warning, not a failure:
    the owner did that on purpose.
    """
    if paused:
        return warn()
    return {"GREEN": ok(), "RED": fail(), "YELLOW": warn()}.get(
        (state or "").upper(), muted())


def severity_colour(severity: str) -> str:
    sev = (severity or "").upper()
    if sev in ("HIGH", "CRITICAL", "RED"):
        return fail()
    if sev in ("MEDIUM", "WARN", "YELLOW", "AMBER"):
        return warn()
    if sev in ("INFO", "GREEN"):
        return ok()
    return muted()


def severity_word(severity: str) -> str:
    """Plain word for the raw log's state column (emoji removed 2026-10-27)."""
    sev = (severity or "").upper()
    return {"HIGH": "High", "CRITICAL": "Critical", "MEDIUM": "Medium",
            "INFO": "Info", "LOW": "Low"}.get(sev, "—")


_LEAD_MARK = re.compile(r"^[^\w]+")


def without_mark(text) -> str:
    return _LEAD_MARK.sub("", str(text or ""), count=1)


def friendly_name(tool: str) -> str:
    return FRIENDLY.get(tool, (tool, ""))[0]


def what_is(tool: str) -> str:
    return FRIENDLY.get(tool, (tool, ""))[1]


def _ip(text: str) -> str:
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return m.group(0) if m else ""


def _path(text: str) -> str:
    m = re.search(r"/[\w./@-]{2,160}", text)
    return m.group(0) if m else ""


def _prog(path: str) -> str:
    path = path.rstrip("/")
    return path.rsplit("/", 1)[-1] if path else "A program"


def sentence(ev: dict) -> str:
    return _sentence(ev.get("from_tool", ""), ev.get("text", ""))


def _sentence(tool: str, t: str) -> str:
    ip = _ip(t)
    path = _path(t)
    sev_low = t.lower()

    if tool == "ufw":
        if "BLOCK_UNKNOWN" in t:
            return f"Firewall blocked unknown {ip or 'address'}"
        return f"Firewall blocked {ip or 'address'}"
    if tool == "fail2ban":
        if "Unban" in t:
            return f"Unbanned {ip}"
        return f"Banned {ip or 'address'}"
    if tool == "responderd":
        if "quarantine" in sev_low:
            return f"Quarantined {path or 'file'}"
        if "kill" in sev_low:
            return "Process stopped (threat rule)"
        if "firewall_drop" in sev_low:
            m = re.search(r"new external listener [\d.]+:(\d+)", t)
            if m:
                return f"Blocked inbound on port {m.group(1)}"
            return f"Blocked {ip or 'address'}"
        if "delete" in sev_low:
            return f"Deleted {path or 'file'}"
        return f"{(_prog(path) or 'Activity')} · logged only"
    if tool in ("yara-watch", "yara-tmp-scan"):
        return f"Malware match: {path or 'unknown file'}"
    if tool == "clamav":
        m = re.search(r"Infected files:\s*(\d+)", t)
        if m and m.group(1) != "0":
            return f"{m.group(1)} infected file(s)"
        if "FOUND" in t:
            return f"Malware in {path}"
        return "Scan clean"
    if tool == "appfw":
        if "deny" in sev_low:
            return f"{_prog(path)} blocked"
        return f"{_prog(path)} allowed"
    if tool == "tetragon":
        return f"{_prog(path)} started"
    if tool == "arpwatch":
        if "new station" in sev_low:
            return f"A device ({ip or 'unknown'}) joined your WiFi."
        return f"A WiFi device changed behavior ({ip or 'check details'})."
    if tool == "auditd":
        if "ANOM_ABEND" in t:
            return "A program crashed on its own; it was recorded."
        if "AVC" in t and "denied" in sev_low:
            # An AppArmor denial relayed through auditd — say what it is.
            return "A program tried something outside its allowed access and was stopped."
        return "The kernel recorded routine system activity."
    if tool == "aide":
        if "no differences" in sev_low:
            return "The file-integrity check: nothing changed."
        return "System files changed since the last check: worth reviewing."
    if tool == "apparmor":
        return "A program tried something outside its allowed access and was stopped."
    if tool == "lynis":
        if "down" in sev_low:
            return "The security auditor is not running."
        return "The security auditor flagged something to improve."
    if tool == "rkhunter":
        # A status line saying the scanner is down is NOT a clean scan —
        # the listing showed 'Rootkit scan clean' above that raw text.
        if "down" in sev_low:
            return "The rootkit scanner is not running."
        if "warning" in sev_low:
            return "The rootkit scanner found something suspicious."
        return "Rootkit scan clean: no hidden malware found."
    if tool == "secops-mcp":
        return "The security helper recorded routine activity."
    return t[:120] or "An event was recorded."
