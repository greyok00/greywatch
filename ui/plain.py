"""PLAIN ENGLISH layer (owner 2026-10-23: "imagine I know nothing about
computers" — nothing may read like a log line).

Every event renders as ONE sentence a non-technical person understands; the
tool's friendly name is shown BESIDE it (the sentence never prefixes the
tool's own name), and every tool has a one-sentence "what is this?".
"""
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
    "suricata": ("Network alarm", "Watches the network for known attacks."),
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
    """Escape text for Pango markup. Every event-derived string goes through
    this before set_markup: an ampersand or angle bracket used to blank a
    card (the repeated grey/blank render bug)."""
    return _xml_escape(str(text or ""))


# ── theme-aware colors (2026-10-25) ──────────────────────────────────────
# Pango markup cannot use CSS var(); the old hardcoded grays (#98a2b3,
# #b9c4d4, …) were dark-theme colors that sat invisibly on the light
# theme's white panels (owner: "white on white"). Every markup color now
# comes from the APPLIED theme. These fall back to the dark default so a
# render before any theme is applied is still readable.


def _token(name: str, fallback: str) -> str:
    try:
        from ui import themes
        return themes.CURRENT.get(name, fallback)
    except ImportError:
        return fallback


def ink() -> str:
    """Main text color of the applied theme."""
    return _token("ink", "#dde5f2")


def soft() -> str:
    """Secondary text color — slightly dimmer than main."""
    return _token("ink_soft", "#8b9bb0")


def muted() -> str:
    """Tertiary text color — hints, tags, timestamps."""
    return _token("mute", "#8b9bb0")


def warn() -> str:
    """Warning color of the applied theme."""
    return _token("warn", "#ffc940")


_LEAD_MARK = re.compile(r"^[^\w]+")


def without_mark(text) -> str:
    """Drop the leading emoji from a plain sentence (the card already shows
    its own state light, so two icons in one line is noise)."""
    return _LEAD_MARK.sub("", str(text or ""), count=1)


def friendly_name(tool: str) -> str:
    return FRIENDLY.get(tool, (tool, ""))[0]


def what_is(tool: str) -> str:
    return FRIENDLY.get(tool, (tool, ""))[1]


def _ip(text: str) -> str:
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return m.group(0) if m else ""


def _path(text: str) -> str:
    # `@` belongs in the class: npm-style paths contain it, and stopping
    # there left a trailing slash (→ an empty program name, " started
    # running."). (Pass 1 defect, 2026-10-23)
    m = re.search(r"/[\w./@-]{2,160}", text)
    return m.group(0) if m else ""


def _prog(path: str) -> str:
    path = path.rstrip("/")
    return path.rsplit("/", 1)[-1] if path else "A program"


def sentence(ev: dict) -> str:
    """One plain sentence, never a log line. Unknown tool + text → the first
    120 characters."""
    return _sentence(ev.get("from_tool", ""), ev.get("text", ""))


def _sentence(tool: str, t: str) -> str:
    ip = _ip(t)
    path = _path(t)
    sev_low = t.lower()

    if tool == "ufw":
        if "BLOCK_UNKNOWN" in t:
            return f"⚠ The firewall blocked an unrecognized connection from {ip or 'an outside address'}."
        return f"🔒 The firewall blocked a connection from {ip or 'an outside address'}."
    if tool == "fail2ban":
        if "Unban" in t:
            return f"✅ A computer ({ip}) was let back in after its lockout."
        return f"🚫 {ip or 'A computer'} was locked out after repeated suspicious attempts."
    if tool == "responderd":
        if "quarantine" in sev_low:
            return f"🚨 A dangerous file ({path or 'file'}) was moved to quarantine. It can no longer run."
        if "kill" in sev_low:
            return "🛑 A running process was stopped because it matched a threat rule."
        if "firewall_drop" in sev_low:
            m = re.search(r"new external listener [\d.]+:(\d+)", t)
            if m:
                return (f"🧱 A program opened port {m.group(1)} to the "
                        f"internet; the firewall blocked access from outside.")
            return f"🔒 The firewall was told to block {ip or 'an attacker'}."
        if "delete" in sev_low:
            return f"🗑 A dangerous file ({path or 'file'}) was deleted."
        return f"👀 {(_prog(path) or 'Activity')} was watched and logged (no action needed)."
    if tool in ("yara-watch", "yara-tmp-scan"):
        return f"🧪 A file matches a known malware fingerprint: {path or 'unknown file'}."
    if tool == "clamav":
        m = re.search(r"Infected files:\s*(\d+)", t)
        if m and m.group(1) != "0":
            return f"🦠 The antivirus found {m.group(1)} infected file(s)!"
        if "FOUND" in t:
            return f"🦠 The antivirus detected malware in {path}."
        return "✅ The antivirus finished its scan: no threats found."
    if tool == "appfw":
        if "deny" in sev_low:
            return f"⛔ {_prog(path)} was denied internet access."
        return f"🌐 {_prog(path)} was allowed to use the internet."
    if tool == "suricata":
        return f"📣 A known attack pattern hit the network from {ip or 'outside'}."
    if tool == "tetragon":
        return f"👀 {_prog(path)} started running."
    if tool == "arpwatch":
        if "new station" in sev_low:
            return f"📶 A device ({ip or 'unknown'}) joined your WiFi."
        return f"📶 A WiFi device changed behavior ({ip or 'check details'})."
    if tool == "auditd":
        if "ANOM_ABEND" in t:
            return "💥 A program crashed on its own; it was recorded."
        return "🫥 The kernel recorded routine system activity."
    if tool == "aide":
        if "no differences" in sev_low:
            return "✅ The file-integrity check: nothing changed."
        return "⚠ System files changed since the last check: worth reviewing."
    if tool == "apparmor":
        return "🚧 A program tried something outside its allowed access and was stopped."
    if tool == "lynis":
        return "📋 The security auditor flagged something to improve."
    if tool == "rkhunter":
        if "warning" in sev_low:
            return "⚠ The rootkit scanner found something suspicious."
        return "✅ Rootkit scan clean: no hidden malware found."
    if tool == "secops-mcp":
        return "🫥 The security helper recorded routine activity."
    return t[:120] or "An event was recorded."