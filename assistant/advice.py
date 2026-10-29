# assistant/advice.py
"""Deterministic advice: what a line means, why it matters, what to do.

The model cannot be trusted to invent remediation (a 360M/2B model gets it
wrong and a wrong fix is worse than none), so every step here comes from
facts the app already has: the tool registry (units, logs), the status
snapshot (state, paused, installed), and the event parsers' vocabulary.

Commands are plain text for the owner to run — this module imports nothing
that can execute anything, and no answer is ever run from chat.
"""
from __future__ import annotations

import re

from ui import plain as _plain
from ui.models import local_clock, status_words

from registry import load_registry

_PLAYBOOKS_LOADED = None


def _registry():
    """Resolved registry (units, log paths) — cached per process."""
    global _PLAYBOOKS_LOADED
    if _PLAYBOOKS_LOADED is None:
        try:
            _PLAYBOOKS_LOADED = {t["name"]: t for t in load_registry()}
        except Exception:
            _PLAYBOOKS_LOADED = {}
    return _PLAYBOOKS_LOADED


def _spec(tool: str) -> dict:
    return _registry().get(tool) or {}


# ---- step builders: the real commands for THIS install --------------------

def _unit_cmd(tool: str, verb: str = "status") -> str | None:
    spec = _spec(tool)
    unit = spec.get("unit")
    if not unit:
        return None
    if spec.get("scope") == "user":
        return f"systemctl --user {verb} {unit}"
    return f"sudo systemctl {verb} {unit}"


def _log_cmd(tool: str) -> str | None:
    spec = _spec(tool)
    for path in spec.get("logs") or []:
        if not path:
            continue
        if str(path) == "journal:kern":
            return "journalctl -k -n 50"
        if str(path).startswith("journal:"):
            continue
        # A cache JSON is not a log; tailing it would print one huge line.
        if str(path).endswith(".json"):
            continue
        if spec.get("scope") == "user":
            return f"tail -n 50 {path}"
        return f"sudo tail -n 50 {path}"
    journal = spec.get("journal") or {}
    if journal.get("filter"):
        return f"journalctl {journal['filter']} -n 50"
    return None


def _app_scan(tool: str) -> str | None:
    """Scan actions the app itself offers (ui/cards.py SCAN_MODES)."""
    return {
        "rkhunter": "Run the Rootkit scan from the Scan strip.",
        "lynis": "Run the Security audit from the Scan strip.",
        "aide": "Run the File-integrity check from the Scan strip.",
        "clamav": "Run the Full antivirus scan from the Scan strip.",
        "yara-tmp-scan": "Run the Quick scan from the Scan strip.",
        "yara-watch": "Start the live malware scanner from its row.",
    }.get(tool)


def _details(tool: str) -> tuple[str, str]:
    return ("app", f"Open the {_plain.friendly_name(tool)} row to see the "
                   f"full log and its guided setup.")


def _steps_for(tool: str, *, scan: bool = False,
               details: bool = True) -> list[tuple[str, str]]:
    steps = []
    if scan:
        action = _app_scan(tool)
        if action:
            steps.append(("app", action))
    if details:
        steps.append(_details(tool))
    cmd = _unit_cmd(tool, "status")
    if cmd:
        steps.append(("command", cmd))
    log = _log_cmd(tool)
    if log:
        steps.append(("command", log))
    return steps


# ---- event classes ---------------------------------------------------------

def _rule(pattern, meaning, risk, *, scan=False, steps=None):
    """steps=None means 'derive the tool's standard steps'; an empty tuple
    means 'nothing to do' (a normal event needs no remediation)."""
    return (re.compile(pattern, re.I), meaning, risk, scan, steps)


# (tool, [rules]) — first match wins; order matters (specific before general).
_RULES = {
    "appfw": [
        _rule(r"engine armed|headless fallback",
              "the app firewall is running without its popup",
              "with no window open it answers 'deny once' by itself, so a "
              "program can be blocked without you seeing a prompt; keeping the "
              "app open (or the tray window available) restores the popup",
              steps=(("info", "Leave the app running when you need a program "
                              "to reach the internet."),)),
        _rule(r"\bdeny\b",
              "the app firewall blocked a program's connection",
              "nothing is broken — this is the policy you (or the downloaded "
              "blocklist) chose; it only matters if that program must connect",
              steps=(("app", "If that program should connect, answer Allow the "
                             "next time its popup appears."),)),
        _rule(r"\ballow\b",
              "the app firewall let a program connect",
              "normal: either you allowed it, a rule covers it, or learning "
              "mode recorded it once",
              steps=()),
    ],
    "apparmor": [
        _rule(r"denied|\bAVC\b",
              "a program tried something outside its jail and was stopped",
              "this is the jail working as designed; it is only a problem if a "
              "program you rely on fails to do its job",
              steps=(("command", "journalctl -k | grep -i apparmor | "
                                 "tail -n 20"),)),
    ],
    "auditd": [
        _rule(r"AVC.*denied|denied.*AVC",
              "an AppArmor denial relayed through the kernel audit log",
              "the same policy stop AppArmor reports; harmless unless the "
              "program you needed failed",
              steps=(("command", "journalctl -k | grep -i 'apparmor=\"DENIED\"' "
                                 "| tail -n 20"),)),
        _rule(r"ANOM_ABEND",
              "a program crashed on its own",
              "usually a browser tab or an app crash; the same program "
              "crashing repeatedly is worth investigating",
              steps=()),
    ],
    "rkhunter": [
        _rule(r"shared memory",
              "the rootkit scanner saw large shared-memory segments",
              "shared memory is normal for browsers, virtual machines and "
              "video drivers, and a firmware/BIOS update can leave a large "
              "segment behind; rkhunter lists it for review, it is not "
              "evidence of malware"),
        _rule(r"is down|could not be repaired|not running",
              "the rootkit scanner is not running",
              "nothing is checking system internals for hidden malware right "
              "now, so a rootkit would go unnoticed",
              scan=True),
        _rule(r"warning|suspicious|suspect",
              "the rootkit scanner flagged something for review",
              "a warning is a candidate, not a conviction — common causes are "
              "package-manager leftovers and replaced system files after an "
              "update; compare the file against the package that owns it",
              scan=True),
        _rule(r"clean|no warnings|no hidden",
              "the rootkit scan came back clean",
              "nothing to do; this is the expected result", steps=()),
    ],
    "lynis": [
        _rule(r"is down|could not be repaired|not running",
              "the security auditor is not running",
              "you get no fresh hardening score or improvement list until it "
              "runs again",
              scan=True),
        _rule(r"warning",
              "the security auditor found a weakness to improve",
              "it is a grading finding, not an attack; read the recommendation "
              "and fix what applies to this machine",
              scan=True),
    ],
    "aide": [
        _rule(r"differences found|changed",
              "system files changed since the last integrity check",
              "often a package update; it matters when it happens without an "
              "update you ran — that is what the tripwire is for",
              scan=True),
        _rule(r"no differences",
              "the file-integrity check found nothing changed",
              "nothing to do", steps=()),
    ],
    "clamav": [
        _rule(r"infected files:?\s*[1-9]|\bFOUND\b",
              "the antivirus found malware",
              "a found file can run if it is opened; quarantine it rather "
              "than opening it, then run a full scan",
              scan=True,
              steps=(("info", "Do not open the file; the auto-responder's "
                              "quarantine popup keeps it locked away."),)),
        _rule(r"infected files 0|scan clean",
              "the antivirus scan came back clean",
              "nothing to do", steps=()),
    ],
    "fail2ban": [
        _rule(r"\bban(ned|s)?\b|Restore Ban",
              "an address was locked out after repeated failed logins",
              "normal internet noise for most addresses; if it is one you "
              "recognise, its password guessing is worth stopping",
              steps=(("command", "sudo fail2ban-client status"),
                     ("command", "sudo tail -n 50 /var/log/fail2ban.log"))),
        _rule(r"\bUnban\b",
              "a locked-out address was released",
              "nothing to do", steps=()),
        _rule(r"\bFound\b",
              "a failed login was seen",
              "low risk on its own; a burst of them is what the blocker "
              "reacts to", steps=()),
    ],
    "ufw": [
        _rule(r"BLOCK_UNKNOWN",
              "the firewall blocked traffic from an unexpected source",
              "worth knowing: the source is not one the rules recognise, and a "
              "repeat pattern suggests scanning",
              steps=(("command", "journalctl -k | grep -i 'UFW BLOCK' | "
                                 "tail -n 20"),)),
        _rule(r"BLOCK",
              "the firewall blocked a connection",
              "normal: this is the firewall doing its job",
              steps=()),
    ],
    "responderd": [
        _rule(r"quarantine",
              "a detected threat was moved into quarantine",
              "the file cannot run where it is now; decide whether to delete "
              "it or restore it (restore only if you are sure it is safe)",
              steps=(("app", "Use the threat popup's Keep it locked away / Put "
                             "it back choice, or open the row for details."),)),
        _rule(r"\bkill\b",
              "the auto-responder stopped a running process",
              "the process is gone; if you did not start it, review where it "
              "came from and run a full scan",
              scan=False),
        _rule(r"firewall_drop",
              "a new network listener was blocked",
              "nothing should be listening that you did not start; if you did "
              "start it, allow it on purpose",
              steps=()),
    ],
    "arpwatch": [
        _rule(r"new station",
              "a device joined your network",
              "expected only for devices you own; an unknown device means "
              "someone else is on the network",
              steps=(("info", "If you do not recognise it, check the router's "
                              "device list and the WiFi password."),)),
        _rule(r"flip|changed|bogon",
              "a device changed its network identity",
              "usually a phone switching between WiFi bands; repeated flips "
              "can also be address spoofing", steps=()),
    ],
    "tetragon": [
        _rule(r"exec",
              "a program started, and the kernel watcher recorded it",
              "recorded only — nothing was blocked; it matters only if you did "
              "not start that program", steps=()),
    ],
    "net-watch": [
        _rule(r"scan|burst|denied",
              "the network watcher saw unusual connection behaviour",
              "something on this machine is contacting many addresses or being "
              "refused repeatedly — check which program before assuming an "
              "attack", steps=()),
    ],
    "yara-watch": [
        _rule(r"match|found|malware",
              "the live malware scanner matched a known-bad pattern in a file",
              "a match is a fingerprint hit, not proof — the auto-responder "
              "quarantines it, and you decide whether it stays locked away",
              scan=True),
        _rule(r"clean|no match",
              "the live malware scanner found nothing",
              "nothing to do", steps=()),
    ],
    "yara-tmp-scan": [
        _rule(r"match|found|malware",
              "the scheduled scan matched a known-bad pattern in the "
              "temporary folder",
              "temporary-folder malware is usually a downloaded installer — "
              "quarantine it and clear the file",
              scan=True),
        _rule(r"clean|no match",
              "the scheduled temporary-folder scan found nothing",
              "nothing to do", steps=()),
    ],
    "freshclam": [
        _rule(r"error|failed|outdated",
              "the antivirus's malware list could not be refreshed",
              "the antivirus would keep scanning with yesterday's signatures",
              steps=(("command", "sudo systemctl status clamav-freshclam.service"),
                     ("command", "sudo freshclam"))),
        _rule(r"updated|up to date|daily",
              "the antivirus's malware list was refreshed",
              "nothing to do — the list stays current on its own", steps=()),
    ],
    "cve-updater": [
        _rule(r"updated|wrote|cache|downloaded",
              "the weekly known-flaw list was refreshed",
              "nothing to do; this list is how the app knows about new "
              "vulnerabilities", steps=()),
    ],
}


def _match(tool: str, text: str):
    for pattern, meaning, risk, scan, steps in _RULES.get(tool, []):
        if pattern.search(text or ""):
            return meaning, risk, scan, steps
    return None


# ---- answer shapes ---------------------------------------------------------

def _render_steps(steps) -> tuple[str, bool]:
    if not steps:
        return "", False
    lines = []
    for i, (kind, text) in enumerate(steps, 1):
        if kind == "command":
            lines.append(f"{i}. run: {text}")
        else:
            lines.append(f"{i}. {text}")
    has_cmd = any(kind == "command" for kind, _ in steps)
    return "What to do:\n" + "\n".join(lines), has_cmd


def _command_note(has_cmd: bool) -> str:
    return ("\n\nCommands are for you to run yourself; the assistant never "
            "executes anything.") if has_cmd else ""


def advise_event(row: dict, extra_steps=None) -> str:
    """Explain one log line and give the steps that actually apply."""
    tool = str(row.get("tool") or row.get("from_tool") or "")
    text = str(row.get("text") or "")
    name, desc = _plain.FRIENDLY.get(tool, (tool, ""))
    sev = str(row.get("severity") or "").upper()
    hit = _match(tool, text)
    if hit is None:
        meaning = _plain.sentence({"from_tool": tool, "text": text})
        risk = ("the tool recorded it; check the row's detail if it repeats"
                if sev in ("INFO", "MEDIUM") else
                "this is high severity — review it before assuming it is fine")
        steps = _steps_for(tool, details=True)
    else:
        meaning, risk, scan, steps = hit
        if steps is None:
            steps = _steps_for(tool, scan=scan, details=False)
    steps = tuple(extra_steps or ()) + tuple(steps or ())
    body, has_cmd = _render_steps(steps)
    head = (f"That line means: {meaning}. "
            f"It came from {name} ({tool}) at "
            f"{local_clock(row.get('ts'))}, severity "
            f"{_plain.severity_word(sev)}.")
    parts = [head, f"Why it matters: {risk}."]
    if body:
        parts.append(body)
    parts.append(f"raw: {text}")
    return "\n\n".join(parts) + _command_note(has_cmd)


def _recent_for(pack: dict, tool: str) -> list[dict]:
    return [e for e in (pack.get("recent") or [])
            if str(e.get("tool") or e.get("from_tool") or "") == tool]


def advise_tool(pack: dict, tool: str) -> str | None:
    """State-aware advice for one named tool, including the case where the
    state column and the event log disagree (the owner's recurring puzzle:
    'all green' while the scanner logged that it is down)."""
    state = next((t for t in pack.get("tools") or [] if t["name"] == tool), None)
    if state is None:
        return None
    name, desc = _plain.FRIENDLY.get(tool, (tool, ""))
    words = status_words(state["state"], state.get("installed", True),
                         state.get("paused", False))
    parts = [f"{name} ({tool}) is {words}."]
    if desc:
        parts.append(f"{name}: {desc[0].lower()}{desc[1:].rstrip('.')}.")

    recent = _recent_for(pack, tool)
    hot = [e for e in recent if str(e.get("severity", "")).upper()
           in ("HIGH", "CRITICAL")]
    down_hit = None
    for e in hot:
        hit = _match(tool, str(e.get("text") or ""))
        if hit is not None and "not running" in hit[0]:
            down_hit = e
            break
    if down_hit is not None and state["state"] != "RED":
        parts.append(
            f"Note the disagreement: the state column says {words}, but the "
            f"log says it is not running (last word at "
            f"{local_clock(down_hit.get('ts'))}). Trust the log — run the "
            f"steps below and check the raw line yourself.")
    elif hot:
        parts.append(f"It also logged {len(hot)} high-severity event(s) "
                     f"recently; ask 'what is that warning' after the listing "
                     f"for the line-by-line reading.")

    if state.get("paused"):
        steps = [("app", f"Resume {name} from its row when you are done."),
                 _details(tool)]
    elif state["state"] in ("RED", "YELLOW") or down_hit is not None:
        steps = _steps_for(tool, scan=True)
    else:
        steps = _steps_for(tool, details=True) if hot else []
    body, has_cmd = _render_steps(steps)
    if body:
        parts.append(body)
    elif not hot:
        parts.append("Nothing to do — this layer is running and nothing "
                     "recent needs a decision.")
    return "\n\n".join(parts) + _command_note(has_cmd)


def needs_attention(pack: dict) -> list[tuple[int, str, str]]:
    """Ranked (priority, tool, one-line why). Lower priority sorts first."""
    out = []
    for t in pack.get("tools") or []:
        if t.get("paused"):
            out.append((3, t["name"], "paused on purpose — resume when done"))
        elif t["state"] == "RED":
            out.append((0, t["name"], "not running"))
        elif t["state"] == "YELLOW":
            out.append((2, t["name"],
                        "not installed" if t.get("installed") is False
                        else "needs attention"))
    seen = {name for _p, name, _w in out}
    for e in pack.get("recent") or []:
        tool = str(e.get("tool") or e.get("from_tool") or "")
        sev = str(e.get("severity") or "").upper()
        if sev not in ("HIGH", "CRITICAL") or tool in seen:
            continue
        hit = _match(tool, str(e.get("text") or ""))
        why = hit[0] if hit else _plain.sentence(
            {"from_tool": tool, "text": e.get("text", "")})
        out.append((1, tool, why))
        seen.add(tool)
    out.sort(key=lambda r: (r[0], r[1]))
    return out


def advise_priorities(pack: dict) -> str:
    """One ranked list: what needs a decision now, with the next step."""
    items = needs_attention(pack)
    total = len(pack.get("tools") or [])
    green = sum(1 for t in pack.get("tools") or [] if t["state"] == "GREEN")
    if not items:
        return (f"Nothing needs a decision right now: {green} of {total} "
                f"protections are green, and no high-severity event is "
                f"waiting.\n\nIf you want to be thorough, ask 'explain the "
                f"newest event' and I will read the last lines out.")
    n = min(len(items), 5)
    head = ("One thing needs a decision, most important first"
            if n == 1 else f"{n} things need a decision, most important first")
    lines = [f"{head} ({green} of {total} protections green):"]
    for i, (_pri, tool, why) in enumerate(items[:5], 1):
        name = _plain.friendly_name(tool)
        steps = _steps_for(tool, scan=True, details=False)
        first = next((s for _k, s in steps), None)
        extra = f" → {first}" if first else ""
        lines.append(f"{i}. {name} ({tool}): {why}.{extra}")
    lines.append("Ask 'how do I fix <name>' for the full steps on any of "
                 "them.")
    return "\n".join(lines)


def advise_state_vs_events(pack: dict) -> str:
    """The two channels the owner keeps confusing: state = health now,
    events = what happened. Say which one a question is about."""
    tools = pack.get("tools") or []
    green = sum(1 for t in tools if t["state"] == "GREEN")
    hot = [e for e in (pack.get("recent") or [])
           if str(e.get("severity", "")).upper() in ("HIGH", "CRITICAL")]
    down = [t for t in tools if t["state"] == "RED"]
    parts = [f"The state column and the event log answer different questions: "
             f"the state says whether a layer is running right now, the events "
             f"are its history of what it saw. Today {green} of {len(tools)} "
             f"layers are green, {len(hot)} high-severity event(s) are in the "
             f"recent window, and {len(down)} layer(s) are stopped."]
    if hot and not down:
        parts.append("So the protections are healthy and the log is "
                     "reporting normal activity — nothing in that list is an "
                     "outage. Ask 'what is that warning' to read one line at a "
                     "time.")
    elif down:
        names = ", ".join(_plain.friendly_name(t["name"]) for t in down[:3])
        parts.append(f"Fix the stopped layer first ({names}) — while it is "
                     f"down its events are history, not fresh findings.")
    else:
        parts.append("Nothing is stopped and nothing high-severity is waiting.")
    return "\n\n".join(parts)
