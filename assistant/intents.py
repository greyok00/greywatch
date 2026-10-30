# assistant/intents.py
"""The only bridge from model words to system actions.

A model answer may carry ONE intent. It is parsed here with code, matched
against the whitelist, validated against the live registry, and described
in plain language for the confirm dialog. The model never names commands.

The set covers what the window can already do with its own buttons:
protections (pause/resume/details), the six scans, the app firewall,
learning mode, the update lists, the trusted-item lists, the panic-restore
("enable everything"), and page navigation. Nothing here executes
anything — ui/window.py runs the same handlers the owner's clicks run,
after the confirm dialog, and writes one audit line.
"""
from __future__ import annotations

import dataclasses
import json
import re

INTENTS = frozenset({
    "pause", "resume", "details", "overview", "scan",
    "enable_all", "firewall", "learning", "update_lists",
    "trust_site", "block_site", "trust_program", "open_page",
})

# Page keys the window's stack knows, and the words a person says for them.
PAGES = {
    "security": "tools",
    "tools": "deep",
    "logs": "logs",
    "settings": "settings",
    "help": "help",
}

_JSON = re.compile(r"\{[^{}]*\}")
_SITE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
_PATH = re.compile(r"(/[^\s]+)")


@dataclasses.dataclass(frozen=True)
class Intent:
    action: str
    tool: str = ""
    value: str = ""


def _model_action(data: dict) -> tuple[str, str] | None:
    raw = str(data.get("action") or "").strip().lower()
    value = str(data.get("value") or data.get("target") or "").strip()
    table = {
        "stop": "pause", "pause": "pause",
        "start": "resume", "resume": "resume",
        "show": "details", "details": "details", "detail": "details",
        "overview": "overview", "status": "overview",
        "scan": "scan", "run": "scan", "sweep": "scan",
        "enable_all": "enable_all", "enable_everything": "enable_all",
        "firewall_on": "firewall", "firewall_off": "firewall",
        "learning_on": "learning", "learning_off": "learning",
        "update": "update_lists", "update_lists": "update_lists",
        "trust": "trust_site", "allow": "trust_site",
        "block": "block_site", "deny": "block_site",
        "trust_program": "trust_program", "open": "open_page",
    }
    action = table.get(raw)
    if action is None:
        return None
    if raw == "firewall_on":
        value = "on"
    elif raw == "firewall_off":
        value = "off"
    elif raw == "learning_on":
        value = "on"
    elif raw == "learning_off":
        value = "off"
    return action, value


def parse_intent(text: str) -> tuple[Intent | None, str]:
    m = _JSON.search(text or "")
    if not m:
        return None, text or ""
    rest = (text[:m.start()] + " " + text[m.end():]).strip()
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return None, rest
    if data.get("task") != "intent":
        return None, rest
    picked = _model_action(data)
    if picked is None:
        return None, rest
    action, value = picked
    return Intent(action, str(data.get("tool") or "").strip(), value), rest


def _site_ok(value: str) -> bool:
    """A plain site name, never a URL with a scheme, a port or a path."""
    text = (value or "").strip().lower()
    return bool(_SITE.fullmatch(text)) and not any(
        c in text for c in ("/", ":", " ", "@"))


def validate(intent: Intent, tool_names: set[str],
             scan_names=()) -> str | None:
    if intent.action not in INTENTS:
        return f"action '{intent.action}' is not allowed"
    if intent.action in ("overview", "enable_all", "update_lists"):
        return None
    if intent.action == "scan":
        if intent.tool not in set(scan_names):
            return f"scan '{intent.tool}' is not one of the app's scans"
        return None
    if intent.action == "open_page":
        if intent.value.lower() not in PAGES:
            return f"'{intent.value}' is not a page in this app"
        return None
    if intent.action in ("firewall", "learning"):
        if intent.value.lower() not in ("on", "off"):
            return f"'{intent.value}' is not on or off"
        return None
    if intent.action in ("trust_site", "block_site"):
        if not _site_ok(intent.value):
            return "that is not a plain site name like example.com"
        return None
    if intent.action == "trust_program":
        if not (intent.value.strip() or intent.tool.strip()):
            return "no program was named"
        return None
    if intent.tool not in tool_names:
        return f"tool '{intent.tool}' is not a known protection"
    return None


def describe(intent: Intent, friendly: dict, scan_titles=None) -> str:
    if intent.action == "overview":
        return "Show the overall protection overview?"
    if intent.action == "enable_all":
        return "Turn every stopped protection back on?"
    if intent.action == "update_lists":
        return "Download the latest security and block lists now?"
    if intent.action == "firewall":
        return ("Turn the app firewall on?" if intent.value == "on"
                else "Turn the app firewall off?")
    if intent.action == "learning":
        return ("Start learning mode — new connections pass once and are "
                "recorded?" if intent.value == "on"
                else "Stop learning mode?")
    if intent.action in ("trust_site", "block_site"):
        verb = ("Trust" if intent.action == "trust_site" else "Block")
        return f"{verb} {intent.value} from now on, without asking?"
    if intent.action == "trust_program":
        name = intent.value or intent.tool
        return f"Let {name} use the internet without asking?"
    if intent.action == "open_page":
        where = {"tools": "Security", "deep": "Tools", "logs": "Logs",
                 "settings": "Settings", "help": "Help"}
        return f"Open the {where.get(PAGES.get(intent.value.lower(), ''), 'page')} page?"
    if intent.action == "scan":
        titles = scan_titles or {}
        if intent.tool == "scan-all":
            return "Start every scanner now?"
        title = titles.get(intent.tool, intent.tool)
        return f"Start the {title.lower()} now?"
    plain = friendly.get(intent.tool, (intent.tool, ""))[0]
    if intent.action == "pause":
        return f"Pause {plain} ({intent.tool}) now?"
    if intent.action == "resume":
        return f"Resume {plain} ({intent.tool}) now?"
    return f"Open the details view for {plain} ({intent.tool})?"
