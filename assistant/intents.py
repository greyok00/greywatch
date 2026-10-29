# assistant/intents.py
"""The only bridge from model words to system actions.

A model answer may carry ONE intent. It is parsed here with code, matched
against the whitelist, validated against the live registry, and described
in plain language for the confirm dialog. The model never names commands.
"""
from __future__ import annotations

import dataclasses
import json
import re

INTENTS = frozenset({"pause", "resume", "details", "overview"})

_JSON = re.compile(r"\{[^{}]*\}")


@dataclasses.dataclass(frozen=True)
class Intent:
    action: str
    tool: str


def parse_intent(text: str) -> tuple[Intent | None, str]:
    m = _JSON.search(text or "")
    if not m:
        return None, text or ""
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return None, text
    if data.get("task") != "intent":
        return None, text
    raw = str(data.get("action") or "").strip().lower()
    if raw in ("stop", "pause"):
        action = "pause"
    elif raw in ("start", "resume"):
        action = "resume"
    elif raw in ("show", "details", "detail"):
        action = "details"
    elif raw in ("overview", "status"):
        action = "overview"
    else:
        return None, text
    rest = (text[:m.start()] + " " + text[m.end():]).strip()
    return Intent(action, str(data.get("tool") or "").strip()), rest


def validate(intent: Intent, tool_names: set[str]) -> str | None:
    if intent.action not in INTENTS:
        return f"action '{intent.action}' is not allowed"
    if intent.action == "overview":
        return None
    if intent.tool not in tool_names:
        return f"tool '{intent.tool}' is not a known protection"
    return None


def describe(intent: Intent, friendly: dict) -> str:
    if intent.action == "overview":
        return "Show the overall protection overview?"
    plain = friendly.get(intent.tool, (intent.tool, ""))[0]
    if intent.action == "pause":
        return f"Pause {plain} ({intent.tool}) now?"
    if intent.action == "resume":
        return f"Resume {plain} ({intent.tool}) now?"
    return f"Open the details view for {plain} ({intent.tool})?"
