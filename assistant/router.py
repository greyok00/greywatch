# assistant/router.py
"""Question → task slot. The model's only decision, so it stays tiny.

One strict JSON parse; two strikes degrade to the summary slot, which
happens to be safe anywhere. words_only flips the whole router off.
An intent whose JSON carries a valid mapped action passes through as the
raw JSON text; assistant.intents owns the whitelist and validation.
"""
from __future__ import annotations

import json
import re

from assistant.intents import parse_intent

SLOTS = ("overview", "explain_event", "tool_status", "intent", "summary")

_JSON = re.compile(r"\{[^{}]*\}")
words_only = False


def _parse(reply: str, tool_names: str):
    m = _JSON.search(reply or "")
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return None
    task = data.get("task")
    tool = str(data.get("tool") or "")
    if task not in SLOTS:
        return None
    if task == "tool_status" and tool not in tool_names.split():
        return None
    action = None
    if task == "intent":
        intent, _ = parse_intent(m.group(0))
        action = intent.action if intent else None
    return task, tool, action, m.group(0)


def route(question: str, ask, tool_names: str = "",
          tries: int = 2) -> tuple[str, str]:
    """At most `tries` model calls total; two failures fall to summary."""
    if words_only:
        return "summary", ""
    names = f"Tools: {tool_names}" if tool_names else "Tools: (none listed)"
    prompt = f"{names}\nquestion: {question}"
    for _ in range(tries):
        reply = ask(prompt)
        got = _parse(reply, tool_names)
        if got:
            slot, tool, action, jtext = got
            if slot == "intent" and action:
                return slot, jtext
            rest = reply.replace(_JSON.search(reply).group(0), "").strip()
            return slot, (tool or rest)
    return "summary", ""
