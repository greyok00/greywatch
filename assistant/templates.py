# assistant/templates.py
"""Deterministic template answers — the assistant's real speaker.

Facts are read from the context pack, never recalled, so these answers
cannot hallucinate. `compose()` is the slot dispatch shared with the
router.
"""
from __future__ import annotations

from ui import plain as _plain
from ui.models import status_words

def _plain_bits(tool: str) -> tuple[str, str]:
    return _plain.FRIENDLY.get(tool, (tool, ""))


def answer_overview(pack: dict) -> str:
    lines = [f"{pack['status_line']}."]
    hot = [t for t in pack["tools"] if t["state"] in ("YELLOW", "RED")]
    for t in hot:
        name, _desc = _plain_bits(t["name"])
        lines.append(f"- {t.get('label') or name} ({t['name']}): {t['state']} — "
                     f"{status_words(t['state'], True, False)}")
    if len(lines) == 1:
        lines.append("Everything is green; nothing needs a decision.")
    return "\n".join(lines)


def answer_event(pack: dict) -> str:
    if not pack["recent"]:
        return "No events have been recorded yet."
    e = pack["recent"][0]
    name, desc = _plain_bits(e["tool"])
    body = (f"The newest event came from {name} ({e['tool']}) at "
            f"{e['ts']}, severity {e['severity']}: {e['text']}.")
    if desc:
        body += f" {name} is the layer that {desc[0].lower() + desc[1:]}".rstrip(
            ) + "; one denial is usually normal policy working."
    return body


def answer_tool_status(pack: dict, tool: str) -> str | None:
    t = next((x for x in pack["tools"] if x["name"] == tool), None)
    if t is None:
        return None
    name, desc = _plain_bits(tool)
    words = status_words(t["state"], True, False)
    return (f"{name} ({tool}) is {words.lower()}. {desc} Current layer "
            f"state: {t['state']}.").strip()


def compose(slot: str, pack: dict, tool: str | None = None) -> str | None:
    if slot == "overview":
        return answer_overview(pack)
    if slot == "explain_event":
        return answer_event(pack)
    if slot == "tool_status":
        return answer_tool_status(pack, tool) if tool else None
    return None
