# assistant/templates.py
"""Deterministic template answers — the assistant's real speaker.

Facts are read from the context pack, never recalled, so these answers
cannot hallucinate. `compose()` is the slot dispatch shared with the
router.
"""
from __future__ import annotations

from ui import plain as _plain
from ui.models import local_clock, status_words

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


def _ev_tool(e: dict) -> str:
    return str(e.get("tool") or e.get("from_tool") or "").lower()


def event_rows(pack: dict, tool_hint: str | None = None) -> list[dict]:
    """The rows an event answer would show, hint-filtered — shared with
    the turn planner so the panel can remember what it just displayed."""
    rows = list(pack.get("recent") or [])
    hint = str(tool_hint or "").lower() or None
    if hint:
        matched = [e for e in rows if _ev_tool(e) == hint]
        if not matched:
            # the tool's warning may be relayed through another channel
            matched = [e for e in rows
                       if hint in str(e.get("text") or "").lower()]
        rows = matched
    return rows


def answer_event(pack: dict, tool_hint: str | None = None) -> str | None:
    """Event answers list the user's actual log lines — the newest one on
    its own, or up to three with a hint narrowing the tool (asking about
    the rootkit scanner must not answer with an appfw allow line, which
    is exactly what the old newest-row-only shape did)."""
    if not pack.get("recent"):
        return "No events have been recorded yet."
    hint = str(tool_hint or "").lower() or None
    rows = event_rows(pack, hint)
    if hint and not rows:
        return None            # no events for that tool in this window
    tool = rows[0].get("tool") or rows[0].get("from_tool", "")
    if hint is None and len(rows) == 1:
        name, desc = _plain_bits(tool)
        body = (f"The newest event came from {name} ({tool}) at "
                f"{rows[0]['ts']}, severity {rows[0]['severity']}: "
                f"{rows[0]['text']}.")
        if desc:
            # Colon form, not 'is the layer that {desc}': auditd's
            # description is a noun phrase and the splice read as
            # nonsense ("is the layer that the kernel's detailed record").
            body += f" {name}: {desc[0].lower()}{desc[1:].rstrip('.')}"
            if str(rows[0].get("severity", "")).upper() in ("INFO", "MEDIUM"):
                body += "; one denial is usually normal policy working"
            body += "."
        return body
    label = _plain.FRIENDLY.get(hint or tool, (tool, ""))[0]
    head = (f"Newest {label} ({hint or tool}) events (local times):"
            if hint else "Newest events (local times):")
    # Each row carries the plain-language meaning AND the raw line: the
    # owner asked to 'explain my logs' and to be able to paste the log.
    lines = []
    for e in rows[:3]:
        friendly = _plain.sentence({"from_tool": e.get("tool")
                                    or e.get("from_tool", ""),
                                    "text": e.get("text", "")})
        lines.append(f"- {local_clock(e.get('ts'))} "
                     f"· {_plain.severity_word(e.get('severity'))}: "
                     f"{friendly}\n  raw: {e.get('text', '')}")
    return head + "\n" + "\n".join(lines)


def answer_detail(row: dict) -> str:
    """Explain ONE previously shown log line ('what is that denied?').

    A follow-up turn has no memory of its own, so the panel anchors the
    rows it last displayed and this explains the one the question points
    at — instead of re-listing the same three rows the owner just read."""
    tool = str(row.get("tool") or row.get("from_tool") or "")
    name, desc = _plain_bits(tool)
    friendly = _plain.sentence({"from_tool": tool, "text": row.get("text", "")})
    sev = str(row.get("severity") or "").upper()
    body = (f"That line means: {friendly.rstrip('.')}. "
            f"It came from {name} ({tool}) at "
            f"{local_clock(row.get('ts'))}, severity "
            f"{_plain.severity_word(sev)}.\n"
            f"raw: {row.get('text', '')}")
    if desc:
        body += f"\n{name}: {desc[0].lower()}{desc[1:].rstrip('.')}."
    if sev in ("INFO", "MEDIUM", "LOW"):
        body += " A single event like this is usually normal policy working."
    return body


def answer_tool_status(pack: dict, tool: str) -> str | None:
    t = next((x for x in pack["tools"] if x["name"] == tool), None)
    if t is None:
        return None
    name, desc = _plain_bits(tool)
    words = status_words(t["state"], t.get("installed", True),
                         t.get("paused", False))
    parts = [f"{name} ({tool}) is {words.lower()}."]
    if desc:
        parts.append(desc)
    parts.append(f"Current layer state: {t['state']}.")
    return " ".join(parts).strip()


def compose(slot: str, pack: dict, tool: str | None = None,
            row: dict | None = None) -> str | None:
    if slot == "overview":
        return answer_overview(pack)
    if slot == "explain_event":
        return answer_event(pack, tool)
    if slot == "detail":
        return answer_detail(row) if row else None
    if slot == "tool_status":
        return answer_tool_status(pack, tool) if tool else None
    return None
