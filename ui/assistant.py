# ui/assistant.py
"""Chat panel + the headless turn planner.

plan_turn() decides HOW a question is answered; the GTK widget only
renders the plan and its stream. GTK imports are guarded so tests can
import plan_turn on headless runners.
"""
from __future__ import annotations

import pathlib
import re
import threading
from html import escape

from assistant import advice, audit, events as _events
from assistant.intents import Intent, describe, parse_intent, validate
from assistant.llm import ROUTER_SYSTEM  # noqa: F401  (router contract)
from assistant.packer import build_pack
from assistant.router import route
from assistant.templates import answer_detail, compose, event_rows
from ui import plain as _plain
from ui.cards import SCAN_MODES
from ui.models import local_clock

SLOTS_WITH_TEMPLATES = ("overview", "explain_event", "tool_status")

# The app's real scan buttons, keyed the same way the confirm gate and the
# window's scan runner expect. A scan intent is validated against these
# keys only — the model can name a scan, never a command.
_SCANS = {m["key"]: m for m in SCAN_MODES}
_SCAN_TITLES = {k: m["title"] for k, m in _SCANS.items()}
_SCAN_NAMES = " ".join(_SCANS)

# The live 360M router returned junk on the owner's real questions (an
# empty reply for the rootkit question, then prose 'fail2ban' as a slot
# tool), so the deterministic engine answers first; the model gets only
# what no keyword engine can match. Its router + free text are tamed in
# assistant/llm.py.
_EVENT_WORDS = ("event", "events", "log", "logs", "alert", "happened",
                "happen", "happening", "newest", "last", "blocked", "blocking",
                "denied", "denying", "deny", "suspicious", "warning", "found",
                "find", "scan", "scanner", "analyze", "analysis", "history",
                "activity", "latest", "recently", "crashed", "crash",
                "quarantined", "quarantine")

_PAUSE_VERBS = ("pause", "suspend", "stop", "disable", "deactivate",
                "turn off", "shut off", "shut down", "switch off", "halt",
                "freeze")
_RESUME_VERBS = ("resume", "unpause", "start", "enable", "activate",
                 "turn on", "turn back on", "back on", "switch on",
                 "bring back", "reactivate")

# "stop everything" is the one action the app deliberately does not offer:
# pausing every layer at once leaves the machine unwatched and is exactly
# the state a stranger at the keyboard would want.
_ALL_TARGETS = ("everything", "all of it", "all of them", "all protections",
                "all the protections", "the whole app", "every protection",
                "every layer")

# An action verb with no target: the model used to be asked to guess, and
# a 1.7B guess at "turn it back on" was a refusal. The panel keeps the
# last protection the conversation touched, so a pronoun can resolve to
# it; with no antecedent the app asks which one instead of guessing.
_PRONOUNS = ("it", "its", "that", "this", "those", "these")

# Questions about the app itself, not about one log row: these must never
# be captured by the anchored-row follow-up rung ("why is this app like
# this?" is not asking about the newest deny line).
_APP_SUBJECTS = ("app", "application", "program", "software", "greywatch",
                 "dashboard", "interface")

_STATE_MEANINGS = {
    "green": ("Green means that protection is running normally. There is "
              "nothing to do about a green layer."),
    "yellow": ("Yellow means a protection needs attention: it is either not "
               "installed, or it is installed but not working the way it "
               "should. Nothing is on fire, but that layer is not guarding "
               "you right now."),
    "red": ("Red means a protection is not running at all. That is the one "
            "to look at first: the rest of the app may be healthy while "
            "this layer is doing nothing."),
}
_STATE_SHORT = {"green": "Green = running normally.",
                "yellow": "Yellow = needs attention.",
                "red": "Red = not running at all."}

# Label words too generic to pin a tool: "what happened to this event?"
# is an event question, not an auditd question.
_LABEL_NOISE = frozenset({"event", "system", "live", "watch", "watcher",
                          "scanner", "program", "helper", "device",
                          "security", "file", "scheduled"})

# Referential follow-ups ("what is that denied?") point at what the chat
# just showed. The panel anchors the rows of its last event answer, and
# the question's keywords pick the row — otherwise the turn re-lists the
# same newest events, which is exactly what the owner reported as a
# canned reply repeating itself.
_REFERENTIAL = ("that", "this", "it", "its", "those", "these")
_ASK_NOISE = frozenset({"what", "which", "where", "when", "why", "how",
                        "does", "mean", "means", "explain", "about",
                        "from", "with", "line", "event", "events", "log",
                        "logs", "they", "them", "there", "here", "was",
                        "were", "have", "into", "your", "app", "apps",
                        "application", "program", "programs", "software",
                        "tool", "tools", "greywatch", "understand",
                        "understood", "doing", "work", "works",
                        "thing", "things", "stuff"})
# The question's word rarely matches the log's spelling exactly, and a
# bare substring lies ('deny-once' in an engine-armed line is not a
# denial). Each keyword maps to ranked patterns — strongest first.
_ROW_PATTERNS = {
    "denied": (r"answered:\s*deny", r"^\s*deny\b", r"\bdenied\b",
               r"\bdeny\b"),
    "blocked": (r"\bblocked\b", r"\bblock\b"),
    "allowed": (r"\ballowed\b", r"\ballow\b"),
    "found": (r"\bfound\b", r"\bfind\b"),
    "warning": (r"\bwarning\b", r"\bwarn\b"),
    "suspicious": (r"\bsuspicious\b",),
    # auditd spells a crash ANOM_ABEND, and the underscore kills \babend\b.
    "crashed": (r"anom_abend", r"\bcrashed\b", r"\bcrash\b"),
    "crash": (r"anom_abend", r"\bcrashed\b", r"\bcrash\b"),
}


def plan_turn(question, pack, llm, registry_names: set, friendly: dict,
              anchor=None, last_tool=None) -> dict:
    """One question -> one answer plan. The widget only renders this.

    Ladder: English action verbs + a named tool -> intent plan; a question
    about the app or a state word -> a plain-language explanation; a
    help/remediation question -> the deterministic advice engine (meaning,
    risk, numbered steps); a referential follow-up over the previously
    shown rows -> one-row detail; a tool word -> tool status; event/log
    wording -> event answers (tool-scoped when the question names one, and
    time-scoped when it says 'last night'); else the model routes or
    summarizes; the overview template is the safe floor.

    `last_tool` is the protection the conversation last talked about, so a
    pronoun ('turn it back on') can resolve to it instead of the model
    guessing."""
    if _wants_everything_on(question):
        return {"kind": "intent", "intent": Intent("enable_all")}
    if _wants_all_actions(question):
        return {"kind": "template", "slot": "concept",
                "text": _ALL_ACTIONS_TEXT}
    settings = _settings_intent(question)
    if settings is not None and validate(settings, registry_names) is None:
        return {"kind": "intent", "intent": settings}
    intent = _intent_from_question(question, friendly, last_tool)
    if intent is not None and validate(intent, registry_names) is None:
        return {"kind": "intent", "intent": intent}
    scan = _scan_intent(question)
    if scan is not None and validate(scan, registry_names, _SCANS) is None:
        # "scan for rootkits" is a request to act, not a question about
        # rootkit scanning; it reaches the same confirm gate as a pause.
        return {"kind": "intent", "intent": scan}
    pause_view = _pause_advice(question, pack, friendly, registry_names)
    if pause_view is not None:
        return {"kind": "template", "slot": "advice",
                "tool": pause_view[0], "text": pause_view[1]}
    unblock = _unblock_intent(question, pack, anchor)
    if unblock is not None and validate(unblock, registry_names) is None:
        return {"kind": "intent", "intent": unblock}
    if _wants_action_without_target(question, friendly, last_tool):
        # An action verb with nothing to act on: asking is honest; guessing
        # would pause the wrong protection.
        return {"kind": "template", "slot": "concept", "text": _ASK_TARGET}
    concept = _concept_answer(question, pack, friendly)
    if concept is not None:
        return {"kind": "template", "slot": "concept", "text": concept}
    signs = _howto_answer(question, pack, friendly)
    if signs is not None:
        return {"kind": "template", "slot": "concept", "text": signs}
    about_scan = _scan_answer(question, pack)
    if about_scan is not None:
        return {"kind": "template", "slot": "concept", "text": about_scan}
    if _wants_attack(question, friendly):
        # "am I under attack?" / "was I hacked?" is the owner's real fear;
        # it deserves the evidence, not a reassurance.
        return {"kind": "template", "slot": "advice", "tool": "",
                "text": advice.advise_attack(pack)}
    actor = _blocked_actor_answer(question, pack, friendly)
    if actor is not None:
        return {"kind": "template", "slot": "explain_event",
                "text": actor, "tool": ""}
    blocked = _blocking_answer(question, pack, friendly)
    if blocked is not None:
        return {"kind": "template", "slot": "explain_event",
                "text": blocked, "tool": ""}
    if _wants_advice(question):
        plan = _advice_plan(question, pack, registry_names, friendly, anchor)
        if plan is not None:
            return plan
    quarantine_text = _quarantine_answer(question, pack)
    if quarantine_text is not None:
        rows = _quarantine_rows(pack)[-1:]
        tool = str(rows[0].get("tool") or rows[0].get("from_tool") or ""
                   ) if rows else ""
        return {"kind": "template", "slot": "explain_event", "tool": tool,
                "text": quarantine_text, "rows": rows}
    window, scoped = _scope_by_time(question, pack)
    if window:
        if not scoped.get("recent"):
            return {"kind": "template", "slot": "explain_event",
                    "text": f"No events were recorded {window}."}
        rows = scoped["recent"]
        weak = any(w in (question or "").lower() for w in _WEAK_SUMMARY_WORDS)
        if ((_wants_summary(question) or (weak and len(rows) > 3))
                and not _tool_from_question(question, friendly)):
            return {"kind": "template", "slot": "explain_event",
                    "text": _window_summary(window, rows, friendly),
                    "rows": rows[:3], "tool": ""}
        pack = scoped
    row = _anchored_row(question, anchor, pack.get("recent") or [],
                        history=pack.get("history"))
    if row is not None:
        tool = str(row.get("tool") or row.get("from_tool") or "")
        return {"kind": "template", "slot": "detail",
                "tool": tool, "text": answer_detail(row)}
    tool = _tool_from_question(question, friendly)
    if tool and registry_names and tool not in registry_names:
        tool = None                    # never stage a tool outside the registry
    named = [t for t in _tools_from_question(question, friendly)
             if not registry_names or t in registry_names]
    if len(named) >= 2 and not _mentions(question):
        # 'what is the difference between the firewall and the app
        # firewall?' used to describe only the first one.
        texts = [compose("tool_status", pack, t) for t in named[:3]]
        texts = [t for t in texts if t]
        if texts:
            return {"kind": "template", "slot": "tool_status",
                    "tool": named[0], "text": "\n\n".join(texts)}
    if tool and not _mentions(question):
        text = compose("tool_status", pack, tool)
        if text is not None:
            return {"kind": "template", "slot": "tool_status",
                    "tool": tool, "text": text}
    if _mentions(question):
        if tool is None and not _points_at_row(question):
            # 'is it bad that chrome crashed?' names something specific.
            # The newest three rows are allows, so listing them answers a
            # different question; the named word still finds its own row.
            kind = _kind_word(question)
            if kind and not _kind_rows(kind, pack):
                if kind in ("warning", "suspicious"):
                    noise = _events.count_noise(
                        list(pack.get("history") or [])
                        + list(pack.get("recent") or []))
                    more = (f"the only serious lines I can read are {noise} "
                            f"test fixtures from the app's own test suite, "
                            f"which are harmless." if noise else
                            "I found no serious line in the log I can read.")
                    return {"kind": "template", "slot": "explain_event",
                            "text": ("Nothing real needs attention: " + more
                                     + " Ask 'what needs attention?' for the "
                                       "current ranking."),
                            "rows": [], "tool": ""}
                return {"kind": "template", "slot": "explain_event",
                        "text": (f"I found no {kind} lines in the log I can "
                                 "read — the newest rows are a different kind "
                                 "of event, so showing them would answer a "
                                 "question you did not ask. Ask 'what needs "
                                 "attention?' for the current ranking, or "
                                 "'explain the newest event' to read what is "
                                 "actually there."),
                        "rows": [], "tool": ""}
            hit = _detail_by_words(question, pack)
            if hit is not None:
                tool = str(hit.get("tool") or hit.get("from_tool") or "")
                return {"kind": "template", "slot": "detail",
                        "tool": tool, "text": answer_detail(hit)}
        if tool is None and _has_any((question or "").lower(),
                                     ("alert", "alerts")):
            # "explain this alert" deserves a serious line, and the newest
            # three rows on a busy minute are allows.
            pool = _dedupe_newest((pack.get("history") or [])
                                  + (pack.get("recent") or []))
            hot = [r for r in pool
                   if str(r.get("severity", "")).upper()
                   in ("HIGH", "CRITICAL") and not _events.is_noise(r)]
            if hot:
                return {"kind": "template", "slot": "explain_event",
                        "text": compose("explain_event", {"recent": hot}),
                        "rows": hot[:3], "tool": ""}
        text = compose("explain_event", pack, tool)
        if text is None and tool:
            # named tool, no events of its own in the window: its status
            # is still a real answer
            text = compose("tool_status", pack, tool)
        if text is not None:
            rows = event_rows(pack, tool)[:3]
            named = tool or (str(rows[0].get("tool")
                                 or rows[0].get("from_tool") or "")
                             if rows else "")
            return {"kind": "template", "slot": "explain_event",
                    "text": text, "rows": rows, "tool": named}
    if llm is not None and llm.is_ready():
        slot, reply = route(question, llm.ask_sync,
                            tool_names=" ".join(sorted(registry_names)),
                            scan_names=_SCAN_NAMES)
        if slot in SLOTS_WITH_TEMPLATES:
            hint = reply if (slot == "explain_event"
                             and reply in registry_names) else None
            text = compose(slot, pack, hint)
            if text is not None:
                plan = {"kind": "template", "slot": slot,
                        "tool": hint or "", "text": text}
                if slot == "explain_event":
                    plan["rows"] = event_rows(pack, hint)[:3]
                return plan
            return {"kind": "summary", "prompt": _pack_prompt(pack, question)}
        if slot == "intent":
            if reply.lstrip().startswith("{"):
                return {"kind": "model", "prompt": question,
                        "intent_reply": reply}
            # Intent slot with no action-bearing JSON: treat as a summary
            # turn — nothing executes, nothing stalls.
            return {"kind": "summary", "prompt": _pack_prompt(pack, question)}
        return {"kind": "summary", "prompt": _pack_prompt(pack, question)}
    return {"kind": "template", "slot": "overview",
            "text": compose("overview", pack)
            or "Docs-only mode: I can describe tool states and recent "
               "events."}


def _mentions(question: str) -> bool:
    low = (question or "").lower()
    return any(w in low for w in _EVENT_WORDS)


def _has_any(low: str, words) -> bool:
    return any(re.search(rf"\b{re.escape(w)}\b", low) for w in words)


# A verb alone does not make a request. "why did the firewall stop?" names
# a pause verb and a tool, and the old ladder answered it by staging a
# pause of the firewall. Only sentence shapes that ask the app to act may
# reach the confirm gate.
_NOT_A_REQUEST = re.compile(
    r"^\s*(what|why|how|when|where|who|which|whose|is|are|was|were|does|"
    r"do|did|has|have|had|should|would|will|can you tell|could you tell|"
    r"tell me|explain)\b")


def _command_shape(low: str) -> bool:
    return _NOT_A_REQUEST.match(low) is None


_ALL_ACTIONS_TEXT = (
    "I will not switch every protection off at once: that is the one state "
    "where the machine is left unwatched, and it is not something to do by "
    "accident. I can pause one protection at a time — say which one, for "
    "example 'pause the firewall' — and the app asks you to confirm before "
    "anything changes. Turning them all back on is fine: say 'turn "
    "everything back on'.")


def _wants_all_actions(question: str) -> bool:
    low = (question or "").lower()
    # "turn everything off" does not contain a contiguous pause verb, so
    # the verb list alone let the most destructive phrasing fall through
    # to an overview. A turn/switch/shut ... off/down over a bulk target
    # is the same request and gets the same refusal.
    bulk_off = re.search(
        r"\b(turn|switch|shut)\b[^?]{0,30}?\b(off|down)\b", low) is not None
    return (_command_shape(low)
            and (_has_any(low, _PAUSE_VERBS + _RESUME_VERBS) or bulk_off)
            and _has_any(low, _ALL_TARGETS))


def _wants_action_without_target(question, friendly, last_tool) -> bool:
    """A verb with no resolvable tool, and no pronoun that could point at
    the previous turn. The answer is a question, not a guess."""
    low = (question or "").lower()
    if not _command_shape(low):
        return False
    if not _has_any(low, _PAUSE_VERBS + _RESUME_VERBS):
        return False
    if _tool_from_question(question, friendly):
        return False
    if last_tool and _has_any(low, _PRONOUNS):
        return False                 # _intent_from_question owns this case
    return True


# "Should I pause the firewall?" is neither a command (it starts with
# 'should') nor a tool-status question. The app answers the trade-off.
_PAUSE_QUESTION = re.compile(
    r"\bshould (i|we)\b[^?]{0,60}?\b(pause|stop|turn off|shut off|disable|"
    r"deactivate|switch off)\b", re.I)


def _pause_advice(question, pack, friendly, registry_names):
    if _PAUSE_QUESTION.search(question or "") is None:
        return None
    tool = _tool_from_question(question, friendly)
    if tool is None or (registry_names and tool not in registry_names):
        return None
    name, desc = friendly.get(tool, (tool, ""))
    desc = desc.rstrip(".")
    text = (f"Short answer: you can, and it is reversible — the app asks you "
            f"to confirm first. {name}: {desc[0].lower()}{desc[1:]}. That "
            f"work stops while it is paused, so nothing else in the app "
            f"covers it. Pause it from its row, then resume it when you are "
            f"done; leaving it paused is the one state where that layer is "
            f"not watching.")
    return tool, text


_ASK_TARGET = (
    "Which protection should I change? I can pause or resume one at a time, "
    "for example the firewall, the antivirus, or the network watcher. Say "
    "the name and I will show a confirm box first.")


_UNBLOCK_VERB = re.compile(r"\bun ?block\b")
_ALLOW_VERB = re.compile(r"\b(allow|trust|permit|let\b[^.]{0,16}\bthrough)\b")
_BLOCK_REFERENT = re.compile(
    r"\b(last|latest|newest)\s+(blocked?|denied?|block|deny|denial)\b"
    r"|\b(blocked|denied)\s+(site|host|address|ip|target|connection|website)\b"
    r"|\b(blocked|denied)\s+site\b"
    r"|\b(that|this|the same)\s+(site|host|address|ip|one|connection|website)\b"
    r"|\b(?:it|them)\b")
_APPFW_ROWS = ("appfw",)


def _block_target(row: dict) -> str | None:
    """The destination a block line was refusing, or None.

    The app firewall writes 'program → host:port deny'; ufw writes
    DST=…/SRC=… pairs, where the site is DST — taking the first address
    there would allow the machine that asked, the opposite of the ask."""
    text = str(row.get("text", ""))
    match = re.search(r"\bDST=(\d{1,3}(?:\.\d{1,3}){3})", text)
    if match:
        return match.group(1)
    dest = _DEST_PAT.search(text)
    if dest:
        host = _strip_port(dest.group(2))
        if host:
            return host
    addr = _ADDR_PAT.search(text)
    return addr.group(1) if addr else None


def _unblock_intent(question, pack, anchor=None):
    """'Unblock the last blocked site' acts on a block the log shows.

    This used to fall through to the blocking advice — the same refusal
    explanation every time, and the owner's allow request did nothing
    (2026-10-30). The newest denied or dropped line from the app firewall
    resolves to a destination, and the request becomes the same
    confirm-gated trust action the Settings page performs. The trust list
    only steers the app firewall: a fail2ban ban is not lifted by it, so
    a newer ban row refuses here and the honest advice covers it."""
    low = (question or "").lower().strip()
    if not low or not _command_shape(low):
        return None
    if _UNBLOCK_VERB.search(low) is None and not (
            _ALLOW_VERB.search(low) and _BLOCK_REFERENT.search(low)):
        return None
    literal = _SITE_WORD.search(low)
    if literal is not None and _UNBLOCK_VERB.search(low) is not None:
        return Intent("trust_site", value=literal.group(1).lower())
    rows = _dedupe_newest(list(anchor or [])
                          + list(pack.get("recent") or []))
    hits = [r for r in rows if _BLOCK_PAT.search(str(r.get("text", "")))]
    if not hits:
        hits = _block_rows(pack)
    newest = next((r for r in hits if str(r.get("tool")
                                            or r.get("from_tool") or "")
                   in _APPFW_ROWS), None)
    if newest is None:
        return None
    host = _block_target(newest)
    if not host:
        return None
    return Intent("trust_site", value=host)


# The app itself as the subject: what it is for, how to read it, and what
# the state colours mean. This rung exists because the model was asked
# these ("what does yellow mean?") and correctly refused — the context
# pack held no glossary, so the app looked broken to someone who simply
# did not know the vocabulary.
_APP_EXPLANATION = (
    "GreyWatch is a local security dashboard for this computer. It runs a "
    "set of independent protections — things like a firewall, an antivirus, "
    "a rootkit scanner and a watcher for programs that connect to the "
    "internet — and shows two things on one page: whether each protection "
    "is running right now (the colours), and what each one has seen (the "
    "event list).\n\n"
    "Green means running normally. Yellow means a protection needs "
    "attention — usually not installed, or installed but not doing its job. "
    "Red means it is not running at all. Grey or 'could not check' means "
    "the app could not read that layer's state.\n\n"
    "You do not need to know any commands. Ask me 'what needs attention', "
    "'explain the last event', or 'pause the firewall', and I will show you "
    "the plain meaning and the next step. Anything that changes the machine "
    "asks you to confirm first.")

_CAPABILITIES = (
    "I can tell you what is running, explain any line in the event list in "
    "plain words, explain what each protection does, tell you what needs "
    "attention, and pause or resume one protection after you confirm. Try "
    "\"what needs attention?\", \"explain the last block\", or \"pause the "
    "firewall\".")


def _quarantine_rows(pack: dict) -> list[dict]:
    """Every log line that reports a quarantine, oldest first. The log
    writes 'quarantine:' and people ask about the 'quarantined' file, so
    the stem is matched on both sides."""
    pool = list(pack.get("history") or []) + list(pack.get("recent") or [])
    rows = [e for e in pool if "quarantin" in str(e.get("text", "")).lower()]
    rows.sort(key=lambda e: str(e.get("ts", "")))
    return rows


# Words that point at ONE line rather than at the vocabulary. The concept
# answer tells the owner to ask 'explain the quarantined file', so that
# exact sentence must reach the line: matching it as a concept question
# made the assistant repeat its own definition and never read the file.
_LINE_POINTERS = ("file", "files", "line", "lines", "that", "this",
                  "these", "those", "newest", "latest", "last")


def _concept_answer(question: str, pack: dict, friendly: dict) -> str | None:
    low = (question or "").lower()
    named_tool = _tool_from_question(question, friendly)
    if ("quarantine" in low or "quarantined" in low) and (
            "mean" in low or "what is" in low or "explain" in low):
        if _has_any(low, _LINE_POINTERS):
            return None      # a specific line: _quarantine_answer reads it
        hits = _quarantine_rows(pack)
        tail = ("" if not hits else
                f" The newest one happened at {local_clock(hits[-1].get('ts'))} "
                f"; ask 'explain the quarantined file' to read that line.")
        return ("Quarantine means the auto-responder found a dangerous file "
                "and moved it to a safe holding area instead of deleting it. "
                "Nothing on your computer ran that file, and it can be "
                "restored if the alert was a mistake." + tail)
    for word, text in _STATE_MEANINGS.items():
        if re.search(rf"\b{word}\b", low) and (
                "mean" in low or "what is" in low or "explain" in low
                or "why" in low or "state" in low):
            others = " ".join(short for name, short in _STATE_SHORT.items()
                              if name != word)
            counts = [t for t in pack.get("tools") or []
                      if t.get("state") == word.upper()]
            tail = (f" Nothing is {word} right now." if not counts else
                    f" Right now {len(counts)} layer(s) are {word}: "
                    + ", ".join(t["name"] for t in counts[:5]) + ".")
            return text + " The other colours: " + others + tail
    if any(re.search(rf"\b{re.escape(w)}\b", low) for w in _APP_SUBJECTS):
        if named_tool:
            return None              # "what does the firewall do?" is a tool
        # "should I worry about the program that was blocked?" contains the
        # app's noun ('program') but asks about a log line. The event and
        # advice rungs below own that question; only a question that names
        # GreyWatch itself gets the app introduction.
        if _mentions(question) and not _has_any(
                low, ("app", "application", "greywatch", "dashboard",
                      "interface")):
            return None
        return _APP_EXPLANATION
    if ("what can you do" in low or "help" == low.strip()
            or "what do you do" in low or "how do i use" in low
            or "how do i start" in low):
        return _CAPABILITIES
    if re.match(r"^\s*(hi|hello|hey|good (morning|afternoon|evening))\b", low):
        return ("Hello. " + _CAPABILITIES)
    return None


# Time-scoped event questions ("what happened last night?") used to answer
# with whatever was newest, which reads as if 'last night' meant nothing.
_BLOCK_WORDS = ("block", "blocks", "blocked", "blocking", "deny", "denies",
                "denied", "denying", "drop", "drops", "dropped", "dropping",
                "reject", "rejects", "rejected", "rejecting")
_BLOCK_PAT = re.compile(r"\b(deny|denied|denying|drop|dropped|dropping|"
                        r"block|blocked|blocking|reject|rejected)\b", re.I)
_ADDR_PAT = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_DEST_PAT = re.compile(r"(\S+)\s*(?:→|->)\s*(\S+)")


_QUARANTINE_ASK = ("explain", "read", "show", "what was", "what happened",
                   "detail", "which file", "what is", "the file", "the line")


def _quarantine_answer(question: str, pack: dict) -> str | None:
    """Read the actual quarantine line once someone asks about it.

    The concept answer ends with "ask 'explain the quarantined file' to
    read that line". Before this rung existed that sentence led back into
    the concept answer, so the assistant repeated its own definition — the
    owner typed exactly what it suggested and got the same paragraph.
    Returns None when the question is not about a quarantine line."""
    low = (question or "").lower()
    if "quarantin" not in low:
        return None
    if not _has_any(low, _QUARANTINE_ASK):
        return None
    rows = _quarantine_rows(pack)
    if not rows:
        return ("No quarantine is recorded in the log I can read right now. "
                "If the dashboard lists one, it may be older than the log "
                "window — ask 'what needs attention?' for the current ranking.")
    row = rows[-1]
    text = answer_detail(row)
    if len(rows) > 1:
        text += (f"\n\nThat is the newest of {len(rows)} quarantine lines "
                 "in the log I can read.")
    return text


def _dedupe_newest(rows) -> list[dict]:
    """Newest first, identical (ts, text) lines collapsed — the digest and
    the history tail overlap, so the same line arrives twice."""
    seen, out = set(), []
    for r in rows or []:
        key = (str(r.get("ts", "")), str(r.get("text", "")))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    out.sort(key=lambda r: str(r.get("ts", "")), reverse=True)
    return out


def _block_rows(pack) -> list[dict]:
    pool = _dedupe_newest((pack.get("history") or [])
                          + (pack.get("recent") or []))
    return [r for r in pool if _BLOCK_PAT.search(str(r.get("text", "")))]


_ACTOR_ASK = ("what program", "which program", "what app", "which app",
              "what process", "which process", "what software",
              "which software", "what executable", "which executable",
              "what was blocked", "what got blocked", "what is blocked",
              "what's blocked", "what was denied", "what got denied",
              "what is being blocked", "what has been blocked",
              "who was blocked", "what did you block")


def _blocked_actor(row: dict) -> str:
    """The program field of a block line, or "" when the log has no name.

    appfw writes '<program> → <destination> deny'; when it could not
    resolve the process the field literally reads <unknown>, and saying so
    is the honest answer rather than inventing a program."""
    match = _DEST_PAT.search(str(row.get("text", "")))
    if not match:
        return ""
    token = match.group(1).strip("[]()'\"")
    if token.lower() in ("<unknown>", "unknown", "-", "none", "n/a"):
        return ""
    return token


_IPPORT_RE = re.compile(r"^(?:\[([0-9A-Fa-f:.]+)\]|([^:]+))(?::\d{1,5})?$")


def _strip_port(destination: str) -> str:
    """``208.82.238.129:443`` → ``208.82.238.129``; ``[::1]:443`` → ``::1``."""
    # Brackets stay: "[2606:4700::1]:443" is how the log writes IPv6.
    dest = (destination or "").strip().strip("()'\",;")
    m = _IPPORT_RE.match(dest)
    if not m:
        return dest
    return m.group(1) or m.group(2) or dest


def _connection_target(pack: dict, plan: dict):
    """(program, host) of the connection a turn is about, or None.

    The chat answer names the program but shows the destination only as an
    address; this pulls both out of the newest row so the panel can draw
    the program's icon and the destination's brand mark or map tile
    (owner 2026-10-29: "make it more visual"). A program the log could not
    resolve comes back as "" — never invented.
    """
    rows = plan.get("rows") or []
    if not rows:
        rows = _block_rows(pack)
    if not rows:
        return None
    text = str(rows[0].get("text", ""))
    program, host = "", ""
    match = _DEST_PAT.search(text)
    if match:
        program = match.group(1).strip("[]()'\"")
        host = _strip_port(match.group(2))
    else:
        addr = _ADDR_PAT.search(text)
        if not addr:
            return None
        host = addr.group(1)
    if not host or host.lower() in ("<unknown>", "unknown", "-"):
        return None
    if program.lower() in ("<unknown>", "unknown", "-", "none", "n/a"):
        program = ""
    return (program, host)


def _program_line(ident: dict, fallback: str = "") -> str:
    """One short line about where a program came from."""
    kind = str(ident.get("kind") or "")
    pkg = str(ident.get("package") or "")
    if kind == "package" and pkg:
        return f"From the {pkg} package"
    if kind == "flatpak":
        return "Flatpak application"
    if kind == "snap":
        return "Snap application"
    if kind == "loose":
        return "Installed outside packages"
    return str(ident.get("binary") or fallback or "Program")


def _blocked_actor_answer(question: str, pack: dict,
                          friendly: dict) -> str | None:
    """'What program was blocked?' asks WHICH, not WHETHER.

    The blocking rung matched the word "blocked" and answered "Yes —
    connections are being refused", with the destinations but no program.
    The owner asked for the program and got the count (2026-10-29)."""
    low = (question or "").lower()
    if not _has_any(low, _ACTOR_ASK):
        return None
    if _has_any(low, _REFERENTIAL):
        return None          # 'the program that was blocked' is an anchor
    hits = _block_rows(pack)
    if not hits:
        return ("Nothing is being blocked right now: the log I can read "
                "holds no denied or dropped connections.")
    newest = hits[0]
    tool = str(newest.get("tool") or newest.get("from_tool") or "")
    name = friendly.get(tool, (tool, ""))[0]
    when = local_clock(newest.get("ts"))
    # "the log I can read", not "the log": this rung sees the recent tail
    # and search hits, not all 4000 lines the Logs page holds.
    more = (f" The log I can read holds {len(hits)} denied lines."
            if len(hits) > 1 else "")
    actor = _blocked_actor(newest)
    if actor:
        return (f"The newest block is {actor}, at {when}, from {name} "
                f"({tool}).{more} If you trust that program, allow it in "
                "Settings → App firewall; if you did not start it, leaving "
                "it blocked is the safe answer.")
    dest = _DEST_PAT.search(str(newest.get("text", "")))
    if dest:                 # appfw shape: '<program> → <host> deny'
        where = f" to {dest.group(2)}"
        why = ("the program field on that line reads <unknown>: the firewall "
               "saw a program ask and refused it, but could not resolve "
               "which one. That happens in a burst of connections, when it "
               "cannot match the request to a running process in time.")
        then = ("The name appears the next time that program asks — the app "
                "firewall shows an identity card naming it at that moment.")
    else:                    # address-only tools: ufw rules, fail2ban bans
        addr = _ADDR_PAT.search(str(newest.get("text", "")))
        where = f" involving {addr.group(1)}" if addr else ""
        why = ("this tool records addresses and ports, not the program that "
               "asked.")
        then = ("The app firewall shows an identity card naming a program "
                "when it asks to connect.")
    return ("The log does not name the program. The newest block — "
            f"{when}, {name} ({tool}) — refused a connection{where}, and "
            f"{why}{more} {then} Settings → App firewall lists what has "
            "been allowed and blocked, and Logs → select the line → "
            "Details shows the raw text.")


def _is_yes_no(question: str) -> bool:
    """'Yes —' belongs on 'are connections blocked?', not on 'why does my
    computer keep blocking connections?', which is not a yes/no question."""
    words = re.findall(r"[a-z']+", (question or "").lower())
    return bool(words) and words[0] in (
        "is", "are", "was", "were", "am", "do", "does", "did", "can",
        "could", "should", "would", "will", "has", "have", "had")


def _blocking_answer(question: str, pack: dict, friendly: dict) -> str | None:
    """'Why does my computer keep blocking connections?' is about the act
    of blocking, not about whichever line is newest. The old event rung
    answered it with the three newest rows, which on a quiet minute are
    'allow' lines — the opposite of what was asked."""
    low = (question or "").lower()
    if not _has_any(low, _BLOCK_WORDS):
        return None
    if _has_any(low, _REFERENTIAL):
        return None          # 'what is that denied' points at an anchored row
    hits = _block_rows(pack)
    named = _tool_from_question(question, friendly)
    if named:
        own = [r for r in hits
               if str(r.get("from_tool") or r.get("tool") or "") == named]
        if not own:
            label = friendly.get(named, (named, ""))[0]
            other = next((str(r.get("from_tool") or r.get("tool") or "")
                          for r in hits
                          if str(r.get("from_tool") or r.get("tool") or "")
                          != named), "")
            extra = ""
            if other:
                oname = friendly.get(other, (other, ""))[0]
                extra = (f" The refusals in the log come from {oname} "
                         f"({other}) instead — that is the layer that asks "
                         "before a program connects, and 'deny' there means "
                         "the answer was no.")
            return (f"I found no denied connections from {label} ({named}) in "
                    "the log I can read." + extra)
        hits = own
    if not hits:
        return ("Nothing is being blocked right now: I found no denied or "
                "dropped connections in the log I can read. A line that says "
                "'allow' is the opposite — that connection was let through, "
                "and the app firewall records allows too, which is why the "
                "event list can look busy without anything being refused.")
    newest = hits[0]
    tool = str(newest.get("tool") or newest.get("from_tool") or "")
    name = friendly.get(tool, (tool, ""))[0]
    dest = _DEST_PAT.search(str(newest.get("text", "")))
    where = f" ({dest.group(1)} → {dest.group(2)})" if dest else ""
    opener = ("Yes — connections are being refused"
              if _is_yes_no(question) else "Connections are being refused")
    return (f"{opener}: the log I can read holds "
            f"{len(hits)} denied or dropped lines, the newest at "
            f"{local_clock(newest.get('ts'))} from {name} ({tool}){where}. "
            "A deny line means a program asked to reach the internet and "
            "nothing allowed it. If that program is one you trust, open the "
            f"app, select {name}, and allow it there; if you did not start "
            "it, leaving it blocked is the safe answer.")


_ATTACK_WORDS = ("under attack", "being attacked", "attacked", "hacked",
                 "hacking", "break in", "broke in", "breaking in", "intruder",
                 "intruders", "intrusion", "compromised", "compromise",
                 "infected", "someone on my", "someone in my", "am i safe",
                 "are we safe", "is my computer safe", "is this safe")

_HOWTO_WORDS = ("how do i tell", "how can i tell", "how would i know",
                "how do i know", "how can i know", "how do i check",
                "how can i check", "how can i see", "how do i see",
                "what are the signs", "what should i look for",
                "how do i find out", "how can i find out")
_BREAKIN_WORDS = ("break in", "breaking in", "break-in", "broke in",
                  "intruder", "intruders", "attacker", "attackers", "hacker",
                  "hackers", "hacked", "compromised", "infected", "virus",
                  "malware", "spyware", "someone", "somebody")


def _wants_attack(question: str, friendly: dict) -> bool:
    """A question about the machine's safety, not about one named tool or
    one shown line."""
    low = (question or "").lower()
    if not _has_any(low, _ATTACK_WORDS):
        return False
    if _tool_from_question(question, friendly):
        return False        # 'is the malware scanner running?' is a tool
    if _has_any(low, ("this line", "that line", "this event", "that event")):
        return False
    return True


def _howto_answer(question: str, pack: dict, friendly: dict) -> str | None:
    """'How can I tell if someone is trying to break in?' is a how-to
    question, and the advice rung used to answer it with a ranked list of
    what is presently wrong — true, but not an answer. This rung explains
    the real signals, then checks the log for each one."""
    low = (question or "").lower()
    if not _has_any(low, _HOWTO_WORDS):
        return None
    if not _has_any(low, _BREAKIN_WORDS):
        return None
    blocks = _block_rows(pack)
    pool = _dedupe_newest((pack.get("history") or [])
                          + (pack.get("recent") or []))
    hot = [r for r in pool
           if str(r.get("severity", "")).upper() in ("HIGH", "CRITICAL")
           and not _events.is_noise(r)]
    attention = [t for t in (pack.get("tools") or [])
                 if t.get("state") in ("YELLOW", "RED")]
    # Repetition is the real signal: one refusal is a program asking; the
    # same outside address refused repeatedly is someone knocking.
    counts: dict[str, int] = {}
    for r in blocks:
        m = _ADDR_PAT.search(str(r.get("text", "")))
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    top_addr, top_n = (max(counts.items(), key=lambda kv: kv[1])
                       if counts else ("", 0))
    parts = [
        "The signs that matter, in this app: 1) a run of deny lines — the "
        "firewall or app firewall refusing a program; one is normal, many "
        "from the same outside address is not. 2) A High or Critical line in "
        "the event list; a quarantine means something dangerous was found "
        "and stopped. 3) A protection turning yellow or red, because a layer "
        "that is not running cannot warn you.",
        f"Right now I can see {len(blocks)} denied connections, "
        f"{len(hot)} High or Critical events, and {len(attention)} "
        f"protection{'s' if len(attention) != 1 else ''} needing attention.",
    ]
    if hot:
        newest = hot[0]
        parts.append(
            f"So there is something real to look at — the newest serious "
            f"line is from {local_clock(newest.get('ts'))}. Ask 'should I "
            "worry?' and I will rank it.")
    elif top_n >= 5:
        parts.append(
            f"So there is a pattern worth a look: {top_addr} was refused "
            f"{top_n} times. Ask 'why does my computer keep blocking "
            "connections?' to read the lines.")
    else:
        parts.append("So nothing in the log looks like a break-in: the "
                     "protections are all running and nothing serious was "
                     "recorded.")
    return " ".join(parts)


_SUMMARY_WORDS = ("explain what happened", "summarize", "summarise",
                  "summary", "simple words", "in plain", "plain english",
                  "overview of", "walk me through", "give me an overview")
# 'what happened last night?' is not a request to compress: with one or
# two lines a raw row is more useful than a summary. Only a busy window
# gets compressed unless the question asks for plain words.
_WEAK_SUMMARY_WORDS = ("what happened", "what went on", "anything bad",
                       "anything serious", "anything happen",
                       "did anything", "anything to worry")


def _wants_summary(question: str) -> bool:
    low = (question or "").lower()
    return any(w in low for w in _SUMMARY_WORDS)


def _window_summary(label: str, rows: list[dict], friendly: dict) -> str:
    """A time-scoped 'what happened' question wants the shape of the
    window, not three raw rows. Counts come from the rows already
    filtered to that window; nothing here is guessed."""
    total = len(rows)
    head = (f"One event was recorded {label}" if total == 1
            else f"{total} events were recorded {label}")
    tools: dict[str, int] = {}
    hot, noise = [], 0
    for r in rows:
        t = str(r.get("tool") or r.get("from_tool") or "")
        tools[t] = tools.get(t, 0) + 1
        if str(r.get("severity", "")).upper() in ("HIGH", "CRITICAL"):
            if _events.is_noise(r):
                noise += 1
            else:
                hot.append(r)
    quiet = (f" ({noise} of them are the app's own test fixtures, not "
             f"threats)" if noise else "")
    fixtures = (" besides the app's own test fixtures" if noise else "")
    top = max(tools, key=tools.get) if tools else ""
    name = friendly.get(top, (top, ""))[0] if top else "the protections"
    if not hot:
        newest = rows[0]
        meaning = _plain.sentence({"from_tool": newest.get("tool")
                                   or newest.get("from_tool", ""),
                                   "text": newest.get("text", "")})
        return (f"{head}. Nothing serious: no High or Critical lines"
                f"{fixtures}. Most of "
                f"them ({tools.get(top, 0)} of {total}) came from {name} "
                f"({top}) — for example {meaning.lower()} — which are routine "
                "records, not alarms. You do not need to do anything.")
    lines = [f"{head}, and {len(hot)} of them were serious{quiet}:"]
    for r in hot[:2]:
        meaning = _plain.sentence({"from_tool": r.get("tool")
                                   or r.get("from_tool", ""),
                                   "text": r.get("text", "")})
        lines.append(f"- {local_clock(r.get('ts'))} · "
                     f"{_plain.severity_word(r.get('severity'))}: {meaning}. "
                     f"raw: {r.get('text', '')}")
    rest = total - len(hot)
    if rest:
        lines.append(f"The other {rest} came mostly from {name} ({top}) and "
                     "are routine. Ask 'should I worry?' for the next step.")
    return "\n".join(lines)


_TIME_WORDS = ("today", "tonight", "yesterday", "last night", "overnight",
               "this morning", "this afternoon", "this evening",
               "last hour", "past hour", "last 24 hours", "past day",
               "this week", "past week")


def _scope_by_time(question: str, pack: dict) -> tuple[str, dict]:
    """Return (window label, pack with `recent` limited to that window).

    Boundaries follow the owner's clock, not UTC: at 4 pm in Tucson 'last
    night' is the previous local evening, and a UTC split answers a
    different question.
    """
    import datetime as _dt

    low = (question or "").lower()
    hit = next((w for w in _TIME_WORDS if w in low), None)
    if hit is None:
        return "", pack
    now = _dt.datetime.now().astimezone()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if hit == "last night":
        start, end, label = (today - _dt.timedelta(hours=6),
                            today + _dt.timedelta(hours=6), "last night")
        end = min(end, now)
    elif hit == "overnight":
        start, end, label = today - _dt.timedelta(hours=6), now, "overnight"
    elif hit == "yesterday":
        start, end, label = today - _dt.timedelta(days=1), today, "yesterday"
    elif hit == "this morning":
        start, end = today, min(today + _dt.timedelta(hours=12), now)
        label = "this morning"
    elif hit == "this afternoon":
        start = today + _dt.timedelta(hours=12)
        end, label = min(today + _dt.timedelta(hours=18), now), "this afternoon"
    elif hit == "this evening":
        start = today + _dt.timedelta(hours=18)
        end, label = min(today + _dt.timedelta(hours=23), now), "this evening"
    elif hit == "tonight":
        start, end, label = today + _dt.timedelta(hours=18), now, "tonight"
    elif hit in ("last hour", "past hour"):
        start, end, label = now - _dt.timedelta(hours=1), now, "in the last hour"
    elif hit in ("last 24 hours", "past day"):
        start, end, label = (now - _dt.timedelta(hours=24), now,
                             "in the last 24 hours")
    elif hit in ("this week", "past week"):
        start, end, label = now - _dt.timedelta(days=7), now, "in the last week"
    else:                                   # today
        start, end, label = today, now, "today"

    def inside(row) -> bool:
        try:
            ts = _dt.datetime.fromisoformat(
                str(row.get("ts", "")).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=_dt.timezone.utc)
        except (ValueError, TypeError):
            return False
        return start <= ts.astimezone() <= end

    pool = list(pack.get("history") or []) + list(pack.get("recent") or [])
    scoped = dict(pack)
    # Newest first: the template prints the first three rows it is given;
    # the digest and the history overlap, so identical lines collapse.
    seen, rows = set(), []
    for r in pool:
        if not inside(r):
            continue
        key = (str(r.get("ts", "")), str(r.get("text", "")))
        if key in seen:
            continue
        seen.add(key)
        rows.append(r)
    rows.sort(key=lambda r: str(r.get("ts", "")), reverse=True)
    scoped["recent"] = rows
    return label, scoped


# Help/remediation wording. The owner's real question ("it should analyze
# and interpret my questions and help me solve issues") is this rung: the
# deterministic advice engine answers it with facts the app holds, because
# a small model inventing fixes would be worse than no answer.
_ADVICE_WORDS = ("fix", "repair", "remediate", "resolve", "address", "solve",
                 "dangerous", "advice", "recommend", "suggest", "help me",
                 "steps", "what should i do", "what can i do",
                 "what do i do", "what needs attention", "needs attention",
                 "how do i", "how can i", "is this normal", "is that normal",
                 "should i worry", "am i safe", "are we safe",
                 "is my computer safe", "is this safe", "anything wrong",
                 "anything is wrong", "something wrong", "is something wrong",
                 "whats wrong", "what's wrong", "safe", "secure", "unsafe",
                 "protected")

# A bare "why is …" asks for an explanation. It becomes a fix request only
# when it names the problem to fix; otherwise "why is my machine safe right
# now?" was answered with a ranked repair list.
_WHY_PROBLEM = ("red", "yellow", "down", "stopped", "not running",
                "not working", "broken", "fail", "failing", "failed",
                "error", "warning", "blocked", "quarantined", "alert",
                "paused", "off", "wrong", "unsafe", "suspicious", "noisy")


def _wants_advice(question: str) -> bool:
    low = (question or "").lower()
    for w in _ADVICE_WORDS:
        if " " in w:
            if w in low:
                return True
        elif re.search(rf"\b{re.escape(w)}\b", low):
            return True
    if re.search(r"\bwhy (is|are|was|were|did|does|do)\b", low):
        if _has_any(low, _REFERENTIAL):
            return False       # 'why was that quarantined?' points at the row
        return _has_any(low, _WHY_PROBLEM)
    return False


# Tools whose advice usually ends in "run a scan": the app has a real scan
# entry for each, so the answer can offer it instead of only describing it.
_SCAN_FOR_TOOL = {"rkhunter": "rkhunter", "lynis": "lynis",
                  "aide": "aide", "clamav": "clamav"}


def _suggestion(tool, pack, registry_names) -> Intent | None:
    """The one app action that moves this tool forward, if there is one.

    A paused protection is offered back; an installed scanner is offered
    its scan. Both go through the same confirm gate as a typed request —
    the button is a shortcut to the dialog, never past it.
    """
    if not tool or (registry_names and tool not in registry_names):
        return None
    entry = next((t for t in pack.get("tools") or []
                  if t.get("name") == tool), None)
    if entry is None:
        return None
    if entry.get("paused"):
        return Intent("resume", tool)
    if entry.get("installed", True) and tool in _SCAN_FOR_TOOL:
        return Intent("scan", _SCAN_FOR_TOOL[tool])
    return None


def _advice_plan(question, pack, registry_names, friendly, anchor):
    """Advice keeps the ladder's facts: a named tool wins, an anchored
    follow-up ('how do I fix that?') explains the row it points at, a
    bare 'what needs attention?' ranks every protection."""
    tool = _tool_from_question(question, friendly)
    if tool and registry_names and tool not in registry_names:
        tool = None
    row = _anchored_row(question, anchor, pack.get("recent") or [],
                        history=pack.get("history"))
    if row is not None:
        row_tool = str(row.get("tool") or row.get("from_tool") or "")
        if tool is None or tool == row_tool:
            return {"kind": "template", "slot": "advice",
                    "tool": row_tool, "text": advice.advise_event(row)}
    if tool is None:
        # A help question about a named kind of line ("what should I do
        # about the quarantined file?") has no pronoun and no tool, but
        # the word itself pins the row.
        low = (question or "").lower()
        words = [w for w in re.split(r"[^a-z0-9]+", low)
                 if len(w) >= 4 and w not in _ASK_NOISE
                 and w not in _REFERENTIAL]
        pool = ((pack.get("recent") or []) + (pack.get("history") or []))
        row = _row_by_words(words, pool)
        if row is not None:
            row_tool = str(row.get("tool") or row.get("from_tool") or "")
            return {"kind": "template", "slot": "advice",
                    "tool": row_tool, "text": advice.advise_event(row)}
        for want in ("yellow", "red"):
            if want in low:
                hit = next((t for t in pack.get("tools") or []
                            if t["state"] == want.upper()), None)
                if hit is not None:
                    tool = hit["name"]
                else:
                    return {"kind": "template", "slot": "advice",
                            "tool": "", "text": advice.advise_state_vs_events(pack)}
                break
    if tool:
        text = advice.advise_tool(pack, tool)
        if text:
            return {"kind": "template", "slot": "advice",
                    "tool": tool, "text": text,
                    "suggest": _suggestion(tool, pack, registry_names)}
    if not advice.needs_attention(pack):
        # Nothing is broken: explain the two channels instead of printing
        # an empty ranked list.
        text = advice.advise_state_vs_events(pack)
    else:
        text = advice.advise_priorities(pack)
    return {"kind": "template", "slot": "advice", "tool": "", "text": text}


def _anchored_row(question: str, anchor, recent=None,
                  history=None) -> dict | None:
    """Which previously shown row does a referential follow-up point at?

    No anchor (first turn, or the last answer was not an event listing)
    means no follow-up handling — the normal ladder decides. With an
    anchor, a keyword like 'denied' picks its row (the live pack is
    searched too, so a line that scrolled out of the last three is still
    reachable); a bare 'what does that mean?' falls back to the newest
    row that was shown."""
    if not anchor:
        return None
    low = (question or "").lower()
    if not any(re.search(rf"\b{w}\b", low) for w in _REFERENTIAL):
        return None
    # "I don't understand what this app does" contains 'this' but is a
    # question about the whole application, not about the newest row. The
    # old ladder answered it with the last deny line.
    if any(re.search(rf"\b{re.escape(w)}\b", low) for w in _APP_SUBJECTS):
        return None
    words = [w for w in re.split(r"[^a-z0-9]+", low)
             if len(w) >= 4 and w not in _ASK_NOISE
             and w not in _REFERENTIAL]
    pool = (list(anchor)
            + [r for r in (recent or []) if r not in anchor]
            + [r for r in (history or []) if r not in anchor])
    row = _row_by_words(words, pool)
    if row is not None:
        return row
    # A bare 'what does that mean?' falls back to the newest row. A
    # follow-up that names something ('that quarantined line') with no
    # match in the pool must not get the newest row instead — that is
    # how a quarantine question was answered about an appfw allow.
    if words:
        return None
    return anchor[0]


def _row_by_words(words, pool) -> dict | None:
    """First row whose text or tool matches any question word.

    Logs use other forms of the question's word: 'quarantined' must reach
    a line that says 'quarantine:'. Exact word first, then the stem, so a
    real denial still outranks a loose prefix hit.

    Event-kind words are searched before subject words: 'is it bad that
    chrome crashed?' matched a routine 'appfw chrome allow' row on
    'chrome' and said 'A program allowed', which is the opposite of the
    crash the question named."""
    ordered = sorted(words, key=lambda w: w not in _ROW_PATTERNS)
    for w in ordered:
        pats = _ROW_PATTERNS.get(
            w, (rf"\b{re.escape(w)}\b", rf"\b{re.escape(w[:6])}"))
        for pat in pats:
            for row in pool:
                hay = (str(row.get("text") or "").lower() + " "
                       + str(row.get("tool")
                             or row.get("from_tool") or "").lower())
                if re.search(pat, hay):
                    return row
    return None


# 'what is that denied' is a pronoun pointing at the last listing; 'is it
# bad that chrome crashed' uses 'that' as a conjunction. Only a referent
# followed by the kind it points at counts.
_POINTS_AT_ROW = re.compile(
    r"\b(that|this|it|its|those|these)\s+("
    + "|".join(sorted({w for w in tuple(_EVENT_WORDS) + tuple(_ROW_PATTERNS)},
                      key=len, reverse=True))
    + r")\b")


def _points_at_row(question: str) -> bool:
    return _POINTS_AT_ROW.search((question or "").lower()) is not None


_WHEN_NOISE = frozenset({"night", "morning", "afternoon", "evening", "today",
                         "tonight", "yesterday", "week", "hour", "hours"})


def _kind_word(question: str) -> str | None:
    """The log kind a question names ('crashed' -> ANOM_ABEND), or None.
    Used to refuse an answer in the wrong kind instead of showing the
    newest rows."""
    low = (question or "").lower()
    for w in _ROW_PATTERNS:
        if re.search(rf"\b{re.escape(w)}s?\b", low):
            return w
    return None


def _kind_rows(kind: str, pack: dict) -> list[dict]:
    pool = _dedupe_newest((pack.get("history") or [])
                          + (pack.get("recent") or []))
    if kind in ("warning", "suspicious"):
        # The log rarely contains the word 'warning'; a warning IS a
        # High/Critical line, minus the test fixtures that are labelled
        # benign.
        return [r for r in pool
                if str(r.get("severity", "")).upper() in ("HIGH", "CRITICAL")
                and not _events.is_noise(r)]
    pats = _ROW_PATTERNS.get(kind, (rf"\b{re.escape(kind)}\b",))
    out = []
    for row in pool:
        hay = (str(row.get("text") or "") + " "
               + str(row.get("tool") or row.get("from_tool") or "")).lower()
        if any(re.search(p, hay) for p in pats):
            out.append(row)
    return out


def _detail_by_words(question: str, pack: dict) -> dict | None:
    """A specific noun in the question ('chrome') pins its own row even
    when the newest rows are unrelated. Generic event vocabulary
    ('happened') still means 'the newest', so it never counts as a needle;
    a word with a known log spelling ('crashed' -> ANOM_ABEND) does."""
    low = (question or "").lower()
    words = [w for w in re.split(r"[^a-z0-9]+", low)
             if len(w) >= 5 and w not in _ASK_NOISE
             and w not in _WHEN_NOISE
             and (w in _ROW_PATTERNS or w not in _EVENT_WORDS)]
    if not words:
        return None
    # A word that names a log kind ('crashed' -> ANOM_ABEND) outranks a
    # plain noun ('chrome'), which also appears in ordinary deny lines.
    words.sort(key=lambda w: 0 if w in _ROW_PATTERNS else 1)
    pool = _dedupe_newest((pack.get("history") or [])
                          + (pack.get("recent") or []))
    return _row_by_words(words, pool)


def _tools_from_question(question: str, friendly: dict) -> list[str]:
    """Every protection the question names, earliest mention first.

    Whole names and whole labels are checked; 'app firewall' must win over
    the bare 'firewall' label that is a substring of it, which is why the
    earliest position decides rather than dict order."""
    low = (question or "").lower()
    hits = []
    for name, plate in friendly.items():
        label = (plate[0] if plate else "").lower()
        for needle in (str(name).lower(), label):
            if needle and needle in low:
                hits.append((low.find(needle), -len(needle), name))
    hits.sort()
    out: list[str] = []
    for _pos, _len, name in hits:
        if name not in out:
            out.append(name)
    return out


def _tool_from_question(question: str, friendly: dict) -> str | None:
    """The one protection a question is about. Whole names/labels first,
    then a single label token (word-bounded; generic words excluded) —
    'rootkit scanner' pins rkhunter this way."""
    named = _tools_from_question(question, friendly)
    if named:
        return named[0]
    low = (question or "").lower()
    for name, plate in friendly.items():
        label = (plate[0] if plate else "").lower()
        for tok in re.split(r"[^a-z0-9]+", label):
            if len(tok) < 4 or tok in _LABEL_NOISE:
                continue
            if re.search(rf"\b{re.escape(tok)}\b", low):
                return name
    return None


_SCAN_VERB = re.compile(
    r"^\s*(?:please\s+)?(?:(?:can|could|would|will)\s+you\s+)?"
    r"(?:scan|sweep)\b", re.I)
_SCAN_CHECK = re.compile(
    r"^\s*(?:please\s+)?(?:(?:can|could|would|will)\s+you\s+)?"
    r"(?:run|start|do|perform|launch|begin|check|look)\b[^.?!]*?"
    r"\b(?:scan|sweep|audit|rootkit|rootkits|virus|viruses|malware|"
    r"spyware|adware|trojan|integrity|threats)\b", re.I)
# Ordered: the more specific scan wins ('full antivirus scan' must not
# become 'scan everything', and 'security audit' must not become AIDE).
_SCAN_TARGETS = (
    ("rkhunter", ("rootkit", "rootkits", "backdoor", "hidden process")),
    ("clamav", ("antivirus", "anti-virus", "virus", "viruses", "malware",
                "spyware", "adware", "trojan", "clam")),
    ("aide", ("integrity", "aide")),
    ("lynis", ("lynis", "security audit", "hardening audit", "audit")),
    ("yara-tmp-scan", ("quick", "temp", "temporary", "tmp", "yara")),
    ("scan-all", ("everything", "all scanners", "whole system", "all scans",
                  "full scan")),
)
# The phrase that triggers each scan, in the words a person would use.
_SCAN_REQUESTS = {
    "rkhunter": "scan for rootkits",
    "clamav": "run a full antivirus scan",
    "aide": "check my file integrity",
    "lynis": "run a security audit",
    "yara-tmp-scan": "do a quick scan",
    "scan-all": "scan my computer",
}


def _scan_key(low: str) -> str:
    for key, words in _SCAN_TARGETS:
        if _has_any(low, words):
            return key
    return "scan-all"


def _scan_answer(question: str, pack: dict) -> str | None:
    """'How do I scan for rootkits?' gets the instruction (and that a
    confirm box comes first); 'did it scan?' gets the scanner's real state.
    Neither is a request to act, so neither may reach the confirm gate."""
    low = (question or "").strip().lower()
    if not re.search(r"\bscans?\b|\bscanning\b|\baudit\b|\bintegrity\b|"
                     r"\brootkits?\b", low):
        return None
    key = _scan_key(low)
    # "how do I fix the rootkit scanner?" is a repair question, and "what
    # did it find?" asks for results — both belong to later rungs.
    asks_how = (re.match(r"^\s*(how|where)\b", low)
                or re.match(r"^\s*what\s+(do|should|can)\b", low))
    if asks_how and not _has_any(low, ("fix", "repair", "broken", "why",
                                       "yellow", "red", "not working",
                                       "find", "found")):
        mode = _SCANS[key]
        title = mode["title"].lower()
        request = _SCAN_REQUESTS[key]
        password = ("It needs your password the first time." if
                    mode.get("scope") == "root" else
                    "It runs as you, so no password.")
        return (f"Say \"{request}\" and I will show a confirm box first — "
                f"nothing starts until you press Confirm. The {title} is "
                f"also a button on the deep-scan page. {password}")
    if re.match(r"^\s*(did|does|has|have|when|was|were|is|are)\b", low):
        tool = key if key != "scan-all" else ""
        if tool:
            text = compose("tool_status", pack, tool)
            if text:
                # "Did it scan?" wants the last time it did something, and
                # state alone cannot say that.
                rows = [r for r in (pack.get("history") or [])
                        + (pack.get("recent") or [])
                        if _events.tool_of(r) == tool]
                if rows:
                    newest = max(rows, key=lambda r: str(r.get("ts", "")))
                    text += (f" The newest line from it is at "
                             f"{local_clock(newest.get('ts'))}.")
                else:
                    text += (" I see no scan line from it in the log I can "
                             "read.")
                return text
        return compose("overview", pack)
    return None


_SCAN_NOUN = re.compile(r"\bscans?\b|\bscanning\b|\bsweep\b", re.I)
# A bare noun is still a request: "full scan", "quick scan", "antivirus
# scan", "i want to scan", "let's scan". The owner reported the assistant
# would not scan, and these fell through to the event rung and answered
# "No events have been recorded yet." Any lead-in is allowed, but the whole
# phrase has to be the request — "the scan is running" and "did it scan?"
# are statements and questions, not orders.
_BARE_SCAN = re.compile(
    r"^\s*(?:(?:please|pls|hey)\s+)?"
    r"(?:(?:i\s+(?:want|need|would\s+like)\s+to|let'?s|go\s+ahead\s+and)\s+)?"
    r"(?:(?:run|start|do|perform|launch|begin|kick\s+off)\s+)?"
    r"(?:a|an|the)?\s*"
    r"(?:(?:full|quick|fast|deep|complete|whole|entire|new)\s+)?"
    r"(?:virus|antivirus|anti-virus|malware|rootkit|rootkits|security|"
    r"system|temp|temporary)?\s*"
    r"(?:scan|sweep)\s*(?:again|now|please)?\s*[.!]?\s*$", re.I)


def _scan_intent(question: str) -> Intent | None:
    """A plainly phrased scan request -> the app's own scan button. The
    question must start with the verb ('scan for rootkits', 'run a quick
    scan') or be nothing but the request itself ('full scan'), so 'the scan
    finished?' and 'did it scan?' stay questions."""
    low = (question or "").strip().lower()
    if not (_SCAN_VERB.search(low) or _SCAN_CHECK.search(low)
            or (_SCAN_NOUN.search(low) and _BARE_SCAN.match(low))):
        return None
    if _NOT_A_REQUEST.match(low):
        # 'do' is both an imperative ("do a quick scan") and an auxiliary
        # ("do the scans run daily?"); only the imperative form acts.
        if low.endswith("?") or not re.match(
                r"^\s*do\s+(?:a|an|the)\b[^.?]*\b(?:scan|sweep|audit)\b",
                low):
            return None
    return Intent("scan", _scan_key(low))


_ON_WORDS = re.compile(
    r"\b(turn on|switch on|enable|start|activate)\b")
_OFF_WORDS = re.compile(
    r"\b(turn off|switch off|disable|stop|deactivate)\b")
_SITE_WORD = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
_PAGE_WORD = re.compile(
    r"\b(?:open|show|go to|take me to|switch to)\b[^?]{0,30}?"
    r"\b(security|tools?|logs?|settings?|help)\b")


def _wants_everything_on(question: str) -> bool:
    """'Turn everything back on' is the safe bulk action and must reach the
    confirm gate; only the bulk OFF is refused."""
    low = (question or "").lower()
    return (_command_shape(low)
            and _has_any(low, _RESUME_VERBS)
            and _has_any(low, _ALL_TARGETS))


def _settings_intent(question: str) -> Intent | None:
    """Deterministic intents for the window's own settings controls.

    These are the same handlers the Settings page buttons call: the app
    firewall, learning mode, the two update lists, the trusted-item lists,
    and page navigation. Every one goes through the same confirm dialog and
    audit ledger — this function only recognises the request.
    """
    low = (question or "").lower().strip()
    if not low or not _command_shape(low):
        return None
    wants_on = bool(_ON_WORDS.search(low))
    wants_off = bool(_OFF_WORDS.search(low))
    if "firewall" in low and (wants_on or wants_off) \
            and not re.search(r"\bpause\b", low):
        return Intent("firewall", value="on" if wants_on else "off")
    if "learning" in low and (wants_on or wants_off):
        return Intent("learning", value="on" if wants_on else "off")
    # "change theme to light mode" is a request, not a question about the
    # theme; the model used to answer it with an intent whose value was
    # empty and the user saw 'not a page in this app'. Colour named -> the
    # theme intent; theme named without a colour -> the Settings page,
    # where the picker lives (owner 2026-10-30).
    if "theme" in low:
        colour = re.search(r"\b(light|dark|swiss|obsidian)\b", low)
        if colour:
            return Intent("theme", value=colour.group(1).lower())
        return Intent("open_page", value="settings")
    look = re.search(r"\b(light|dark)\b", low)
    if look:
        # Every request-shaped sentence whose ask is the look itself —
        # 'switch to dark', 'make it light again', 'turn off dark mode'
        # (the owner's dark request fell past the theme-word patterns and
        # the model answered with boilerplate, 2026-10-30). OFF + dark
        # means go light.
        value = "light" if (wants_off and look.group(1) == "dark") \
            else look.group(1)
        return Intent("theme", value=value)
    if re.search(r"\bupdate\b", low) and re.search(
            r"\b(list|lists|definitions|virus|antivirus|security list|"
            r"block list)\b", low):
        return Intent("update_lists")
    site = _SITE_WORD.search(low)
    if site and re.search(r"\b(trust|allow|block|deny)\b", low) \
            and "program" not in low:
        action = ("block_site" if re.search(r"\b(block|deny)\b", low)
                  else "trust_site")
        return Intent(action, value=site.group(1).lower())
    prog = re.search(
        r"\b(?:trust|allow)\b(?: the)?(?: program| app| application)\s+"
        r"(/\S+|\S+)\s*$", low)
    if prog:
        return Intent("trust_program", value=prog.group(1))
    page = _PAGE_WORD.search(low)
    if page:
        word = page.group(1)
        key = ("settings" if word.startswith("setting")
               else "logs" if word.startswith("log")
               else "tools" if word.startswith("tool")
               else "security" if word.startswith("security")
               else "help")
        return Intent("open_page", value=key)
    return None


def _intent_from_question(question: str, friendly: dict,
                          last_tool=None) -> Intent | None:
    """Plain-English action verb + a named tool, or a pronoun resolving to
    the protection the conversation last touched. An action with no
    credible target never resolves — asking is safer than guessing."""
    low = (question or "").lower()
    if not _command_shape(low):
        return None
    # Longest phrase first: "turn back on" must win over "turn on".
    hit = next((w for w in sorted(_PAUSE_VERBS + _RESUME_VERBS,
                                  key=len, reverse=True)
                if re.search(rf"\b{re.escape(w)}\b", low)), None)
    if not hit:
        return None
    tool = _tool_from_question(question, friendly)
    if not tool and last_tool and _has_any(low, _PRONOUNS):
        tool = last_tool
    if not tool:
        return None
    return Intent("pause" if hit in _PAUSE_VERBS else "resume", tool)


def _pack_prompt(pack: dict, question: str) -> str:
    lines = ["Context pack:", f"- {pack['status_line']}"]
    hot = [f"- {t['name']} {t['state']}" for t in pack["tools"]
           if t["state"] in ("YELLOW", "RED")]
    lines += hot or ["- no protection needs attention"]
    lines += ["Recent events:"] + [f"- {e['tool']}: {e['text']} ({e['ts']})"
                                   for e in pack["recent"][:5]]
    for s in pack["snippets"][:3]:
        lines.append(f"- docs[{s['source'][:60]}]: {s['text'][:200]}")
    # Vocabulary and purpose sit in the pack so the model can explain the
    # app to someone who does not know it. Without this it was asked
    # "what does yellow mean?" and answered, correctly but uselessly, that
    # the pack did not say.
    lines.append("App facts (always true): GreyWatch is a local security "
                 "dashboard. Green = the protection is running normally. "
                 "Yellow = it needs attention (usually not installed or not "
                 "working). Red = it is not running. The event list is "
                 "history; the colours are the present. The app look is "
                 "light or dark and changes when asked ('change the theme "
                 "to light mode', or the Settings page).")
    lines.append("Answer for someone who is not technical: plain words, no "
                 "commands unless the question asks for one.")
    # The instruction sits ABOVE the question and the question is last:
    # a tiny model "continues" the prompt's final line — with the old
    # order the stream echoed "Summarize in 2-3 plain sentences" verbatim
    # instead of answering (seen live with 'make it stop').
    lines.append("Summarize in 2-3 plain sentences. If the pack genuinely "
                 "lacks the fact asked for, say which fact is missing.")
    lines.append(f"question: {question}")
    return "\n".join(lines)


_CONTRADICTION = re.compile(
    r"\b(protection|layer|tool|firewall|antivirus|scanner|watcher|app)\b"
    r"[^.]{0,40}?\b(is not running|not running|is down|is stopped|is off|"
    r"has failed|is failing|is red|is yellow)\b", re.I)


def contradicts_status(text: str, pack: dict) -> bool:
    """A model answer that claims a protection is down when the live
    status says every layer is green. Definitions ('yellow means it needs
    attention') do not count: the pattern requires a named protection."""
    hot = [t for t in (pack.get("tools") or [])
           if str(t.get("state", "")).upper() in ("YELLOW", "RED")]
    if hot:
        return False
    return bool(_CONTRADICTION.search(text or ""))


def offer_label(intent, friendly: dict, scan_titles=None) -> str:
    """The button under an advice answer: the action in the offer's own
    words, so the owner knows what the dialog will ask before clicking."""
    if intent.action == "scan":
        title = (scan_titles or {}).get(intent.tool, "a scan")
        return f"Run {title.lower()}"
    if intent.action == "resume":
        return f"Resume {friendly.get(intent.tool, (intent.tool, ''))[0]}"
    if intent.action == "pause":
        return f"Pause {friendly.get(intent.tool, (intent.tool, ''))[0]}"
    return "Do it"


def warning_line(action: str, state: str) -> str:
    """Extra confirm-dialog warning when the target is down (spec: warn
    when the target tool is RED)."""
    if action == "pause" and state == "RED":
        return ("\nThis protection is currently RED — pausing it leaves "
                "nothing running in its place.")
    if action == "firewall" and state == "off":
        return ("\nWith the firewall off, new connections are not checked "
                "and nothing asks you about them.")
    return ""


GIOMM_OK = True
try:
    from gi.repository import GLib, Gtk, Pango
except Exception:        # headless CI: widget tests skip, plan_turn still runs
    GIOMM_OK = False

if GIOMM_OK:
    from ui import visuals as _visuals

    # Short enough to fit whole inside the chat column at the 1100px window
    # (three long chips forced the ellipsis on every one). Each chip's
    # tooltip still carries the full question.
    CHIPS = ("Needs a look?", "Last block", "Why yellow?")

    class AssistantPanel(Gtk.Box):
        def __init__(self, registry, get_status, get_recent, get_llm,
                     on_intent):
            super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self._names = {t["name"] for t in registry}
            self._get_status, self._get_recent = get_status, get_recent
            self._get_llm, self._on_intent = get_llm, on_intent
            from ui.plain import FRIENDLY
            self._friendly = FRIENDLY
            # Rows the last event answer displayed: a follow-up ("what is
            # that denied?") resolves against these, not a fresh listing.
            self._last_rows = []
            # The protection the conversation last talked about: "turn it
            # back on" resolves against this instead of asking the model
            # to guess.
            self._last_tool = None
            self.append(self._build_header())
            self.banner = Gtk.Label(xalign=0)
            # The banner is one long sentence. Without wrapping it became
            # the widest thing in the chat column: at the 1280px default the
            # column could not shrink to fit, so GTK scrolled the page
            # horizontally and the assistant card's left edge was cut off
            # (seen in the 2026-10-30 Light-theme capture).
            self.banner.set_wrap(True)
            self.banner.set_max_width_chars(58)
            self.banner.add_css_class("gw-banner")
            self.append(self.banner)
            # Chat transcript takes the vertical space; the suggestion chips
            # sit just above the composer where a chat app puts them, not
            # between the header and the first message.
            self.stream = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                  spacing=10)
            self.stream.add_css_class("gw-stream")
            # Breathing room lives in CSS padding, not widget margins: a
            # margin is not part of what measure(VERTICAL) reports, so
            # _fit_stream would add it again on every pass and creep the
            # transcript 8px taller each time.

            # The transcript starts under the header, the way an assistant
            # thread does. It used to be bottom-anchored so a lone greeting
            # sat above the composer; once the chat card grew to take the
            # page's spare height that left half a screen of empty box above
            # the first message. The head widget stays (the scroll pin skips
            # it) but no longer pushes everything down.
            self._stream_head = Gtk.Box()
            self._stream_head.set_vexpand(False)
            self.stream.append(self._stream_head)
            sc = Gtk.ScrolledWindow()
            # Horizontal NEVER, not AUTOMATIC: with an automatic bar the
            # scroller hands the transcript its natural width (58 chars from
            # the bubble cap) even when the chat card is narrower, so the
            # greeting ran off the card's right edge instead of wrapping.
            sc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            sc.set_child(self.stream)
            # A narrower card reflows wrapped text to more lines, but the
            # explicit transcript height was measured at the old width, so
            # the extra line was clipped (the greeting ended mid-sentence
            # at the 1100px window). Re-measure whenever the width changes.
            sc.connect("notify::width", lambda *_a: GLib.timeout_add(
                30, self._fit_stream))
            sc.set_vexpand(True)
            # A floor, not elasticity only: at the window's 1028x706 floor
            # the page's other children squeezed the transcript to a ~30px
            # slit — one clipped line, no working scroll (wave-3 sweep).
            # 160px keeps a turn readable; the Recent-activity table below
            # yields instead.
            sc.set_size_request(-1, 160)
            self._stream_scroll = sc
            # Bounds change whenever an answer grows the transcript or the
            # card: re-pin the newest turn after that layout, not only when
            # the text was set.
            adj = sc.get_vadjustment()
            if adj is not None:
                adj.connect("changed", lambda *_a: GLib.timeout_add(
                    20, self._scroll_to_end))
            self.append(sc)
            chips = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            chips.add_css_class("gw-chips")
            chips.set_halign(Gtk.Align.START)
            for c in CHIPS:
                b = Gtk.Button(label=c)
                b.add_css_class("gw-chip")
                # Ellipsised label: a Button's minimum width is its label's,
                # and three full-length chips set a 522px floor on the whole
                # chat column — wider than the 1100px window can give it once
                # the rail is beside it, which clipped the dashboard. Short
                # labels shrink at narrow widths; the full text stays in the
                # button's tooltip.
                child = b.get_child()
                if isinstance(child, Gtk.Label):
                    child.set_ellipsize(Pango.EllipsizeMode.END)
                b.set_tooltip_text(c)
                b.connect("clicked", self._chip)
                chips.append(b)
            self.append(chips)
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            row.add_css_class("gw-composer")
            self.entry = Gtk.Entry()
            self.entry.set_placeholder_text("Ask about your protections…")
            self.entry.set_hexpand(True)
            self.entry.connect("activate", self._send)
            row.append(self.entry)
            send = Gtk.Button(label="Send")
            send.add_css_class("gw-send")
            send.connect("clicked", self._send)
            row.append(send)
            self.append(row)
            # One short line, not a paragraph: at the 1100x720 minimum the
            # transcript is only a few lines tall, and a seven-line greeting
            # filled it before the owner could ask anything. The header
            # above already explains what the assistant is.
            intro = self._bubble(
                "Hi — ask me about a protection, a log line, or anything "
                "you see here.", intro=True)
            intro.add_css_class("gw-assistant-intro")

        def _build_header(self):
            """The panel should look like an assistant, not like a text box:
            a small mascot (the wolf mark, downscaled), the name, and one
            sentence saying what it is and what it will not do."""
            head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            head.add_css_class("gw-assistant-head")
            # The product's own mark, the light wolf badge the desktop and
            # the tray already show — not a separate blue assistant logo
            # (owner: "the wolf logo should be the white one, the same as
            # the icon. i dont want to use the blue one").
            art = (pathlib.Path(__file__).resolve().parents[1] / "assets"
                   / "logo" / "greywatch-icon-128.png")
            pic = None
            if art.exists():
                # Scale the pixbuf, not the Picture: a size request is only a
                # floor, so a 40px request still painted the 128px art and
                # shoved the whole header down.
                try:
                    from gi.repository import GdkPixbuf
                    pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(
                        str(art), 44, 44, True)
                    pic = Gtk.Image.new_from_pixbuf(pb)
                    pic.set_pixel_size(44)
                except Exception:
                    pic = None
            if pic is not None:
                pic.set_valign(Gtk.Align.START)
                head.append(pic)
            else:
                ic = Gtk.Image.new_from_icon_name("security-high-symbolic")
                ic.set_pixel_size(28)
                head.append(ic)
            words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            title = Gtk.Label(label="GreyWatch Assistant", xalign=0)
            title.add_css_class("gw-assistant-title")
            sub = Gtk.Label(
                label="Local AI assistant — reads your protections and event "
                      "log, explains them in plain words, and asks before "
                      "changing anything.",
                xalign=0)
            sub.set_wrap(True)
            sub.add_css_class("gw-assistant-sub")
            words.append(title)
            words.append(sub)
            words.set_hexpand(True)
            head.append(words)
            # One click copies the whole conversation. Selecting text inside
            # a bubble is still possible, but a person reading a long
            # answer wants the thread in the clipboard, not one paragraph
            # at a time (owner 2026-10-30).
            copy = Gtk.Button(label="Copy chat")
            copy.add_css_class("gw-mini")
            copy.set_valign(Gtk.Align.START)
            copy.set_tooltip_text(
                "Copy every message in this conversation as plain text")
            copy.connect("clicked", self._copy_chat)
            head.append(copy)
            return head

        def _copy_chat(self, btn):
            lines = []
            for text, mine, _intro in getattr(self, "_transcript", []):
                lines.append(f"{'You' if mine else 'GreyWatch'}: {text}")
            body = "\n\n".join(lines).strip()
            if not body:
                return
            try:
                from gi.repository import Gdk
                Gdk.Display.get_default().get_clipboard().set(body)
                btn.set_label("Copied")
                GLib.timeout_add_seconds(
                    2, lambda: btn.set_label("Copy chat") and False)
            except Exception:
                btn.set_label("Copy failed")

        def note_state(self, ok: bool, err: str) -> None:
            # "Assistant ready." in monospace read like debug output, and a
            # permanent all-good line is not macOS. Hide it when healthy;
            # show a real sentence only when the model could not wake.
            self.banner.set_visible(not ok)
            if not ok:
                self.banner.set_text(
                    f"The local model could not start ({err}). I can still "
                    "explain the dashboard from its own data.")

        def _chip(self, b):
            self.entry.set_text(b.get_label())
            self._send()

        def _bubble(self, text, mine: bool = False, intro: bool = False):
            # A bubble is a padded surface behind selectable text, aligned
            # to the speaker: assistant left on panel, you right on accent
            # tint. The label is returned so callers keep the selectable
            # text handle they had before.
            lbl = Gtk.Label(xalign=0.0)
            lbl.set_wrap(True)
            # Cap the measure so lines stay readable in a wide window
            # instead of stretching a one-sentence answer across 1,200 px.
            lbl.set_max_width_chars(58)
            # Selectable: the owner copies a log line straight out of the
            # chat (asked for when the rkhunter answer couldn't be pasted).
            lbl.set_selectable(True)
            # But never focusable: when focus landed on a bubble (scroll,
            # tab, or the newest answer) GTK selected the whole label, and
            # the answer painted as a highlighted band (popup sweep
            # 2026-10-30). Selection by mouse still works.
            lbl.set_focusable(False)
            lbl.set_text(text)
            # Keep the transcript for handover: a theme switch rebuilds the
            # page this panel lives in (rebuilding the panel with it), and
            # the conversation must survive the look change (owner saw the
            # whole chat vanish, 2026-10-30). The pair updates in place as
            # the label's text does — a placeholder becomes its answer.
            if not hasattr(self, "_transcript"):
                self._transcript = []
            pair = [str(text), bool(mine), bool(intro)]
            self._transcript.append(pair)
            lbl.connect("notify::label",
                        lambda *_a: pair.__setitem__(0, lbl.get_text() or ""))
            # Both the base shape and the speaker variant: "mine" only
            # overrides the fill, so it must still carry the padding,
            # radius and border from .gw-bubble (without it the user's own
            # lines painted as bare text on the card).
            shell = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            shell.add_css_class("gw-bubble")
            if mine:
                shell.add_css_class("gw-bubble-mine")
            shell.append(lbl)
            # A Box gives its child the leftover width, so halign alone left
            # every bubble 79% wide. A greedy spacer on the far side pins the
            # bubble to its measured text width instead.
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            if mine:
                row.append(spacer)
                row.append(shell)
            else:
                row.append(shell)
                row.append(spacer)
            self.stream.append(row)
            self._last_row = row
            # Every later text change (placeholder → answer) needs the same
            # re-measure, so the fix hangs off the label itself instead of
            # being repeated at each of the eight set_text call sites.
            lbl.connect("notify::label", lambda *_a: GLib.timeout_add(
                30, self._fit_stream))
            GLib.timeout_add(30, self._fit_stream)
            return lbl

        def snapshot_transcript(self):
            """The handover for a look change: this panel is rebuilt with
            its page, and the conversation must carry to the next one.
            Text-only — offer buttons and evidence strips are transient —
            and the placeholder ("…") of an in-flight answer is dropped."""
            rows = [(str(p[0]), bool(p[1]))
                    for p in getattr(self, "_transcript", [])
                    if len(p) > 2 and not p[2] and p[0].strip()
                    and p[0] != "…"]
            if not rows:
                return None
            return {"rows": rows,
                    "last_rows": list(self._last_rows or []),
                    "last_tool": self._last_tool}

        def restore_transcript(self, snap):
            """Rehydrate a snapshot_transcript() handover: text bubbles in
            order, then the anchors follow-ups resolve against ('how do I
            fix that?')."""
            for text, mine in snap.get("rows", []):
                self._bubble(text, mine=mine)
            self._last_rows = list(snap.get("last_rows") or [])
            if snap.get("last_tool"):
                self._last_tool = snap["last_tool"]

        def _offer(self, intent):
            """The one-click shortcut under an advice answer.

            It executes nothing on its own: clicking opens the same
            confirm dialog a typed request opens, and the window runs the
            same handler the Settings page button runs.
            """
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            btn = Gtk.Button(label=offer_label(intent, self._friendly,
                                               _SCAN_TITLES))
            btn.add_css_class("gw-mini")
            btn.set_tooltip_text(describe(intent, self._friendly, _SCAN_TITLES))
            btn.connect("clicked", lambda *_a: self._confirm(intent))
            row.append(btn)
            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            row.append(spacer)
            self.stream.append(row)
            GLib.timeout_add(30, self._fit_stream)

        def _evidence(self, seq, plan, pack, holder):
            """The picture strip under a connection answer.

            The answer names the program but shows the destination only as
            an address. Two tiles sit under it — the program's own icon and
            the destination's brand mark, or a map pinned on its country
            when no brand is known — with the country and network beside
            them (owner 2026-10-29: "it could show an amazon logo... or a
            geoip map of the location... use the name of the program as
            well"). The lookup runs in a worker because whois can take
            seconds; the sentence answer is already on screen.
            """
            target = _connection_target(pack, plan)
            if target is None:
                return
            token, host = target
            answer = str(plan.get("text") or "")

            card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                           spacing=14)
            card.add_css_class("gw-evidence")

            def part(title, line):
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                              spacing=10)
                pic = Gtk.Image()
                # GTK4 sizes an image from a pixbuf at the default 16px
                # unless the pixel size is set explicitly; the tile is 40.
                pic.set_pixel_size(36)
                blank = _visuals.glyph_tile("…", 36)
                if blank is not None:
                    pic.set_from_pixbuf(blank)
                col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
                col.set_valign(Gtk.Align.CENTER)
                head = Gtk.Label(label=title, xalign=0)
                head.add_css_class("gw-ev-head")
                head.set_ellipsize(Pango.EllipsizeMode.END)
                head.set_max_width_chars(22)
                sub = Gtk.Label(label=line, xalign=0)
                sub.add_css_class("gw-ev-line")
                sub.set_ellipsize(Pango.EllipsizeMode.END)
                sub.set_max_width_chars(26)
                col.append(head)
                col.append(sub)
                row.append(pic)
                row.append(col)
                return row, pic, head, sub

            prog_row, prog_pic, prog_head, prog_line = part(
                token or "Unidentified program", "Looking up this program…")
            host_row, host_pic, host_head, host_line = part(
                "Destination", host)
            card.append(prog_row)
            sep = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
            card.append(sep)
            card.append(host_row)

            wrap = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            wrap.append(card)
            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            wrap.append(spacer)
            self.stream.append(wrap)
            GLib.timeout_add(30, self._fit_stream)

            def fill(result):
                if seq != getattr(self, "_turn_seq", 0):
                    return False
                result = result if isinstance(result, dict) else {}
                p = result.get("program") or {}
                ident = result.get("host") or {}
                hcard = result.get("host_card") or {}
                if token:
                    title = p.get("title") or token
                    prog_head.set_text(title)
                    prog_line.set_text(_program_line(p, token))
                else:
                    # The log really has no name on this line; saying that
                    # is the honest label, not a generic "Unknown program".
                    title = "Unidentified program"
                    prog_head.set_text(title)
                    prog_line.set_text("Not named in the log")
                made = _visuals.program_tile(
                    p.get("icon") or "", title, 36,
                    binary=p.get("binary") or "",
                    package=p.get("package") or "")
                if made is not None:
                    prog_pic.set_from_pixbuf(made)
                host_head.set_text(hcard.get("title") or "Destination")
                place = " · ".join(x for x in (
                    ident.get("country_name") or "",
                    ident.get("asn") or "") if x)
                host_line.set_text(place or host)
                picture = _visuals.host_tile(ident, 36)
                if picture is not None:
                    host_pic.set_from_pixbuf(picture)
                sentence = hcard.get("sentence") or ""
                if sentence:
                    # The answer now says what the picture shows: "This is
                    # Amazon — a network registered in the United States."
                    holder.set_text(
                        f"{answer.rstrip()}\n\n{sentence}")
                self._fit_stream()
                return False

            def work():
                import shutil
                from ui import identity
                path = shutil.which(token) if token else ""
                try:
                    result = identity.describe_connection(host, path, token)
                except Exception:
                    result = {}
                GLib.idle_add(fill, result, priority=GLib.PRIORITY_DEFAULT)

            threading.Thread(target=work, daemon=True,
                             name="gw-assistant-evidence").start()

        def _fit_stream(self, attempt=0):
            """Give the transcript an explicit height at its real width.

            A wrapped label asked for its natural height at unbounded width
            reports one line, so the ScrolledWindow sized the transcript to
            the viewport and squeezed it: long answers grew wider instead of
            taller and their tail was unreachable. Measuring at the width the
            stream actually has gives the viewport something to scroll.

            It can take two passes: growing the transcript summons the
            scrollbar, the narrower width reflows the text taller, and the
            first height is then a few pixels short.
            """
            width = self.stream.get_width()
            if width > 0:
                natural = self.stream.measure(
                    Gtk.Orientation.VERTICAL, width).natural
                if self.stream.get_size_request()[1] != natural:
                    self.stream.set_size_request(-1, natural)
                    if attempt < 2:
                        GLib.timeout_add(40, self._fit_stream, attempt + 1)
                    # The adjustment still describes the old height until
                    # the next layout pass; pin it after that pass or the
                    # newest bubble stays half-hidden under the composer.
                    GLib.timeout_add(20, self._scroll_to_end)
            return False

        def _scroll_to_end(self):
            """Show the newest turn whole, never a half-clipped line.

            Scrolling to the absolute bottom slices whatever bubble crosses
            the top edge, so an answer arrived under the first two letters
            of the greeting. If the last turn (question + answer) fits the
            transcript, align its top; if the answer alone is taller than
            the transcript, align the answer's top instead — the way
            Messages shows a long message from its beginning.
            """
            adj = self._stream_scroll.get_vadjustment()
            if adj is None:
                return False
            page = adj.get_page_size()
            if page <= 0:
                return False
            rows = []
            child = self.stream.get_first_child()
            while child is not None:
                if child is not self._stream_head:
                    rows.append(child)
                child = child.get_next_sibling()
            if not rows:
                adj.set_value(adj.get_upper() - page)
                return False
            ok, last = rows[-1].compute_bounds(self.stream)
            if not ok:
                adj.set_value(adj.get_upper() - page)
                return False
            bottom = last.origin.y + last.size.height
            if last.size.height > page - 12:
                adj.set_value(last.origin.y - 4)
                return False
            if len(rows) > 1:
                ok, prev = rows[-2].compute_bounds(self.stream)
                if ok and bottom - prev.origin.y <= page - 8:
                    adj.set_value(prev.origin.y - 4)
                    return False
            adj.set_value(bottom - page + 4)
            return False

        def ask(self, question: str, finding: dict | None = None):
            """Ask a question from outside the composer (a finding row).

            `finding` pins the answer to that exact row: the advice engine
            explains this line, rather than the router guessing a tool from
            the question's words.
            """
            if finding:
                self._pinned_finding = dict(finding)
            self.entry.set_text(question)
            self._send()

        def _send(self, *_a):
            question = self.entry.get_text().strip()
            if not question:
                return
            self.entry.set_text("")
            self._bubble(question, mine=True)
            self._turn_seq = getattr(self, "_turn_seq", 0) + 1
            seq = self._turn_seq
            holder = self._bubble("…")
            pinned, self._pinned_finding = \
                getattr(self, "_pinned_finding", None), None

            def work():
                try:
                    pack = build_pack(self._get_status(), self._get_recent(),
                                      question)
                    if pinned:
                        plan = {"kind": "template", "slot": "advice",
                                "tool": pinned.get("tool"),
                                "text": advice.advise_event(pinned)}
                    else:
                        plan = plan_turn(question, pack, self._get_llm(),
                                         self._names, self._friendly,
                                         anchor=self._last_rows,
                                         last_tool=self._last_tool)
                except Exception as err:               # never eat the question
                    GLib.idle_add(self._plan_error, seq, holder, str(err))
                    return
                GLib.idle_add(self._turn_planned, seq, holder, plan, pack)

            threading.Thread(target=work, daemon=True,
                             name="gw-assistant-plan").start()

        def _plan_error(self, seq, holder, err):
            """Main thread. A planning failure falls back to a readable bubble."""
            if seq != getattr(self, "_turn_seq", 0):
                return False
            holder.set_text(f"Something went wrong answering that ({err}). "
                            "Ask again, or use the rail buttons.")
            return False

        def _turn_planned(self, seq, holder, plan, pack):
            """Main thread. The sequence guard drops superseded plans."""
            if seq != getattr(self, "_turn_seq", 0):
                return False
            try:
                if plan.get("tool"):
                    self._last_tool = plan["tool"]
                if plan["kind"] == "template":
                    if plan.get("slot") == "explain_event":
                        self._last_rows = plan.get("rows") or []
                    holder.set_text(plan["text"])
                    if plan.get("slot") == "explain_event":
                        self._evidence(seq, plan, pack, holder)
                    if plan.get("suggest") is not None:
                        self._offer(plan["suggest"])
                    return False
                if plan["kind"] == "intent":
                    if plan["intent"].action != "scan":
                        self._last_tool = plan["intent"].tool
                    # Deterministic English intent (or a model one): straight
                    # to the confirm gate — no stream sits between the
                    # question and the dialog.
                    holder.set_text(describe(plan["intent"], self._friendly,
                                             _SCAN_TITLES))
                    self._confirm(plan["intent"])
                    return False
                if plan["kind"] == "model" and plan.get("intent_reply"):
                    # The router already named an allowed action: asking the
                    # model to talk about it first only delays the confirm
                    # box (and invents prose about a step it is about to
                    # take). Validate, then gate it.
                    intent, _ = parse_intent(plan["intent_reply"])
                    if (intent is not None
                            and validate(intent, self._names, _SCANS) is None):
                        if intent.action != "scan":
                            self._last_tool = intent.tool
                        holder.set_text(describe(intent, self._friendly,
                                                 _SCAN_TITLES))
                        self._confirm(intent)
                        return False
                llm = self._get_llm()
                if llm is None or not llm.is_ready():
                    holder.set_text("The model is unavailable right now; from "
                                    "the data:\n"
                                    + (compose("overview", pack)
                                       or compose("explain_event", pack) or ""))
                    return False
                acc = []

                def on_token(tok):
                    acc.append(tok)
                    GLib.idle_add(holder.set_text, "".join(acc)[-600:])

                def on_done(full):
                    GLib.idle_add(self._finished, plan, full, pack, holder)

                def on_error(e):
                    GLib.idle_add(holder.set_text,
                                  "Model error; from the data:\n"
                                  + (compose("overview", pack) or str(e)))

                llm.ask_stream(plan["prompt"], on_token, on_done, on_error)
            except Exception as err:
                holder.set_text(f"Something went wrong answering that ({err}). "
                                "Ask again, or use the rail buttons.")
            return False

        def _finished(self, plan, full, pack, holder):
            """Stream done: route a model intent through the whitelist."""
            if contradicts_status(full, pack):
                # Seen live: asked why connections were blocked, the 1.7B
                # invented "a protection is not running" while all 17 were
                # green. A wrong diagnosis is worse than a plain status.
                holder.set_text(compose("overview", pack)
                                or "The protections are all green right now.")
                return False
            intent, _rest = parse_intent(full)
            if intent is None and plan.get("intent_reply"):
                intent, _ = parse_intent(plan["intent_reply"])
            if intent is None:
                return False
            reason = validate(intent, self._names, _SCANS)
            if reason is not None:
                # An intent with no name in it asks back instead of quoting
                # the validator's empty string ('' was not a real answer).
                if intent.action == "open_page" and not intent.value.strip():
                    holder.set_text("Which page should I open — Security, "
                                    "Tools, Logs, Settings, or Help?")
                else:
                    holder.set_text(f"I can't do that: {reason}")
                return False
            self._confirm(intent)
            return False

        def _confirm(self, intent):
            # Gtk.Dialog, not MessageDialog: repo lint bans Gtk3-era widget
            # names in ui/*.py (tests/test_ui_smoke.py); body idiom per
            # _pause_tool in ui/window.py.
            what = describe(intent, self._friendly, _SCAN_TITLES)
            dlg = Gtk.Dialog(title=what,
                             transient_for=self.get_root(), modal=True)
            # Dialog scale, not text-width scale: a wrapped Gtk.Label's
            # natural width is the whole unwrapped sentence, so without a
            # default the confirm box stretched to ~970px (bug sweep S2 —
            # same rule as the 560px decision popup).
            dlg.set_default_size(560, -1)
            # The app's own palette, not Adwaita's default: a bare dialog
            # rendered mismatched against both themes (popup sweep
            # 2026-10-30).
            dlg.add_css_class("gw-popup")
            ok = dlg.add_button("Confirm", Gtk.ResponseType.ACCEPT)
            ok.add_css_class("destructive-action")
            dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
            state = intent.value if intent.action in ("firewall", "learning") else ""
            if intent.action in ("pause", "resume"):
                t = (self._get_status() or {}).get("tools", {}).get(intent.tool) or {}
                state = str(t.get("state", "UNKNOWN"))
            body = Gtk.Label(xalign=0)
            body.set_xalign(0)
            body.set_wrap(True)
            body.set_max_width_chars(60)
            # Scans run in the root background service, which the app asks
            # for by writing one request file — there is no password prompt
            # any more, so the old "Some scans ask for your password" line
            # promised a step that never comes (2026-10-30).
            extra = ("\nThe scan runs in the background service; there is "
                     "no password to enter." if intent.action == "scan" else "")
            body.set_text(
                "Confirm and the app does this with its own normal controls — "
                "the same buttons you would click yourself. Cancel leaves "
                "everything as it is." + extra
                + warning_line(intent.action, state))
            content = dlg.get_content_area()
            content.set_margin_top(14); content.set_margin_bottom(14)
            content.set_margin_start(20); content.set_margin_end(20)
            # This desktop draws no title bar, so the question has to be in
            # the body or the box arrives asking nothing (same lesson as the
            # decision popup, 2026-10-27).
            heading = Gtk.Label(xalign=0)
            heading.set_xalign(0)
            heading.set_wrap(True)
            heading.set_max_width_chars(44)
            heading.set_markup(
                f"<span size='15000' weight='bold'>{escape(what)}</span>")
            content.append(heading)
            content.append(body)
            dlg.connect("response", self._confirmed, intent)
            dlg.present()

        def _confirmed(self, dlg, resp, intent):
            dlg.destroy()
            if resp != Gtk.ResponseType.ACCEPT:
                return
            if intent.action == "details":
                # synchronous and truly executed — record here
                self._on_intent(intent.action, intent.tool, intent.value)
                audit.record(intent.action, intent.tool, True)
                return
            # pause/resume, scans, and the settings actions: the window
            # records the OUTCOME (or records it directly when there is
            # nothing async to wait for) — one accurate audit line per
            # accepted intent.
            self._on_intent(intent.action, intent.tool, intent.value)
