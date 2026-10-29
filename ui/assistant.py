# ui/assistant.py
"""Chat panel + the headless turn planner.

plan_turn() decides HOW a question is answered; the GTK widget only
renders the plan and its stream. GTK imports are guarded so tests can
import plan_turn on headless runners.
"""
from __future__ import annotations

import re
import threading

from assistant import advice, audit
from assistant.intents import Intent, describe, parse_intent, validate
from assistant.llm import ROUTER_SYSTEM  # noqa: F401  (router contract)
from assistant.packer import build_pack
from assistant.router import route
from assistant.templates import answer_detail, compose, event_rows

SLOTS_WITH_TEMPLATES = ("overview", "explain_event", "tool_status")

# The live 360M router returned junk on the owner's real questions (an
# empty reply for the rootkit question, then prose 'fail2ban' as a slot
# tool), so the deterministic engine answers first; the model gets only
# what no keyword engine can match. Its router + free text are tamed in
# assistant/llm.py.
_EVENT_WORDS = ("event", "events", "log", "logs", "alert", "happened",
                "newest", "last", "blocked", "denied", "suspicious",
                "warning", "found", "find", "scan", "scanner", "analyze",
                "analysis", "history", "activity", "latest", "recently")

_PAUSE_VERBS = ("pause", "suspend", "stop", "disable", "deactivate",
                "turn off", "shut off", "shut down")
_RESUME_VERBS = ("resume", "unpause", "start", "enable", "activate",
                 "turn on")

# Label words too generic to pin a tool: "what happened to this event?"
# is an event question, not an auditd question.
_LABEL_NOISE = frozenset({"event", "system", "live", "watch", "watcher",
                          "scanner", "program", "helper", "device",
                          "security"})

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
                        "were", "have", "into", "your"})
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
}


def plan_turn(question, pack, llm, registry_names: set, friendly: dict,
              anchor=None) -> dict:
    """One question -> one answer plan. The widget only renders this.

    Ladder: English action verbs + a named tool -> intent plan; a
    help/remediation question -> the deterministic advice engine (meaning,
    risk, numbered steps); a referential follow-up over the previously
    shown rows -> one-row detail; a tool word -> tool status; event/log
    wording -> event answers (tool-scoped when the question names one);
    else the model routes or summarizes; the overview template is the
    safe floor."""
    intent = _intent_from_question(question, friendly)
    if intent is not None and validate(intent, registry_names) is None:
        return {"kind": "intent", "intent": intent}
    if _wants_advice(question):
        plan = _advice_plan(question, pack, registry_names, friendly, anchor)
        if plan is not None:
            return plan
    row = _anchored_row(question, anchor, pack.get("recent") or [])
    if row is not None:
        return {"kind": "template", "slot": "detail",
                "text": answer_detail(row)}
    tool = _tool_from_question(question, friendly)
    if tool and registry_names and tool not in registry_names:
        tool = None                    # never stage a tool outside the registry
    if tool and not _mentions(question):
        text = compose("tool_status", pack, tool)
        if text is not None:
            return {"kind": "template", "slot": "tool_status", "text": text}
    if _mentions(question):
        text = compose("explain_event", pack, tool)
        if text is None and tool:
            # named tool, no events of its own in the window: its status
            # is still a real answer
            text = compose("tool_status", pack, tool)
        if text is not None:
            return {"kind": "template", "slot": "explain_event",
                    "text": text,
                    "rows": event_rows(pack, tool)[:3]}
    if llm is not None and llm.is_ready():
        slot, reply = route(question, llm.ask_sync,
                            tool_names=" ".join(sorted(registry_names)))
        if slot in SLOTS_WITH_TEMPLATES:
            hint = reply if (slot == "explain_event"
                             and reply in registry_names) else None
            text = compose(slot, pack, hint)
            if text is not None:
                plan = {"kind": "template", "slot": slot, "text": text}
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


# Help/remediation wording. The owner's real question ("it should analyze
# and interpret my questions and help me solve issues") is this rung: the
# deterministic advice engine answers it with facts the app holds, because
# a small model inventing fixes would be worse than no answer.
_ADVICE_WORDS = ("fix", "repair", "remediate", "resolve", "address", "solve",
                 "dangerous", "advice", "recommend", "suggest", "help me",
                 "steps", "what should i do", "what can i do",
                 "what do i do", "what needs attention", "needs attention",
                 "how do i", "how can i", "is this normal", "is that normal",
                 "should i worry", "why is")


def _wants_advice(question: str) -> bool:
    low = (question or "").lower()
    for w in _ADVICE_WORDS:
        if " " in w:
            if w in low:
                return True
        elif re.search(rf"\b{re.escape(w)}\b", low):
            return True
    return False


def _advice_plan(question, pack, registry_names, friendly, anchor):
    """Advice keeps the ladder's facts: a named tool wins, an anchored
    follow-up ('how do I fix that?') explains the row it points at, a
    bare 'what needs attention?' ranks every protection."""
    tool = _tool_from_question(question, friendly)
    if tool and registry_names and tool not in registry_names:
        tool = None
    row = _anchored_row(question, anchor, pack.get("recent") or [])
    if row is not None:
        row_tool = str(row.get("tool") or row.get("from_tool") or "")
        if tool is None or tool == row_tool:
            return {"kind": "template", "slot": "advice",
                    "text": advice.advise_event(row)}
    if tool is None:
        low = (question or "").lower()
        for want in ("yellow", "red"):
            if want in low:
                hit = next((t for t in pack.get("tools") or []
                            if t["state"] == want.upper()), None)
                if hit is not None:
                    tool = hit["name"]
                else:
                    return {"kind": "template", "slot": "advice",
                            "text": advice.advise_state_vs_events(pack)}
                break
    if tool:
        text = advice.advise_tool(pack, tool)
        if text:
            return {"kind": "template", "slot": "advice", "text": text}
    if not advice.needs_attention(pack):
        # Nothing is broken: explain the two channels instead of printing
        # an empty ranked list.
        text = advice.advise_state_vs_events(pack)
    else:
        text = advice.advise_priorities(pack)
    return {"kind": "template", "slot": "advice", "text": text}


def _anchored_row(question: str, anchor, recent=None) -> dict | None:
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
    words = [w for w in re.split(r"[^a-z0-9]+", low)
             if len(w) >= 4 and w not in _ASK_NOISE
             and w not in _REFERENTIAL]
    pool = list(anchor) + [r for r in (recent or []) if r not in anchor]
    for w in words:
        pats = _ROW_PATTERNS.get(w, (rf"\b{re.escape(w)}\b",))
        for pat in pats:
            for row in pool:
                hay = (str(row.get("text") or "").lower() + " "
                       + str(row.get("tool")
                             or row.get("from_tool") or "").lower())
                if re.search(pat, hay):
                    return row
    return anchor[0]


def _tool_from_question(question: str, friendly: dict) -> str | None:
    """Tool name, then whole label, then single label token (word-bounded;
    generic words excluded). 'rootkit scanner' pins rkhunter this way."""
    low = (question or "").lower()
    for name in friendly:
        if name and name in low:
            return name
    for name, plate in friendly.items():
        label = (plate[0] if plate else "").lower()
        if label and label in low:
            return name
    for name, plate in friendly.items():
        label = (plate[0] if plate else "").lower()
        for tok in re.split(r"[^a-z0-9]+", label):
            if len(tok) < 4 or tok in _LABEL_NOISE:
                continue
            if re.search(rf"\b{re.escape(tok)}\b", low):
                return name
    return None


def _intent_from_question(question: str, friendly: dict) -> Intent | None:
    """Plain-English action verb + a named tool. An action with no
    credible target never resolves — the model path keeps that case."""
    low = (question or "").lower()
    hit = next((w for w in _PAUSE_VERBS + _RESUME_VERBS
                if re.search(rf"\b{re.escape(w)}\b", low)), None)
    if not hit:
        return None
    tool = _tool_from_question(question, friendly)
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
    # The instruction sits ABOVE the question and the question is last:
    # a tiny model "continues" the prompt's final line — with the old
    # order the stream echoed "Summarize in 2-3 plain sentences" verbatim
    # instead of answering (seen live with 'make it stop').
    lines.append("Summarize in 2-3 plain sentences. If the pack lacks the "
                 "answer, say so.")
    lines.append(f"question: {question}")
    return "\n".join(lines)


def warning_line(action: str, state: str) -> str:
    """Extra confirm-dialog warning when the target is down (spec: warn
    when the target tool is RED)."""
    if action == "pause" and state == "RED":
        return ("\nThis protection is currently RED — pausing it leaves "
                "nothing running in its place.")
    return ""


GIOMM_OK = True
try:
    from gi.repository import GLib, Gtk
except Exception:        # headless CI: widget tests skip, plan_turn still runs
    GIOMM_OK = False

if GIOMM_OK:

    CHIPS = ("What needs attention?", "Explain the last block",
             "Why is this yellow?")

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
            self.banner = Gtk.Label(xalign=0)
            self.banner.add_css_class("gw-meta")
            self.append(self.banner)
            chips = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            for c in CHIPS:
                b = Gtk.Button(label=c)
                b.connect("clicked", self._chip)
                chips.append(b)
            self.append(chips)
            self.stream = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                  spacing=6)
            sc = Gtk.ScrolledWindow()
            sc.set_child(self.stream)
            sc.set_vexpand(True)
            self.append(sc)
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            self.entry = Gtk.Entry()
            self.entry.set_placeholder_text("Ask about your protections…")
            self.entry.set_hexpand(True)
            self.entry.connect("activate", self._send)
            row.append(self.entry)
            send = Gtk.Button(label="Send")
            send.connect("clicked", self._send)
            row.append(send)
            self.append(row)

        def note_state(self, ok: bool, err: str) -> None:
            self.banner.set_text("Assistant ready." if ok
                                 else f"Docs-only assistant: {err}")

        def _chip(self, b):
            self.entry.set_text(b.get_label())
            self._send()

        def _bubble(self, text, mine: bool = False):
            lbl = Gtk.Label(xalign=1.0 if mine else 0.0)
            lbl.set_wrap(True)
            # Selectable: the owner copies a log line straight out of the
            # chat (asked for when the rkhunter answer couldn't be pasted).
            lbl.set_selectable(True)
            lbl.set_text(text)
            self.stream.append(lbl)
            return lbl

        def _send(self, *_a):
            question = self.entry.get_text().strip()
            if not question:
                return
            self.entry.set_text("")
            self._bubble(question, mine=True)
            self._turn_seq = getattr(self, "_turn_seq", 0) + 1
            seq = self._turn_seq
            holder = self._bubble("…")

            def work():
                try:
                    pack = build_pack(self._get_status(), self._get_recent(),
                                      question)
                    plan = plan_turn(question, pack, self._get_llm(),
                                     self._names, self._friendly,
                                     anchor=self._last_rows)
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
                if plan["kind"] == "template":
                    if plan.get("slot") == "explain_event":
                        self._last_rows = plan.get("rows") or []
                    holder.set_text(plan["text"])
                    return False
                if plan["kind"] == "intent":
                    # Deterministic English intent (or a model one): straight
                    # to the confirm gate — no stream sits between the
                    # question and the dialog.
                    holder.set_text(describe(plan["intent"], self._friendly))
                    self._confirm(plan["intent"])
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
            intent, _rest = parse_intent(full)
            if intent is None and plan.get("intent_reply"):
                intent, _ = parse_intent(plan["intent_reply"])
            if intent is None:
                return False
            reason = validate(intent, self._names)
            if reason is not None:
                holder.set_text(f"I can't do that: {reason}")
                return False
            self._confirm(intent)
            return False

        def _confirm(self, intent):
            # Gtk.Dialog, not MessageDialog: repo lint bans Gtk3-era widget
            # names in ui/*.py (tests/test_ui_smoke.py); body idiom per
            # _pause_tool in ui/window.py.
            dlg = Gtk.Dialog(title=describe(intent, self._friendly),
                             transient_for=self.get_root(), modal=True)
            ok = dlg.add_button("Confirm", Gtk.ResponseType.ACCEPT)
            ok.add_css_class("destructive-action")
            dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
            state = ""
            if intent.action in ("pause", "resume"):
                t = (self._get_status() or {}).get("tools", {}).get(intent.tool) or {}
                state = str(t.get("state", "UNKNOWN"))
            body = Gtk.Label(xalign=0)
            body.set_xalign(0)
            body.set_wrap(True)
            body.set_text(
                "Confirm and the app does this with its own normal controls — "
                "the same buttons you would click yourself. Cancel leaves "
                "everything as it is." + warning_line(intent.action, state))
            content = dlg.get_content_area()
            content.set_margin_top(14); content.set_margin_bottom(14)
            content.set_margin_start(20); content.set_margin_end(20)
            content.append(body)
            dlg.connect("response", self._confirmed, intent)
            dlg.present()

        def _confirmed(self, dlg, resp, intent):
            dlg.destroy()
            if resp != Gtk.ResponseType.ACCEPT:
                return
            if intent.action == "details":
                # synchronous and truly executed — record here
                self._on_intent(intent.action, intent.tool)
                audit.record(intent.action, intent.tool, True)
                return
            # pause/resume: the window records the OUTCOME after its final
            # gate and toggle — one accurate audit line per accepted intent.
            self._on_intent(intent.action, intent.tool)
