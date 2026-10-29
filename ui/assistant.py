# ui/assistant.py
"""Chat panel + the headless turn planner.

plan_turn() decides HOW a question is answered; the GTK widget only
renders the plan and its stream. GTK imports are guarded so tests can
import plan_turn on headless runners.
"""
from __future__ import annotations

import threading

from assistant import audit
from assistant.intents import describe, parse_intent, validate
from assistant.llm import ROUTER_SYSTEM  # noqa: F401  (router contract)
from assistant.packer import build_pack
from assistant.router import route
from assistant.templates import compose

SLOTS_WITH_TEMPLATES = ("overview", "explain_event", "tool_status")

_EVENT_WORDS = ("event", "alert", "happened", "newest", "last", "blocked",
                "denied")


def plan_turn(question, pack, llm, registry_names: set, friendly: dict) -> dict:
    """One question -> one answer plan. The widget only renders this."""
    if llm is not None and llm.is_ready():
        slot, reply = route(question, llm.ask_sync,
                            tool_names=" ".join(sorted(registry_names)))
        if slot in SLOTS_WITH_TEMPLATES:
            text = compose(slot, pack, reply)
            if text is not None:
                return {"kind": "template", "slot": slot, "text": text}
            return {"kind": "summary", "prompt": _pack_prompt(pack, question)}
        if slot == "intent":
            if reply.lstrip().startswith("{"):
                return {"kind": "model", "prompt": question,
                        "intent_reply": reply}
            # Intent slot with no action-bearing JSON: treat as a summary
            # turn — nothing executes, nothing stalls.
            return {"kind": "summary", "prompt": _pack_prompt(pack, question)}
        return {"kind": "summary", "prompt": _pack_prompt(pack, question)}
    # No model (or not warm yet): deterministic matching from the pack.
    name = _tool_from_question(question, friendly)
    if name and compose("tool_status", pack, name) is not None:
        return {"kind": "template", "slot": "tool_status",
                "text": compose("tool_status", pack, name)}
    if _mentions(question):
        return {"kind": "template", "slot": "explain_event",
                "text": compose("explain_event", pack)}
    return {"kind": "template", "slot": "overview",
            "text": compose("overview", pack)
            or "Docs-only mode: I can describe tool states and recent "
               "events."}


def _mentions(question: str) -> bool:
    low = (question or "").lower()
    return any(w in low for w in _EVENT_WORDS)


def _tool_from_question(question: str, friendly: dict) -> str | None:
    low = (question or "").lower()
    for name in friendly:
        if name and name in low:
            return name
    return None


def _pack_prompt(pack: dict, question: str) -> str:
    lines = ["Context pack:", f"- {pack['status_line']}"]
    hot = [f"- {t['name']} {t['state']}" for t in pack["tools"]
           if t["state"] in ("YELLOW", "RED")]
    lines += hot or ["- no protection needs attention"]
    lines += ["Recent events:"] + [f"- {e['tool']}: {e['text']} ({e['ts']})"
                                   for e in pack["recent"][:5]]
    for s in pack["snippets"][:3]:
        lines.append(f"- docs[{s['source'][:60]}]: {s['text'][:200]}")
    lines.append(f"question: {question}")
    lines.append("Summarize in 2-3 plain sentences. If the pack lacks the "
                 "answer, say so.")
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
                                     self._names, self._friendly)
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
                    holder.set_text(plan["text"])
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
