"""GUI-side decision pump (Task 6b) — the ONE pipeline's UI half.

New unanswered specs found in events.jsonl → ONE dialog each (async, never
blocks the GUI main loop) → answer forwarded to decisions.jsonl via the SAME
factory/record path as the CLI; the helper then runs exactly as it would from
`greywatch answer`. No separate Notify *decision* notifications (plan:
zero duplicate notifications) — a passive "N pending" nudge is the only
optional popup, answering happens in the dialog.

GTK4 notes (Pass 2, 2026-10-25): Gtk.MessageDialog is deprecated and
Gtk.Dialog.run()/Gtk.WindowPosition are GONE — decisions are plain Gtk.Dialog
windows (buttons via add_button, answers are response ids) that are shown
with present() and answered entirely through the "response" signal; the
synchronous app-fw bridge waits on a threading.Event the dialog's response
handler sets.
"""
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Notify", "0.7")
from gi.repository import Gtk, GLib, Notify as _NotifyModule  # noqa: E402

import greywatch_daemon as dm
from decisions_factory import pending_ids, record_answer


def _decision_dialog(spec, modal=False):
    """A Gtk.Dialog with ONE plain button per option; response id = the
    option index (MessageDialog-based dialogs were the old GTK3 shape;
    Gtk.Dialog is the GTK4-safe manual form)."""
    opts = spec.get("options", [])
    dlg = Gtk.Dialog(title=f"{spec['id']}: {spec['question']}", modal=modal)
    for i, o in enumerate(opts):
        dlg.add_button(f"{o['id']}: {o['label']}", i)
    return dlg


class DecisionBroker:
    """Event-driven: the window's on_status_change calls pump(events)."""

    def __init__(self):
        self._shown = set()          # one dialog per spec id
        self._tray = None

    def set_tray(self, tray):
        self._tray = tray

    # ── called by the window on every events/status change ────────────────
    def pump(self, events) -> int:
        try:
            answered = pending_ids(dm.DATA_DIR / "decisions.jsonl")
        except OSError:
            answered = set()
        fresh = [e["interaction"] for e in reversed(events)
                 if isinstance(e, dict) and e.get("interaction")
                 and e["interaction"]["id"] not in answered
                 and e["interaction"]["id"] not in self._shown]
        # suite-native specs only: app-fw asks are answered HEADLESS by
        # the daemon (trust list / default); a per-connection modal would
        # block browsing (the popup-mess bug) — they surface as feed events.
        self._shown.update(s["id"] for s in fresh if s["id"].startswith("appfw:"))
        fresh = [s for s in fresh if not s["id"].startswith("appfw:")]
        self._shown.update(s["id"] for s in fresh)
        opened = 0
        for spec in fresh:
            self._show_dialog(spec)
            opened += 1
        # ── the ONE blocked-traffic square (owner spec 2026-10-24): only
        # app-fw DENY events surface here; one replaceable popup, buttons
        # for unblock-all + review; never a scrolling stack.
        try:
            self._notify_denies(events)
        except Exception:
            pass
        # ── the ONE critical-events square (master prompt §4, Pass 3):
        # fail2ban bans / YARA hits / rkhunter alerts — newest wins, coalesced.
        try:
            self._notify_critical(events)
        except Exception:
            pass
        return opened

    def _notify_critical(self, events) -> None:
        from ui.notify_alert import CriticalSquare, CriticalEvents, \
            critical_filter
        square = getattr(self, "_crit_square", None)
        if square is None:
            square = CriticalSquare(CriticalEvents())
            self._crit_square = square
            self._crit_state = square.blocked     # CriticalEvents instance
        fresh = [t for t in critical_filter(events)
                 if t != self._crit_state.latest]
        for tool, text in fresh:
            shown = self._crit_state.add(tool, text)
            square.show(shown)

    def _notify_denies(self, events) -> None:
        from ui.notify_alert import NotifyAlert, BlockedQueue, parse_deny
        alert = getattr(self, "_alert", None)
        if alert is None:
            alert = NotifyAlert(BlockedQueue(dm.DATA_DIR))
            self._alert = alert
        seen = getattr(self, "_deny_seen", None)
        if seen is None:
            seen = set()
            self._deny_seen = seen
        for e in reversed(events):
            if not isinstance(e, dict) or e.get("from_tool") != "appfw":
                continue
            ts = e.get("ts", "")
            if ts in seen:
                continue
            seen.add(ts)
            parsed = parse_deny(e.get("text", ""))
            if parsed and parsed["action"] == "deny":
                alert.handle_deny(parsed["app"], parsed["host"])

    def pump_once(self) -> int:
        return self.pump(dm.read_events(dm.DATA_DIR / "events.jsonl", 2000))

    def badge(self) -> int:
        """Unanswered count for the tray + GUI status bar."""
        try:
            answered = pending_ids(dm.DATA_DIR / "decisions.jsonl")
            from cli import _gather_specs
            specs, _ = _gather_specs()
            return sum(1 for s in specs if s["id"] not in answered)
        except Exception:
            return 0

    # ── ONE decision dialog per spec; async (never blocks the loop) ───────
    def _show_dialog(self, spec: dict):
        dlg = _decision_dialog(spec, modal=False)
        dlg.connect("response", self._on_response, spec,
                    spec.get("options", []))
        dlg.present()

    def _on_response(self, dlg, response_id, spec, opts, *_a):
        dlg.destroy()
        if not isinstance(response_id, int) or response_id == \
                Gtk.ResponseType.DELETE_EVENT or response_id < 0 or \
                response_id >= len(opts):
            return                       # dismissed; stays pending, no answer
        opt = opts[response_id]
        ok = record_answer(dm.DATA_DIR / "decisions.jsonl", spec["id"], opt["id"])
        if not ok:
            return                       # answered earlier (answer-once honored)
        if self._tray:
            GLib.idle_add(self._tray.refresh_badge)

    # ── app-fw decision bridge (in-suite) ─────────────────────────────────
    def ask_appfw(self, spec):
        """Called on a gRPC worker thread: marshal the dialog to the GTK main
        thread and wait on an Event until its response handler fills it.
        Gtk.Dialog.run() no longer exists, so the (only) synchronous wait is
        the worker's; the GTK loop stays free. Returns (action, duration) —
        the same REAL duration enums the daemon applies."""
        import threading
        done = threading.Event()
        box = {}

        def in_main():
            try:
                opts = spec.get("options", [])
                dlg = Gtk.Dialog(title="App firewall", modal=True)
                for i, o in enumerate(opts):
                    dlg.add_button(f"{o['id']}: {o['label']}", i)

                def on_resp(d, rid, *_a):
                    d.destroy()
                    box["res"] = self._answer_from_response(rid, spec, opts)
                    done.set()
                dlg.connect("response", on_resp)
                dlg.present()
            except Exception:
                box["res"] = ("allow", "once")
                done.set()
            return False

        GLib.idle_add(in_main)
        done.wait(timeout=90)          # unanswered → daemon default applies
        r = box.get("res")
        return (r if isinstance(r, tuple) else (r or ("allow", "once"))) \
            if r else ("allow", "once")

    @staticmethod
    def _answer_from_response(rid, spec, opts):
        if not isinstance(rid, int) or rid < 0 or rid >= len(opts):
            return ("allow", "once")
        opt = opts[rid]
        args = opt.get("args", [])
        dur = args[1] if len(args) > 1 else "once"
        act = args[0] if args and args[0] in ("allow", "deny") else "allow"
        host = spec.get("host", "")
        if "trust" in args or "trust-block" in args:
            # owner-ordered trust list: this domain stops prompting
            from ui.settings import TrustList
            TrustList().add(host, "block" if "trust-block" in args else "allow")
            return act, "always", host      # operator matches the domain
        return act, dur

    # ── passive nudge only (never an answering surface) ──────────────────
    _notify_ready = False

    def nudge(self, count: int):
        if not DecisionBroker._notify_ready:
            if not _NotifyModule.init("greywatch"):
                return
            DecisionBroker._notify_ready = True
        note = _NotifyModule.Notification.new(
            "greywatch", f"{count} pending decision(s): open the GUI", )
        note.show()