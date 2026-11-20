# ui/assistant_page.py
"""The Assistant page (v4): the restored chat panel on the v4 shell.

The chat brain (plan_turn) and its surface (AssistantPanel) live in
ui/assistant.py, restored from the window build that answered real
questions (event explainers, follow-ups, confirm-gated actions, the
owner-toggled GPU tier). This page supplies the v4 seams around it:
status and events through ui.cliapi, the tool registry, and a
confirm-gated intent handler that reaches only paths that already exist -
the same polkit helpers the CLI verbs drive, the trust verb, and this
app's own pages.

The local-only law keeps its shape: nothing here loads a model on its
own - the panel's owner toggle is the only loader - and actions never
reach the model.
"""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from ui import cliapi
from ui.assistant import AssistantPanel
from ui.widgets import card, headline, meta, state_pill

# The assistant's open_page words (the old window's stack keys) mapped to
# this app's rail labels. validate() only lets through values in its own
# PAGES table, so anything else here answers honestly instead of guessing.
_PAGES = {
    "security": "Security Center", "protect": "Security Center",
    "protections": "Security Center", "network": "Network",
    "tools": "Tools", "logs": "Timeline", "timeline": "Timeline",
    "scans": "Security Center", "response": "Security Center",
    "baseline": "Security Center", "help": "Help",
}

def build(window) -> Gtk.Widget:
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page.set_hexpand(True)
    scroll.set_child(page)
    scroll._gw_body = page
    _build_into(page)
    return scroll


def refresh(page: Gtk.Widget) -> None:
    """A light repaint only: the library pill. The conversation thread
    is the page's own state and survives every page change - build()
    happens once, at window build time."""
    pill = getattr(page, "_gw_library_pill", None)
    if pill is None:
        return
    idx = cliapi.read_state("knowledge-index.json") or {}
    chunks = idx.get("chunks") or []
    pill.set_label(f"Library: {len(chunks)} passages" if idx
                   else "Library unavailable")


def _build_into(page: Gtk.Box) -> None:
    idx = cliapi.read_state("knowledge-index.json") or {}
    chunks = idx.get("chunks") or []

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    head.append(headline("Assistant"))
    pill = state_pill(f"Library: {len(chunks)} passages" if idx
                      else "Library unavailable", "ok" if idx else "warn")
    head.append(pill)
    head.set_halign(Gtk.Align.START)
    page.append(head)
    page._gw_library_pill = pill

    page.append(meta("The assistant answers from the machine's own facts, "
                     "the knowledge library and the local model on your "
                     "toggle. Actions you accept run through the app's "
                     "own helpers, nothing else."))

    host = _ChatHost(page)
    panel = AssistantPanel(host.registry_rows(), host.get_status,
                           host.get_recent, host.get_llm, host.on_intent,
                           get_gpu=host.get_gpu())
    panel.add_css_class("gw-chat")
    page._gw_panel = panel          # the shot harness and tests reach it here
    panel.set_vexpand(True)
    chat = card(panel, cls="gw-card")
    chat.set_vexpand(True)
    page.append(chat)

    page.append(_facts_card(idx))


def _facts_card(idx: dict) -> Gtk.Widget:
    idx_chunks = idx.get("chunks") or []
    return card(
        meta(f"{len(idx_chunks)} passages, version "
             f"{idx.get('version', '?')}, built "
             f"{str(idx.get('built_at') or '')[:19].replace('T', ' ')}. "
             "The sync rebuilds it as root."),
        cls="gw-card gw-card-quiet")


class _ChatHost:
    """The chat's v4 seams: reads, the tier state, and confirm-gated
    actions. Every action branch either runs a path that already exists
    (a helper on the polkit lane, the trust verb, this app's pages) or it
    says so in one honest note and the audit line records it as not
    done. No branch invents state and no branch reaches the model."""

    def __init__(self, page):
        self._page = page
        self.chat_llm = None          # loaded ONLY by the owner's toggle
        self._chat_state = (True, "")
        self._registry_cache = None

    # -- reads the panel plans from -------------------------------
    def get_status(self):
        return cliapi.read_state("status.json") or {}

    def get_recent(self):
        return cliapi.read_jsonl("events.jsonl", last=200)

    def registry_rows(self):
        if self._registry_cache is None:
            try:
                from registry import load_registry
                self._registry_cache = load_registry()
            except Exception:                    # noqa: BLE001
                self._registry_cache = []
        return self._registry_cache

    # -- the GPU tier: residency is the owner's explicit toggle -----
    def get_llm(self):
        return self.chat_llm

    def get_gpu(self):
        return self._gpu_enable, self._gpu_disable

    def _gpu_enable(self, on_stage, on_ready):
        """The only call site that may load the model (the tiers guard
        it); the load happens on a worker thread and reports its real
        stages back to the panel."""
        import gwpaths
        from assistant.llm import Llm
        from assistant.model import MODEL_FILENAME
        model = gwpaths.data_dir() / "models" / MODEL_FILENAME
        if not model.exists():
            self._chat_state = (False, "not installed")
            on_ready(False, f"the model file is not installed at {model}")
            return
        self._chat_state = (None, "loading")

        def settled(ok, err):
            self._chat_state = (ok, err or "")
            on_ready(ok, err)

        self.chat_llm = Llm(model_path=str(model))
        self.chat_llm.start(settled, on_stage=on_stage)

    def _gpu_disable(self):
        """Toggle off: the model frees now, nothing unloads it later
        (no timer, no refresh, no page change)."""
        llm = getattr(self, "chat_llm", None)
        self.chat_llm = None
        if llm is not None:
            llm.unload()
        self._chat_state = (True, "")

    # -- confirm-gated actions --------------------------------------
    def on_intent(self, action, tool, value=""):
        """The confirm dialog was already shown by the panel; this runs
        the accepted action through the app's own paths and records the
        OUTCOME in the assistant audit ledger. The panel calls this on
        the GTK main thread; each long step runs on its own worker."""
        handler = getattr(self, f"_do_{action.replace('-', '_')}", None)
        if handler is None:
            self._honest_note(
                f"\"{action}\" has no wired action in this app build yet.",
                action, tool)
            return
        handler(tool, value)

    # One honest note for anything this build cannot do yet.
    def _honest_note(self, why, action, tool):
        self._note(why)
        from assistant import audit
        try:
            audit.record(str(action), str(tool), False)
        except Exception:                      # noqa: BLE001
            pass

    def _note(self, text):
        win = getattr(self._page, "_gw_window", None)
        if win is not None:
            win.note(text)

    def _tool_row(self, tool):
        for row in self.registry_rows():
            if row.get("name") == tool:
                return row
        return {}

    # pause/resume, firewall, enable_all: one helper, the polkit lane.
    def _unit_action(self, helper_args, action, tool, word):
        import threading

        def work():
            from cli import helper_exec, helper_last_err
            try:
                rc = helper_exec("tool-control", list(helper_args))
                err = helper_last_err()
            except Exception as e:             # noqa: BLE001
                rc, err = 124, str(e)
            GLib.idle_add(self._after_unit, rc, err, action, tool, word)

        threading.Thread(target=work, daemon=True,
                         name="gw-assist-action").start()

    def _after_unit(self, rc, err, action, tool, word):
        from assistant import audit
        done = rc == 0
        audit.record(action, tool, done)
        self._note(
            f"{tool or 'the tool'}: {'done' if done else 'not done'} "
            f"({word})" + (f" - {err}" if err and not done else ""))
        return False

    def _do_pause(self, tool, _value=""):
        unit = self._tool_row(tool).get("unit")
        if not unit:
            self._honest_note(
                f"{tool} has no systemd unit this app may stop.", tool, tool)
            return
        self._unit_action(["stop", unit], "pause", tool, "stopped")

    def _do_resume(self, tool, _value=""):
        unit = self._tool_row(tool).get("unit")
        if not unit:
            self._honest_note(
                f"{tool} has no systemd unit this app may start.", tool, tool)
            return
        self._unit_action(["start", unit], "resume", tool, "started")

    def _do_firewall(self, _tool, value=""):
        want = (value or "").lower()
        if want not in ("on", "off"):
            self._honest_note(f"\"{want}\" is not on or off.",
                              "firewall", "")
            return
        self._unit_action([("start" if want == "on" else "stop"),
                           "ufw.service"], "firewall", "ufw", want)

    def _do_enable_all(self, _tool, _value=""):
        self._unit_action(["start-all"], "enable_all", "", "started")

    # scans: one door, the Security Center scan block. The chat never
    # files a request and never starts a scan (owner 2026-11-19).
    def _do_scan(self, mode, _value=""):
        win = getattr(self._page, "_gw_window", None)
        if win is not None:
            win.show_page("Security Center")
            win.note("Start scans from the Security Center scan block.")
        from assistant import audit
        try:
            audit.record("scan", mode, False)
        except Exception:                      # noqa: BLE001
            pass

    # pages: this app's own shelves.
    def _do_open_page(self, _tool, value=""):
        label = _PAGES.get((value or "").lower())
        win = getattr(self._page, "_gw_window", None)
        if label is None or win is None or not hasattr(win, "show_page"):
            self._honest_note(f"\"{value}\" is not a page in this app.",
                              "open_page", value)
            return
        win.show_page(label)
        from assistant import audit
        audit.record("open_page", label, True)

    def _do_details(self, tool, _value=""):
        from assistant import audit
        audit.record("details", tool, True)
        self._note(f"Details for {tool}: the Tools page holds the per-tool "
                   f"desk; `greywatch tool {tool}` prints the full row.")

    # trust: the same machinery the `trust` verb drives.
    def _do_trust_site(self, _tool, value=""):
        self._trust_entry(value, "allow")

    def _do_block_site(self, _tool, value=""):
        self._trust_entry(value, "block")

    def _trust_entry(self, entry, verdict):
        import threading

        def work():
            rc, _out, _err = cliapi.call("trust", verdict, entry, timeout=30)
            GLib.idle_add(self._after_trust, rc, verdict, entry, False)

        threading.Thread(target=work, daemon=True,
                         name="gw-assist-trust").start()

    def _after_trust(self, rc, verdict, entry, program):
        from assistant import audit
        audit.record("trust_program" if program else "trust_site",
                     entry, rc == 0)
        self._note(f"{entry} {'accepted' if rc == 0 else 'was not accepted'}"
                   f" ({verdict}).")
        return False

    def _do_trust_program(self, _tool, value=""):
        import threading

        def work():
            try:
                from core.settings import TrustList
                ok = TrustList().add_app((value or "").strip())
            except Exception:                  # noqa: BLE001
                ok = False
            GLib.idle_add(self._after_trust, 0 if ok else 1, "allow",
                          value, True)

        threading.Thread(target=work, daemon=True,
                         name="gw-assist-trust").start()

    # the bulk-fix family, on the paths the decisions desk itself uses.
    def _do_clear_decisions(self, _tool, _value=""):
        import threading

        def work():
            from pathlib import Path
            from decisions_factory import pending_spec_pairs, record_answer
            try:
                import gwpaths
                ddir = gwpaths.data_dir()
            except Exception:                  # noqa: BLE001
                ddir = Path("/var/lib/greywatch")
            try:
                rows = pending_spec_pairs(ddir)
            except Exception:                  # noqa: BLE001
                rows = []
            n = 0
            for spec, _ts in rows:
                sid = str(spec.get("id") or "")
                if sid and record_answer(ddir / "decisions.jsonl", sid,
                                         "keep"):
                    n += 1
            GLib.idle_add(self._after_clear, n)

        threading.Thread(target=work, daemon=True,
                         name="gw-assist-clear").start()

    def _after_clear(self, n):
        from assistant import audit
        audit.record("clear_decisions", "", True)
        word = "decision" if n == 1 else "decisions"
        self._note(f"Answered {n} pending {word} with Keep.")
        return False

    def _do_purge_quarantine(self, _tool, _value=""):
        import threading

        def work():
            from cli import helper_exec, helper_last_err
            try:
                rc = helper_exec("purge-quarantine", [])
                err = helper_last_err()
            except Exception as e:             # noqa: BLE001
                rc, err = 124, str(e)
            GLib.idle_add(self._after_purge, rc, err)

        threading.Thread(target=work, daemon=True,
                         name="gw-assist-purge").start()

    def _after_purge(self, rc, err):
        from assistant import audit
        audit.record("purge_quarantine", "", rc == 0)
        self._note("Quarantine purged." if rc == 0
                   else f"The purge did not run ({err or 'helper error'}).")
        return False

    # Not wired in this build: said honestly, once, with the truth of it.
    def _do_learning(self, _tool, value=""):
        self._honest_note(
            "Learning mode has no wired control in this app build yet; the "
            "daemon carries it. Try the CLI.", "learning", value)

    def _do_update_lists(self, _tool, _value=""):
        self._honest_note(
            "The feed refresh needs root here: `sudo freshclam` then "
            "`sudo systemctl start greywatch-feeds.service`.",
            "update_lists", "")

    def _do_dismiss_all_findings(self, _tool, _value=""):
        self._honest_note(
            "Batch-hiding findings is not wired into this build yet; the "
            "Security Center keeps every finding visible.",
            "dismiss_all_findings", "")
