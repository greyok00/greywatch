"""The Overview page (rebuild Phase 3): one anchor desk for the suite.

Ribbon of suite-wide counts, the advisory strip above the feed, a
two-lane event stream (the events.lane_for classifier's lanes, never a
shared control strip), the assistant terminal on the right, and the
action gate's pending rows at the bottom - the same list the pill
counts, rendered whole.

The page reads ONLY the daemon's published status digest; the row
metadata card opens without leaving the page, and its controls come
from that row's lane alone (threat rows offer the stored decision's
options; tool rows offer nothing but a copy - service lifecycle never
appears on this page, the two-lane law).
"""
from __future__ import annotations

import pathlib
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ui.decisionlist import (_clear, _helper_exec, card_widget,
                             record_answer)
from ui.threatcards import threat_card_options
from ui.plain import friendly_name
from ui.assistant import AssistantPanel
from ui import metrics
from events import lane_for

TIME_W = 84      # "18:35:39" plus breathing room (window.py carries twin)


def _time_of(ev):
    ts = str(ev.get("ts", ""))
    return " ".join(ts.split("T")[1].split("+")[0])[:8] if "T" in ts else "-"


class _StatCard(Gtk.Box):
    """One ribbon card: a big number over a plain caption."""

    def __init__(self, caption):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.add_css_class("gw-card")
        self.set_size_request(150, -1)
        self._value = Gtk.Label(xalign=0)
        self._value.add_css_class("gw-headline")
        cap = Gtk.Label(label=caption, xalign=0)
        cap.add_css_class("gw-eyebrow")
        self.append(self._value)
        self.append(cap)

    def set_value(self, text):
        self._value.set_text(text)


class _LaneFeed(Gtk.Box):
    """One lane's stream: rows of event sentences, clickable to their
    metadata card. The lane never grows controls that belong to the
    other lane."""

    def __init__(self, title, on_pick):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        head = Gtk.Label(label=title, xalign=0)
        head.add_css_class("gw-page-title")
        self.append(head)
        self.empty = Gtk.Label(label="Nothing in this lane lately.",
                               xalign=0, wrap=True)
        self.empty.add_css_class("gw-meta")
        self.append(self.empty)
        self._rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.append(self._rows)
        self.picked = None
        self.on_pick = on_pick

    def paint(self, evs):
        _clear(self._rows)
        self.empty.set_visible(not evs)
        for row in self._rows_of(evs):
            self._rows.append(row)

    def _rows_of(self, evs):
        for ev in evs[:40]:
            btn = Gtk.Button()
            btn.add_css_class("gw-quiet")
            btn.set_has_frame(False)
            btn.set_child(self._row_face(ev))
            btn.connect("clicked", self._pick, ev)
            yield btn

    def _row_face(self, ev):
        face = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        t = Gtk.Label(label=_time_of(ev), xalign=0)
        t.add_css_class("gw-meta")
        t.set_size_request(TIME_W, -1)
        who = Gtk.Label(label=friendly_name(str(ev.get("from_tool", "?"))),
                        xalign=0)
        who.set_size_request(120, -1)
        face.append(t)
        face.append(who)
        text = Gtk.Label(label=str(ev.get("text", "")), xalign=0, wrap=True)
        text.set_max_width_chars(60)
        face.append(text)
        return face

    def _pick(self, _btn, ev):
        self.picked = ev
        self.on_pick(ev)


class MetadataCard(Gtk.Box):
    """The picked row's metadata card: facts + that lane's controls only.
    Threat rows offer the stored decision's options through the window's
    confirm pipeline; tool rows stay inert beyond a copy button."""
    SEV_INK = {"CRITICAL": "gw-danger", "HIGH": "gw-danger",
               "MEDIUM": "gw-warn", "LOW": "gw-quiet"}

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add_css_class("gw-card")
        self._eyebrow = Gtk.Label(xalign=0)
        self._eyebrow.add_css_class("gw-eyebrow")
        self._title = Gtk.Label(xalign=0, wrap=True, selectable=True)
        self._title.add_css_class("gw-headline")
        self._meta = Gtk.Label(xalign=0, wrap=True, selectable=True)
        self._meta.add_css_class("gw-meta")
        self._body = Gtk.Label(xalign=0, wrap=True, selectable=True)
        self._acts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                             spacing=8)
        self.append(self._eyebrow)
        self.append(self._title)
        self.append(self._meta)
        self.append(self._body)
        self.append(self._acts)

    def paint(self, ev, on_run_option):
        _clear(self._acts)
        lane = "threat" if lane_for(ev) == "threat" else "tool"
        self._eyebrow.set_text(("threat lane" if lane == "threat"
                                else "tool lane") + " - " + str(
            ev.get("ts", "")))
        self._title.set_text(str(ev.get("text", "")))
        self._title.set_markup("<b>" + GLib.markup_escape_text(
            str(ev.get("text", ""))) + "</b>")
        self._meta.set_text(
            f"{friendly_name(str(ev.get('from_tool', '?')))}"
            f"{(' · ' + str(ev['severity'])) if ev.get('severity') else ''}")
        # the facts body and the row sentence overlap when the sentence is
        # all there is; keep the card to eyebrow + title + meta + actions
        self._body.set_visible(False)
        if lane != "threat":
            self._acts.append(self._copy_button(ev))
            return
        for opt in threat_card_options(ev):
            b = Gtk.Button(label=str(opt.get("label", opt.get("id"))))
            b.add_css_class("gw-primary" if opt.get("tone") == "primary"
                            else "gw-danger")
            b.connect("clicked", on_run_option, dict(opt))
            self._acts.append(b)

    def _copy_button(self, ev):
        b = Gtk.Button(label="Copy details")
        b.add_css_class("gw-quiet")

        def copy(_b, ev=ev):
            detail = (f"{str(ev.get('severity', ''))} - "
                      f"{friendly_name(str(ev.get('from_tool', '')))}"
                      f" ({ev.get('from_tool', '')})\n{ev.get('text', '')}")
            try:
                from gi.repository import Gdk
                Gdk.Display.get_default().get_clipboard().set(detail)
            except Exception:
                pass
        b.connect("clicked", copy)
        return b


class OverviewPage(Gtk.Box):
    """The anchor page: counts above, advisories next, feed left,
    assistant right, the gate's pending rows at the bottom."""

    def __init__(self, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self.add_css_class("gw-console")
        self.add_css_class("gw-lane-threat")
        self._win = win
        self._answering = set()
        self.set_vexpand(True)

        ribbon = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._stats = {cap: _StatCard(cap) for cap in
                       ("blocked", "tools online", "CVE rules",
                        "pending decisions")}
        for cap, card in self._stats.items():
            ribbon.append(card)
        self.append(ribbon)

        strip_head = Gtk.Label(label="Advisories", xalign=0)
        strip_head.add_css_class("gw-page-title")
        self.append(strip_head)
        self._advisories = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                   spacing=6)
        self.append(self._advisories)

        self._detail = MetadataCard()
        self._feed = {"threat": _LaneFeed("Threat lane",
                                          self._show_detail),
                      "tool": _LaneFeed("Tool lane", self._show_detail)}
        self._detail.set_visible(False)

        split = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        feedbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        feedbox.append(self._feed["threat"])
        feedbox.append(self._feed["tool"])
        feedbox.append(self._detail)
        feedbox.set_size_request(420, -1)
        feedbox.set_hexpand(True)
        split.append(feedbox)

        self._assistant = self._make_assistant()
        self._assistant.set_size_request(380, -1)
        split.append(self._assistant)
        self.append(split)

        gate_head = Gtk.Label(label="Action gate", xalign=0)
        gate_head.add_css_class("gw-page-title")
        self.append(gate_head)
        self._gate = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                             spacing=6)
        self.append(self._gate)

    # -- wiring ------------------------------------------------------------
    def _make_assistant(self):
        """The assistant terminal: the same chat brain the home page
        carries, wired through the window's own callbacks so intents run
        the exact manual paths (whitelist + audit, unchanged)."""
        w = self._win
        panel = AssistantPanel(w.registry, w._get_status, w._get_recent,
                               lambda: w.chat_llm, w._assistant_intent)
        panel.add_css_class("gw-chat")
        panel.set_vexpand(True)
        return panel

    def _show_detail(self, ev):
        self._detail.paint(ev, self._on_run_option)
        self._detail.set_visible(True)

    def _on_run_option(self, _btn, opt):
        if self._win is not None and hasattr(self._win, "_run_log_option"):
            self._win._run_log_option(_btn, dict(opt))

    # the gate's own answer pipeline (same bookkeeping the decisions
    # window and the firewall page carry: one recorded answer per id)
    def _on_answer(self, _btn, spec, opt, buttons, state):
        sid = str(spec["id"])
        if sid in self._answering:
            return
        self._answering.add(sid)
        for b in buttons:
            b.set_sensitive(False)
        state.set_visible(True)
        state.set_text(f"running {opt.get('helper')}…")

        def work():
            try:
                rc = _helper_exec(opt.get("helper"),
                                  list(opt.get("args", [])))
            except Exception:
                rc = -1
            GLib.idle_add(self._after_answer, sid, opt, buttons, state, rc,
                          priority=GLib.PRIORITY_DEFAULT)

        threading.Thread(target=work, daemon=True).start()

    def _after_answer(self, sid, opt, buttons, state, rc):
        self._answering.discard(sid)
        if rc == 0:
            from ui.actiongate import _resolve_data_dir
            record_answer(self._data_dir() / "decisions.jsonl", sid,
                          opt["id"])
            self.refresh(self._win._get_status() if self._win else None)
            if self._win is not None and getattr(self._win, "_on_change",
                                                 None) is not None:
                self._win._on_change()
        else:
            for b in buttons:
                b.set_sensitive(True)
            state.set_text(f"{opt.get('helper')} did not finish "
                           f"(exit code {rc}). You can try again.")
        return GLib.SOURCE_REMOVE

    def _data_dir(self):
        from ui.actiongate import _resolve_data_dir
        return _resolve_data_dir()

    # -- paint -------------------------------------------------------------
    def refresh(self, snap=None):
        snap = snap or {}
        self._paint_ribbon(snap)
        self._paint_advisories(snap.get("pending_list"))
        self._paint_feed(snap.get("recent") or [])
        self._paint_gate()

    def _paint_ribbon(self, snap):
        from ui.defense import cve_rows
        tools = snap.get("tools") or {}
        online = sum(1 for t in tools.values()
                     if t.get("state") == "GREEN")
        self._stats["tools online"].set_value(f"{online} / {len(tools)}")
        blocks = len((snap.get("defense") or {}).get("blocked") or [])
        self._stats["blocked"].set_value(str(blocks))
        asks = snap.get("pending_list")
        if asks is None:
            asks = snap.get("pending_decisions") or 0
        self._stats["pending decisions"].set_value(
            str(len(asks) if isinstance(asks, list) else asks))
        rules = cve_rows(self._data_dir())
        self._stats["CVE rules"].set_value(
            str(len(rules)) if rules is not None else "not fetched")

    def _paint_advisories(self, asks):
        _clear(self._advisories)
        ads = [d for d in (asks or [])
               if isinstance(d, dict) and d.get("kind") == "advisory"]
        lbl = Gtk.Label(
            xalign=0, wrap=True,
            label=("nothing needs your attention in the background" if not
                   ads else
                   "every advisory and question the suite is holding"))
        lbl.add_css_class("gw-meta")
        self._advisories.append(lbl)
        for d in ads:
            spec = d.get("spec")
            if isinstance(spec, dict) and spec.get("id"):
                self._advisories.append(
                    card_widget(spec, str(d.get("ts", "")),
                                self._on_answer))

    def _paint_feed(self, evs):
        lanes = {"threat": [], "tool": []}
        for ev in evs:
            lanes.setdefault(lane_for(ev), []).append(ev)
        for lane in ("threat", "tool"):
            self._feed[lane].paint(lanes[lane])

    def _paint_gate(self):
        _clear(self._gate)
        from ui.actiongate import _status_path_rows
        data_dir = self._data_dir()
        rows = _status_path_rows(data_dir)
        if rows is None:
            try:
                from decisions_factory import pending_spec_pairs
                rows = pending_spec_pairs(data_dir)
            except Exception:
                rows = []
        lbl = Gtk.Label(
            xalign=0, wrap=True,
            label="everything waiting for you, in one list" if rows
            else "nothing waits on you right now")
        lbl.add_css_class("gw-meta")
        self._gate.append(lbl)
        for spec, ts in rows[:20]:
            self._gate.append(card_widget(spec, ts, self._on_answer))
