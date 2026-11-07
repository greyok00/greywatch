"""The Full-logs page (wave D split): one mixin for the rows, the
clear action, the click-to-fix cards and the refresh. MainWindow
inherits; names and behavior are unchanged."""
from __future__ import annotations

import pathlib
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Pango    # noqa: E402

import greywatch_daemon as daemon_mod
from ui import metrics
from ui.models import local_clock
from ui.plain import friendly_name, severity_colour as pc_severity_colour
from ui.eventclock import present_now
from ui.threatcards import (log_row_values, threat_card_options,
                            _fixed, _threat_target)

DATA_DIR = daemon_mod.DATA_DIR


class LogsDeskMixin:
    def _logs_view(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(metrics.PAGE_TOP)
        box.set_margin_start(metrics.PAGE_X)
        box.set_margin_end(metrics.PAGE_X)
        box.append(self._h1("Full logs: every tool, raw"))
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.logs_pick = Gtk.ComboBoxText()
        self.logs_pick.append("", "All tools")
        for t in self.registry:
            self.logs_pick.append(t["name"], friendly_name(t["name"]))
        self.logs_pick.set_active_id("")
        self.logs_pick.set_size_request(280, -1)
        self.logs_pick.connect("changed", lambda _c: self._refresh_logs())
        row.append(Gtk.Label(label="Show:"))
        row.append(self.logs_pick)
        clear_btn = Gtk.Button(label="Clear the log")
        clear_btn.add_css_class("gw-quiet")
        clear_btn.set_tooltip_text(
            "Empties this event log. Answers, scan results and quarantine "
            "records are not touched.")
        clear_btn.connect("clicked", self._clear_log_pressed)
        row.append(clear_btn)
        self.logs_status = Gtk.Label(xalign=0)
        self.logs_status.set_xalign(0)
        self.logs_status.set_text(
            "Click a row to resolve it; identical consecutive lines are"
            " grouped, newest first.")
        self.logs_status.set_hexpand(True)
        row.append(self.logs_status)
        box.append(row)

        # 0 tool icon name, 1 severity word, 2 severity ink, 3 time/tool,
        # 4 event, 5 raw event, 6 lane. The severity used to be an emoji
        # (🔴/🟡/🟢); it is now the tool's own drawn symbol plus a word in
        # the theme's status ink. GW-197 adds the raw event and its lane,
        # so clicking a row can fix it right there, with that lane's
        # controls only.
        self.logs_store = Gtk.ListStore(str, str, str, str, str, object,
                                        str)
        view = Gtk.TreeView(model=self.logs_store, headers_visible=False)
        log_icon = Gtk.CellRendererPixbuf()
        log_icon.set_property("width", 22)
        view.append_column(_fixed(
            Gtk.TreeViewColumn(None, log_icon, icon_name=0), 44))
        sev = Gtk.CellRendererText()
        view.append_column(_fixed(
            Gtk.TreeViewColumn(None, sev, text=1, foreground=2), 86))
        view.append_column(_fixed(
            Gtk.TreeViewColumn(None, Gtk.CellRendererText(), text=3), 300))
        # The event column takes whatever width is left, and ellipsises
        # inside it. Without the ellipsis a long apparmor line measured the
        # column wider than the card and the row ran under the window edge,
        # cut mid-word with no hint that there was more.
        event_cell = Gtk.CellRendererText()
        event_cell.set_property("ellipsize", Pango.EllipsizeMode.END)
        last = Gtk.TreeViewColumn(None, event_cell, text=4)
        last.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        # A fixed floor plus expand: the floor keeps the table's MINIMUM
        # width inside the card, expand hands it every pixel left over.
        # Without the floor the column asked for the longest line's width,
        # which pushed the whole card past the page edge.
        last.set_fixed_width(200)
        last.set_expand(True)
        view.append_column(last)
        # GW-197: a row is clickable. Activation opens that row's lane
        # card, so fixing happens here instead of hunting for the lever.
        view.connect("row-activated", self._log_row_activated)
        # the affordance has to be visible, not folklore: the pointer
        # announces the fix card on any row, and the status line above
        # says what a click does
        view.set_has_tooltip(True)
        view.connect("query-tooltip", self._log_row_tooltip)
        # Same header treatment as Recent activity: plain labels over the
        # fixed column widths, so "State" sits over the severity words.
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        head.add_css_class("gw-th-row")
        head.set_margin_start(10)
        head.set_margin_end(10)
        pad = Gtk.Box()
        pad.set_size_request(44, -1)
        head.append(pad)
        for title, width in (("State", 86), ("Time / tool", 300),
                             ("Event", 0)):
            lbl = Gtk.Label(label=title, xalign=0)
            lbl.set_xalign(0)
            lbl.add_css_class("gw-th")
            if width:
                lbl.set_size_request(width, -1)
            else:
                lbl.set_hexpand(True)
            head.append(lbl)
        lbody = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        lbody.append(head)
        wrap = self._wrap(view)
        wrap.set_hexpand(True)
        lbody.append(wrap)
        lcard = Gtk.Frame()
        lcard.add_css_class("gw-card")
        lcard.set_child(lbody)
        lcard.set_vexpand(True)
        box.append(lcard)
        box.set_vexpand(True)
        self._refresh_logs()
        # The log table pages inside its own card; the page itself never
        # scrolls, so its filter row can never be pushed off-screen.
        return box

    def _log_row_tooltip(self, view, x, y, kb, tip):
        """Every row announces its fix card where the pointer is: the
        affordance must be discoverable, not remembered."""
        try:
            path, _col, _cx, _cy = view.get_path_at_pos(x, y)
        except Exception:
            return False
        if path is None or tip is None:
            return False
        tip.set_text(
            "Click to open this row's fix card - it offers that lane's"
            " controls and a link to the page that owns it.")
        return True

    def _clear_log_pressed(self, _btn):
        d = Gtk.Dialog(title="Empty the event log?", transient_for=self,
                       modal=False)
        d.set_destroy_with_parent(True)
        body = d.get_content_area()
        body.set_margin_start(18); body.set_margin_end(18)
        body.set_margin_top(12); body.set_margin_bottom(12)
        ask = Gtk.Label(xalign=0, wrap=True)
        ask.set_xalign(0)
        ask.set_text("Just the log. Your answers, scan results and "
                     "quarantine records stay.")
        body.append(ask)
        d.add_button("Cancel", Gtk.ResponseType.CANCEL)
        d.add_button("Clear the log", Gtk.ResponseType.OK)
        d.connect("response", self._on_clear_response)
        present_now(d)

        def _filled(_dlg):
            note = Gtk.Label(xalign=0, wrap=True)
            note.set_text("Just the log. Your answers, scan results and "
                          "quarantine records stay.")
            note.set_margin_top(6)
            d.get_message_area().append(note)

        d.connect("map", _filled)
        d.connect("response", self._on_clear_response)
        present_now(d)

    def _on_clear_response(self, d, rid):
        d.destroy()
        if rid != Gtk.ResponseType.OK:
            return

        def worker():
            try:
                from wiz import common
                rc = common.run_helper("clear-events", [], timeout=60)
            except Exception:
                rc = -1
            GLib.idle_add(self._after_clear, rc)

        threading.Thread(target=worker, daemon=True).start()

    def _after_clear(self, rc):
        self._refresh_logs()
        self.logs_status.set_text(
            "Log cleared." if rc == 0 else
            f"Clearing did not finish (helper rc {rc}).")
        return False

    def _log_row_activated(self, _view, path, _col):
        ev = self.logs_store[path][-2]          # the raw event, GW-197
        lane = self.logs_store[path][-1]
        if isinstance(ev, dict):
            self._log_action_card(ev, str(lane))

    def _log_action_card(self, ev, lane):
        """One row, one card, controls from its lane only: a tool row
        starts/updates its tool, a threat row answers the decision it
        carries. Neither lane ever borrows the other's controls."""
        title = "Threat" if lane == "threat" else "Fix this"
        dlg = Gtk.Dialog(transient_for=self, modal=False, title=title)
        dlg.set_destroy_with_parent(True)
        body = dlg.get_content_area()
        body.set_margin_top(12); body.set_margin_bottom(12)
        body.set_margin_start(18); body.set_margin_end(18)
        what = Gtk.Label(xalign=0, wrap=True)
        what.set_xalign(0)
        what.set_text(str(ev.get("text", ""))[:400])
        body.append(what)
        acts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        acts.set_margin_top(10)
        if lane == "threat":
            self._log_threat_actions(ev, acts)
        else:
            self._log_tool_actions(ev, acts)
        copy = Gtk.Button(label="Copy details")
        copy.add_css_class("gw-quiet")
        copy.connect("clicked", self._copy_log_row, ev)
        acts.append(copy)
        # the page that owns this event, one click away: a threat row
        # resolves fastest on the Firewall page (block ledger, Defense),
        # a tool row on Services (lifecycle only)
        jump = Gtk.Button(label="Open Firewall" if lane == "threat"
                          else "Open Services")
        jump.add_css_class("gw-quiet")
        jump.set_tooltip_text(
            "The page that manages this kind of event.")
        jump.connect("clicked", lambda *_a, k=("defense" if lane == "threat"
                                               else "services"): self._show(k))
        acts.append(jump)
        body.append(acts)
        dlg.connect("response", lambda d, _r: d.destroy())
        present_now(dlg)

    def _log_tool_actions(self, ev, acts):
        name = str(ev.get("from_tool", ""))
        tools = {t["name"]: t for t in self.registry}
        known = tools.get(name)
        if not known:
            return
        from ui.toolsdesk import control_label
        b = Gtk.Button(label=control_label({
            "name": name, "unit": known.get("unit"),
            "paused": self.paused.is_paused(name)}))
        b.add_css_class("gw-primary")
        b.connect("clicked", lambda *_a, k=name: self._control_requested(k))
        acts.append(b)

    def _log_threat_actions(self, ev, acts):
        for o in threat_card_options(ev):
            b = Gtk.Button(label=o.get("label") or o.get("id"))
            b.add_css_class("gw-primary" if o.get("tone") == "primary"
                            else "gw-danger")
            b.connect("clicked", self._run_log_option, dict(o))
            acts.append(b)
        target = _threat_target(ev)
        if target and pathlib.Path(target).exists():
            show = Gtk.Button(label="Show in folder")
            show.add_css_class("gw-quiet")
            show.connect("clicked", lambda *_a, p=target: self._show_folder(p))
            acts.append(show)

    def _run_log_option(self, _btn, opt):
        d = Gtk.Dialog(title=f"{opt.get('label')} : are you sure?",
                       transient_for=self, modal=False)
        d.set_destroy_with_parent(True)
        body = d.get_content_area()
        body.set_margin_start(18); body.set_margin_end(18)
        body.set_margin_top(12); body.set_margin_bottom(12)
        lbl = Gtk.Label(xalign=0, wrap=True)
        lbl.set_xalign(0)
        args = ", ".join(str(a) for a in (opt.get("args") or []))
        lbl.set_text(f"{opt.get('helper')} {args}\n\n"
                     "You will be asked for your password.")
        body.append(lbl)
        d.add_button("Cancel", Gtk.ResponseType.CANCEL)
        d.add_button(opt.get("label") or "Run", Gtk.ResponseType.OK)
        d.connect("response", self._on_log_option_response, opt)
        present_now(d)

    def _on_log_option_response(self, d, rid, opt):
        d.destroy()
        if rid != Gtk.ResponseType.OK:
            return

        def worker():
            from ui import decisionlist as dl
            try:
                rc = dl._helper_exec(opt.get("helper"),
                                     list(opt.get("args", [])))
            except Exception:
                rc = -1
            GLib.idle_add(self._after_log_option, opt.get("label"), rc)

        threading.Thread(target=worker, daemon=True).start()

    def _after_log_option(self, label, rc):
        self._refresh_logs()
        status = getattr(self, "logs_status", None)
        if status is not None:
            status.set_text(
                f"{label}: done." if rc == 0 else
                f"{label}: the helper exited {rc}.")
        return False

    def _copy_log_row(self, _btn, ev):
        detail = (f"{ev.get('severity', '')} - "
                  f"{friendly_name(ev.get('from_tool', ''))}"
                  f" ({ev.get('from_tool', '')})\n{ev.get('text', '')}")
        try:
            from gi.repository import Gdk
            Gdk.Display.get_default().get_clipboard().set(detail)
            self.logs_status.set_text("Copied. Paste it into a note.")
        except Exception:
            self.logs_status.set_text("Could not reach the clipboard.")

    def _refresh_logs(self):
        tool = self.logs_pick.get_active_id() or None
        try:
            events = daemon_mod.read_events(DATA_DIR / "events.jsonl", 4000)
        except OSError:
            events = []
        grouped = []
        ordered = sorted(events, key=lambda e: str(e.get("ts", "")),
                         reverse=True)
        for e in ordered:
            if tool and e.get("from_tool") != tool:
                continue
            key = (e.get("from_tool"), e.get("text", ""))
            if grouped and grouped[-1]["key"] == key:
                grouped[-1]["count"] += 1
                continue
            grouped.append({"key": key, "count": 1, "ev": e})
            if len(grouped) >= 500:
                break
        self.logs_store.clear()
        for g in grouped:
            e = g["ev"]
            sev = e.get("severity", "")
            suffix = f"   ×{g['count']}" if g["count"] > 1 else ""
            values, raw, lane = log_row_values(
                e, f"{local_clock(e.get('ts', ''))} "
                   f"{friendly_name(e.get('from_tool', ''))}",
                str(e.get("text", ""))[:400] + suffix,
                pc_severity_colour(sev))
            self.logs_store.append([*values, raw, lane])
