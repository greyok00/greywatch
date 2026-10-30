import datetime as _dt
import json
import os
import pathlib
import subprocess
import threading
import time

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gtk, GLib, Gio, Pango    # noqa: E402

from assistant import audit
from registry import load_registry
from ui.models import (status_words, recent_rows, age_words, local_clock)
from ui.plain import (sentence as plain_sentence, friendly_name, what_is,
                      escape, without_mark, soft as pc_soft,
                      muted as pc_muted, ok as pc_ok, state_colour as pc_state_colour,
                      severity_colour as pc_severity_colour,
                      severity_word as pc_severity_word)
from ui.themes import (ThemeStore, dark_default, load_setting,
                       THEME_CHOICES)
from ui.cards import SCAN_MODES, quiet_note
from ui.assistant import AssistantPanel
from ui.toolicons import icon_name as tool_icon
from ui.settings import (TrustList, PausedStore, LearningStore,
                         FirewallModeStore)
from ui import discover, metrics
from ui.blocklist import BlockList
import greywatch_daemon as daemon_mod

DATA_DIR = daemon_mod.DATA_DIR
PAINT_MERGE_MS = 250

# Recent-activity table geometry. The header row in `_security_view` draws
# plain labels over these widths, so they are shared rather than guessed in
# two places (a centred stock header never lines up with the cells).
ICON_W = 18      # tool glyph column
DOT_W = 22       # severity dot column
TIME_W = 84      # "18:35:39" plus breathing room

# Which guided task configures a given protection. Shared by the Details
# dialog and the Tools page so a tool offers the SAME entry point in both
# places (it used to differ: Details offered seven, the card none).
WIZARD_FOR = {"appfw": "appfw", "ufw": "ufw", "fail2ban": "fail2ban",
              "tetragon": "tetragon", "arpwatch": "arpwatch",
              "yara-watch": "yara", "yara-tmp-scan": "yara"}


def _fixed(col, width):
    col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
    col.set_fixed_width(width)
    return col


class MainWindow(Gtk.Window):
    def __init__(self, on_status_change=None, tray_available=True,
                 quit_cb=None):
        super().__init__(title="Greywatch")
        # A share of the monitor, not a fixed pixel count: the same
        # build opens on a 1366px laptop and on a 4K panel.
        self.set_default_size(*metrics.window_size())
        self.set_icon_name("greywatch")
        self._tray_available = tray_available
        self.quit_cb = quit_cb
        self.connect("close-request", self._close_to_tray)

        self.registry = load_registry()
        self.by_name = {t["name"]: t for t in self.registry}
        self.on_status_change = on_status_change
        self._events = []
        self._merge_pending = False
        self._recent_seen = None
        self._chat_state = None
        self._chat_snapshot = None
        self._scan_watch = None
        self._detail_dialog = None
        self._chooser = None
        self._wizard_win = None
        self._setup_win = None
        self._selected_tool = None
        self._state_override = {}
        self.chat_llm = None             # assistant brain, woken on realize
        self.chat_retry = None
        self._trust = TrustList()
        self.paused = PausedStore()
        self._learn_store = LearningStore()
        self._fw_mode_store = FirewallModeStore()
        self._blocklist = BlockList()   # mtime-cached; never re-parsed per tick
        self._learn_sel = None
        self._learn_guard = False
        self._fw_mode_guard = False
        self._scan_runner = self._run_scan

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_child(outer)
        self._header(outer)
        root = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        outer.append(root)
        self._rail(root)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)
        root.append(self.stack)

        self._views = {}
        self._theme_store = ThemeStore(self)
        self._apply_saved_theme()
        self._build_all()
        self._show("tools")
        self._rail_btns["tools"].grab_focus()
        self._watchers()
        self.refresh()
        self._glib_ids = []
        self._glib_ids.append(
            GLib.timeout_add_seconds(5, self._periodic_refresh))
        self.connect("destroy", self._kill_timers)

    def _tick_id(self, fn, ms=200, seconds=False):
        sid = (GLib.timeout_add_seconds(seconds and ms or 0, fn)
               if seconds else GLib.timeout_add(ms, fn))
        self._glib_ids.append(sid)
        return sid

    def _kill_timers(self, *_a):
        for sid in list(self._glib_ids):
            try:
                GLib.source_remove(sid)
            except (RuntimeError, TypeError):
                pass                     # already fired / not on this context
        self._glib_ids.clear()
        return False

    def _close_to_tray(self, *_a):
        if self.quit_cb and self._tray_available:
            self.hide()              # live in the tray: Show summons, Quit exits
        elif self.quit_cb:
            self.quit_cb()           # no tray to summon from: hiding orphans it
        else:
            self.destroy()           # no app loop (tests): really close
        return True                  # close handled here; never the default kill

    def _header(self, parent):
        """One line at the top: name, what this is, and the current verdict."""
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        bar.add_css_class("gw-titlebar")
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        title = Gtk.Label(label="Greywatch", xalign=0)
        title.add_css_class("gw-title")
        sub = Gtk.Label(label="Endpoint security", xalign=0)
        sub.add_css_class("gw-subtitle")
        left.append(title)
        left.append(sub)
        bar.append(left)
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        bar.append(spacer)
        self.header_pill = Gtk.Label(label="Checking…")
        self.header_pill.add_css_class("gw-pill")
        # A label stretches to the bar height by default; with a 999px
        # radius that painted a CIRCLE around the words instead of a chip.
        self.header_pill.set_valign(Gtk.Align.CENTER)
        bar.append(self.header_pill)
        parent.append(bar)

    def _apply_saved_theme(self):
        picked = load_setting()
        name = picked if picked in THEME_CHOICES.values() \
            else dark_default(self._theme_store.names())
        self._theme_store.apply(name)

    def _rail(self, parent):
        """A real macOS-style sidebar: icon + label on one line, 34px rows,
        a quiet caption per section. The wizard moved to its own 'Setup'
        section at the bottom instead of competing with the five pages."""
        rail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        rail.add_css_class("gw-rail")
        rail.set_size_request(212, -1)
        parent.append(rail)

        cap = Gtk.Label(label="Workspace", xalign=0)
        cap.add_css_class("gw-side-cap")
        rail.append(cap)

        self._rail_btns = {}
        for key, icon, label in (
                ("tools", "security-high-symbolic", "Security"),
                ("deep", "applications-system-symbolic", "Tools"),
                ("logs", "document-open-recent-symbolic", "Logs"),
                ("settings", "preferences-system-symbolic", "Settings"),
                ("help", "help-about-symbolic", "Help")):
            b = Gtk.Button()
            lv = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            ic = Gtk.Image.new_from_icon_name(icon)
            ic.set_pixel_size(17)
            lb = Gtk.Label(label=label, xalign=0)
            lb.add_css_class("gw-rail-label")
            lv.append(ic)
            lv.append(lb)
            b.set_child(lv)
            b.connect("clicked", self._rail_pick, key)
            rail.append(b)
            self._rail_btns[key] = b

        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        rail.append(spacer)
        setup = Gtk.Label(label="Setup", xalign=0)
        setup.add_css_class("gw-side-cap")
        rail.append(setup)

        self._rail_wiz = wiz = Gtk.Button()
        wv = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        wi = Gtk.Image.new_from_icon_name("system-run-symbolic")
        wi.set_pixel_size(17)
        wl = Gtk.Label(label="Wizard", xalign=0)
        wl.add_css_class("gw-rail-label")
        wv.append(wi)
        wv.append(wl)
        wiz.set_child(wv)
        # The hub, not the baseline pass: the baseline is one of the tasks
        # inside it now (owner report 2026-10-27 — it used to be the shell
        # that swallowed the per-tool wizards).
        wiz.set_tooltip_text("Guided setup: pick one task")
        wiz.connect("clicked", lambda *_b: self._open_wizard())
        rail.append(wiz)

    def _rail_pick(self, _b, key):
        self._show(key)

    def _show(self, key):
        if key not in self._builders:
            key = "tools"
        if key not in self._views:
            self._add_view(key, self._builders[key]())
        self.stack.set_visible_child_name(key)
        for k, b in self._rail_btns.items():
            b.remove_css_class("gw-active")
            if k == key:
                b.add_css_class("gw-active")
        # A page built on demand starts with placeholder text ("checking…")
        # and the periodic refresh is up to five seconds away, so the owner
        # saw empty cards right after switching. Paint the real snapshot the
        # moment the page is shown.
        self.refresh()

    def _build_all(self):
        self._views = {}
        # "harden" is deliberately absent: baseline hardening is a task in
        # the Wizard hub, not a top-level page duplicating the wizard.
        self._builders = {"tools": self._security_view,
                          "deep": self._tools_view, "logs": self._logs_view,
                          "help": self._help_view,
                          "settings": self._settings_view}
        self._add_view("tools", self._builders["tools"]())

    def _add_view(self, key, widget):
        self.stack.add_named(widget, key)
        self._views[key] = widget

    def _ensure_view(self, key):
        if key not in self._views:
            self._add_view(key, self._builders[key]())

    def _security_view(self):
        # Assistant-first dashboard: the centre (chat) and the far-right
        # protection rail share one pane, so resizing the chat can never
        # squeeze the rail away.
        pane = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        pane.set_vexpand(True)
        pane.set_hexpand(True)
        st = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        st.set_margin_top(26); st.set_margin_start(30); st.set_margin_end(26)
        st.set_margin_bottom(18)

        # Page header, macOS-style: a quiet eyebrow, one large verdict, and
        # the tally underneath. Two labels on one line (the old layout) made
        # the verdict and the count read as the same rank.
        top = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        eyebrow = Gtk.Label(label="Overview", xalign=0)
        eyebrow.add_css_class("gw-eyebrow")
        top.append(eyebrow)
        self.status_words = Gtk.Label(xalign=0)
        self.status_words.set_xalign(0)
        self.status_words.add_css_class("gw-headline")
        top.append(self.status_words)
        # Counts header: the tally behind the headline's big words, filled
        # by refresh() from the same status snapshot (no extra reads).
        self.counts = Gtk.Label(xalign=0)
        self.counts.set_xalign(0)
        self.counts.add_css_class("gw-page-meta")
        top.append(self.counts)
        st.append(top)

        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        # 6 = the state dot's ink (bound to the "foreground" cell property).
        self.list_store = Gtk.ListStore(str, str, str, str, str, str, str)
        lv = Gtk.TreeView(model=self.list_store)
        lv.set_headers_visible(True)
        # Column 0 carries an icon NAME (see ui/toolicons.py): the renderer
        # is a pixbuf cell bound to the themed symbolic icon, so every tool
        # is drawn in one stroke weight and picks up the row's ink colour.
        icon_cell = Gtk.CellRendererPixbuf()
        icon_cell.set_property("width", 22)
        icon_col = Gtk.TreeViewColumn("", icon_cell, icon_name=0)
        lv.append_column(_fixed(icon_col, 44))
        # State is a drawn dot in the theme's status ink, not an emoji:
        # emoji ignore the theme and render differently on every machine
        # (design pass 2026-10-27).
        dot = Gtk.CellRendererText()
        dot.set_property("xalign", 0.5)
        dot_col = Gtk.TreeViewColumn("", dot, text=1, foreground=6)
        lv.append_column(_fixed(dot_col, 40))
        for idx, title, width in [(2, "Tool", 430), (3, "Status", 170)]:
            cell = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, cell, text=idx)
            lv.append_column(_fixed(col, width))
        cell = Gtk.CellRendererText()
        last = Gtk.TreeViewColumn("Last activity", cell, text=4)
        last.set_expand(True)
        lv.append_column(last)
        self.list_view = lv
        sel = lv.get_selection()
        sel.set_mode(Gtk.SelectionMode.SINGLE)
        sel.connect("changed", self._list_selected)
        self.table_stack = Gtk.Stack()
        self.table_stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.table_stack.add_named(self._wrap(lv), "list")
        empty = Gtk.Label(
            label="Nothing needs attention.\n"
                  "Tick \u201cShow healthy\u201d to see every protection.",
            justify=Gtk.Justification.CENTER)
        empty.add_css_class("gw-meta")
        self.table_stack.add_named(empty, "empty")
        frame.set_child(self.table_stack)
        frame.set_vexpand(False)
        self.table_stack.set_size_request(-1, 470)
        # The list stack kept: selection, restore and refresh still drive
        # it, and the v1 rail replaces the big table — it stays built and
        # updated, just no longer featured on the dashboard.
        self.list_frame = frame

        # The four controls the old actions strip had now live in the rail
        # footer (same attributes, same handlers); the selection note rides
        # along so "Select a protection first." still lands somewhere visible.
        # "Show healthy" moves too — the rail header — still driving the same
        # filter (healthy rows are the long tail: reachable, not competing
        # for the top of the screen; unticking hid all seventeen healthy
        # rows once and read as "the app is broken", so it is on by default).
        # A macOS switch, not a tick box: the rail header names it and the
        # control is the familiar pill. get_active() keeps the same contract
        # the filter code already uses.
        self.show_all_btn = Gtk.Switch()
        self.show_all_btn.set_active(True)
        self.show_all_btn.set_valign(Gtk.Align.CENTER)
        self.show_all_btn.set_tooltip_text(
            "List every protection. Turn off to see only the ones that "
            "need attention.")
        self.show_all_btn.connect("notify::active", lambda *_a: self.refresh())
        self.sel_note = Gtk.Label(xalign=0)
        self.sel_note.set_xalign(0)
        self.sel_note.set_text("Select a protection.")
        self.sel_note.set_hexpand(True)
        self.pause_btn = Gtk.Button(label="Pause")
        self.pause_btn.connect("clicked", lambda *_b: self._pause_selected())
        self.resume_btn = Gtk.Button(label="Resume")
        self.resume_btn.connect("clicked", lambda *_b: self._resume_selected())
        self.details_btn = Gtk.Button(label="Details")
        self.details_btn.connect(
            "clicked", lambda *_b: self._details_selected())
        self.panic_btn = Gtk.Button(label="Enable all")
        self.panic_btn.set_tooltip_text(
            "Starts what is stopped and turns the app firewall on.")
        self.panic_btn.connect("clicked", self._on_panic)

        # Chat centre: the assistant takes the big table's old place, and a
        # visible restart affordance covers a failed model wake (a fresh Llm
        # restarts — start() is one-shot per instance).
        self.assistant_panel = AssistantPanel(
            self.registry, self._get_status, self._get_recent,
            lambda: self.chat_llm, self._assistant_intent)
        self.assistant_panel.add_css_class("gw-chat")
        self.chat_retry = Gtk.Button(label="Retry model")
        self.chat_retry.set_visible(False)
        self.chat_retry.connect(
            "clicked", lambda *_a: self._start_chat_llm())
        self.assistant_panel.append(self.chat_retry)
        # The chat is the point of the page: it takes every pixel the
        # activity feed does not need (owner: "have the recent activity be
        # about half its current size and the chat larger").
        self.assistant_panel.set_vexpand(True)
        self.assistant_panel.set_valign(Gtk.Align.FILL)
        # A floor, not a height: the chat takes whatever the header and the
        # activity feed leave. 280 keeps the composer and two answers usable
        # inside the 720px minimum window without forcing a page scroll.
        self.assistant_panel.set_size_request(-1, 280)
        st.append(self.assistant_panel)
        # A theme switch rebuilds this page — and the panel with it. Hand
        # back the conversation and the anchors the previous panel carried,
        # then re-apply the model state to the banner (owner watched the
        # whole chat vanish after 'change theme to light mode', 2026-10-30).
        snap = getattr(self, "_chat_snapshot", None)
        if snap:
            self.assistant_panel.restore_transcript(snap)
            self._chat_snapshot = None
        if getattr(self, "_chat_state", None) is not None:
            ok, err = self._chat_state
            self.assistant_panel.note_state(ok, err)
            if getattr(self, "chat_retry", None) is not None:
                self.chat_retry.set_visible(not ok)

        st.append(self._h2("Recent activity"))
        # [tool icon name, severity dot, time, sentence]
        # 4 = severity ink for the state dot in column 1.
        self.recent_store = Gtk.ListStore(str, str, str, str, str)
        # The feed reads as a table only with a Finder-style header row over
        # the columns. A stock TreeView header centres and mis-measures its
        # labels, so the header is an ordinary box using the same fixed
        # column widths as the cells below it.
        recent = Gtk.TreeView(model=self.recent_store, headers_visible=False)
        # Half the height it had: the feed is a glance at what just
        # happened, and the chat is what the page is for.
        recent.set_size_request(-1, 110)
        icon_cell = Gtk.CellRendererPixbuf()
        icon_cell.set_property("width", ICON_W)
        icon_col = Gtk.TreeViewColumn(None, icon_cell, icon_name=0)
        icon_col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        icon_col.set_fixed_width(ICON_W + 8)
        recent.append_column(icon_col)
        dot = Gtk.CellRendererText()
        dot.set_property("xalign", 0.5)
        dot_col = Gtk.TreeViewColumn(None, dot, text=1, foreground=4)
        dot_col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        dot_col.set_fixed_width(DOT_W)
        recent.append_column(dot_col)
        time_cell = Gtk.CellRendererText()
        time_col = Gtk.TreeViewColumn(None, time_cell, text=2)
        time_col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        time_col.set_fixed_width(TIME_W)
        recent.append_column(time_col)
        event_cell = Gtk.CellRendererText()
        # Fixed + expand, not content-sized: a TreeView's minimum width is
        # the sum of its columns, and an auto column sized to the longest
        # event line made the whole start column minimum 668px — wider than
        # the 577px pane can give at the 1100px window, so the dashboard
        # clipped its left edge. The cell ellipsises; the row tooltip has
        # the full sentence.
        event_cell.set_property("ellipsize", Pango.EllipsizeMode.END)
        event_col = Gtk.TreeViewColumn(None, event_cell, text=3)
        event_col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        event_col.set_fixed_width(260)
        event_col.set_expand(True)
        recent.append_column(event_col)
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        head.add_css_class("gw-th-row")
        # 10px matches the row padding the cells are drawn inside, so the
        # labels sit exactly over the values.
        head.set_margin_start(10)
        head.set_margin_end(10)
        pad = Gtk.Box()
        pad.set_size_request(ICON_W + 8 + DOT_W, -1)
        head.append(pad)
        for title, width in (("Time", TIME_W), ("Event", 0)):
            lbl = Gtk.Label(label=title, xalign=0)
            lbl.set_xalign(0)
            lbl.add_css_class("gw-th")
            if width:
                lbl.set_size_request(width, -1)
            else:
                lbl.set_hexpand(True)
            head.append(lbl)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        body.append(head)
        body.append(recent)
        rf = Gtk.Frame()
        rf.add_css_class("gw-card")
        rf.set_child(body)
        rf.set_vexpand(False)
        st.append(rf)

        # No page scroller: the dashboard is one viewport. The chat absorbs
        # the spare height and the activity feed keeps a fixed glance size,
        # so every page fits the window at its 1100x720 minimum instead of
        # hiding the newest activity below the fold.
        st.set_vexpand(True)
        pane.set_start_child(st)
        pane.set_end_child(self._build_assistant_rail())
        pane.set_resize_start_child(True)
        pane.set_shrink_end_child(False)
        # A first-run default; the divider stays user-draggable. Through the
        # property, not the method: the repo lint bans the `set_position(`
        # spelling (Gtk3-era window API) and the name collides here.
        pane.set_property("position", 760)
        # ...and the default is a SHARE of the pane, not a pixel count: a
        # fixed divider left the protection rail more than a thousand pixels
        # wide on a 4K window while crushing the chat on a small one. The
        # rail keeps a laptop-sized width and the page takes the rest; once
        # the owner drags the divider, their choice wins.
        rail_state = {"width": -1, "auto": True, "setting": False}

        def _rail_dragged(_pane, _pspec):
            if not rail_state["setting"]:
                rail_state["auto"] = False

        pane.connect("notify::position", _rail_dragged)

        def _keep_rail(_widget, _clock):
            width = pane.get_width()
            if width == rail_state["width"] or width <= 0:
                return True
            rail_state["width"] = width
            if rail_state["auto"]:
                rail = metrics.span(width, 0.24, 280, 420)
                rail_state["setting"] = True
                pane.set_property("position", max(360, width - rail))
                rail_state["setting"] = False
            return True

        pane.add_tick_callback(_keep_rail)
        return pane

    def _list_selected(self, selection):
        model, it = selection.get_selected()
        self._selected_tool = model[it][5] if it else None
        if self._selected_tool:
            self.sel_note.set_text(f"Selected: {model[it][2]}")
        else:
            self.sel_note.set_text(
                "Select a protection.")

    def _restore_list_selection(self):
        sel = self.list_view.get_selection()
        _model, it = sel.get_selected()
        if self._selected_tool and it and \
                self.list_store[it][5] == self._selected_tool:
            return
        if not self._selected_tool:
            return
        for i, row in enumerate(self.list_store):
            if row[5] == self._selected_tool:
                sel.select_iter(self.list_store.get_iter_from_string(str(i)))
                return
        self._selected_tool = None

    def _details_selected(self):
        if self._selected_tool:
            self._open_detail(self._selected_tool)

    def _build_assistant_rail(self):
        """Far-right rail: one row per protection — icon, drawn dot, name,
        pause/play; the footer carries the four controls the old actions
        strip had. Drawn glyphs only (theme-consistent, design invariant)."""
        # The protections are a card, not a floating table: same surface as
        # the chat, one radius, one hairline. The switch sits in the header
        # with its own small caption.
        card = Gtk.Frame()
        card.add_css_class("gw-card")
        card.set_margin_top(26)
        card.set_margin_bottom(18)
        card.set_margin_end(20)
        card.set_size_request(272, -1)
        card.set_vexpand(True)
        card.set_valign(Gtk.Align.FILL)
        rail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        rail.set_margin_top(2)
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        top.append(self._h2("Protections"))
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        top.append(spacer)
        # A bare switch next to a static "Healthy" read as "Healthy: on" —
        # the owner saw a control with no name and a status word that never
        # changed. Say what the switch does, and keep the health tally in
        # the headline above where it is already computed.
        show_all_label = Gtk.Label(label="Show all")
        show_all_label.add_css_class("gw-page-meta")
        top.append(show_all_label)
        top.append(self.show_all_btn)          # moved from the dashboard
        rail.append(top)
        self.rail_list = Gtk.ListBox()
        # Compact row metrics for the rail only; the global 40px row rule
        # is right for tables and wrong for a 17-item list in 240px.
        self.rail_list.add_css_class("gw-rail-rows")
        self.rail_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.rail_state = {}
        self.rail_rows = {}
        for t in self.registry:
            name = t["name"]
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            ic = Gtk.Image.new_from_icon_name(tool_icon(name))
            ic.set_pixel_size(16)
            box.append(ic)
            lbl = Gtk.Label(label=friendly_name(name), xalign=0)
            lbl.set_xalign(0)
            lbl.set_hexpand(True)
            # Pango is imported up top (minitile idiom); ellipsising without
            # it would overflow the 240px rail on long plain names.
            lbl.set_ellipsize(Pango.EllipsizeMode.END)
            lbl.set_tooltip_text(f"{t.get('label') or name} · {name}")
            box.append(lbl)
            dot = Gtk.Label(label="●")
            dot.set_markup(f"<span color='{pc_muted()}'>●</span>")
            box.append(dot)
            tog = Gtk.Button()
            tog_img = Gtk.Image.new_from_icon_name(
                "media-playback-pause-symbolic")
            tog_img.set_pixel_size(12)
            tog.set_child(tog_img)             # drawn glyph, never an emoji
            tog.connect("clicked", lambda *_b, name=name:
                        self._rail_toggle(name))
            box.append(tog)
            row.set_child(box)
            self.rail_rows[name] = (row, dot, tog)
            self.rail_list.append(row)
        self.rail_list.connect("row-selected", self._rail_selected)
        sc = Gtk.ScrolledWindow()
        # EXTERNAL, not AUTOMATIC: GTK still creates (and can paint) a
        # scrollbar node for an automatic scroller even when CSS sets its
        # opacity to zero, which is the grey pill that kept appearing over
        # the pause/play buttons at the row's right edge. EXTERNAL never
        # creates the bar at all; the wheel still scrolls the list.
        sc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.EXTERNAL)
        sc.set_child(self.rail_list)
        sc.set_vexpand(True)
        sc.set_overlay_scrolling(False)
        sc.add_css_class("gw-rail-scroll")
        rail.append(sc)
        self.sel_note.add_css_class("gw-page-meta")
        rail.append(self.sel_note)
        # The four controls the old actions strip had, rebuilt here verbatim:
        # same attributes, same handlers, no second code path. Three act on
        # the selection so they read as one segmented control; "Enable all"
        # is the only whole-system action, so it gets its own quiet row.
        foot = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        foot.add_css_class("gw-segmented")
        foot.set_homogeneous(True)
        for b in (self.pause_btn, self.resume_btn, self.details_btn):
            foot.append(b)                     # reuse existing buttons
        rail.append(foot)
        self.panic_btn.add_css_class("gw-quiet")
        rail.append(self.panic_btn)
        card.set_child(rail)
        return card

    def _rail_toggle(self, name):
        """Same click path as the footer buttons, for a rail row."""
        self._selected_tool = name
        if self.rail_state.get(name) == "paused":
            self._resume_selected()
        else:
            self._pause_selected()

    def _rail_selected(self, _box, row):
        """Row click selects; the footer buttons act on the selection."""
        for name, (r, _dot, _tog) in self.rail_rows.items():
            if r is row:
                self._selected_tool = name
                self.sel_note.set_text(
                    f"Selected: {friendly_name(name)} · {name}")

    def _refresh_rail(self, tools, updated):
        """Paint the rail from the snapshot refresh() already read: one dot
        per protection plus the pause/play glyph — no new daemon traffic."""
        rows = getattr(self, "rail_rows", None)
        if not rows:
            return
        alive = getattr(self, "show_all_btn", None)
        show = alive is None or alive.get_active()
        for t in self.registry:
            name = t["name"]
            entry = rows.get(name)
            if entry is None:
                continue
            row, dot, tog = entry
            paused = self.paused.is_paused(name)
            state = self._display_state(name, tools.get(name, {}), updated)
            # Same drawn-dot ink the cards and the list use; no emoji.
            dot.set_markup(
                f"<span color='{pc_state_colour(state, paused)}'>●</span>")
            self.rail_state[name] = "paused" if paused else "running"
            img = Gtk.Image.new_from_icon_name(
                "media-playback-start-symbolic" if paused
                else "media-playback-pause-symbolic")
            img.set_pixel_size(12)
            tog.set_child(img)
            tog.set_tooltip_text(
                f"Resume {friendly_name(name)}" if paused
                else f"Pause {friendly_name(name)}")
            # "Show healthy" still does its one job, just from the rail:
            # an unticked box hides the long tail of green rows.
            row.set_visible(show or paused or state != "GREEN")

    def _get_status(self):
        return dict(getattr(self, "_status_snapshot", {}) or {})

    def _get_recent(self):
        return list(getattr(self, "_recent_snapshot", []) or [])

    def _assistant_intent(self, action, tool, value=""):
        """Confirm-gated execution. The panel showed the assistant confirm
        dialog; the window runs the action through the exact manual paths
        and records the OUTCOME (ui.assistant._confirmed records details
        directly).

        `value` carries the target of the settings intents: "on"/"off" for
        the firewall and learning mode, the site name for trust/block, the
        program path for trust_program, and the page key for open_page.
        Nothing here is a new capability — every branch calls the handler
        the Settings page button calls."""
        if action == "details":
            self._selected_tool = tool
            self._open_detail(tool)
            return
        if action == "scan":
            mode = next((m for m in SCAN_MODES if m["key"] == tool), None)
            if mode is None:                # validated by the panel already
                return
            self._assistant_pending = ("scan", tool)
            self._start_scan(None, mode)    # the same runner the card uses
            return
        if action in ("pause", "resume"):
            self._assistant_pending = (action, tool)
            self._selected_tool = tool
            self._pause_selected() if action == "pause" \
                else self._resume_selected()
            return
        if action == "enable_all":
            # The bulk restore is best-effort by design; the accepted
            # request is the outcome, and the per-tool toggles it starts
            # must not overwrite this line with their own rc.
            audit.record("enable_all", "", True)
            self._enable_everything()
            return
        if action == "firewall":
            want_on = value == "on"
            if self._fw_is_on() == want_on:
                audit.record("firewall", value, True)
                return
            self._assistant_pending = ("firewall", value)
            self._on_fw_toggle(None)       # the Settings button's handler
            return
        if action == "learning":
            want_on = value == "on"
            if self.learn_check.get_active() == want_on:
                audit.record("learning", value, True)
                return
            if want_on and hasattr(self, "learn_for"):
                self.learn_for.set_active_id("60")
            self.learn_check.set_active(want_on)
            audit.record("learning", value, True)
            return
        if action == "update_lists":
            self._assistant_pending = ("update_lists", "")
            self._on_update_now(None)
            return
        if action in ("trust_site", "block_site"):
            # self._trust, not self.trust: the alias only exists once the
            # Settings page builds, so the first allow confirm from chat
            # crashed before recording (owner 2026-10-30).
            verdict = "allow" if action == "trust_site" else "block"
            ok = self._trust.add(value, verdict)
            if ok:
                self._refresh_trust()
            audit.record(action, value, ok)
            return
        if action == "trust_program":
            ok = self._trust.add_app(value)
            if ok:
                self._refresh_apps()
            audit.record(action, value, ok)
            return
        if action == "open_page":
            from assistant.intents import PAGES
            key = PAGES.get(value)
            if key:
                self._show(key)
                audit.record("open_page", value, True)
            return
        if action == "theme":
            from assistant.intents import theme_kit
            kit = theme_kit(value)      # "light mode" -> the swiss kit
            if self._theme_store.apply(kit):
                combo = getattr(self, "theme_combo", None)
                if combo is not None:
                    combo.handler_block_by_func(self._on_theme_pick)
                    combo.set_active_id(kit)   # keep the picker in step
                    combo.handler_unblock_by_func(self._on_theme_pick)
                self._tick_id(self._retheme, 0)
                audit.record("theme", kit, True)

    def _assistant_record_outcome(self, ok):
        """One accurate audit line per accepted assistant intent; manual
        toggles leave no pending marker, so this is a no-op for them."""
        pending = getattr(self, "_assistant_pending", None)
        if pending:
            self._assistant_pending = None
            audit.record(pending[0], pending[1], ok)

    def _start_chat_llm(self):
        """Wake the assistant model in-process (the installer drops the
        gguf under $DATA/models). A retry builds a NEW Llm instance, since
        start() is one-shot per instance (assistant/llm.py contract)."""
        from assistant.llm import Llm
        from assistant.model import MODEL_FILENAME
        import gwpaths
        model = gwpaths.data_dir() / "models" / MODEL_FILENAME
        self.assistant_panel.banner.set_text(
            "Assistant loading…"
            + ("" if getattr(self, "chat_llm", None) is None else " retrying"))
        if getattr(self, "chat_retry", None) is not None:
            self.chat_retry.set_visible(False)
        self.chat_llm = Llm(model_path=str(model))
        self.chat_llm.start(
            lambda ok, err: GLib.idle_add(self._on_llm_ready, ok, err))

    def _on_llm_ready(self, ok, err):
        self._chat_state = (ok, err)
        self.assistant_panel.note_state(ok, err)
        if getattr(self, "chat_retry", None) is not None:
            self.chat_retry.set_visible(not ok)
        return False

    def _tools_view(self):
        """Every protection on one screen.

        This page used to be seventeen tall cards in a scroller: two cards
        were visible and the rest lived below the fold. A protection is
        one line of facts — name, real tool, live state, the two actions
        that apply — so it is built as a compact row, two or three per
        line depending on width. The page now fits the 720px minimum
        window without scrolling.
        """
        tools = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        tools.set_margin_top(16); tools.set_margin_start(34); tools.set_margin_end(34)
        tools.set_margin_bottom(12)
        tools.append(self._h1("Your protections"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        intro.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "Each row shows the plain name, the real tool behind it and its "
            "live state. Configure anything without typing a command."
            "</span>")
        tools.append(intro)
        tools.append(self._scan_strip())
        tools.append(self._baseline_card())

        grid = Gtk.Grid()
        grid.set_column_spacing(8)
        grid.set_row_spacing(2)
        grid.set_column_homogeneous(True)
        grid.set_hexpand(True)
        grid.set_vexpand(False)
        self.cards_flow = grid
        self.card_widgets = {}
        self._card_order = [t["name"] for t in self.registry]
        for t in self.registry:
            self.card_widgets[t["name"]] = self._tool_card(t)
        # Start in the three-column shape: it is the shortest, so the page's
        # minimum height is right from the first layout. _flow upgrades to
        # two columns once there is room.
        cols = {"n": 3}
        for i, name in enumerate(self._card_order):
            grid.attach(self.card_widgets[name], i % 3, i // 3, 1, 1)

        def _flow(_widget, _clock):
            width = grid.get_width()
            if width <= 0:
                return True
            # The mono tool id is a fact, not decoration, but at the 1100px
            # minimum it costs the name the room it needs to stay readable.
            # Show it whenever the page can afford it; the tooltip always
            # has it either way.
            show_tool = width >= 1240
            for widget in self.card_widgets.values():
                widget._tool.set_visible(show_tool)
            want = 3 if width >= 1420 else 2
            if want == cols["n"]:
                return True
            cols["n"] = want
            for widget in self.card_widgets.values():
                if widget.get_parent() is grid:
                    grid.remove(widget)
            for i, name in enumerate(self._card_order):
                grid.attach(self.card_widgets[name], i % want, i // want,
                            1, 1)
            return True

        grid.add_tick_callback(_flow)
        tools.append(grid)
        fill = Gtk.Box()
        fill.set_vexpand(True)
        tools.append(fill)
        return tools

    def _baseline_card(self):
        """The baseline pass lives in the wizard, so this is the doorway.

        The old top-level Harden page duplicated the wizard's scan/apply
        flow with a second journal; two implementations of one job is how
        they drift apart. One task, one home.
        """
        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        ic = Gtk.Image.new_from_icon_name("security-high-symbolic")
        ic.set_pixel_size(24)
        ic.set_valign(Gtk.Align.CENTER)
        box.append(ic)
        words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        words.set_hexpand(True)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_markup("<span size='14000' font_family='Inter' weight='600'>"
                        "Security baseline hardening</span>")
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        body.set_markup(
            f"<span size='11500' font_family='Inter' color='{pc_muted()}'>"
            "Check this computer against the baseline, preview every change, "
            "apply them with one password prompt, then verify or undo.</span>")
        words.append(head)
        words.append(body)
        box.append(words)
        go = Gtk.Button(label="Open the baseline wizard")
        # The one real call to action on this page, so it gets the accent.
        go.add_css_class("gw-primary")
        go.set_valign(Gtk.Align.CENTER)
        go.connect("clicked", lambda *_a: self._open_setup_wizard())
        box.append(go)
        frame.set_child(box)
        return frame

    def _scan_strip(self):
        strip = Gtk.Frame()
        strip.add_css_class("gw-card")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self.circle = ProgressCircle()
        self.circle.set_valign(Gtk.Align.CENTER)
        box.append(self.circle)
        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.scan_status = Gtk.Label(xalign=0)
        self.scan_status.set_xalign(0)
        self.scan_status.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "Scans run in the background. Results appear here."
            "</span>")
        right.append(self.scan_status)
        btns = Gtk.FlowBox()
        # One compact row of six actions at their natural width: a 3-wide
        # stretch made each scan button a 600px banner across the card.
        btns.set_max_children_per_line(6)
        btns.set_min_children_per_line(1)
        btns.set_homogeneous(False)
        btns.set_selection_mode(Gtk.SelectionMode.NONE)
        btns.set_halign(Gtk.Align.START)
        btns.set_row_spacing(8)
        btns.set_column_spacing(8)
        self._scan_btns = {}
        for m in SCAN_MODES:
            # Drawn icons, not emoji: they inherit the theme's ink colour
            # like every other glyph in the app.
            b = Gtk.Button()
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            row.set_halign(Gtk.Align.CENTER)
            ic = Gtk.Image.new_from_icon_name(m["icon"])
            ic.set_pixel_size(16)
            row.append(ic)
            row.append(Gtk.Label(label=m.get("short") or m["title"]))
            b.set_child(row)
            b.add_css_class("gw-cta")
            b.set_tooltip_text(m["about"])
            b.connect("clicked", self._start_scan, m)
            btns.append(b)
            self._scan_btns[m["key"]] = b
        right.append(btns)
        right.set_hexpand(True)
        box.append(right)
        strip.set_child(box)
        return strip

    def _tool_card(self, tool: dict):
        """One protection as a compact row: drawn icon, plain name, real
        tool name, live state, then the actions that belong to it.

        The old card stacked a heading, a description and two rows of
        buttons, so seventeen of them could never fit one screen. The
        description moved to the row's tooltip and to Help; the row keeps
        the facts the page is actually for. `_sub` and `_pause_btn` stay
        as attributes because refresh() paints every row in place.
        """
        name = tool["name"]
        frame = Gtk.Frame()
        frame.add_css_class("gw-prow")
        # 2px, not 4: nine rows of these at the 1100x720 minimum pushed the
        # last protection 25px past the fold, which grew the window's own
        # minimum instead of scrolling (owner: "no scrolling").
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        box.set_margin_top(2); box.set_margin_bottom(2)
        box.set_margin_start(10); box.set_margin_end(6)
        box.set_valign(Gtk.Align.CENTER)

        ic = Gtk.Image.new_from_icon_name(tool_icon(name))
        ic.set_pixel_size(18)
        ic.set_valign(Gtk.Align.CENTER)
        box.append(ic)

        names = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        names.set_hexpand(True)
        names.set_valign(Gtk.Align.CENTER)
        fn = Gtk.Label(xalign=0)
        fn.set_xalign(0)
        fn.set_ellipsize(Pango.EllipsizeMode.END)
        fn.set_markup(
            f"<span size='13000' font_family='Inter' weight='600'>"
            f"{escape(friendly_name(name))}</span>")
        names.append(fn)
        tool_name = Gtk.Label(xalign=0)
        tool_name.set_xalign(0)
        tool_name.set_ellipsize(Pango.EllipsizeMode.END)
        tool_name.set_markup(
            f"<span size='10250' font_family='JetBrains Mono'"
            f" color='{pc_muted()}'>{escape(name)}</span>")
        names.append(tool_name)
        box.append(names)

        # Live state only — "● running" / "● needs attention". The extra
        # detail sentence lives in the row's tooltip; at a 400px column it
        # used to truncate to "● runni…" and read as a defect.
        sub = Gtk.Label(xalign=0)
        sub.set_xalign(0)
        sub.set_size_request(78, -1)
        sub.set_ellipsize(Pango.EllipsizeMode.END)
        sub.set_markup(f"<span size='11000' font_family='Inter' "
                       f"color='{pc_muted()}'>checking…</span>")
        box.append(sub)

        # One optional action slot, always reserved, so Pause and the row
        # edges line up down the column instead of shifting per row.
        slot = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        slot.set_size_request(42, -1)
        slot.set_halign(Gtk.Align.END)
        wizard_key = WIZARD_FOR.get(name)
        scan_keys = {m["key"] for m in SCAN_MODES}
        if wizard_key:
            cfg = Gtk.Button()
            cfg_i = Gtk.Image.new_from_icon_name("preferences-system-symbolic")
            cfg_i.set_pixel_size(13)
            cfg.set_child(cfg_i)
            cfg.add_css_class("gw-mini")
            cfg.set_tooltip_text("Guided setup — no commands to type")
            cfg.connect("clicked",
                        lambda *_b, k=wizard_key: self._open_wizard_for(k))
            slot.append(cfg)
        elif name in scan_keys or name == "yara-watch":
            b = Gtk.Button(label="Scan")
            b.add_css_class("gw-mini")
            b.set_tooltip_text("Run this protection's scan now")
            b.connect("clicked", self._open_scan_for, name)
            slot.append(b)
        box.append(slot)

        pause = Gtk.Button(label="Pause")
        pause.add_css_class("gw-mini")
        pause.set_sensitive(bool(tool.get("unit")))
        pause.connect("clicked", lambda *_b, n=name:
                      self._resume_tool(n) if self.paused.is_paused(n)
                      else self._pause_tool(n))
        box.append(pause)

        # The whole row opens Details — a row is the affordance, the way a
        # Finder/System Settings list row is. A fourth button in every row
        # squeezed the name column to an ellipsis at the minimum width.
        click = Gtk.GestureClick()

        def _row_clicked(_g, _n, _x, _y, n=name):
            self._selected_tool = n
            self._open_detail(n)

        click.connect("released", _row_clicked)
        frame.add_controller(click)

        frame.set_child(box)
        frame.set_tooltip_text(f"{friendly_name(name)} — {what_is(name)}")
        frame._sub = sub
        frame._tool = tool_name
        frame._pause_btn = pause
        return frame

    def _run_scan(self, mode: dict):
        if mode.get("scope") == "user":
            rc = subprocess.run(["systemctl", "--user", "start",
                                 mode["unit"]], capture_output=True,
                                text=True, timeout=20).returncode
            return rc, ("started" if rc == 0
                        else f"could not start (rc {rc})")
        from wiz import common
        helper = mode.get("helper", "scan-now")
        if helper == "tool-control":
            # scan-all: one polkit call starts every scanner at once
            rc = common.run_helper("tool-control", ["scan-all"])
        else:
            rc = common.run_helper(helper, [mode["key"]])
        return rc, ("started" if rc == 0
                    else "needs your password, or the scan helper failed")

    def _start_scan(self, _btn, mode):
        self._ensure_view("deep")        # the strip + ring live here
        self._show("deep")
        self.circle.start(mode["title"])
        self.scan_status.set_markup(
            f"<span size='13000' font_family='Inter'>"
            f"{escape(mode['title'])}: starting…</span>")

        def worker():
            try:
                rc, msg = self._scan_runner(mode)
            except Exception as e:                   # never kill the UI
                rc, msg = -1, str(e)
            GLib.idle_add(self._scan_done, mode, rc, msg)

        threading.Thread(target=worker, daemon=True).start()

    def _scan_done(self, mode, rc, msg):
        # A scan the assistant started gets one audit line with its real
        # outcome; a scan started from the card has no pending marker.
        pending = getattr(self, "_assistant_pending", None)
        if pending and pending == ("scan", mode.get("key")):
            self._assistant_pending = None
            audit.record("scan", mode.get("key", ""), rc == 0)
        if rc == 0:
            self.circle.text = mode["title"]
            if mode.get("key") == "scan-all":
                # five scanners start at once; each finishes independently
                self.circle.stop()
                self.scan_status.set_markup(
                    "<span size='13000' font_family='Inter'>"
                    "All scanners launched. Each card updates as its "
                    "scan finishes.</span>")
                return False
            self.scan_status.set_markup(
                f"<span size='13000' font_family='Inter'>"
                f"{escape(mode['title'])} started. The card updates when "
                f"it finishes.</span>")
            if mode.get("scope") == "user" and mode.get("unit"):
                self._scan_watch = [mode, 0]
                self._tick_id(self._poll_scan, 2, seconds=True)
            elif mode.get("proc"):
                self._scan_watch = [mode, 0]
                self._tick_id(self._poll_process, 2, seconds=True)
            elif mode.get("unit"):
                self._scan_watch = [mode, 0]
                self._tick_id(self._poll_scan, 2, seconds=True)
            else:
                self.circle.stop()
        else:
            self.circle.stop("idle")
            self.scan_status.set_markup(
                f"<span size='13000' font_family='Inter'>"
                f"{escape(mode['title'])}: {escape(msg)}.</span>")
        return False

    def _poll_scan(self):
        if not self._scan_watch:
            return False
        mode, ticks = self._scan_watch
        self._scan_watch[1] += 1
        cmd = (["systemctl", "--user"] if mode.get("scope") == "user"
               else ["systemctl"]) + ["is-active", mode["unit"]]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=8).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            out = ""
        if out == "active" and ticks < 2400:
            return True
        self._finish_scan_watch(mode)
        return False

    def _poll_process(self):
        if not self._scan_watch:
            return False
        mode, ticks = self._scan_watch
        self._scan_watch[1] += 1
        try:
            out = subprocess.run(["pgrep", "-x", mode["proc"]],
                                 capture_output=True, text=True,
                                 timeout=6).returncode
        except (OSError, subprocess.SubprocessError):
            out = 1
        if out == 0 and ticks < 7200:
            return True
        self._finish_scan_watch(mode)
        return False

    def _finish_scan_watch(self, mode):
        self.circle.done()
        self.scan_status.set_markup(
            f"<span size='13000' font_family='Inter'>"
            f"{escape(mode['title'])} finished. See the card and the "
            f"Logs screen.</span>")
        self._scan_watch = None

    def _open_scan_for(self, _btn, tool_name):
        key = "yara-tmp-scan" if tool_name == "yara-watch" else tool_name
        mode = next((m for m in SCAN_MODES if m["key"] == key), None)
        self._show("deep")
        if mode:
            self._start_scan(None, mode)

    def _pause_selected(self):
        if self._selected_tool:
            self._pause_tool(self._selected_tool)
        else:
            self.sel_note.set_text("Select a protection first.")

    def _resume_selected(self):
        if self._selected_tool:
            self._resume_tool(self._selected_tool)
        else:
            self.sel_note.set_text("Select a protection first.")

    def _pause_tool(self, name):
        tool = self.by_name.get(name) or {}
        if not tool.get("unit"):
            self._ensure_view("deep")
            self.scan_status.set_markup(
                f"<span size='13000' font_family='Inter'>"
                f"{escape(friendly_name(name))} has no service to pause.</span>")
            self._assistant_record_outcome(False)
            return
        dlg = Gtk.Dialog(title=f"Pause {friendly_name(name)}?",
                         transient_for=self, modal=True)
        dlg.add_button("Keep it running", Gtk.ResponseType.CANCEL)
        dlg.add_button("Pause it", Gtk.ResponseType.OK)
        body = Gtk.Label(xalign=0)
        body.set_xalign(0); body.set_wrap(True)
        body.set_markup(
            f"<span size='13000'>Pause {escape(friendly_name(name))}?</span>"
            "\nProtection is reduced until you resume it."
            " Your choice is remembered as paused, not a fault.")
        content = dlg.get_content_area()
        content.set_margin_top(14); content.set_margin_bottom(14)
        content.set_margin_start(20); content.set_margin_end(20)
        content.append(body)

        def _on_pause(d, rid, *_a):
            d.destroy()
            if rid == Gtk.ResponseType.OK:
                self._toggle_tool(name, pause=True)
            else:
                self._assistant_record_outcome(False)
        dlg.connect("response", _on_pause)
        dlg.present()

    def _resume_tool(self, name):
        self._toggle_tool(name, pause=False)

    def _reconcile_pause_markers(self, snap):
        # A pause may only be claimed while the protection is really
        # stopped. If the monitor reports it running, the marker lied —
        # it is dropped, and no row ever says paused over a live guard.
        tools = snap.get("tools", {})
        appfw_running = str(snap.get("appfw_engine",
                                     "")).startswith("running")
        setter = getattr(self.paused, "set", None)
        if not callable(setter):
            return
        for t in self.registry:
            name = t["name"]
            if not self.paused.is_paused(name):
                continue
            if name == "appfw":
                really_running = appfw_running
            else:
                really_running = self._display_state(
                    name, tools.get(name, {}),
                    snap.get("updated")) == "GREEN"
            if really_running:
                setter(name, False)

    def _on_panic(self, _btn):
        dlg = Gtk.Dialog(title="Panic lockdown",
                         transient_for=self, modal=True)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dlg.add_button("Enable everything", Gtk.ResponseType.OK)
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        body.set_markup(
            "<span size='13000'>Starts and enables every protection "
            "now?</span>")
        sub = Gtk.Label(xalign=0)
        sub.set_xalign(0)
        sub.set_wrap(True)
        sub.set_text(
            "Stops nothing. Unpauses everything, including the app firewall.")
        dlg.get_content_area().set_margin_top(14)
        dlg.get_content_area().set_margin_bottom(14)
        dlg.get_content_area().set_margin_start(20)
        dlg.get_content_area().set_margin_end(20)
        dlg.get_content_area().append(body)
        dlg.get_content_area().append(sub)

        def _answered(d, rid, *_a):
            d.destroy()
            if rid == Gtk.ResponseType.OK:
                self._enable_everything()
        dlg.connect("response", _answered)
        dlg.present()

    def _enable_everything(self):
        started = []
        try:
            snap = daemon_mod.load_status(str(DATA_DIR / "status.json"))
            tools = snap.get("tools", {})
            for t in self.registry:
                name = t["name"]
                if not t.get("unit"):
                    continue
                if self._display_state(name, tools.get(name, {}),
                                       snap.get("updated")) == "GREEN":
                    continue
                started.append(name)
                self._toggle_tool(name, pause=False)
        except Exception:
            pass
        self._ensure_appfw_enabled()
        dropped = [t["name"] for t in self.registry
                   if self.paused.is_paused(t["name"])]
        for name in dropped:
            self.paused.set(name, False)
        if not started and not dropped:
            msg = ("Nothing to do: every protection is already running.")
        elif started and dropped:
            msg = (f"Panic done: started {', '.join(started)}; the pause"
                   f" record dropped {', '.join(dropped)}.")
        elif started:
            msg = f"Panic done: {', '.join(started)} started."
        else:
            msg = ("Nothing needed starting. Cleared stale pause records:"
                   f" {', '.join(dropped)}.")
        if hasattr(self, "scan_status"):
            self.scan_status.set_markup(
                f"<span size='13000' font_family='Inter'>{escape(msg)}"
                f"</span>")
        else:
            print(msg, flush=True)
        self.refresh()
        return False

    def _ensure_appfw_enabled(self):
        try:
            from appfw.engine import read_enabled, write_enabled
            if not read_enabled(DATA_DIR):
                write_enabled(DATA_DIR, True)
                if hasattr(self, "fw_status"):
                    self.fw_status.set_text(
                        "App firewall re-enabled (default: on).")
        except Exception:
            pass
        return None

    def _ensure_default_on(self):
        # Standing rule: nothing in this app pauses a protection by
        # itself; on launch the auto-responder and the app firewall are
        # simply brought back if something left them off.
        self._ensure_appfw_enabled()
        try:
            snap = daemon_mod.load_status(str(DATA_DIR / "status.json"))
            info = (snap.get("tools") or {}).get("responderd") or {}
            if info.get("state") != "GREEN":
                self._resume_tool("responderd")
        except Exception:
            pass
        return None

    def _toggle_tool(self, name, pause: bool):
        tool = self.by_name.get(name) or {}
        unit = tool.get("unit")
        action = "stop" if pause else "start"

        if name == "appfw":
            try:
                from appfw.engine import write_enabled
                write_enabled(DATA_DIR, not pause)
                rc = 0
            except Exception:
                rc = -1
            self._after_toggle("appfw", pause, rc)
            self._refresh_fw()
            return

        def worker():
            try:
                if tool.get("scope") == "user":
                    rc = subprocess.run(
                        ["systemctl", "--user", action, unit],
                        capture_output=True, text=True, timeout=20).returncode
                else:
                    from wiz import common
                    rc = common.run_helper("tool-control", [action, unit])
                state = self._probe_unit(tool) if rc == 0 else None
            except Exception:
                rc, state = -1, None
            GLib.idle_add(self._after_toggle, name, pause, rc, state)

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _probe_unit(tool):
        unit = tool.get("unit")
        if not unit:
            return None
        cmd = ["systemctl"] + (["--user"] if tool.get("scope") == "user"
                               else []) + ["is-active", unit]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None
        if out == "active":
            return "GREEN"
        if out in ("inactive", "failed", "activating", "deactivating"):
            return "RED"
        return None

    def _effective_state(self, name, info, updated):
        ov = self._state_override.get(name)
        if not ov:
            return info.get("state", "UNKNOWN")
        state, when = ov
        try:
            snap_t = _dt.datetime.fromisoformat(
                str(updated).replace("Z", "+00:00"))
            if snap_t.tzinfo is None:
                snap_t = snap_t.replace(tzinfo=_dt.timezone.utc)
            if snap_t >= when:
                self._state_override.pop(name, None)
                return info.get("state", "UNKNOWN")
        except (ValueError, TypeError):
            pass
        return state

    def _display_state(self, name, info, updated):
        state = self._effective_state(name, info, updated)
        if name == "cve-updater":
            from ui import updates
            if updates.cve_list() is not None:
                return "GREEN" if updates.cve_is_fresh() else "YELLOW"
        return state

    def _update_detail(self, name):
        from ui import updates
        if name == "cve-updater":
            info = updates.cve_list() or {}
            return (f"list fetched {updates.human_stamp(info.get('ts'))}"
                    if info.get("ts") else "no list fetched yet")
        if name == "freshclam":
            info = updates.clamav_definitions() or {}
            return (f"definitions updated {updates.human_stamp(info.get('ts'))}"
                    if info.get("ts") else "no definitions yet")
        return ""

    def _after_toggle(self, name, pause, rc, state=None):
        self._assistant_record_outcome(rc == 0)
        if rc == 0:
            if state:
                self._state_override[name] = (
                    state, _dt.datetime.now(_dt.timezone.utc))
            self.paused.set(name, pause)
            msg = (f"{friendly_name(name)} was "
                   f"{'paused' if pause else 'resumed'}.")
        else:
            if rc in (126, 127):
                msg = (f"{friendly_name(name)}: not authorised. The "
                       f"password prompt was cancelled or refused.")
            else:
                msg = (f"Could not {'pause' if pause else 'resume'} "
                       f"{friendly_name(name)} (code {rc}).")
        if hasattr(self, "scan_status"):
            self.scan_status.set_markup(
                f"<span size='13000' font_family='Inter'>{escape(msg)}</span>")
        else:
            print(f"toggle {name}: {msg}", flush=True)
        if name == "appfw" and hasattr(self, "fw_status"):
            self.fw_btn.set_sensitive(True)
            self.fw_status.set_text(msg)
            if rc == 0:
                started = ("App firewall started. New connections pass "
                           "once without a pop-up.")
                recorded = "Learning mode records them. Strict stops unknown ones."
                self.fw_status.set_text(started + " " + recorded)
            self._refresh_fw()
        self.refresh()
        return False

    def _open_detail(self, name):
        if self._detail_dialog:
            self._detail_dialog.destroy()
        dlg = Gtk.Dialog(title=friendly_name(name), transient_for=self,
                         modal=True)
        dlg.add_button("Close", Gtk.ResponseType.CLOSE)
        dlg.set_default_size(780, 600)
        content = dlg.get_content_area()
        content.set_margin_top(14); content.set_margin_bottom(14)
        content.set_margin_start(14); content.set_margin_end(14)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_wrap(True)
        head.set_markup(
            f"<span size='20000' font_family='Barlow Condensed' "
            f"weight='600'>{escape(friendly_name(name))}</span>\n"
            f"<span size='13000' font_family='Inter'>"
            f"{escape(what_is(name))}</span>")
        content.append(head)
        self._detail_store = Gtk.ListStore(str)
        view = Gtk.TreeView(model=self._detail_store, headers_visible=False)
        view.set_size_request(-1, 260)
        # markup: the severity dot is a coloured span; every other part of
        # the line is escaped at build time.
        col = Gtk.TreeViewColumn(None, Gtk.CellRendererText(), markup=0)
        col.set_expand(True)
        view.append_column(col)
        # The feed is read-only: leaving row 0 selected painted it brass
        # (looked like a chosen action) the moment the dialog opened.
        sel = view.get_selection()
        if sel is not None:
            sel.set_mode(Gtk.SelectionMode.NONE)
        self._detail_view = view
        wrap = self._wrap(view)
        wrap.set_hexpand(True)
        content.append(wrap)

        wizard_key = WIZARD_FOR.get(name)
        if wizard_key:
            cfg = Gtk.Label(xalign=0)
            cfg.set_xalign(0)
            cfg.set_markup("<span size='16000' font_family='Barlow Condensed' "
                           "weight='600'>Configure</span>")
            content.append(cfg)
            guide = Gtk.Button(label="Open the guided setup. No typing")
            guide.add_css_class("gw-cta")
            guide.connect("clicked",
                          lambda *_a, k=wizard_key: self._open_wizard_for(k))
            content.append(guide)
        dlg.connect("response", lambda d, _r: d.destroy())
        self._detail_dialog = dlg
        self._fill_detail(name)
        dlg.present()

    def _fill_detail(self, name):
        self._detail_store.clear()
        try:
            events = daemon_mod.read_events(DATA_DIR / "events.jsonl", 8000)
        except OSError:
            events = []
        mine = [e for e in events if e.get("from_tool") == name
                and not str(e.get("text", "")).startswith("check-in:")]
        mine.sort(key=lambda e: str(e.get("ts", "")), reverse=True)
        grouped = []
        for e in mine:
            key = e.get("text", "")
            if grouped and grouped[-1]["key"] == key:
                grouped[-1]["count"] += 1
            else:
                grouped.append({"key": key, "count": 1, "ev": e})
        if not grouped:
            self._detail_store.append(
                ["Nothing recorded yet. An event is written only "
                 "when something happens."])
        for g in grouped[:300]:
            e = g["ev"]
            # Severity travels as a coloured dot in the same sentence
            # markup the view already renders (emoji removed 2026-10-27).
            mark = (f"<span foreground='"
                    f"{pc_severity_colour(e.get('severity', ''))}'>●</span>")
            ts = local_clock(e.get("ts", ""))
            suffix = f"  ×{g['count']}" if g["count"] > 1 else ""
            self._detail_store.append(
                [f"{mark} {escape(ts)} {escape(plain_sentence(e))}"
                 f"{escape(suffix)}   "
                 f"[{escape(e.get('text', '')[:160])}]"])

    def _logs_view(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(26); box.set_margin_start(30); box.set_margin_end(30)
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
        self.logs_status = Gtk.Label(xalign=0)
        self.logs_status.set_xalign(0)
        self.logs_status.set_text(
            "Identical consecutive lines are grouped; newest first.")
        self.logs_status.set_hexpand(True)
        row.append(self.logs_status)
        box.append(row)

        # 0 tool icon name, 1 severity word, 2 severity ink, 3 time/tool,
        # 4 event. The severity used to be an emoji (🔴/🟡/🟢); it is now the
        # tool's own drawn symbol plus a word in the theme's status ink, so
        # the raw log matches the rest of the dashboard.
        self.logs_store = Gtk.ListStore(str, str, str, str, str)
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
            self.logs_store.append(
                [tool_icon(e.get("from_tool", "")), pc_severity_word(sev),
                 pc_severity_colour(sev),
                 f"{local_clock(e.get('ts', ''))} "
                 f"{friendly_name(e.get('from_tool', ''))}",
                 e.get("text", "")[:400] + suffix])

    def _help_view(self):
        """Help as an index and a pane, matching Settings.

        The old page was one long column: a six-row key, seventeen
        protection cards in two columns, then ten questions and a command
        table — it ran on and lost its shape at the end. Each part is now
        its own section, one at a time, with nothing to scroll.
        """
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        page.set_vexpand(True)

        head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        head.set_margin_top(22); head.set_margin_start(34)
        head.set_margin_end(34); head.set_margin_bottom(14)
        head.append(self._h1("Help"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        intro.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "Every protection on this computer, in one place. Plain words "
            "here; raw detail is one click away.</span>")
        head.append(intro)
        page.append(head)

        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        body.set_vexpand(True)
        index = Gtk.ListBox()
        index.add_css_class("gw-index")
        index.set_selection_mode(Gtk.SelectionMode.SINGLE)
        index.set_size_request(190, -1)
        index.set_valign(Gtk.Align.START)
        index.set_margin_start(20); index.set_margin_end(12)
        index.set_margin_bottom(20)
        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.NONE)
        stack.set_hexpand(True); stack.set_vexpand(True)
        stack.set_margin_start(12); stack.set_margin_end(30)
        stack.set_margin_bottom(18)

        self._help_stack = stack
        self._help_index = index
        for key, icon, label, builder in (
                ("start", "help-contents-symbolic", "Using it",
                 self._help_start),
                ("tools", "applications-system-symbolic", "Protections",
                 self._help_tools),
                ("questions", "dialog-question-symbolic", "Questions",
                 self._help_questions),
                ("terminal", "utilities-terminal-symbolic", "Terminal",
                 self._help_terminal),
                ("about", "help-about-symbolic", "About",
                 self._help_about)):
            row = Gtk.ListBoxRow()
            row._key = key
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=9)
            ic = Gtk.Image.new_from_icon_name(icon)
            ic.set_pixel_size(15)
            line.append(ic)
            name = Gtk.Label(label=label, xalign=0)
            name.set_xalign(0)
            name.add_css_class("gw-index-label")
            line.append(name)
            row.set_child(line)
            index.append(row)
            stack.add_named(builder(), key)

        def _picked(_lb, row):
            if row is not None:
                stack.set_visible_child_name(row._key)

        index.connect("row-selected", _picked)
        index.select_row(index.get_row_at_index(0))
        body.append(index)
        body.append(stack)
        page.append(body)
        return page

    def _help_start(self):
        """Where each page is and what it is for, in one glance."""
        guide = Gtk.Grid()
        guide.set_column_spacing(22)
        guide.set_row_spacing(8)
        for row, (name, what) in enumerate((
                ("Wizard", "Guided setup, one task at a time."),
                ("Security", "State of every protection at a glance."),
                ("Tools", "Every protection, its scans and progress."),
                ("Settings", "Theme, app firewall, trusted items, updates."),
                ("Logs", "The raw record, newest first."),
                ("Help", "What each protection does, in plain words."))):
            left = Gtk.Label(xalign=0)
            left.set_xalign(0)
            left.set_markup(f"<span size='13500' font_family='Inter' "
                            f"weight='600'>{escape(name)}</span>")
            right = Gtk.Label(xalign=0)
            right.set_xalign(0)
            right.set_wrap(True)
            # A minimum width, so the wrapped minimum HEIGHT is measured at
            # a readable width and not one word per line (see the Questions
            # pane: without it the page's minimum height doubles).
            right.set_width_chars(24)
            right.set_markup(f"<span size='13000' font_family='Inter' "
                             f"color='{pc_muted()}'>{escape(what)}</span>")
            guide.attach(left, 0, row, 1, 1)
            guide.attach(right, 1, row, 1, 1)
        card, inner = self._settings_card(
            "How to use it",
            "Six pages, one job each. Nothing here needs a command.")
        inner.append(guide)
        return self._settings_section(card)

    def _help_tools(self):
        """One line per protection: what it is, in a sentence.

        Two columns, one line of copy each, is the only shape in which all
        seventeen entries fit the 720px floor with every sentence intact —
        two-line rows need 65px each, which is 828px of window. The copy in
        ui/plain.py is written to that line (see the note there). On a wide
        pane the grid becomes three columns, where there is room to spare.
        """
        from ui.plain import FRIENDLY
        card, inner = self._settings_card("What each protection does")
        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(2)
        grid.set_column_homogeneous(True)
        cells = []
        for name, (fname, what) in FRIENDLY.items():
            if name not in self.by_name:
                continue
            cell = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            cell.add_css_class("gw-help-row")
            ic = Gtk.Image.new_from_icon_name(tool_icon(name))
            ic.set_pixel_size(14)
            ic.set_valign(Gtk.Align.CENTER)
            cell.append(ic)
            words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            words.set_hexpand(True)
            title = Gtk.Label(xalign=0)
            title.set_xalign(0)
            title.set_ellipsize(Pango.EllipsizeMode.END)
            title.set_markup(f"<span size='12500' font_family='Inter' "
                             f"weight='600'>{escape(fname)}</span>")
            words.append(title)
            body = Gtk.Label(xalign=0)
            body.set_xalign(0)
            # One line per tool, and the copy in ui/plain.py is written to
            # fit it — seventeen entries at two lines each need 65px a row,
            # which is 828px of window, past the 720px floor. width-chars
            # raises the label's MINIMUM width so the pane's minimum height
            # is measured at a readable width, not at a single word.
            body.set_wrap(True)
            body.set_lines(1)
            body.set_width_chars(16)
            body.set_max_width_chars(46)
            body.set_ellipsize(Pango.EllipsizeMode.END)
            body.set_markup(f"<span size='11000' font_family='Inter' "
                            f"color='{pc_muted()}'>{escape(what)}</span>")
            words.append(body)
            cell.append(words)
            cell.set_tooltip_text(f"{fname} ({name}) — {what}")
            cells.append(cell)

        # Two columns is the shape the page is measured in, so its minimum
        # height is right from the first layout. The grid widens to three
        # only on a wide pane, keyed on the grid's own width: that width is
        # the size the parent gives it, which does not change with the
        # column count (the columns are homogeneous and hexpanding), so the
        # decision cannot feed back into itself.
        cols = {"n": 2}
        for i, cell in enumerate(cells):
            grid.attach(cell, i % 2, i // 2, 1, 1)

        def _flow(_widget, _clock):
            width = grid.get_width()
            if width <= 0:
                return True
            want = 3 if width >= 1000 else 2
            if want == cols["n"]:
                return True
            cols["n"] = want
            for cell in cells:
                if cell.get_parent() is grid:
                    grid.remove(cell)
            for i, cell in enumerate(cells):
                grid.attach(cell, i % want, i // want, 1, 1)
            return True

        grid.add_tick_callback(_flow)
        inner.append(grid)
        return self._settings_section(card)

    def _help_questions(self):
        """The ten questions owners ask most, two columns of five."""
        faq_lines = [
            ("What does greywatch do?",
             "One dashboard for every protection already on this computer."),
            ("How do I run a scan?",
             "Tools: press a scan button; the circle shows progress."),
            ("How do I pause a protection?",
             "Security: press Pause on its row; Resume brings it back."),
            ("What does At risk mean?",
             "A protection that should be running is not. Not a detection."),
            ("A detection appeared — what now?",
             "Read the Recent line or Logs. Quarantine what you didn't cause."),
            ("How do I isolate my machine?",
             "No one-click panic. Keep the firewall on; unplug to disconnect."),
            ("How do I change the theme?",
             "Settings — Appearance — Dark or Light."),
            ("Why is my antivirus quiet?",
             "Its full scan runs daily. Quiet means nothing bad was found."),
            ("Is my disk encrypted — how do I check?",
             "Not checked today. Run lsblk in a terminal; LUKS shows crypto."),
            ("How do I undo a wizard change?",
             "Wizard — Security baseline hardening — Undo last change."),
        ]
        card, inner = self._settings_card(
            "Questions",
            "The ten things owners ask most, each answered in one sentence.")
        grid = Gtk.Grid()
        grid.set_column_spacing(24)
        grid.set_row_spacing(10)
        grid.set_column_homogeneous(True)
        for i, (q, a) in enumerate(faq_lines):
            row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            qlabel = Gtk.Label(xalign=0)
            qlabel.set_xalign(0)
            qlabel.set_wrap(True)
            # max-width-chars sets the label's MINIMUM width, so GTK measures
            # the wrapped minimum HEIGHT at a readable width. Without it the
            # minimum height is computed at one character per line and this
            # pane alone reported 1162px — enough to force the whole window
            # taller than its 720px minimum.
            qlabel.set_width_chars(30)
            qlabel.set_max_width_chars(34)
            qlabel.set_markup(f"<span size='12500' font_family='Inter' "
                              f"weight='600'>{escape(q)}</span>")
            alabel = Gtk.Label(xalign=0)
            alabel.set_xalign(0)
            alabel.set_wrap(True)
            alabel.set_width_chars(30)
            alabel.set_max_width_chars(40)
            alabel.set_markup(f"<span size='12000' font_family='Inter' "
                              f"color='{pc_muted()}'>{escape(a)}</span>")
            row.append(qlabel)
            row.append(alabel)
            grid.attach(row, i % 2, i // 2, 1, 1)
        inner.append(grid)
        return self._settings_section(card)

    def _help_terminal(self):
        card, inner = self._settings_card(
            "From a terminal",
            "Optional. Everything the window shows can be read from a shell.")
        cmds = (("greywatch status", "Every protection and its state."),
                ("greywatch events", "The newest log lines."),
                ("greywatch tail", "Follow the log as it grows."),
                ("greywatch decisions", "What the app firewall decided."),
                ("greywatch rules", "The rules currently enforced."))
        cmd_grid = Gtk.Grid()
        cmd_grid.set_column_spacing(20)
        cmd_grid.set_row_spacing(7)
        for r, (cmd, what) in enumerate(cmds):
            cl = Gtk.Label(xalign=0)
            cl.set_xalign(0)
            cl.set_markup(f"<span size='12500' font_family='monospace'>"
                          f"{escape(cmd)}</span>")
            wl = Gtk.Label(xalign=0)
            wl.set_xalign(0)
            wl.set_wrap(True)
            wl.set_markup(f"<span size='12500' font_family='Inter' "
                          f"color='{pc_muted()}'>{escape(what)}</span>")
            cmd_grid.attach(cl, 0, r, 1, 1)
            cmd_grid.attach(wl, 1, r, 1, 1)
        inner.append(cmd_grid)
        where = Gtk.Label(xalign=0)
        where.set_xalign(0)
        where.set_wrap(True)
        where.set_markup(
            f"<span size='11500' font_family='Inter' color='{pc_soft()}'>"
            "The root watch daemon is greywatch.service. Events live in "
            "data/events.jsonl, status in data/status.json. Every privileged "
            "change runs through a helper with a backup and rollback."
            "</span>")
        inner.append(where)
        return self._settings_section(card)

    def _help_about(self):
        """The suite itself: what it is, which version, where to reach it.

        The About the owner asked for lives here, next to the protections
        it explains, not in a separate dialog (owner 2026-10-30: "update
        the about and all the links, including randybarham.com").
        """
        card, inner = self._settings_card(
            "About greywatch",
            "AI-enabled endpoint security for the Linux desktop.")
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        mark = Gtk.Image()
        mark.set_pixel_size(48)          # a pixbuf on its own paints at 16px
        wolf = (pathlib.Path(__file__).resolve().parents[1] / "assets"
                / "logo" / "greywatch-icon-128.png")
        if wolf.exists():
            mark.set_from_file(str(wolf))
        row.append(mark)
        words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        name = Gtk.Label(xalign=0)
        name.set_xalign(0)
        name.set_markup(f"<span size='13500' font_family='Inter' "
                        f"weight='700'>greywatch {escape(self._version())}"
                        "</span>")
        words.append(name)
        why = Gtk.Label(xalign=0)
        why.set_xalign(0)
        why.set_wrap(True)
        why.set_width_chars(24)          # measure minimum height at a width
        why.set_markup(
            f"<span size='12500' font_family='Inter' "
            f"color='{pc_muted()}'>Protections watch this machine, the "
            "event trail stays on this machine, and the assistant's "
            "answers are composed from your own logs by a model that "
            "runs on your own CPU.</span>")
        words.append(why)
        row.append(words)
        inner.append(row)
        for uri, label in (
                ("https://github.com/greyok00/greywatch",
                 "Source and releases — github.com/greyok00/greywatch"),
                ("https://www.randybarham.com",
                 "The author's site — randybarham.com")):
            link = Gtk.LinkButton(uri=uri)
            link.set_label(label)
            link.add_css_class("gw-quiet")
            link.set_halign(Gtk.Align.START)
            inner.append(link)
        return self._settings_section(card)

    def _version(self) -> str:
        try:
            import tomllib
            with open(pathlib.Path(__file__).resolve().parents[1]
                      / "pyproject.toml", "rb") as fh:
                return str(tomllib.load(fh)["project"]["version"])
        except Exception:
            return ""

    def _cfg6(self) -> bool:
        from appfw import config as acfg
        return bool(acfg.load(DATA_DIR).get("ipv6_enabled"))

    def _on_v6_toggle(self, check):
        from appfw import config as acfg
        try:
            cfg = acfg.load(DATA_DIR)
            cfg["ipv6_enabled"] = bool(check.get_active())
            acfg.save(DATA_DIR, cfg)
        except Exception:
            pass

    def _ws_pref(self) -> int:
        from ui.settings import ws_pref
        return ws_pref(DATA_DIR)

    def _on_ws_pick(self, combo):
        from ui.settings import ws_set
        try:
            ws_set(DATA_DIR, int(combo.get_active_id() or 3))
        except (ValueError, TypeError):
            pass

    def _unit_facts(self) -> list:
        """(label, value, plain meaning) for the daemon's unit settings.

        Values are the real `systemctl show` properties — nothing invented —
        but each one is paired with a sentence a person can act on, because
        the page used to print `ProtectSystem=no` and leave the reader to
        work out what that meant.
        """
        # systemd 257 exposes `WatchdogTimestamp` (+ the monotonic variant);
        # `WatchdogLastPingUSec` / `WatchdogTimestampUSec` are not properties
        # here, and querying them made the page claim "no ping" while the
        # daemon was pinging every 30 s.
        props = ("Restart", "MemoryMax", "ProtectSystem", "WatchdogUSec",
                 "WatchdogTimestamp", "WatchdogTimestampMonotonic")
        raw = {}
        try:
            p = subprocess.run(
                ["systemctl", "show", "greywatch.service"]
                + [x for prop in props for x in ("-p", prop)],
                capture_output=True, text=True, timeout=5)
        except Exception:                 # noqa: BLE001 - the page must paint
            return [("Service settings", "could not check",
                     "systemctl is not answering, so nothing below is known.")]
        for line in p.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                raw[key.strip()] = value.strip()
        rows = []
        mem = raw.get("MemoryMax", "")
        if mem.isdigit() and int(mem) > 0:
            rows.append(("Memory cap", f"{int(mem) // (1024 * 1024)} MB",
                         "The service is restarted if it grows past this."))
        else:
            rows.append(("Memory cap", "no limit",
                         "Nothing stops a runaway service from taking all "
                         "of the memory."))
        rows.append(("Crash restart", raw.get("Restart") or "—",
                     "What the service manager does when the program exits."))
        prot = (raw.get("ProtectSystem") or "").lower()
        locked = prot in ("yes", "strict", "full")
        rows.append((
            "System files", "locked" if locked else "not locked",
            "Not locked: even root under the service can write to /usr, "
            "/boot and /etc. This service must write /etc, so it is left "
            "open." if not locked
            else "Even root under the service cannot write to /usr, /boot "
                 "or /etc."))
        pinging = (raw.get("WatchdogTimestamp", "") not in
                   ("", "0", "n/a")
                   or raw.get("WatchdogTimestampMonotonic", "") not in
                   ("", "0"))
        period = raw.get("WatchdogUSec", "") or ""
        every = (f"every {period.rstrip('s').replace('.000000', '')} "
                 f"seconds") if period and period != "0" else ""
        rows.append((
            "Watchdog", "pinging" if pinging else "no ping yet",
            (f"The service manager expects a ping {every}; silence restarts "
             "the service." if every else
             "No watchdog is set, so systemd does not expect pings.")))
        return rows

    def _diag_truth(self) -> str:
        lines = []
        try:
            p = subprocess.run(
                ["systemctl", "show", "greywatch.service", "-p", "MainPID",
                 "-p", "ExecMainStartTimestamp", "-p", "ActiveState"],
                capture_output=True, text=True, timeout=5)
            lines += [l for l in p.stdout.splitlines() if l.strip()]
        except Exception:
            lines.append("daemon service: systemctl unavailable")
        snap = pathlib.Path(DATA_DIR) / "status.json"
        try:
            age = time.time() - snap.stat().st_mtime
            verdict = "fresh" if age < 90 else \
                "STALE: the daemon pipeline may be wedged (restart it)"
            lines.append(f"status snapshot age: {age:.0f} s · {verdict}")
        except OSError:
            lines.append("status snapshot: missing (daemon has not written yet)")
        try:
            tail = (pathlib.Path(DATA_DIR) / "appfw" / "events.jsonl") \
                .read_text(errors="ignore").strip().splitlines()
            lines.append("appfw last event: " + (tail[-1][-110:] if tail
                                                 else "empty"))
        except OSError:
            lines.append("appfw events: none yet")
        try:
            p = subprocess.run(["nft", "list", "tables"],
                               capture_output=True, text=True, timeout=5)
            present = "greywatch_appfw" in p.stdout
            lines.append("firewall nft table: "
                         + ("present (armed)" if present else "absent (off)"))
        except Exception:
            lines.append("firewall nft table: could not check")
        try:
            p = subprocess.run(
                ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} "
                 "%{time_total}s", "--max-time", "6", "https://example.com"],
                capture_output=True, text=True, timeout=8)
            lines.append("network check: " + (p.stdout.strip() or "failed"))
        except Exception:
            lines.append("network check: timed out")
        return "\n".join(lines)

    def _on_diag_refresh(self, btn):
        btn.set_sensitive(False)
        def run():
            text = self._diag_truth()
            def done():
                self._diag_label.set_text(text)
                btn.set_sensitive(True)
                return False
            GLib.idle_add(done)
        threading.Thread(target=run, daemon=True).start()

    def _settings_card(self, title, about=""):
        """One settings group: a heading, one sentence saying what it is
        for, and a card holding the controls.

        The page used to be a flat column of ten headings with the raw unit
        file pasted in, so "Workspace" or "ProtectSystem" had no explanation
        anywhere (owner: redo the rest of the UI, 2026-10-27).
        """
        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        # The card itself already carries 18px of padding; matching margins
        # here stacked to 34px and made every group read as airy to the
        # point of wasted space.
        inner.set_margin_top(2); inner.set_margin_bottom(2)
        inner.set_margin_start(2); inner.set_margin_end(2)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_wrap(True)
        markup = (f"<span size='16000' font_family='Inter' weight='600'>"
                  f"{escape(title)}</span>")
        if about:
            markup += ("\n<span size='12000' font_family='Inter' "
                       f"color='{pc_muted()}'>{escape(about)}</span>")
        head.set_markup(markup)
        inner.append(head)
        frame.set_child(inner)
        return frame, inner

    def _settings_row(self, label, control, hint=""):
        """One macOS settings row: title (and, when there is one, the
        sentence that explains it) on the left, the control at the trailing
        edge. The old row pinned the title to a 190px column and floated
        the control right after it, so on a wide window every switch sat
        in the middle of the card with 900px of dead space beside it.
        """
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        row.add_css_class("gw-srow")
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        left.set_hexpand(True)
        name = Gtk.Label(xalign=0)
        name.set_xalign(0)
        name.set_markup(f"<span size='14000' font_family='Inter'>"
                        f"{escape(label)}</span>")
        left.append(name)
        if hint:
            tip = Gtk.Label(xalign=0)
            tip.set_xalign(0)
            tip.set_wrap(True)
            tip.set_markup(f"<span size='12000' font_family='Inter' "
                           f"color='{pc_muted()}'>{escape(hint)}</span>")
            left.append(tip)
        row.append(left)
        control.set_valign(Gtk.Align.CENTER)
        row.append(control)
        return row

    def _settings_view(self):
        """Settings as an index and a pane, the way macOS settings work.

        Seven groups stacked in one scrolling column meant two were visible
        and the other five lived below the fold. The index names every
        group; the pane shows one at a time, each sized to fit the 720px
        minimum window. There is no page scroller, so nothing can hide.
        """
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        page.set_vexpand(True)

        head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        head.set_margin_top(22); head.set_margin_start(34)
        head.set_margin_end(34); head.set_margin_bottom(14)
        head.append(self._h1("Settings"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        intro.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "How the dashboard behaves, what the app firewall does, and "
            "what this computer is really running.</span>")
        head.append(intro)
        page.append(head)

        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        body.set_vexpand(True)

        index = Gtk.ListBox()
        index.add_css_class("gw-index")
        index.set_selection_mode(Gtk.SelectionMode.SINGLE)
        index.set_size_request(190, -1)
        index.set_valign(Gtk.Align.START)
        index.set_margin_start(20); index.set_margin_end(12)
        index.set_margin_bottom(20)

        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.NONE)
        stack.set_hexpand(True); stack.set_vexpand(True)
        stack.set_margin_start(12); stack.set_margin_end(30)
        stack.set_margin_bottom(18)

        self._settings_stack = stack
        self._settings_index = index
        self.trust = self._trust
        sections = (
            ("look", "preferences-desktop-symbolic", "Appearance",
             self._settings_look),
            ("firewall", "security-high-symbolic", "App firewall",
             self._settings_firewall),
            ("connections", "network-wireless-symbolic", "Connections",
             self._settings_connections),
            ("computer", "computer-symbolic", "This computer",
             self._settings_computer),
            ("diagnostics", "utilities-system-monitor-symbolic", "Diagnostics",
             self._settings_diagnostics),
            ("updates", "software-update-available-symbolic", "Updates",
             self._settings_updates),
            ("sites", "web-browser-symbolic", "Trusted sites",
             self._settings_sites),
            ("programs", "applications-system-symbolic", "Trusted programs",
             self._settings_programs),
        )
        for key, icon, label, builder in sections:
            row = Gtk.ListBoxRow()
            row._key = key
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=9)
            ic = Gtk.Image.new_from_icon_name(icon)
            ic.set_pixel_size(15)
            line.append(ic)
            name = Gtk.Label(label=label, xalign=0)
            name.set_xalign(0)
            name.add_css_class("gw-index-label")
            line.append(name)
            row.set_child(line)
            index.append(row)
            stack.add_named(builder(), key)

        def _picked(_lb, row):
            if row is not None:
                stack.set_visible_child_name(row._key)

        index.connect("row-selected", _picked)
        index.select_row(index.get_row_at_index(0))
        body.append(index)
        body.append(stack)
        page.append(body)
        self._refresh_trust()
        self._refresh_apps()
        return page

    @staticmethod
    def _settings_section(*cards):
        """A top-aligned pane: cards keep their natural height instead of
        stretching to fill a tall window."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_valign(Gtk.Align.START)
        for card in cards:
            box.append(card)
        return box

    def _settings_look(self):
        app_frame, app_inner = self._settings_card(
            "Appearance and placement",
            "Changes are remembered on this computer.")
        theme_combo = Gtk.ComboBoxText()
        for label, kit in THEME_CHOICES.items():
            theme_combo.append(kit, label)
        picked = load_setting() or dark_default(self._theme_store.names())
        shown = picked if picked in THEME_CHOICES.values() \
            else dark_default(self._theme_store.names())
        theme_combo.set_active_id(shown)
        theme_combo.connect("changed", self._on_theme_pick)
        self.theme_combo = theme_combo
        app_inner.append(self._settings_row(
            "Theme", theme_combo, "Colours and type for every screen."))
        ws_combo = Gtk.ComboBoxText()
        for i in range(1, 7):
            ws_combo.append(str(i), f"Workspace {i}")
        ws_combo.set_active_id(str(self._ws_pref()))
        ws_combo.connect("changed", self._on_ws_pick)
        app_inner.append(self._settings_row(
            "Workspace", ws_combo,
            "The virtual desktop the dashboard opens on."))
        return self._settings_section(app_frame)

    def _settings_firewall(self):
        fw_frame, fw_inner = self._settings_card(
            "App firewall",
            "Decides whether a program may use the internet. It asks once, "
            "then enforces your answer.")
        fw_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.fw_note = Gtk.Label(xalign=0)
        self.fw_note.set_xalign(0)
        self.fw_note.set_wrap(True)
        self.fw_btn = Gtk.Button(label="Turn on")
        self.fw_btn.add_css_class("gw-cta")
        self.fw_btn.connect("clicked", self._on_fw_toggle)
        self.fw_note.set_hexpand(True)
        fw_row.append(self.fw_note)
        fw_row.append(self.fw_btn)
        fw_inner.append(fw_row)
        self.fw_status = Gtk.Label(xalign=0)
        self.fw_status.set_xalign(0)
        self.fw_status.set_wrap(True)
        fw_inner.append(self.fw_status)

        # macOS switches, not tick boxes. Gtk.Switch has no "toggled"
        # signal, so the handlers hang off notify::active.
        self.learn_title = Gtk.Label(xalign=0)
        self.learn_title.set_xalign(0)
        self.learn_title.set_markup("<span size='14000' font_family='Inter'>"
                                    "Learning mode</span>")
        self.learn_check = Gtk.Switch()
        self.learn_check.set_valign(Gtk.Align.CENTER)
        self.learn_check.connect(
            "notify::active", lambda w, _p: self._on_learning_toggle(w))
        learn_for = Gtk.ComboBoxText()
        for ident, label in (("15", "15 minutes"), ("60", "1 hour"),
                             ("480", "8 hours"), ("0", "until I stop it")):
            learn_for.append(ident, label)
        learn_for.set_active_id("60")
        self.learn_for = learn_for
        learn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        learn_row.add_css_class("gw-srow")
        learn_left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        learn_left.set_hexpand(True)
        learn_left.append(self.learn_title)
        self.learn_note = Gtk.Label(xalign=0)
        self.learn_note.set_xalign(0)
        self.learn_note.set_wrap(True)
        learn_left.append(self.learn_note)
        learn_row.append(learn_left)
        learn_controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                                 spacing=8)
        learn_controls.set_valign(Gtk.Align.CENTER)
        learn_controls.append(self.learn_check)
        learn_controls.append(learn_for)
        learn_row.append(learn_controls)
        fw_inner.append(learn_row)

        self.fw_block_title = Gtk.Label(xalign=0)
        self.fw_block_title.set_xalign(0)
        self.fw_block_title.set_markup("<span size='14000' "
                                       "font_family='Inter'>Block unknown "
                                       "apps</span>")
        self.fw_block = Gtk.Switch()
        self.fw_block.set_valign(Gtk.Align.CENTER)
        self.fw_block.connect(
            "notify::active", lambda w, _p: self._on_fw_block_toggle(w))
        block_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        block_row.add_css_class("gw-srow")
        block_left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        block_left.set_hexpand(True)
        block_left.append(self.fw_block_title)
        block_row.append(block_left)
        block_row.append(self.fw_block)
        fw_inner.append(block_row)

        v6_check = Gtk.Switch()
        v6_check.set_valign(Gtk.Align.CENTER)
        v6_check.set_active(bool(self._cfg6()))
        v6_check.connect(
            "notify::active", lambda w, _p: self._on_v6_toggle(w))
        self._v6_check = v6_check
        fw_inner.append(self._settings_row(
            "Filter IPv6", v6_check,
            "Off by default: IPv6 traffic is not filtered unless you turn "
            "this on. Takes about ten seconds to apply."))
        return self._settings_section(fw_frame)

    def _settings_connections(self):
        card, inner = self._settings_card(
            "Connections seen while learning",
            "Nothing is blocked unless you press a button. Trusting one here "
            "is the same answer the popup would have offered.")
        self.learn_store = Gtk.ListStore(str, str, str, str)   # path, app, site, last
        self.learn_view = Gtk.TreeView(model=self.learn_store,
                                       headers_visible=False)
        for i, width in ((0, 250), (1, 0), (2, 110)):
            cell = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(None, cell, text=i + 1)  # 0 = full path
            if width:
                col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
                col.set_fixed_width(width)
            else:
                col.set_expand(True)
            self.learn_view.append_column(col)
        self.learn_view.connect("cursor-changed", self._learn_selected)
        self.learn_view.set_size_request(-1, 210)
        learn_head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        learn_head.add_css_class("gw-th-row")
        learn_head.set_margin_start(10)
        learn_head.set_margin_end(10)
        for title, width in (("Program", 250), ("Site", 0), ("Last seen", 110)):
            lbl = Gtk.Label(label=title, xalign=0)
            lbl.set_xalign(0)
            lbl.add_css_class("gw-th")
            if width:
                lbl.set_size_request(width, -1)
            else:
                lbl.set_hexpand(True)
            learn_head.append(lbl)
        learn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        learn_box.append(learn_head)
        learn_scroll = self._wrap(self.learn_view)
        learn_scroll.set_size_request(-1, 210)
        learn_box.append(learn_scroll)
        # An empty table is a header over nothing; swap the whole table for
        # one muted sentence instead of faking a row.
        self.learn_empty = Gtk.Label(xalign=0)
        self.learn_empty.set_xalign(0)
        self.learn_empty.set_wrap(True)
        self.learn_empty.set_text("Nothing learned yet. Turn learning on "
                                  "under App firewall.")
        self.learn_empty.add_css_class("gw-page-meta")
        self.learn_empty.set_margin_top(6)
        self.learn_empty.set_margin_bottom(6)
        self.learn_box = learn_box
        inner.append(self.learn_empty)
        inner.append(learn_box)
        learn_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        # macOS dims an action that has nothing to act on.
        self._learn_row_btns = []
        for label, handler in (
                ("Trust this program", self._on_learn_trust),
                ("Trust this site", self._on_learn_site),
                ("Block this site", self._on_learn_block)):
            b = Gtk.Button(label=label)
            b.connect("clicked", handler)
            b.set_sensitive(False)
            self._learn_row_btns.append(b)
            learn_btns.append(b)
        self.learn_clear_btn = Gtk.Button(label="Clear")
        self.learn_clear_btn.connect("clicked", self._on_learn_clear)
        self.learn_clear_btn.set_sensitive(False)
        learn_btns.append(self.learn_clear_btn)
        inner.append(learn_btns)
        return self._settings_section(card)

    def _settings_computer(self):
        unit_frame, unit_inner = self._settings_card(
            "This computer",
            "What the service manager is actually enforcing on the daemon.")
        for label, value, meaning in self._unit_facts():
            val = Gtk.Label(xalign=0)
            val.set_xalign(0)
            val.set_markup(f"<span size='13000' font_family='JetBrains Mono'>"
                           f"{escape(value)}</span>")
            unit_inner.append(self._settings_row(label, val, meaning))
        return self._settings_section(unit_frame)

    def _settings_diagnostics(self):
        diag_frame, diag_inner = self._settings_card(
            "Diagnostics",
            "A live glance at the running service. A stale snapshot means "
            "stop and restart the app.")
        self._diag_label = Gtk.Label(xalign=0)
        self._diag_label.set_xalign(0)
        self._diag_label.set_wrap(True)
        self._diag_label.add_css_class("gw-meta")
        self._diag_label.set_text("Checking…")
        diag_inner.append(self._diag_label)
        d_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        d_btn = Gtk.Button(label="Re-check")
        d_btn.connect("clicked", self._on_diag_refresh)
        self._on_diag_refresh(d_btn)      # first truth arrives off-thread
        d_row.append(d_btn)
        d_note = Gtk.Label(label="")
        d_note.set_tooltip_text(
            "A stale snapshot means stop and restart the app.")
        d_row.append(d_note)
        diag_inner.append(d_row)
        return self._settings_section(diag_frame)

    def _settings_updates(self):
        up_frame, up_inner = self._settings_card(
            "Updates",
            "The two lists the dashboard reads: antivirus definitions and "
            "the weekly list of known security flaws.")
        self.updates_note = Gtk.Label(xalign=0)
        self.updates_note.set_xalign(0)
        self.updates_note.set_wrap(True)
        up_inner.append(self.updates_note)
        up_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.update_btn = Gtk.Button(label="Update lists")
        self.update_btn.connect("clicked", self._on_update_now)
        self.update_note = Gtk.Label(xalign=0)
        self.update_note.set_xalign(0)
        self.update_note.set_wrap(True)
        self.update_note.set_hexpand(True)
        up_row.append(self.update_btn)
        up_row.append(self.update_note)
        up_inner.append(up_row)
        return self._settings_section(up_frame)

    def _settings_sites(self):
        trust_frame, trust_inner = self._settings_card(
            "Trusted websites",
            "Allowed without asking, or blocked without asking. Subdomains "
            "are included.")
        entry_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.trust_combo = Gtk.ComboBoxText.new_with_entry()
        for choice in discover.site_choices():
            self.trust_combo.append(
                choice["host"], f"{choice['host']} · {choice['why']}")
        self.trust_entry = self.trust_combo.get_child()
        self.trust_entry.set_placeholder_text("Site name")
        self.trust_entry.connect("activate", self._on_trust_add, "allow")
        self.trust_combo.set_hexpand(True)
        entry_row.append(self.trust_combo)
        for label, verdict in (("Trust always", "allow"),
                               ("Block always", "block")):
            b = Gtk.Button(label=label)
            b.add_css_class("gw-cta")
            b.connect("clicked", self._on_trust_add, verdict)
            entry_row.append(b)
        trust_inner.append(entry_row)
        self.trust_note = Gtk.Label(xalign=0)
        self.trust_note.set_xalign(0)
        self.trust_note.set_wrap(True)
        trust_inner.append(self.trust_note)
        self.trust_store = Gtk.ListStore(str, str)
        self.trust_view = Gtk.TreeView(model=self.trust_store)
        for i, title in enumerate(("policy", "site")):
            cell = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, cell, text=i)
            if i == 1:
                col.set_expand(True)
            self.trust_view.append_column(col)
        self.trust_view.connect("cursor-changed", self._trust_selected)
        # A floor, not a fixed height: at the 720px minimum the 260px table
        # ran past the card's bottom edge and the last row was sliced. The
        # table now takes the room the card has and scrolls inside itself.
        self.trust_view.set_size_request(-1, 120)
        trust_scroll = self._wrap(self.trust_view)
        trust_scroll.set_size_request(-1, 120)
        trust_scroll.set_vexpand(True)
        # A reserved scrollbar, not a floating overlay: when the list is
        # longer than the card the owner should see at a glance that there
        # is more to read.
        trust_scroll.set_overlay_scrolling(False)
        trust_inner.append(trust_scroll)
        del_b = Gtk.Button(label="Remove site")
        del_b.set_halign(Gtk.Align.START)
        del_b.connect("clicked", self._on_trust_remove)
        trust_inner.append(del_b)
        section = self._settings_section(trust_frame)
        section.set_valign(Gtk.Align.FILL)
        trust_frame.set_vexpand(True)
        trust_inner.set_vexpand(True)
        return section

    def _settings_programs(self):
        trust_frame, trust_inner = self._settings_card(
            "Trusted programs",
            "These connect without asking. Pick from the list, or browse for "
            "the program you mean.")
        app_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.app_combo = Gtk.ComboBoxText.new_with_entry()
        for prog in discover.programs():
            self.app_combo.append(prog["path"], prog["label"])
        self.app_entry = self.app_combo.get_child()
        self.app_entry.set_placeholder_text("Program")
        self.app_entry.connect("activate", self._on_app_add, None)
        self.app_combo.set_hexpand(True)
        app_row.append(self.app_combo)
        browse_b = Gtk.Button(label="Browse…")
        browse_b.connect("clicked", self._on_app_browse)
        app_row.append(browse_b)
        add_app = Gtk.Button(label="Trust program")
        add_app.add_css_class("gw-cta")
        add_app.connect("clicked", self._on_app_add, None)
        app_row.append(add_app)
        trust_inner.append(app_row)
        self.app_note = Gtk.Label(xalign=0)
        self.app_note.set_xalign(0)
        self.app_note.set_wrap(True)
        trust_inner.append(self.app_note)
        self.app_store = Gtk.ListStore(str)
        self.app_view = app_view = Gtk.TreeView(model=self.app_store)
        app_col = Gtk.TreeViewColumn("trusted program", Gtk.CellRendererText(),
                                     text=0)
        app_col.set_expand(True)
        app_view.append_column(app_col)
        app_view.connect("cursor-changed", self._app_selected)
        app_view.set_size_request(-1, 120)
        app_scroll = self._wrap(app_view)
        app_scroll.set_size_request(-1, 120)
        app_scroll.set_vexpand(True)
        app_scroll.set_overlay_scrolling(False)
        trust_inner.append(app_scroll)
        del_app = Gtk.Button(label="Remove program")
        del_app.set_halign(Gtk.Align.START)
        del_app.connect("clicked", self._on_app_remove)
        trust_inner.append(del_app)
        section = self._settings_section(trust_frame)
        section.set_valign(Gtk.Align.FILL)
        trust_frame.set_vexpand(True)
        trust_inner.set_vexpand(True)
        return section

    def _refresh_trust(self):
        store = getattr(self, "trust_store", None)
        if store is None:
            return      # Settings has not built its widgets yet; the page
                        # refills both lists from the trust list when it
                        # opens. The exec path runs before that build, and
                        # crashed here after the add had already landed
                        # (no audit line, owner 2026-10-30).
        self.trust_store.clear()
        empty = True
        # Sentence case: the policy column read as an API constant.
        for verdict, entries in (("Allowed", sorted(self.trust.allow)),
                                 ("Blocked", sorted(self.trust.block))):
            for e in entries:
                self.trust_store.append([verdict, e])
                empty = False
        if empty:
            self.trust_store.append(["", "Nothing trusted or blocked yet. "
                                         "Add a site above."])

    def _refresh_apps(self):
        store = getattr(self, "app_store", None)
        if store is None:
            return      # same pre-Settings guard as _refresh_trust
        self.app_store.clear()
        if not self.trust.apps_allow:
            self.app_store.append(["Nothing trusted yet. Programs you "
                                   "trust appear here."])
        for e in sorted(self.trust.apps_allow):
            self.app_store.append([e])

    def _trust_selected(self, view):
        path, _col = view.get_cursor()
        verdict = self.trust_store[path[0]][0] if path else ""
        self._trust_sel = (self.trust_store[path[0]][1]
                           if path and verdict in ("Allowed", "Blocked")
                           else None)

    def _on_trust_add(self, _btn, verdict):
        text = (self.trust_combo.get_active_id()
                or self.trust_entry.get_text()).strip()
        if not text:
            self.trust_note.set_text(
                "Pick a site from the list first.")
            return
        if not self.trust.add(text, verdict):
            self.trust_note.set_text(
                "That address was not accepted. Use a plain site name like "
                "example.com.")
            return
        self._refresh_trust()
        self.trust_combo.set_active(-1)
        self.trust_entry.set_text("")
        self.trust_note.set_text(
            f"Added: {text} is now "
            f"{'always allowed' if verdict == 'allow' else 'always blocked'}.")

    def _on_trust_remove(self, _btn):
        name = getattr(self, "_trust_sel", None)
        if name:
            self.trust.remove(name)
            self._refresh_trust()
            self._trust_sel = None
            self.trust_note.set_text(f"Removed {name}.")
        else:
            self.trust_note.set_text(
                "Select a site in the list first, then remove it.")

    def _app_selected(self, view):
        path, _col = view.get_cursor()
        name = self.app_store[path[0]][0] if path else None
        self._app_sel = name if name in self.trust.apps_allow else None

    def _fw_is_on(self) -> bool:
        try:
            snap = daemon_mod.load_status(str(DATA_DIR / "status.json"))
            return (snap.get("appfw_engine") or "") == "running"
        except (OSError, ValueError):
            return False

    def _on_fw_toggle(self, _btn):
        was_on = self._fw_is_on()
        self.fw_btn.set_sensitive(False)
        self.fw_btn.set_label("Stopping…" if was_on else "Starting…")
        self.fw_status.set_text(
            "Waiting for the admin password…" if not was_on else
            "Stopping the firewall…")
        try:
            (DATA_DIR / "appfw").mkdir(parents=True, exist_ok=True)
            (DATA_DIR / "appfw" / "enable.json").write_text(
                json.dumps({"enabled": not was_on}) + "\n")
            self._after_toggle("appfw", was_on, 0)
        except OSError as e:
            self.fw_btn.set_sensitive(True)
            self.fw_status.set_text(f"could not switch the engine: {e}")
        self._tick_id(self._refresh_fw, 2, seconds=True)

    def _on_learning_toggle(self, check):
        if getattr(self, "_learn_guard", False):
            return
        if check.get_active():
            pick = (self.learn_for.get_active_id()
                    if hasattr(self, "learn_for") else None) or "60"
            minutes = 60 * 24 * 365 if pick == "0" else int(pick)
            self._learn_store.start(minutes)
            if hasattr(self, "fw_block") and self.fw_block.get_active():
                self._fw_mode_guard = True
                self.fw_block.set_active(False)
                self._fw_mode_guard = False
                self._fw_mode_store.set_block_unknown(False)
        else:
            self._learn_store.stop()
        self._refresh_fw()

    def _on_fw_block_toggle(self, check):
        if getattr(self, "_fw_mode_guard", False):
            return
        self._fw_mode_store.set_block_unknown(check.get_active())
        if check.get_active() and self._learn_store.active():
            self._learn_store.stop()
            self._learn_guard = True
            self.learn_check.set_active(False)
            self._learn_guard = False
        self._refresh_fw()

    def _learn_cutoff(self) -> float:
        try:
            return float(json.loads(
                (DATA_DIR / "learning-clear.json").read_text()).get("since") or 0)
        except (OSError, ValueError, TypeError):
            return 0.0

    def _on_learn_clear(self, _btn):
        try:
            (DATA_DIR / "learning-clear.json").write_text(
                json.dumps({"since": time.time()}))
        except OSError:
            pass
        self._refresh_fw()

    def _learned(self) -> list:
        path = DATA_DIR / "learning-seen.jsonl"
        cutoff = self._learn_cutoff()
        seen = {}
        try:
            with path.open("rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 300_000))
                lines = f.read().decode("utf-8", "replace").splitlines()
        except OSError:
            return []
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            app = str(rec.get("app") or "")
            host = str(rec.get("host") or "")
            if not app and not host:
                continue
            ts = str(rec.get("ts") or "")
            try:
                when = _dt.datetime.fromisoformat(
                    ts.replace("Z", "+00:00")).timestamp()
            except (ValueError, TypeError):
                when = 0.0
            if when < cutoff:
                continue
            try:
                if (app and self.trust.decide_app(app) == "allow") or \
                        (host and self.trust.decide(host)):
                    continue
            except Exception:
                pass
            key = (app, host)
            cur = seen.get(key)
            if cur is None:
                seen[key] = {"app": app, "host": host, "ts": ts,
                             "time": when, "count": 1}
            else:
                cur["count"] += 1
                if when >= cur["time"]:
                    cur["ts"], cur["time"] = ts, when
        return sorted(seen.values(), key=lambda r: r["time"],
                      reverse=True)[:200]

    def _learn_selected(self, view):
        path, _col = view.get_cursor()
        if not path:
            self._learn_sel = None
            self._learn_actions_sensitive()
            return
        row = self.learn_store[path[0]]
        self._learn_sel = (row[0], row[2]) if row[0] else None
        self._learn_actions_sensitive()

    def _learn_actions_sensitive(self):
        """Nothing selected (or nothing recorded) means the row actions have
        no subject, so they dim rather than offering a dead click."""
        if not hasattr(self, "learn_clear_btn"):
            return
        rows = self.learn_store.iter_n_children(None) > 0
        picked = bool(getattr(self, "_learn_sel", None))
        for b in self._learn_row_btns:
            b.set_sensitive(rows and picked)
        self.learn_clear_btn.set_sensitive(rows)

    def _on_learn_trust(self, _btn):
        sel = getattr(self, "_learn_sel", None)
        if not sel:
            self.learn_note.set_text("Select a row in the list first.")
            return
        ok = self.trust.add_app(sel[0])
        self.learn_note.set_text(
            f"Trusted: {os.path.basename(sel[0]) or sel[0]} can use the "
            f"internet without asking." if ok
            else "That program could not be trusted.")
        self._refresh_apps()

    def _on_learn_site(self, _btn):
        sel = getattr(self, "_learn_sel", None)
        if not sel:
            self.learn_note.set_text("Select a row in the list first.")
            return
        ok = self.trust.add(sel[1], "allow")
        self.learn_note.set_text(
            f"Trusted: {sel[1]} is always allowed." if ok
            else "That address could not be trusted.")
        self._refresh_trust()

    def _on_learn_block(self, _btn):
        sel = getattr(self, "_learn_sel", None)
        if not sel:
            self.learn_note.set_text("Select a row in the list first.")
            return
        ok = self.trust.add(sel[1], "block")
        self.learn_note.set_text(
            f"Blocked: {sel[1]} is never allowed." if ok
            else "That address could not be blocked.")
        self._refresh_trust()

    def _refresh_fw(self):
        if not hasattr(self, "fw_note"):
            return
        on = self._fw_is_on()
        learning = self._learn_store.active()
        block = self._fw_mode_store.load().block_unknown
        if not on:
            ink = pc_muted()
            text = ("Firewall off: programs use the internet without "
                    "asking.")
        elif block:
            ink = pc_ok()
            text = ("Firewall on, strict. Nothing you have not trusted "
                    "is allowed.")
        elif learning:
            ink = pc_ok()
            text = ("Firewall on, learning. New connections pass once. "
                    "Press Trust to keep one.")
        else:
            ink = pc_ok()
            text = ("Firewall on, watching. New connections pass once. "
                    "Learning mode records them.")
        # One drawn dot in the status ink; the emoji that used to carry
        # this meaning is gone (design pass 2026-10-27).
        self.fw_note.set_markup(
            f"<span size='13000' font_family='Inter'>"
            f"<span foreground='{ink}'>●</span> {escape(text)}</span>")
        if self.fw_btn.get_sensitive():     # while busy it says Starting…
            self.fw_btn.set_label("Turn off" if on else "Turn on")
        active = self._learn_store.active()
        if self.learn_check.get_active() != active:
            self._learn_guard = True
            self.learn_check.set_active(active)
            self._learn_guard = False
        block = self._fw_mode_store.load().block_unknown
        if self.fw_block.get_active() != block:
            self._fw_mode_guard = True
            self.fw_block.set_active(block)
            self._fw_mode_guard = False
        rows = self._learned()
        self.learn_store.clear()
        if hasattr(self, "learn_box"):
            self.learn_box.set_visible(bool(rows))
            self.learn_empty.set_visible(not rows)
            if not rows:
                self._learn_sel = None
        for r in rows:
            site = r["host"] + (f"  ×{r['count']}" if r["count"] > 1 else "")
            self.learn_store.append([
                r["app"], os.path.basename(r["app"]) or "(unknown)",
                site, local_clock(r["ts"])])
        if hasattr(self, "learn_box"):
            self._learn_actions_sensitive()
        if block:
            self.learn_note.set_text(
                f"Blocking anything not trusted. {len(rows)} connection(s) "
                f"recorded. Trust one below to let it through.")
        elif active:
            self.learn_note.set_text(
                f"Learning is ON. {len(rows)} connection(s) recorded. "
                f"Approve them below; nothing is permanent until you do.")
        elif not on:
            fw_off_note = "The firewall is off, so nothing is intercepted yet."
            self.learn_note.set_text(fw_off_note + " Turn it on above first.")
        else:
            quiet_a = "New connections pass once. Nothing is recorded."
            quiet_b = "Turn learning on to record them. Tick strict to stop unknowns."
            self.learn_note.set_text(quiet_a + " " + quiet_b)

    def _refresh_updates(self):
        if not hasattr(self, "updates_note"):
            return
        from ui import updates
        s = updates.summary()
        cve = s.get("cve") or {}
        clam = s.get("clamav") or {}
        lines = []
        if clam.get("ts"):
            lines.append("ClamAV virus definitions: updated "
                         f"{updates.human_stamp(clam['ts'])} "
                         f"({clam.get('file', '')}).")
        else:
            lines.append("ClamAV virus definitions: none found yet.")
        if cve.get("ts"):
            lines.append(f"Security list (CVE): {cve.get('count', 0)} entries, "
                         f"fetched {updates.human_stamp(cve['ts'])}.")
        else:
            lines.append("Security list (CVE): nothing fetched yet.")
        bl = self._blocklist
        bmeta = bl.meta()
        if bmeta.get("fetched_utc"):
            lines.append(f"Tracker/malware block list: {bl.count()} domains, "
                         f"updated {updates.human_stamp(bmeta['fetched_utc'])}.")
        else:
            lines.append(f"Tracker/malware block list: {bl.count()} domains. "
                         f"Download it below.")
        self_note = "ClamAV updates itself."
        bl_note = "The lists refresh on demand here and weekly by the monitor."
        lines.append(self_note + " " + bl_note)
        self.updates_note.set_text("\n".join(lines))

    def _on_update_now(self, _btn):
        self.update_btn.set_sensitive(False)
        self.update_note.set_text(
            "Downloading the latest security list. This takes about a "
            "minute…")

        def worker():
            from ui import updates, blocklist
            rc, msg = updates.refresh_cve()
            ok, count, bl_msg = blocklist.download()
            GLib.idle_add(self._update_done, rc, msg, ok, count, bl_msg)

        threading.Thread(target=worker, daemon=True).start()

    def _update_done(self, rc, msg, bl_ok=True, bl_count=0, bl_msg=""):
        pending = getattr(self, "_assistant_pending", None)
        if pending and pending[0] == "update_lists":
            self._assistant_pending = None
            audit.record("update_lists", "", rc == 0 and bl_ok)
        self.update_btn.set_sensitive(True)
        self._refresh_updates()
        parts = []
        parts.append("security list up to date" if rc == 0
                     else f"security list failed ({msg or 'no answer'})")
        parts.append(f"block list up to date ({bl_count} domains)" if bl_ok
                     else f"block list failed ({bl_msg or 'no answer'})")
        self.update_note.set_text(" · ".join(parts))
        return False

    def _on_app_browse(self, _btn):
        dlg = Gtk.FileChooserNative(
            title="Choose the program to trust", transient_for=self,
            action=Gtk.FileChooserAction.OPEN)
        try:
            dlg.set_current_folder("/usr/bin")
        except Exception:
            pass

        def _on_pick(d, rid, *_a):
            if rid == Gtk.ResponseType.OK:
                chosen = (d.get_file().get_path() or ""
                          if d.get_file() is not None else "")
                if chosen:
                    self.app_combo.set_active(-1)
                    self.app_entry.set_text(chosen)
            d.destroy()
        dlg.connect("response", _on_pick)
        dlg.show()

    def _on_app_add(self, _btn, _x):
        text = (self.app_combo.get_active_id()
                or self.app_entry.get_text().strip())
        if not text:
            self.app_note.set_text(
                "Pick a program from the list or browse for it first.")
            return
        if not self.trust.add_app(text):
            self.app_note.set_text("That program name was not accepted.")
            return
        self._refresh_apps()
        self.app_combo.set_active(-1)
        self.app_entry.set_text("")
        self.app_note.set_text(
            f"Added: {text} can use the internet without asking.")

    def _on_app_remove(self, _btn):
        name = getattr(self, "_app_sel", None)      # capture before refresh
        if name:
            self.trust.remove_app(name)
            self._refresh_apps()
            self._app_sel = None
            self.app_note.set_text(f"Removed {name}.")
        else:
            self.app_note.set_text(
                "Select a program in the list first, then remove it.")

    def _on_theme_pick(self, combo):
        pick = combo.get_active_id()
        name = pick if pick in self._theme_store.themes \
            else dark_default(self._theme_store.names())
        if self._theme_store.apply(name):
            self._tick_id(self._retheme, 0)

    def _retheme(self):
        visible = self.stack.get_visible_child_name()
        panel = getattr(self, "assistant_panel", None)
        if panel is not None:
            # The rebuild recreates every page, including the one that owns
            # the chat; the conversation crosses to the next panel.
            self._chat_snapshot = panel.snapshot_transcript()
        # The security view builds a fresh activity store; a rebuild must
        # not depend on the seen-guard to fill it again (the feed went
        # blank after a theme switch, 2026-10-30).
        self._recent_seen = None
        for key, widget in list(self._views.items()):
            self.stack.remove(widget)
            del self._views[key]
        self._show(visible or "tools")
        self.refresh()
        return False

    def _reload_trust(self, *_a):
        self.trust.load()
        self._refresh_trust()
        self._refresh_apps()

    # Headings are class-driven now: one type scale in the theme (macOS
    # weights and tracking) instead of per-call Pango markup, so every page
    # heading stays in step with the rest of the chrome.
    @staticmethod
    def _h1(text):
        l = Gtk.Label(label=text, xalign=0)
        l.set_xalign(0)
        l.add_css_class("gw-headline")
        return l

    @staticmethod
    def _h2(text):
        l = Gtk.Label(label=text, xalign=0)
        l.set_xalign(0)
        l.add_css_class("gw-h2")
        return l

    @staticmethod
    def _scroll(widget):
        s = Gtk.ScrolledWindow()
        s.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        s.set_hexpand(True)
        s.set_vexpand(True)
        s.set_child(widget)
        return s

    @staticmethod
    def _column(widget, fraction=None, maximum=None, minimum=None, inset=26):
        """Scroll a page inside a centred column sized as a share of the
        window.

        macOS caps settings-style pages; without a cap a wide window gives
        a card with its controls under the first word and dead space beside
        them. The cap cannot be a fixed pixel count though: the same build
        runs on a 1366px laptop and a 4K panel, and 900px is generous on
        one and cramped on the other. So the column is a fraction of the
        window (ui/metrics.py owns the numbers), and Gtk has no max-width,
        so it is produced by symmetric side margins.
        """
        sc = Gtk.ScrolledWindow()
        sc.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sc.set_hexpand(True)
        sc.set_vexpand(True)
        sc.set_child(widget)

        seen = {"width": -1}

        def fit():
            width = sc.get_width()
            side = inset
            if width > 0:
                content = metrics.span(
                    width,
                    metrics.COLUMN_FRACTION if fraction is None else fraction,
                    metrics.COLUMN_MIN if minimum is None else minimum,
                    metrics.COLUMN_MAX if maximum is None else maximum)
                side = max(inset, (width - content) // 2)
            widget.set_margin_start(side)
            widget.set_margin_end(side)

        # notify::width arrives before the new size is allocated, so reading
        # it from an idle still saw the old window (the column landed at the
        # 1440px default and never widened). A tick callback reads the
        # settled width each frame and only touches the margins on resize.
        def on_tick(_widget, _clock):
            width = sc.get_width()
            if width != seen["width"]:
                seen["width"] = width
                fit()
            return True

        sc.add_tick_callback(on_tick)
        return sc

    @staticmethod
    def _wrap(widget):
        s = Gtk.ScrolledWindow()
        s.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        s.set_vexpand(True)
        s.set_child(widget)
        return s

    def _watchers(self):
        self._monitors = []
        for fname in ("events.jsonl", "status.json", "paused.json"):
            f = Gio.File.new_for_path(str(DATA_DIR / fname))
            m = f.monitor_file(Gio.FileMonitorFlags.NONE)
            m.connect("changed", lambda *_a: self._schedule_paint())
            self._monitors.append(m)

    def _periodic_refresh(self):
        self.refresh()
        return True

    def _schedule_paint(self):
        if self._merge_pending:
            return False
        self._merge_pending = True
        self._tick_id(self._paint, PAINT_MERGE_MS)
        return False

    def _paint(self):
        self._merge_pending = False
        self.refresh()
        return False

    @staticmethod
    def _plain_row(e: dict):
        sev = e.get("severity", "")
        return [tool_icon(e.get("from_tool", "")), "●",
                local_clock(e.get("ts", "")), plain_sentence(e),
                pc_severity_colour(sev)]

    def refresh(self):
        snap = daemon_mod.load_status(str(DATA_DIR / "status.json"))
        try:
            events = daemon_mod.read_events(DATA_DIR / "events.jsonl", 400)
        except OSError:
            events = []
        if not events:                    # the event store is root-only (0600)
            events = snap.get("recent") or []   # → the daemon's public digest
        # The assistant facts source: the very snapshots refresh() already
        # loaded — _get_status/_get_recent hand these over, no new reads.
        self._status_snapshot = snap
        self._recent_snapshot = events
        if events != self._recent_seen:
            self._recent_seen = events
            self.recent_store.clear()
            for e in recent_rows(events, 6):
                self.recent_store.append(self._plain_row(e))
        if self.on_status_change:
            self.on_status_change(events)
        tools = snap.get("tools", {})
        updated = snap.get("updated")
        self._reconcile_pause_markers(snap)
        paused_n = sum(1 for t in self.registry
                       if self.paused.is_paused(t["name"]))
        running = sum(1 for t in self.registry
                      if self._display_state(t["name"],
                                             tools.get(t["name"], {}),
                                             updated) == "GREEN"
                      and not self.paused.is_paused(t["name"]))
        attention = len(self.registry) - running - paused_n
        attention = max(0, attention)
        known = sum(1 for t in self.registry
                    if (tools.get(t["name"]) or {}).get("state")
                    in ("GREEN", "RED", "YELLOW"))
        pill_state = "ok"
        if known == 0 and not self._state_override:
            lead = "No status yet"
            pill = "Waiting for monitor"
            pill_state = "warn"
        else:
            if attention == 0 and paused_n == 0:
                lead = "All clear"
                pill = "All clear"
            elif attention == 0:
                lead = f"{paused_n} paused"
                pill = f"{paused_n} paused"
                pill_state = "warn"
            else:
                lead = f"{attention} need attention"
                if paused_n:
                    lead += f" · {paused_n} paused"
                pill = lead
                pill_state = "fail"
        # Plain text: the headline is a theme class now, and the running
        # tally lives in the meta line below it rather than shrinking into
        # the same sentence.
        self.status_words.set_text(lead)
        if getattr(self, "header_pill", None) is not None:
            self.header_pill.set_text(pill)
            for cls in ("ok", "warn", "fail"):
                self.header_pill.remove_css_class(cls)
            self.header_pill.add_css_class(pill_state)
        # Counts header: green count, pauses and the attention tail, in the
        # monitor's own words when it has not reported yet.
        if getattr(self, "counts", None) is not None:
            self.counts.set_text(
                "waiting for the monitor"
                if known == 0 and not self._state_override
                else f"{running} running · {paused_n} paused · "
                     f"{attention} need attention")

        now = _dt.datetime.now(_dt.timezone.utc)
        # Rank by what needs a human, not by registry order: anything failed
        # or unverified sits at the top, paused next, healthy last. A flat
        # alphabetical table makes the one broken tool the 14th row.
        _rank = {"RED": 0, "YELLOW": 1, "UNKNOWN": 1}
        def _urgency(t):
            paused = self.paused.is_paused(t["name"])
            state = self._display_state(t["name"], tools.get(t["name"], {}),
                                        updated)
            return (1.5 if paused else _rank.get(state, 2),
                    friendly_name(t["name"]))
        ordered = sorted(self.registry, key=_urgency)
        if getattr(self, "show_all_btn", None) is not None \
                and not self.show_all_btn.get_active():
            ordered = [t for t in ordered if _urgency(t)[0] < 2]

        if getattr(self, "table_stack", None) is not None:
            self.table_stack.set_visible_child_name(
                "list" if ordered else "empty")
        fresh = len(self.list_store) != len(ordered)
        if fresh:
            self.list_store.clear()

        for idx, t in enumerate(ordered):
            name = t["name"]
            info = tools.get(name, {})
            state = self._display_state(name, info, updated)
            paused = self.paused.is_paused(name)
            words = status_words(state, info.get("installed"), paused)
            stamp = self._update_detail(name)
            if stamp and not paused:
                words = ("up to date" if state == "GREEN"
                         else "the list is old")
            row = [tool_icon(name), "●",
                   f"{friendly_name(name)} · {name}", words,
                   stamp or age_words(info.get("last_event"), now), name,
                   pc_state_colour(state, paused)]
            if fresh:
                self.list_store.append(row)
            else:
                it = self.list_store.get_iter_from_string(str(idx))
                for col, val in enumerate(row):
                    self.list_store[it][col] = val
        self._restore_list_selection()
        self._refresh_rail(tools, updated)
        if hasattr(self, "card_widgets"):
            for t in self.registry:
                frame = self.card_widgets.get(t["name"])
                if not frame:
                    continue
                name = t["name"]
                info = tools.get(name, {})
                state = self._display_state(name, info, updated)
                paused = self.paused.is_paused(name)
                ev = next((e for e in reversed(events)
                           if e.get("from_tool") == name
                           and not str(e.get("text", "")).startswith(
                               "check-in:")), None)
                state_color = pc_state_colour(state, paused)
                words = status_words(state, info.get("installed"), paused)
                stamp = self._update_detail(name)
                if stamp and not paused:
                    words = ("up to date" if state == "GREEN"
                             else "the list is old")
                head = (f"<span size='11000' font_family='Inter' "
                        f"color='{state_color}'>● "
                        f"{escape(words)}</span>")
                detail = ""
                if stamp and not paused:
                    detail = stamp
                elif ev:
                    age = ""
                    try:
                        when = _dt.datetime.fromisoformat(
                            str(ev.get("ts", "")).replace("Z", "+00:00"))
                        age = age_words(when.isoformat(), now)
                    except (ValueError, TypeError):
                        age = ""
                    detail = without_mark(plain_sentence(ev))
                    if age:
                        detail += f" · {age}"
                else:
                    detail = quiet_note(name, None)
                frame._sub.set_markup(head)
                frame.set_tooltip_text(
                    f"{friendly_name(name)} — {what_is(name)}"
                    f"{(' · ' + detail) if detail else ''}")
                frame._pause_btn.set_label("Resume" if paused else "Pause")
                if hasattr(frame, "_pause_btn") and t.get("unit"):
                    frame._pause_btn.set_sensitive(True)

        if self._detail_dialog and self._detail_dialog.get_visible() and \
                self._selected_tool:
            pass
        if self._views.get("logs") and self.stack.get_visible_child_name() == "logs":
            self._refresh_logs()
        self._refresh_fw()
        self._refresh_updates()

    def _open_setup_wizard(self):
        from wizard.ui_pages import SetupWizardWindow

        if self._setup_win is not None:      # one setup window, not many
            try:
                self._setup_win.present()
            except Exception:
                self._setup_win = None
            else:
                return

        def open_dashboard():
            self.present()
            self._show("tools")

        def open_chooser():
            # "Set up something else" hands back to the hub; the baseline
            # window closes so only one wizard is on screen at a time.
            win = self._setup_win
            self._open_wizard()
            if win is not None:
                win.destroy()

        self._setup_win = SetupWizardWindow(
            parent=self,
            open_dashboard=open_dashboard,
            open_chooser=open_chooser)
        self._setup_win.present()
        self._setup_win.connect(
            "destroy", lambda _w: setattr(self, "_setup_win", None))

    def _open_wizard_for(self, key):
        if key == "baseline":
            # The baseline is its own multi-step flow, but it is launched
            # from the hub like every other task — not the other way round.
            self._open_setup_wizard()
            return
        from ui.wizard import RuleWizard
        self._wizard_win = RuleWizard(key, parent=self)
        self._wizard_win.connect("destroy", self._reload_trust)

    def _open_wizard(self):
        from ui.wizard import ToolChooser

        existing = getattr(self, "_chooser", None)
        if existing is not None:            # one hub, never a stack of them
            try:
                existing.present()
                return
            except Exception:
                self._chooser = None

        def picked(key):
            self._open_wizard_for(key)

        self._chooser = ToolChooser(on_pick=picked, parent=self)
        self._chooser.connect(
            "destroy", lambda _w: setattr(self, "_chooser", None))
        self._chooser.present()
        try:
            self._chooser.cancel_btn.grab_focus()
        except Exception:
            pass


def _theme_g():
    from ui import themes
    return themes.CURRENT or {"bg": "#0d1117", "panel": "#161b22",
                              "line": "#2a3140", "ink": "#dde5f2",
                              "accent": "#5b8def", "ok": "#4dd07a",
                              "warn": "#ffc940", "fail": "#ff5a52"}


class ProgressCircle(Gtk.DrawingArea):

    def __init__(self):
        super().__init__()
        self.text = ""
        self._tick = 0.0
        self._started = 0.0
        self._running = False
        self.set_size_request(170, 170)
        self.hide()
        self.set_draw_func(self._draw)
        self._pulse_id = GLib.timeout_add(200, self._pulse)
        self.connect("destroy", self._stop_pulse)

    def _stop_pulse(self, *_a):
        sid = getattr(self, "_pulse_id", None)
        if sid is not None:
            try:
                GLib.source_remove(sid)
            except (RuntimeError, TypeError):
                pass
            self._pulse_id = None
        return False

    def start(self, label):
        self.text = str(label or "scan")
        self._running = True
        self._started = time.monotonic()
        self._tick = 0.0
        self.show()
        self.queue_draw()

    def stop(self, _label=""):
        self._running = False
        self._tick = 0.0
        self.text = ""
        self.hide()
        self.queue_draw()

    def done(self):
        self.stop()

    def elapsed(self) -> int:
        return int(time.monotonic() - self._started) if self._running else 0

    def _pulse(self):
        if self._running:
            self._tick = (self._tick + 0.04) % 1.0
            self.queue_draw()
        return True

    def _draw(self, _area, cr, _width, _height):
        def _hex_rgba(h):
            h = h.lstrip("#")
            if len(h) == 3:
                h = "".join(c * 2 for c in h)
            return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)) + (1.0,)

        if not self._running:
            return False
        aw = _width
        ah = _height
        cx, cy, r = aw / 2, ah / 2, min(aw, ah) / 2 - 14
        cr.set_line_width(11)
        cr.set_line_cap(1)
        T = _theme_g()
        cr.arc(cx, cy, r, 0, 6.2832)
        cr.set_source_rgba(*_hex_rgba(T.get("line", "#2a3140")))
        cr.stroke()
        a0 = -1.5708 + 6.2832 * self._tick
        a1 = a0 + 1.9
        cr.arc(cx, cy, r, a0, a1)
        cr.set_source_rgba(*_hex_rgba(T["accent"]))
        cr.stroke()
        ink = _hex_rgba(T["ink"])
        cr.set_source_rgba(*ink)
        cr.select_font_face(T.get("display", "Inter"), 0, 0)
        cr.set_font_size(r * 0.42)
        txt = f"{self.elapsed()}s"
        _, _, tw, th, _, _ = cr.text_extents(txt)
        cr.move_to(cx - tw / 2, cy + th / 2)
        cr.show_text(txt)
        cr.set_font_size(r * 0.16)
        label = self.text[:16]
        _, _, lw, _lh, _, _ = cr.text_extents(label)
        cr.move_to(cx - lw / 2, cy - r * 0.36)
        cr.show_text(label)
        return False
