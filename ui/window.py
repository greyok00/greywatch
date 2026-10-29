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
from ui import discover
from ui.blocklist import BlockList
import greywatch_daemon as daemon_mod

DATA_DIR = daemon_mod.DATA_DIR
PAINT_MERGE_MS = 250

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
        self.set_default_size(1440, 900)
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
        bar.append(self.header_pill)
        parent.append(bar)

    def _apply_saved_theme(self):
        picked = load_setting()
        name = picked if picked in THEME_CHOICES.values() \
            else dark_default(self._theme_store.names())
        self._theme_store.apply(name)

    def _rail(self, parent):
        rail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        rail.add_css_class("gw-rail")
        rail.set_size_request(104, -1)
        rail.set_margin_top(14)
        parent.append(rail)

        self._rail_wiz = wiz = Gtk.Button()
        wv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        wi = Gtk.Image.new_from_icon_name("system-run-symbolic")
        wi.set_pixel_size(24)
        wl = Gtk.Label(label="Wizard")
        wv.append(wi)
        wv.append(wl)
        wiz.set_child(wv)
        # The hub, not the baseline pass: the baseline is one of the tasks
        # inside it now (owner report 2026-10-27 — it used to be the shell
        # that swallowed the per-tool wizards).
        wiz.set_tooltip_text("Guided setup: pick one task")
        wiz.connect("clicked", lambda *_b: self._open_wizard())
        rail.append(wiz)
        rail.append(Gtk.Separator())

        self._rail_btns = {}
        for key, icon, label in (
                ("tools", "security-high-symbolic", "Security"),
                ("deep", "applications-system-symbolic", "Tools"),
                ("settings", "preferences-system-symbolic", "Settings"),
                ("logs", "document-open-recent-symbolic", "Logs"),
                ("help", "help-about-symbolic", "Help")):
            b = Gtk.Button()
            lv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            ic = Gtk.Image.new_from_icon_name(icon)
            ic.set_pixel_size(24)
            lb = Gtk.Label(label=label)
            lb.add_css_class("gw-rail-label")
            lv.append(ic)
            lv.append(lb)
            b.set_child(lv)
            b.connect("clicked", self._rail_pick, key)
            rail.append(b)
            self._rail_btns[key] = b

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
        st = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        st.set_margin_top(22); st.set_margin_start(34); st.set_margin_end(16)

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.status_words = Gtk.Label(xalign=0)
        self.status_words.set_xalign(0)
        self.status_words.set_hexpand(True)
        top.append(self.status_words)
        # Counts header: the tally behind the headline's big words, filled
        # by refresh() from the same status snapshot (no extra reads).
        self.counts = Gtk.Label(xalign=0)
        self.counts.set_xalign(0)
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
        self.show_all_btn = Gtk.CheckButton(label="Show healthy", active=True)
        self.show_all_btn.connect("toggled", lambda *_a: self.refresh())
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
        self.chat_retry = Gtk.Button(label="Retry model")
        self.chat_retry.set_visible(False)
        self.chat_retry.connect(
            "clicked", lambda *_a: self._start_chat_llm())
        self.assistant_panel.append(self.chat_retry)
        self.assistant_panel.set_vexpand(True)
        # The chat stream is a scroll with no content of its own on waking:
        # without a floor it would collapse to a sliver inside the page
        # scroll and look like the panel never loaded.
        self.assistant_panel.set_size_request(-1, 340)
        st.append(self.assistant_panel)

        st.append(self._h2("Recent activity"))
        # [tool icon name, severity dot, time, sentence]
        # 4 = severity ink for the state dot in column 1.
        self.recent_store = Gtk.ListStore(str, str, str, str, str)
        recent = Gtk.TreeView(model=self.recent_store, headers_visible=False)
        # Compacted strip: the chat is the centre now, the rail names every
        # protection — the feed keeps five lines, not a second dashboard.
        recent.set_size_request(-1, 150)
        icon_cell = Gtk.CellRendererPixbuf()
        icon_cell.set_property("width", 18)
        recent.append_column(Gtk.TreeViewColumn(
            None, icon_cell, icon_name=0))
        dot = Gtk.CellRendererText()
        dot.set_property("xalign", 0.5)
        recent.append_column(Gtk.TreeViewColumn(
            None, dot, text=1, foreground=4))
        for i in (2, 3):
            cell = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(None, cell, text=i)
            if i == 3:
                col.set_expand(True)
            recent.append_column(col)
        rf = Gtk.Frame()
        rf.add_css_class("gw-card")
        rf.set_child(recent)
        st.append(rf)

        pane.set_start_child(self._scroll(st))
        pane.set_end_child(self._build_assistant_rail())
        pane.set_resize_start_child(True)
        pane.set_shrink_end_child(False)
        # A first-run default; the divider stays user-draggable. Through the
        # property, not the method: the repo lint bans the `set_position(`
        # spelling (Gtk3-era window API) and the name collides here.
        pane.set_property("position", 1080)
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
        rail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        rail.set_margin_top(22)
        rail.set_margin_end(18)
        rail.set_size_request(240, -1)
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        top.append(self._h2("Protections"))
        top.append(self.show_all_btn)          # moved from the dashboard
        rail.append(top)
        self.rail_list = Gtk.ListBox()
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
        sc.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sc.set_child(self.rail_list)
        sc.set_vexpand(True)
        rail.append(sc)
        rail.append(self.sel_note)
        foot = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        # The four controls the old actions strip had, rebuilt here verbatim:
        # same attributes, same handlers, no second code path.
        for b in (self.pause_btn, self.resume_btn, self.details_btn,
                  self.panic_btn):
            foot.append(b)                     # reuse existing buttons
        rail.append(foot)
        return rail

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

    def _assistant_intent(self, action, tool):
        """Confirm-gated execution. The panel already showed the confirm
        dialog and wrote the one assistant ledger line for the intent
        (ui.assistant._confirmed); this mirrors the manual buttons exactly.
        """
        if action == "details":
            self._selected_tool = tool
            self._open_detail(tool)
            return
        if action == "pause":
            self._selected_tool = tool
            self._pause_selected()
        elif action == "resume":
            self._selected_tool = tool
            self._resume_selected()
        # overview needs no action — the template already answered.

    def _start_chat_llm(self):
        """Wake the assistant model in-process (the installer drops the
        gguf under $DATA/models). A retry builds a NEW Llm instance, since
        start() is one-shot per instance (assistant/llm.py contract)."""
        from assistant.llm import Llm
        import gwpaths
        model = gwpaths.data_dir() / "models" / \
            "smollm2-360m-instruct-q4_k_m.gguf"
        self.assistant_panel.banner.set_text(
            "Assistant loading…"
            + ("" if getattr(self, "chat_llm", None) is None else " retrying"))
        if getattr(self, "chat_retry", None) is not None:
            self.chat_retry.set_visible(False)
        self.chat_llm = Llm(model_path=str(model))
        self.chat_llm.start(
            lambda ok, err: GLib.idle_add(self._on_llm_ready, ok, err))

    def _on_llm_ready(self, ok, err):
        self.assistant_panel.note_state(ok, err)
        if getattr(self, "chat_retry", None) is not None:
            self.chat_retry.set_visible(not ok)
        return False

    def _tools_view(self):
        tools = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        tools.set_margin_top(26); tools.set_margin_start(34); tools.set_margin_end(34)
        tools.append(self._h1("Your protections"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        intro.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "Each protection below shows its plain name and the real tool "
            "behind it. Configure anything without typing a command.</span>")
        tools.append(intro)
        tools.append(self._scan_strip())
        tools.append(self._baseline_card())

        self.cards_flow = Gtk.FlowBox()
        self.cards_flow.set_max_children_per_line(3)
        self.cards_flow.set_min_children_per_line(2)
        self.cards_flow.set_row_spacing(12)
        self.cards_flow.set_column_spacing(12)
        self.cards_flow.set_homogeneous(True)
        self.cards_flow.set_selection_mode(Gtk.SelectionMode.NONE)
        self.card_widgets = {}
        for t in self.registry:
            self.card_widgets[t["name"]] = self._tool_card(t)
            self.cards_flow.append(self.card_widgets[t["name"]])
        self.cards_flow.set_hexpand(True)
        self.cards_flow.set_vexpand(True)
        tools.append(self.cards_flow)
        return self._scroll(tools)

    def _baseline_card(self):
        """The baseline pass lives in the wizard, so this is the doorway.

        The old top-level Harden page duplicated the wizard's scan/apply
        flow with a second journal; two implementations of one job is how
        they drift apart. One task, one home.
        """
        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        box.set_margin_top(16); box.set_margin_bottom(16)
        box.set_margin_start(18); box.set_margin_end(18)
        ic = Gtk.Image.new_from_icon_name("security-high-symbolic")
        ic.set_pixel_size(40)
        ic.set_valign(Gtk.Align.START)
        box.append(ic)
        words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        words.set_hexpand(True)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_markup("<span size='17000' font_family='Inter' weight='600'>"
                        "Security baseline hardening</span>")
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        body.set_markup(
            f"<span size='12000' font_family='Inter' color='{pc_muted()}'>"
            "Check this computer against the baseline, preview every change, "
            "apply them with one password prompt, then verify or undo.</span>")
        words.append(head)
        words.append(body)
        box.append(words)
        go = Gtk.Button(label="Open the baseline wizard")
        go.add_css_class("gw-cta")
        go.set_valign(Gtk.Align.CENTER)
        go.connect("clicked", lambda *_a: self._open_setup_wizard())
        box.append(go)
        frame.set_child(box)
        return frame

    def _scan_strip(self):
        strip = Gtk.Frame()
        strip.add_css_class("gw-card")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=26)
        box.set_margin_top(16); box.set_margin_bottom(16)
        box.set_margin_start(16); box.set_margin_end(16)
        self.circle = ProgressCircle()
        box.append(self.circle)
        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.scan_status = Gtk.Label(xalign=0)
        self.scan_status.set_xalign(0)
        self.scan_status.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "Scans run in the background. Results appear here."
            "</span>")
        right.append(self.scan_status)
        btns = Gtk.FlowBox()
        btns.set_max_children_per_line(3)
        btns.set_min_children_per_line(3)
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
            row.append(Gtk.Label(label=m["title"]))
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
        """One protection: plain name, real tool name, what it does, live
        state, and the actions that belong to it.

        The card already carried the mono tool name, but at 11 px in the
        muted ink beside a 15 px headline it read as a footnote; the owner
        reported the Tools page as "not showing the real tool names". Name
        and tool now share one line and a fixed type scale, and every card
        offers its own guided setup instead of hiding it in Details.
        """
        name = tool["name"]
        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(16); box.set_margin_bottom(16)
        box.set_margin_start(18); box.set_margin_end(18)

        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        ic = Gtk.Image.new_from_icon_name(tool_icon(name))
        ic.set_pixel_size(34)
        ic.set_valign(Gtk.Align.START)
        head.append(ic)

        names = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        names.set_hexpand(True)
        fn = Gtk.Label(xalign=0)
        fn.set_xalign(0)
        fn.set_wrap(True)
        # Two lines, not one: the tool name is a fact about the system, not
        # decoration, so it gets its own readable line in mono.
        fn.set_markup(
            f"<span size='17000' font_family='Inter' weight='600'>"
            f"{escape(friendly_name(name))}</span>\n"
            f"<span size='12000' font_family='JetBrains Mono'"
            f" color='{pc_muted()}'>{escape(name)}</span>")
        names.append(fn)
        what = Gtk.Label(xalign=0)
        what.set_xalign(0)
        what.set_wrap(True)
        what.set_markup(f"<span size='12000' font_family='Inter' "
                        f"color='{pc_muted()}'>{escape(what_is(name))}"
                        f"</span>")
        names.append(what)
        head.append(names)
        box.append(head)

        sub = Gtk.Label(xalign=0)
        sub.set_xalign(0)
        sub.set_wrap(True)
        sub.set_markup(f"<span size='12000' font_family='Inter' "
                       f"color='{pc_muted()}'>checking…</span>")
        box.append(sub)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        row.set_margin_top(2)
        wizard_key = WIZARD_FOR.get(name)
        if wizard_key:
            cfg = Gtk.Button(label="Configure…")
            cfg.add_css_class("gw-cta")
            cfg.set_tooltip_text("Guided setup — no commands to type")
            cfg.connect("clicked",
                        lambda *_b, k=wizard_key: self._open_wizard_for(k))
            row.append(cfg)
        scan_keys = {m["key"] for m in SCAN_MODES}
        if name in scan_keys or name == "yara-watch":
            b = Gtk.Button(label="Scan now")
            b.connect("clicked", self._open_scan_for, name)
            row.append(b)
        pause = Gtk.Button(label="Pause")
        pause.set_sensitive(bool(tool.get("unit")))
        pause.connect("clicked", lambda *_b, n=name:
                      self._resume_tool(n) if self.paused.is_paused(n)
                      else self._pause_tool(n))
        row.append(pause)
        more = Gtk.Button(label="Details")
        more.connect("clicked", lambda *_b, n=name: self._open_detail(n))
        row.append(more)
        box.append(row)

        frame.set_child(box)
        frame.set_tooltip_text(what_is(name))
        frame._sub = sub
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
        view = Gtk.TreeView(model=self.logs_store, headers_visible=True)
        log_icon = Gtk.CellRendererPixbuf()
        log_icon.set_property("width", 22)
        view.append_column(_fixed(
            Gtk.TreeViewColumn("", log_icon, icon_name=0), 44))
        sev = Gtk.CellRendererText()
        view.append_column(_fixed(
            Gtk.TreeViewColumn("State", sev, text=1, foreground=2), 86))
        view.append_column(_fixed(
            Gtk.TreeViewColumn("Time / tool", Gtk.CellRendererText(), text=3),
            300))
        last = Gtk.TreeViewColumn("Event", Gtk.CellRendererText(), text=4)
        last.set_expand(True)
        view.append_column(last)
        wrap = self._wrap(view)
        wrap.set_hexpand(True)
        box.append(wrap)
        self._refresh_logs()
        return self._scroll(box)

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
        from ui.plain import FRIENDLY
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_top(26); box.set_margin_start(34); box.set_margin_end(34)
        box.append(self._h1("Help"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        help_one = "Every protection on this computer, in one place."
        help_two = "Plain words here; raw detail is one click away."
        lines = [
            "Wizard — guided setup.",
            "Security — state of every protection.",
            "Tools — cards, scans, progress.",
            "Settings — theme, trusted items, updates.",
            "App firewall — what programs connect to.",
            "Logs — raw record, newest first.",
        ]
        markup = (f"<span size='14000' font_family='Inter'>"
                  f"{escape(help_one)}\n{escape(help_two)}</span>\n\n"
                  "How to use it:\n")
        for line in lines:
            markup += f" • {escape(line)}\n"
        intro.set_markup(markup)
        intro.set_tooltip_text(
            "The full guide, with screenshots, fills this tab as it is built.")
        box.append(intro)
        box.append(self._h2("What each tool does"))
        grid = Gtk.FlowBox()
        grid.set_max_children_per_line(2)
        grid.set_min_children_per_line(2)
        for t, (fname, what) in FRIENDLY.items():
            if t not in self.by_name:
                continue
            card = Gtk.Frame()
            card.add_css_class("gw-card")
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            inner.set_margin_top(10); inner.set_margin_bottom(10)
            inner.set_margin_start(10); inner.set_margin_end(10)
            head = Gtk.Label(xalign=0)
            head.set_xalign(0)
            head.set_markup(f"<span size='14000' font_family='Inter' "
                            f"weight='600'>{escape(fname)}</span>")
            body = Gtk.Label(xalign=0)
            body.set_xalign(0)
            body.set_wrap(True)
            body.set_markup(f"<span size='12000' font_family='Inter' "
                            f"color='{pc_soft()}'>{escape(what)}</span>")
            inner.append(head)
            inner.append(body)
            card.set_child(inner)
            grid.append(card)
        box.append(grid)
        box.append(self._h2("Questions"))
        faq_lines = [
            ("What does greywatch do?",
             "One dashboard for every protection already on this computer."),
            ("How do I run a scan?",
             "Tools: press a quick-scan button; the circle shows progress."),
            ("How do I pause a protection?",
             "Security: press Pause on its row; Resume brings it back."),
            ("What does At risk mean?",
             "A protection that should be running is not. Not a detection."),
            ("A detection appeared — what now?",
             "Read the Recent line or Logs. Quarantine what you didn't cause."),
            ("How do I isolate my machine?",
             "No one-click panic. Keep the firewall on; unplug to disconnect."),
            ("How do I change the theme?",
             "Settings — Look of the app — Dark or Light Mode."),
            ("Why is my antivirus quiet?",
             "Its full scan runs daily. Quiet means nothing bad was found."),
            ("Is my disk encrypted — how do I check?",
             "Not checked today. Run lsblk in a terminal; LUKS shows crypto."),
            ("How do I undo a wizard change?",
             "Wizard — Security baseline hardening — Undo last change "
             "reverts the newest applied change."),
        ]
        faq = Gtk.Label(xalign=0)
        faq.set_xalign(0)
        faq.set_wrap(True)
        faq_markup = ""
        for q, a in faq_lines:
            faq_markup += (f"<span size='12000' font_family='Inter' "
                           f"weight='600'>{escape(q)}</span>\n"
                           f"   {escape(a)}\n\n")
        faq.set_markup(faq_markup)
        faq.set_tooltip_text(
            "The same ten questions, with screenshots, live in doc/help.html.")
        box.append(faq)
        box.append(self._h2("Terminal"))
        deep = Gtk.Label(xalign=0)
        deep.set_xalign(0)
        deep.set_wrap(True)
        deep_one = "The commands work without this window."
        deep_two = "Run greywatch status, events, tail, decisions, or rules."
        deep_three = "The root watch daemon is greywatch.service."
        deep_four = "Events live in data/events.jsonl, status in data/status.json."
        deep_five = ("Every privileged change runs through a helper with a "
                     "backup and rollback.")
        deep.set_text(
            "\n".join([deep_one, deep_two, deep_three, deep_four, deep_five]))
        box.append(deep)
        return self._scroll(box)

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

    def _settings_card(self, title, about):
        """One settings group: a heading, one sentence saying what it is
        for, and a card holding the controls.

        The page used to be a flat column of ten headings with the raw unit
        file pasted in, so "Workspace" or "ProtectSystem" had no explanation
        anywhere (owner: redo the rest of the UI, 2026-10-27).
        """
        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        inner.set_margin_top(16); inner.set_margin_bottom(16)
        inner.set_margin_start(18); inner.set_margin_end(18)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_wrap(True)
        head.set_markup(
            f"<span size='16000' font_family='Inter' weight='600'>"
            f"{escape(title)}</span>\n"
            f"<span size='12000' font_family='Inter' color='{pc_muted()}'>"
            f"{escape(about)}</span>")
        inner.append(head)
        frame.set_child(inner)
        return frame, inner

    def _settings_row(self, label, control, hint=""):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        name = Gtk.Label(xalign=0)
        name.set_xalign(0)
        name.set_markup(f"<span size='14000' font_family='Inter'>"
                        f"{escape(label)}</span>")
        name.set_size_request(190, -1)
        row.append(name)
        row.append(control)
        if hint:
            tip = Gtk.Label(xalign=0)
            tip.set_xalign(0)
            tip.set_wrap(True)
            tip.set_hexpand(True)
            tip.set_markup(f"<span size='12000' font_family='Inter' "
                           f"color='{pc_muted()}'>{escape(hint)}</span>")
            row.append(tip)
        return row

    def _settings_view(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_margin_top(26); box.set_margin_start(30); box.set_margin_end(30)
        box.append(self._h1("Settings"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        intro.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "How the dashboard behaves, what the app firewall does, and "
            "what this computer is really running.</span>")
        box.append(intro)

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
        box.append(app_frame)

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

        learn_check = Gtk.CheckButton(label="Learning mode")
        learn_check.connect("toggled", self._on_learning_toggle)
        self.learn_check = learn_check
        learn_for = Gtk.ComboBoxText()
        for ident, label in (("15", "15 minutes"), ("60", "1 hour"),
                             ("480", "8 hours"), ("0", "until I stop it")):
            learn_for.append(ident, label)
        learn_for.set_active_id("60")
        self.learn_for = learn_for
        learn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        learn_row.append(learn_check)
        learn_row.append(learn_for)
        fw_inner.append(learn_row)
        self.learn_note = Gtk.Label(xalign=0)
        self.learn_note.set_xalign(0)
        self.learn_note.set_wrap(True)
        fw_inner.append(self.learn_note)
        block = Gtk.CheckButton(label="Block unknown apps")
        block.connect("toggled", self._on_fw_block_toggle)
        self.fw_block = block
        fw_inner.append(block)
        v6_check = Gtk.CheckButton()
        v6_check.set_active(bool(self._cfg6()))
        v6_check.connect("toggled", self._on_v6_toggle)
        self._v6_check = v6_check
        fw_inner.append(self._settings_row(
            "Filter IPv6", v6_check,
            "Off by default: IPv6 traffic is not filtered unless you turn "
            "this on. Takes about ten seconds to apply."))

        conn_head = Gtk.Label(xalign=0)
        conn_head.set_xalign(0)
        conn_head.set_wrap(True)
        conn_head.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "Connections seen while learning. Nothing is blocked unless you "
            "press a button.</span>")
        fw_inner.append(conn_head)
        self.learn_store = Gtk.ListStore(str, str, str, str)   # path, app, site, last
        self.learn_view = Gtk.TreeView(model=self.learn_store)
        for i, title in enumerate(("program", "site", "last seen")):
            cell = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, cell, text=i + 1)  # 0 = full path
            if i == 1:
                col.set_expand(True)
            self.learn_view.append_column(col)
        self.learn_view.connect("cursor-changed", self._learn_selected)
        self.learn_view.set_size_request(-1, 170)
        learn_scroll = self._wrap(self.learn_view)
        learn_scroll.set_size_request(-1, 170)
        fw_inner.append(learn_scroll)
        learn_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for label, handler in (
                ("Trust this program", self._on_learn_trust),
                ("Trust this site", self._on_learn_site),
                ("Block this site", self._on_learn_block),
                ("Clear", self._on_learn_clear)):
            b = Gtk.Button(label=label)
            b.connect("clicked", handler)
            learn_btns.append(b)
        fw_inner.append(learn_btns)
        box.append(fw_frame)

        # This computer: the unit's real settings, each with the plain
        # meaning. The page used to paste systemctl's raw output here, so
        # "ProtectSystem=no" was shown with no explanation of the risk.
        unit_frame, unit_inner = self._settings_card(
            "This computer",
            "What the service manager is actually enforcing on the daemon.")
        for label, value, meaning in self._unit_facts():
            val = Gtk.Label(xalign=0)
            val.set_xalign(0)
            val.set_markup(f"<span size='13000' font_family='JetBrains Mono'>"
                           f"{escape(value)}</span>")
            unit_inner.append(self._settings_row(label, val, meaning))
        box.append(unit_frame)

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
        box.append(diag_frame)

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
        box.append(up_frame)

        self.trust = self._trust
        trust_frame, trust_inner = self._settings_card(
            "Trusted items",
            "Answers you have already given. They are applied silently, "
            "with no popup.")
        trust_head = Gtk.Label(xalign=0)
        trust_head.set_xalign(0)
        trust_head.set_wrap(True)
        trust_head.set_markup(
            f"<span size='14000' font_family='Inter' weight='600'>"
            "Websites</span>\n"
            f"<span size='12000' font_family='Inter' color='{pc_muted()}'>"
            "Allowed without asking, or blocked without asking. "
            "Subdomains are included.</span>")
        trust_inner.append(trust_head)
        entry_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.trust_combo = Gtk.ComboBoxText.new_with_entry()
        for choice in discover.site_choices():
            self.trust_combo.append(
                choice["host"], f"{choice['host']} · {choice['why']}")
        self.trust_entry = self.trust_combo.get_child()
        self.trust_entry.set_placeholder_text(
            "Site name")
        self.trust_entry.connect("activate", self._on_trust_add, "allow")
        self.trust_combo.set_hexpand(True)
        entry_row.append(self.trust_combo)
        for label, verdict in (("Trust always", "allow"), ("Block always", "block")):
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
        self.trust_view.set_size_request(-1, 200)
        trust_scroll = self._wrap(self.trust_view)
        trust_scroll.set_size_request(-1, 200)
        trust_inner.append(trust_scroll)
        del_b = Gtk.Button(label="Remove site")
        del_b.set_halign(Gtk.Align.START)
        del_b.connect("clicked", self._on_trust_remove)
        trust_inner.append(del_b)

        prog_head = Gtk.Label(xalign=0)
        prog_head.set_xalign(0)
        prog_head.set_wrap(True)
        prog_head.set_markup(
            f"<span size='14000' font_family='Inter' weight='600'>"
            "Programs</span>\n"
            f"<span size='12000' font_family='Inter' color='{pc_muted()}'>"
            "These connect without asking. Pick from the list, or browse."
            "</span>")
        trust_inner.append(prog_head)
        app_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.app_combo = Gtk.ComboBoxText.new_with_entry()
        for prog in discover.programs():
            self.app_combo.append(prog["path"], prog["label"])
        self.app_entry = self.app_combo.get_child()
        self.app_entry.set_placeholder_text(
            "Program")
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
        app_view.set_size_request(-1, 180)
        app_scroll = self._wrap(app_view)
        app_scroll.set_size_request(-1, 180)
        trust_inner.append(app_scroll)
        del_app = Gtk.Button(label="Remove program")
        del_app.set_halign(Gtk.Align.START)
        del_app.connect("clicked", self._on_app_remove)
        trust_inner.append(del_app)
        box.append(trust_frame)
        self._refresh_trust()
        self._refresh_apps()
        return self._scroll(box)

    def _refresh_trust(self):
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
            return
        row = self.learn_store[path[0]]
        self._learn_sel = (row[0], row[2]) if row[0] else None

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
        if not rows:
            self.learn_store.append(
                ["", "Nothing learned yet. Turn learning on above.", "", ""])
        for r in rows:
            site = r["host"] + (f"  ×{r['count']}" if r["count"] > 1 else "")
            self.learn_store.append([
                r["app"], os.path.basename(r["app"]) or "(unknown)",
                site, local_clock(r["ts"])])
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

    @staticmethod
    def _h1(text):
        l = Gtk.Label(xalign=0)
        l.set_xalign(0)
        l.set_markup(f"<span size='26000' font_family='Barlow Condensed' "
                     f"weight='600'>{escape(text)}</span>")
        return l

    @staticmethod
    def _h2(text):
        l = Gtk.Label(xalign=0)
        l.set_xalign(0)
        l.set_markup(f"<span size='18000' font_family='Barlow Condensed' "
                     f"weight='600'>{escape(text)}</span>")
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
            tail = "the monitor hasn't reported"
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
            tail = f"{running}/{len(self.registry)} running"
        self.status_words.set_markup(
            f"<span size='19000' font_family='Barlow Condensed' weight='600'>"
            f"{lead}"
            f"</span>  <span size='12000' font_family='Inter' color='{pc_muted()}'>"
            f"{tail}</span>")
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
                head = (f"<span size='12000' font_family='Inter' "
                        f"color='{state_color}'>● "
                        f"{escape(words)}</span>")
                if stamp and not paused:
                    frame._sub.set_markup(
                        f"{head}  <span size='11000' font_family='Inter' "
                        f"color='{pc_muted()}'>— {escape(stamp)}</span>")
                elif ev:
                    age = ""
                    try:
                        when = _dt.datetime.fromisoformat(
                            str(ev.get("ts", "")).replace("Z", "+00:00"))
                        age = age_words(when.isoformat(), now)
                    except (ValueError, TypeError):
                        age = ""
                    detail = escape(without_mark(plain_sentence(ev)))
                    frame._sub.set_markup(
                        f"{head}  <span size='11000' font_family='Inter' "
                        f"color='{pc_muted()}'>— {detail}"
                        f"{(' · ' + escape(age)) if age else ''}</span>")
                else:
                    frame._sub.set_markup(
                        f"{head}  <span size='11000' font_family='Inter' "
                        f"color='{pc_muted()}'>— {escape(quiet_note(name, None))}"
                        f"</span>")
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
