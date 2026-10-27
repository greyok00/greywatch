import datetime as _dt
import json
import os
import pathlib
import subprocess
import threading
import time

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Gio    # noqa: E402

from registry import load_registry
from ui.models import (MARK_BY_SEVERITY, status_mark, status_words, recent_rows, age_words,
                       local_clock)
from ui.plain import (sentence as plain_sentence, friendly_name, what_is,
                      escape, without_mark, soft as pc_soft,
                      muted as pc_muted)
from ui.themes import (ThemeStore, dark_default, load_setting,
                       THEME_CHOICES)
from ui.cards import CARD_ICONS, SCAN_MODES, quiet_note
from ui.settings import (TrustList, PausedStore, LearningStore,
                         FirewallModeStore)
from ui import discover
from ui.blocklist import BlockList
import greywatch_daemon as daemon_mod

DATA_DIR = daemon_mod.DATA_DIR
PAINT_MERGE_MS = 250


def _fixed(col, width):
    col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
    col.set_fixed_width(width)
    return col


class MainWindow(Gtk.Window):
    def __init__(self, on_status_change=None, tray_available=True,
                 quit_cb=None):
        super().__init__(title="greywatch: Endpoint Security Suite")
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
        self._trust = TrustList()
        self.paused = PausedStore()
        self._learn_store = LearningStore()
        self._fw_mode_store = FirewallModeStore()
        self._blocklist = BlockList()   # mtime-cached; never re-parsed per tick
        self._learn_sel = None
        self._learn_guard = False
        self._fw_mode_guard = False
        self._scan_runner = self._run_scan

        root = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.set_child(root)
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
        wv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        wi = Gtk.Label()
        wi.set_markup("<span size='22000'>🧙</span>")
        wl = Gtk.Label(label="Wizard")
        wv.append(wi)
        wv.append(wl)
        wiz.set_child(wv)
        wiz.set_tooltip_text("The Setup Wizard: scan, preview, apply, verify")
        wiz.connect("clicked", lambda *_b: self._open_setup_wizard())
        rail.append(wiz)
        rail.append(Gtk.Separator())

        self._rail_btns = {}
        for key, icon, label in (("tools", "🛡", "Security"),
                                 ("deep", "🧩", "Tools"),
                                 ("harden", "⛨", "Harden"),
                                 ("settings", "⚙", "Settings"),
                                 ("logs", "📜", "Logs"),
                                 ("help", "?", "Help")):
            b = Gtk.Button()
            lv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            ic = Gtk.Label()
            ic.set_markup(f"<span size='24000'>{icon}</span>")
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

    def _build_all(self):
        self._views = {}
        self._builders = {"tools": self._security_view,
                          "deep": self._tools_view, "logs": self._logs_view,
                          "help": self._help_view,
                          "harden": self._harden_view,
                          "settings": self._settings_view}
        self._add_view("tools", self._builders["tools"]())

    def _add_view(self, key, widget):
        self.stack.add_named(widget, key)
        self._views[key] = widget

    def _ensure_view(self, key):
        if key not in self._views:
            self._add_view(key, self._builders[key]())

    def _security_view(self):
        st = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        st.set_margin_top(22); st.set_margin_start(34); st.set_margin_end(34)

        self.status_words = Gtk.Label(xalign=0)
        self.status_words.set_xalign(0)
        st.append(self.status_words)

        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        self.list_store = Gtk.ListStore(str, str, str, str, str, str)
        lv = Gtk.TreeView(model=self.list_store)
        lv.set_headers_visible(True)
        cols = [(0, "Icon", 48), (1, "State", 56), (2, "Protection", 280),
                (3, "Status", 170)]
        for idx, title, width in cols:
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
        frame.set_child(lv)
        frame.set_vexpand(True)
        st.append(frame)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sel_note = Gtk.Label(xalign=0)
        self.sel_note.set_xalign(0)
        self.sel_note.set_text("Select one protection to pause it or open details.")
        self.sel_note.set_hexpand(True)
        actions.append(self.sel_note)
        self.pause_btn = Gtk.Button(label="Pause")
        self.pause_btn.connect("clicked", lambda *_b: self._pause_selected())
        self.resume_btn = Gtk.Button(label="Resume")
        self.resume_btn.connect("clicked", lambda *_b: self._resume_selected())
        details_btn = Gtk.Button(label="View details")
        details_btn.connect("clicked", lambda *_b: self._details_selected())
        self.panic_btn = Gtk.Button(label="Panic: enable every protection")
        self.panic_btn.set_tooltip_text(
            "Starts what is stopped and turns the app firewall on.")
        self.panic_btn.connect("clicked", self._on_panic)
        for b in (self.pause_btn, self.resume_btn, details_btn, self.panic_btn):
            actions.append(b)
        st.append(actions)

        st.append(self._h2("Recent: the short log"))
        self.recent_store = Gtk.ListStore(str, str, str)
        recent = Gtk.TreeView(model=self.recent_store, headers_visible=False)
        recent.set_size_request(-1, 200)
        for i in range(3):
            cell = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(None, cell, text=i)
            if i == 2:
                col.set_expand(True)
            recent.append_column(col)
        rf = Gtk.Frame()
        rf.add_css_class("gw-card")
        rf.set_child(recent)
        st.append(rf)
        return self._scroll(st)

    def _list_selected(self, selection):
        model, it = selection.get_selected()
        self._selected_tool = model[it][5] if it else None
        if self._selected_tool:
            self.sel_note.set_text(f"Selected: {model[it][2]}")
        else:
            self.sel_note.set_text(
                "Select one protection to pause it or view details.")

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

    def _tools_view(self):
        tools = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        tools.set_margin_top(26); tools.set_margin_start(34); tools.set_margin_end(34)
        tools.append(self._h1("Your protections: tools"))
        tools.append(self._scan_strip())

        self.cards_flow = Gtk.FlowBox()
        self.cards_flow.set_max_children_per_line(4)
        self.cards_flow.set_min_children_per_line(3)
        self.cards_flow.set_selection_mode(Gtk.SelectionMode.NONE)
        self.card_widgets = {}
        for t in self.registry:
            self.card_widgets[t["name"]] = self._tool_card(t)
            self.cards_flow.append(self.card_widgets[t["name"]])
        self.cards_flow.set_hexpand(True)
        self.cards_flow.set_vexpand(True)
        tools.append(self.cards_flow)
        return self._scroll(tools)

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
            b = Gtk.Button(label=f"{m['icon']} {m['title']}")
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
        name = tool["name"]
        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_top(16); box.set_margin_bottom(16)
        box.set_margin_start(16); box.set_margin_end(16)
        ic = Gtk.Label()
        ic.set_markup(f"<span size='30000'>{CARD_ICONS.get(name, '•')}</span>")
        ic.set_xalign(0)
        box.append(ic)
        fn = Gtk.Label(xalign=0)
        fn.set_xalign(0)
        fn.set_markup(f"<span size='15000' font_family='Inter'>"
                      f"{escape(friendly_name(name))}</span>")
        box.append(fn)
        sub = Gtk.Label(xalign=0)
        sub.set_xalign(0)
        sub.set_wrap(True)
        sub.set_markup("<span size='12000' font_family='Inter'>loading…</span>")
        box.append(sub)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
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
                    f"<span size='13000' font_family='Inter'>"
                    f"All scanners launched. Each card updates as its "
                    f"scan finishes.</span>")
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
        col = Gtk.TreeViewColumn(None, Gtk.CellRendererText(), text=0)
        col.set_expand(True)
        view.append_column(col)
        wrap = self._wrap(view)
        wrap.set_hexpand(True)
        content.append(wrap)

        wizard_key = {"ufw": "ufw", "fail2ban": "fail2ban",
                      "tetragon": "tetragon", "arpwatch": "arpwatch",
                      "yara-watch": "yara", "yara-tmp-scan": "yara"}.get(name)
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
                ["📭 Nothing recorded yet. An event is written only "
                 "when something happens."])
        for g in grouped[:300]:
            e = g["ev"]
            mark = MARK_BY_SEVERITY.get(e.get("severity", ""), "")
            ts = local_clock(e.get("ts", ""))
            suffix = f"  ×{g['count']}" if g["count"] > 1 else ""
            self._detail_store.append(
                [f"{mark} {ts} {plain_sentence(e)}{suffix}   "
                 f"[{e.get('text', '')[:160]}]"])

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

        self.logs_store = Gtk.ListStore(str, str, str)
        view = Gtk.TreeView(model=self.logs_store, headers_visible=True)
        view.append_column(_fixed(
            Gtk.TreeViewColumn("State", Gtk.CellRendererText(), text=0), 56))
        view.append_column(_fixed(
            Gtk.TreeViewColumn("Time / tool", Gtk.CellRendererText(), text=1),
            300))
        last = Gtk.TreeViewColumn("Event", Gtk.CellRendererText(), text=2)
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
            mark = {"HIGH": "🔴", "CRITICAL": "🔴", "MEDIUM": "🟡",
                    "INFO": "🟢"}.get(e.get("severity", ""), "⚪")
            suffix = f"   ×{g['count']}" if g["count"] > 1 else ""
            self.logs_store.append(
                [mark, f"{local_clock(e.get('ts', ''))} "
                       f"{friendly_name(e.get('from_tool', ''))}",
                 e.get("text", "")[:400] + suffix])

    def _help_view(self):
        from ui.plain import FRIENDLY
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_top(26); box.set_margin_start(34); box.set_margin_end(34)
        box.append(self._h1("Help: what everything means"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        help_one = "The ONE dashboard for every tool protecting this computer."
        help_two = "Everything is in plain English. Raw details are a click away."
        lines = [
            "Wizard: a few plain questions, then a real change.",
            "Security: every protection, its state in words, pause or resume.",
            "Tools: the protections as cards, with scans and live progress.",
            "Settings: the look of the app, trusted items, and update lists.",
            "App firewall: watch what programs connect to, with learning mode.",
            "Updates: the lists show when they were fetched.",
            "Logs: the raw record, newest first.",
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
        box.append(self._h2("Every tool, one sentence each"))
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
        box.append(self._h2("Questions people ask"))
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
             "Harden — Undo last change reverts the newest applied change."),
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
        box.append(self._h2("Technical details"))
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

    def _harden_view(self):
        from ui.harden import HardenView
        return self._scroll(HardenView(win=self))

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

    def _hardening_truth(self) -> str:
        lines = []
        try:
            p = subprocess.run(
                ["systemctl", "show", "greywatch.service", "-p", "Restart",
                 "-p", "MemoryMax", "-p", "ProtectSystem"],
                capture_output=True, text=True, timeout=5)
            lines += [l for l in p.stdout.splitlines() if l.strip()]
        except Exception:
            lines.append("systemctl unavailable: unit truth hidden")
        try:
            p = subprocess.run(
                ["systemctl", "show", "greywatch.service", "-p",
                 "WatchdogLastPingUSec", "-p", "WatchdogTimestampUSec"],
                capture_output=True, text=True, timeout=5)
            wd = [l.split("=", 1)[-1].strip()
                  for l in p.stdout.splitlines() if l.strip()]
            if not wd:
                lines.append("watchdog: could not check")
                return "\n".join(lines)
            got_pings = bool(wd[-1] not in ("0", ""))
            lines.append(
                "watchdog: built-in (WatchdogSec=30, daemon self-pings, "
                + ("alive, pinging" if got_pings else "NO PINGS YET") + ")")
        except Exception:
            lines.append("watchdog: could not check")
        return "\n".join(lines)

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

    def _settings_view(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_top(26); box.set_margin_start(30); box.set_margin_end(30)
        box.append(self._h1("Settings"))

        theme_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        theme_row.append(Gtk.Label(label="Look of the app:"))
        self.theme_combo = Gtk.ComboBoxText()
        for label, kit in THEME_CHOICES.items():
            self.theme_combo.append(kit, label)
        picked = load_setting() or dark_default(self._theme_store.names())
        shown = picked if picked in THEME_CHOICES.values() \
            else dark_default(self._theme_store.names())
        self.theme_combo.set_active_id(shown)
        self.theme_combo.connect("changed", self._on_theme_pick)
        theme_row.append(self.theme_combo)
        theme_row.append(Gtk.Label(label="(changes instantly, remembered)"))
        box.append(theme_row)

        box.append(self._h2("Dashboard placement"))
        ws_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        ws_row.append(Gtk.Label(label="Launch workspace:"))
        ws_combo = Gtk.ComboBoxText()
        for i in range(1, 7):
            ws_combo.append(str(i), f"Workspace {i}")
        ws_combo.set_active_id(str(self._ws_pref()))
        ws_combo.connect("changed", self._on_ws_pick)
        ws_row.append(ws_combo)
        ws_row.append(Gtk.Label(
            label="(remembered; launch-ws3.sh honors it on every launch)"))
        box.append(ws_row)

        box.append(self._h2("App firewall options"))
        v6_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        v6_row.append(Gtk.Label(label="Filter IPv6 too:"))
        self._v6_check = Gtk.CheckButton()
        self._v6_check.set_active(bool(self._cfg6()))
        self._v6_check.connect("toggled", self._on_v6_toggle)
        v6_row.append(self._v6_check)
        v6_note = Gtk.Label(label="(off by default; IPv6 untouched)")
        v6_note.set_tooltip_text(
            "Turn on to filter IPv6 too. The daemon re-arms within ~10 s.")
        v6_row.append(v6_note)
        box.append(v6_row)

        box.append(self._h2("Daemon hardening (read-only, live truth)"))
        h_frame = Gtk.Frame()
        h_frame.add_css_class("gw-card")
        h_inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        h_inner.set_margin_top(10); h_inner.set_margin_bottom(10)
        h_inner.set_margin_start(10); h_inner.set_margin_end(10)
        h_label = Gtk.Label(xalign=0)
        h_label.set_xalign(0)
        h_label.set_wrap(True)
        h_label.set_text(self._hardening_truth())
        h_inner.append(h_label)
        h_frame.set_child(h_inner)
        box.append(h_frame)

        box.append(self._h2("Diagnostics (live)"))
        d_frame = Gtk.Frame()
        d_frame.add_css_class("gw-card")
        d_inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        d_inner.set_margin_top(10); d_inner.set_margin_bottom(10)
        d_inner.set_margin_start(10); d_inner.set_margin_end(10)
        self._diag_label = Gtk.Label(xalign=0)
        self._diag_label.set_xalign(0)
        self._diag_label.set_wrap(True)
        self._diag_label.set_text("Checking daemon, snapshot, firewall and "
                                  "network…")
        d_inner.append(self._diag_label)
        d_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        d_btn = Gtk.Button(label="Re-check now")
        d_btn.connect("clicked", self._on_diag_refresh)
        self._on_diag_refresh(d_btn)      # first truth arrives off-thread
        d_row.append(d_btn)
        d_note = Gtk.Label(label="(re-runs the checks)")
        d_note.set_tooltip_text(
            "A stale snapshot means stop and restart the app.")
        d_row.append(d_note)
        d_inner.append(d_row)
        d_frame.set_child(d_inner)
        box.append(d_frame)

        box.append(self._h2("Installed tools and their lights"))
        self.lights_store = Gtk.ListStore(str, str, str)
        lights_view = Gtk.TreeView(model=self.lights_store, headers_visible=False)
        lights_view.append_column(_fixed(
            Gtk.TreeViewColumn(None, Gtk.CellRendererText(), text=0), 56))
        lights_view.append_column(_fixed(
            Gtk.TreeViewColumn(None, Gtk.CellRendererText(), text=1), 320))
        last = Gtk.TreeViewColumn(None, Gtk.CellRendererText(), text=2)
        last.set_expand(True)
        lights_view.append_column(last)
        lights_view.set_size_request(-1, 360)
        lights_scroll = self._wrap(lights_view)
        lights_scroll.set_size_request(-1, 360)
        box.append(lights_scroll)
        legend = Gtk.Label(xalign=0)
        legend.set_xalign(0)
        legend.set_wrap(True)           # a long legend must wrap, not push
        legend.set_text(                # the whole page sideways (Pass 2)
            "\n".join([
                "Green = running. Red = installed but not running.",
                "Amber = paused in the app (a choice, not a fault).",
                "Yellow = needs attention or not installed.",
                "White = could not check.",
            ]))
        box.append(legend)

        box.append(self._h2("App firewall: what may use the internet"))
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
        box.append(fw_row)
        self.fw_status = Gtk.Label(xalign=0)
        self.fw_status.set_xalign(0)
        self.fw_status.set_wrap(True)
        box.append(self.fw_status)

        learn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.learn_check = Gtk.CheckButton(
            label="Learning mode: allow now, record, review later")
        self.learn_check.connect("toggled", self._on_learning_toggle)
        self.learn_for = Gtk.ComboBoxText()
        for ident, label in (("15", "15 minutes"), ("60", "1 hour"),
                             ("480", "8 hours"), ("0", "until I stop it")):
            self.learn_for.append(ident, label)
        self.learn_for.set_active_id("60")
        learn_row.append(self.learn_check)
        learn_row.append(self.learn_for)
        box.append(learn_row)
        self.learn_note = Gtk.Label(xalign=0)
        self.learn_note.set_xalign(0)
        self.learn_note.set_wrap(True)
        box.append(self.learn_note)
        self.fw_block = Gtk.CheckButton(
            label="Block anything not trusted (unknown apps stop until "
                  "you allow them)")
        self.fw_block.connect("toggled", self._on_fw_block_toggle)
        box.append(self.fw_block)

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
        box.append(learn_scroll)
        learn_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for label, handler in (
                ("Trust this program", self._on_learn_trust),
                ("Trust this site", self._on_learn_site),
                ("Block this site", self._on_learn_block),
                ("Clear the list", self._on_learn_clear)):
            b = Gtk.Button(label=label)
            b.connect("clicked", handler)
            learn_btns.append(b)
        box.append(learn_btns)

        box.append(self._h2("Updates: virus definitions and the "
                            "security list"))
        self.updates_note = Gtk.Label(xalign=0)
        self.updates_note.set_xalign(0)
        self.updates_note.set_wrap(True)
        box.append(self.updates_note)
        up_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.update_btn = Gtk.Button(label="Download the lists now")
        self.update_btn.connect("clicked", self._on_update_now)
        self.update_note = Gtk.Label(xalign=0)
        self.update_note.set_xalign(0)
        self.update_note.set_wrap(True)
        self.update_note.set_hexpand(True)
        up_row.append(self.update_btn)
        up_row.append(self.update_note)
        box.append(up_row)

        self.trust = self._trust
        box.append(self._h2("Sites trust list"))
        box.append(Gtk.Label(
            label="Sites on TRUSTED: allowed without asking. On BLOCKED: "
                  "never allowed. Subdomains included.", xalign=0))
        entry_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.trust_combo = Gtk.ComboBoxText.new_with_entry()
        for choice in discover.site_choices():
            self.trust_combo.append(
                choice["host"], f"{choice['host']} · {choice['why']}")
        self.trust_entry = self.trust_combo.get_child()
        self.trust_entry.set_placeholder_text(
            "pick a site from the list, or type one you know")
        self.trust_entry.connect("activate", self._on_trust_add, "allow")
        self.trust_combo.set_hexpand(True)
        entry_row.append(self.trust_combo)
        for label, verdict in (("Trust always", "allow"), ("Block always", "block")):
            b = Gtk.Button(label=label)
            b.add_css_class("gw-cta")
            b.connect("clicked", self._on_trust_add, verdict)
            entry_row.append(b)
        box.append(entry_row)
        self.trust_note = Gtk.Label(xalign=0)
        self.trust_note.set_xalign(0)
        self.trust_note.set_wrap(True)
        box.append(self.trust_note)
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
        box.append(trust_scroll)
        del_b = Gtk.Button(label="Remove the selected site")
        del_b.connect("clicked", self._on_trust_remove)
        box.append(del_b)

        box.append(self._h2("Trusted programs"))
        prog_one = "A trusted program connects to the internet without asking."
        prog_two = "Pick it from the list, or browse. No path to type."
        box.append(Gtk.Label(
            label=prog_one + "\n" + prog_two, xalign=0))
        app_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.app_combo = Gtk.ComboBoxText.new_with_entry()
        for prog in discover.programs():
            self.app_combo.append(prog["path"], prog["label"])
        self.app_entry = self.app_combo.get_child()
        self.app_entry.set_placeholder_text(
            "pick a program from the list, or browse…")
        self.app_entry.connect("activate", self._on_app_add, None)
        self.app_combo.set_hexpand(True)
        app_row.append(self.app_combo)
        browse_b = Gtk.Button(label="Browse…")
        browse_b.connect("clicked", self._on_app_browse)
        app_row.append(browse_b)
        add_app = Gtk.Button(label="Trust this program")
        add_app.add_css_class("gw-cta")
        add_app.connect("clicked", self._on_app_add, None)
        app_row.append(add_app)
        box.append(app_row)
        self.app_note = Gtk.Label(xalign=0)
        self.app_note.set_xalign(0)
        self.app_note.set_wrap(True)
        box.append(self.app_note)
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
        box.append(app_scroll)
        del_app = Gtk.Button(label="Remove the selected program")
        del_app.connect("clicked", self._on_app_remove)
        box.append(del_app)
        self._refresh_trust()
        self._refresh_apps()
        return self._scroll(box)

    def _refresh_trust(self):
        self.trust_store.clear()
        empty = True
        for verdict, entries in (("ALLOWED", sorted(self.trust.allow)),
                                 ("BLOCKED", sorted(self.trust.block))):
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
                           if path and verdict in ("ALLOWED", "BLOCKED")
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
            text = ("⚪ Firewall off: programs use the internet without "
                    "asking.")
        elif block:
            text = ("🟢 Firewall on, strict. Nothing you have not trusted "
                    "is allowed.")
        elif learning:
            learn_head = "🟢 Firewall on, learning."
            learn_body = "New connections pass once. Press Trust to keep one."
            text = learn_head + " " + learn_body
        else:
            watch_head = "🟢 Firewall on, watching."
            watch_body = "New connections pass once. Learning mode records them."
            text = watch_head + " " + watch_body
        self.fw_note.set_markup(
            f"<span size='13000' font_family='Inter'>{text}</span>")
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
        m = MARK_BY_SEVERITY.get(e.get("severity", ""), "-")
        return [m, local_clock(e.get("ts", "")), plain_sentence(e)]

    def refresh(self):
        snap = daemon_mod.load_status(str(DATA_DIR / "status.json"))
        try:
            events = daemon_mod.read_events(DATA_DIR / "events.jsonl", 400)
        except OSError:
            events = []
        if not events:                    # the event store is root-only (0600)
            events = snap.get("recent") or []   # → the daemon's public digest
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
        if known == 0 and not self._state_override:
            lead = "⚪ Status not available yet"
            tail = ("the monitor has not reported. Nothing was checked")
            if paused_n:
                tail += f" · {paused_n} paused in the app, not a fault"
        else:
            if attention == 0 and paused_n == 0:
                lead = "🛡 All protections running"
            elif attention == 0:
                lead = f"⏸ {paused_n} protection(s) paused in the app"
            else:
                lead = f"⚠ {attention} protection(s) need attention"
                if paused_n:
                    lead += f" · {paused_n} paused"
            tail = f"({running} of {len(self.registry)} running)"
        self.status_words.set_markup(
            f"<span size='19000' font_family='Barlow Condensed' weight='600'>"
            f"{lead}"
            f"</span>  <span size='12000' font_family='Inter' color='{pc_muted()}'>"
            f"{tail}</span>")

        now = _dt.datetime.now(_dt.timezone.utc)
        fresh = len(self.list_store) != len(self.registry)
        if fresh:
            self.list_store.clear()
        for idx, t in enumerate(self.registry):
            name = t["name"]
            info = tools.get(name, {})
            state = self._display_state(name, info, updated)
            paused = self.paused.is_paused(name)
            words = status_words(state, info.get("installed"), paused)
            stamp = self._update_detail(name)
            if stamp and not paused:
                words = ("up to date" if state == "GREEN"
                         else "the list is old")
            row = [CARD_ICONS.get(name, "•"), status_mark(state, paused),
                   friendly_name(name), words,
                   stamp or age_words(info.get("last_event"), now), name]
            if fresh:
                self.list_store.append(row)
            else:
                it = self.list_store.get_iter_from_string(str(idx))
                for col, val in enumerate(row):
                    self.list_store[it][col] = val
        self._restore_list_selection()
        if hasattr(self, "lights_store"):
            self.lights_store.clear()
            for t in self.registry:
                name = t["name"]
                info = tools.get(name, {})
                state = self._display_state(name, info, updated)
                self.lights_store.append([
                    status_mark(state, self.paused.is_paused(name)),
                    friendly_name(name),
                    status_words(state, info.get("installed"),
                                 self.paused.is_paused(name))])

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
                state_color = "#ffc940" if paused else {
                    "GREEN": "#4dd07a", "RED": "#ff5a52",
                    "YELLOW": "#ffc940",
                    "UNKNOWN": pc_muted()}.get(state, pc_muted())
                words = status_words(state, info.get("installed"), paused)
                stamp = self._update_detail(name)
                if stamp and not paused:
                    words = ("up to date" if state == "GREEN"
                             else "the list is old")
                head = (f"<span size='12000' font_family='Inter' "
                        f"color='{state_color}'>{status_mark(state, paused)} "
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

        self._setup_win = SetupWizardWindow(
            parent=self,
            open_dashboard=open_dashboard,
            open_chooser=lambda *_a: self._open_wizard())
        self._setup_win.present()
        self._setup_win.connect(
            "destroy", lambda _w: setattr(self, "_setup_win", None))

    def _open_wizard_for(self, key):
        from ui.wizard import RuleWizard
        self._wizard_win = RuleWizard(key, parent=self)
        self._wizard_win.connect("destroy", self._reload_trust)

    def _open_wizard(self):
        from ui.wizard import ToolChooser

        def picked(key):
            self._open_wizard_for(key)

        self._chooser = ToolChooser(on_pick=picked, parent=self)
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
