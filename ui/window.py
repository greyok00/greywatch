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
from ui.models import (service_words, recent_rows, age_words,
                       local_clock, recent_alerts, verdict_words)
from ui.plain import (sentence as plain_sentence, friendly_name, what_is,
                      escape, without_mark, soft as pc_soft,
                      muted as pc_muted, ok as pc_ok, state_colour as pc_state_colour,
                      severity_colour as pc_severity_colour,
                      severity_word as pc_severity_word)
from ui.themes import (ThemeStore, dark_default, load_setting, tab_symbol,
                       tab_symbol_active, THEME_CHOICES)
from ui.cards import SCAN_MODES, STRIP_MODES, quiet_note
from ui.scanview import NAMES as SCAN_NAMES
from ui.scanview import (ScanConsole, SCANNER_ORDER, card_text,
                         read_live, read_history, status_line)
from ui.protectdesk import ProtectDesk
from ui.toolsdesk import ToolsDesk
from ui.desk import aperture, related_box
from ui.assistant import AssistantPanel
from ui.harden import HardenView
from ui.hunterview import HunterPanel, unread_notes as hunter_unread
from ui.eventclock import attach as clock_attach, present_now
from hunter import store as hunter_store   # the hunter tick's read pointer
from ui.homepage import HomeDigest, SuiteCard, unread_notes as home_unread
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

# The six-tab shell: Home carries the AI, Threat Hunter
# carries every hunter output, the rest keep their jobs.  keeps the
# same six but orders them suite-first — the security suite reads before
# the hunter that supports it.
TABS = (("home", "Home"), ("scans", "Scans"), ("protect", "Protections"),
        ("tools", "Tools"), ("thunter", "Threat Hunter"),
        ("settings", "Settings"))

# Retired rail keys resolve once, centrally: 'security' and 'deep' were the
# two pages that split one job (the assistant's page words, and any caller
# that stored the key) — their content now lives on Protections.
_LEGACY_PAGE = {"security": "protect", "deep": "protect"}

# The settings panes' related-in-suite footers (approved mockup):
# where/what/Open hand-offs to pages that genuinely hold the subject.
# Open moves inside Settings when the key is a pane, else across pages.
_SETTINGS_RELATED = {
    "look": (("Connections", "The lists the firewall consults", "connections"),
             ("Tools", "Every protection, its row in the suite", "tools"),
             ("Threat Hunter", "The findings desk", "thunter")),
    "firewall": (("Connections", "Add trusted sites or programs", "connections"),
                 ("Protections", "Its row in the suite, with its last events",
                  "protect"),
                 ("Logs", "Decisions recorded as events via=appfw", "logs")),
    "connections": (("App firewall", "Learning answers move to the "
                     "firewall's lists", "firewall"),
                    ("Trusted sites", "The sites list the firewall consults",
                     "sites"),
                    ("Logs", "Connections seen while learning", "logs")),
    "computer": (("Diagnostics", "gw doctor's last check of the service",
                  "diagnostics"),
                 ("Logs", "The service's own words", "logs")),
    "diagnostics": (("This computer", "What the service is actually "
                     "enforcing", "computer"),
                    ("Logs", "The service's own words", "logs")),
    "updates": (("Tools", "Each scanner row in the registry", "tools"),
                ("Scans", "Run the scanners on request", "scans")),
    "sites": (("Trusted programs", "The programs that connect without "
               "asking", "programs"),
              ("Protections", "Its row in the suite, with its last events",
               "protect")),
    "programs": (("Trusted sites", "The sites the firewall consults", "sites"),
                 ("Connections", "Programs seen while learning",
                  "connections")),
}


def _fixed(col, width):
    col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
    col.set_fixed_width(width)
    return col


class MainWindow(Gtk.Window):
    def __init__(self, on_status_change=None, tray_available=True,
                 quit_cb=None):
        super().__init__(title="GreyWatch - Linux Endpoint Security")
        # A share of the monitor, not a fixed pixel count: the same
        # build opens on a 1366px laptop and on a 4K panel. Owner
        #: it then opens maximized, so the monitor's own
        # 16:9 or 16:10 shape is what it fills.
        self.set_default_size(*metrics.window_size())
        self.maximize()
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
        # Scans are the daemon's job: this app writes one request file and
        # renders what comes back. No process handle, no polling, nothing
        # to lose if the window closes mid-scan.
        self.data_dir = pathlib.Path(DATA_DIR)
        self._scan_live = None
        self._detail_dialog = None
        self._chooser = None
        self._wizard_win = None
        self._setup_win = None
        self._decisions_win = None
        self._selected_tool = None
        self._selected_from: str | None = None   # which desk holds it
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

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_child(outer)
        self._header(outer)
        self._tab_bar(outer)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)
        outer.append(self.stack)

        self._views = {}
        self._theme_store = ThemeStore(self)
        self._apply_saved_theme()
        self._build_all()
        self._show("home")
        self._tabs["home"].grab_focus()
        self._watchers()
        self.refresh()
        self._glib_ids = []
        self._glib_ids.append(
            GLib.timeout_add_seconds(5, self._periodic_refresh))
        # The scan half of the Protections page redraws once a second while
        # it is visible: the daemon rewrites scan-live.json at 1 Hz, so
        # anything faster would repaint identical text.
        self._glib_ids.append(
            GLib.timeout_add_seconds(1, self._scan_tick))
        # The bar moves far more often than the counter changes. A running
        # scanner reports no total, so the bar is indeterminate and every
        # pulse call steps it; without this it stayed an empty trough and
        # a long-empty counter read as "stuck at 0".
        self._tick_id(self._pulse_bars, 160)
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
        # The data-dir file monitors hold GLib sources too; a cancelled
        # one is the only way their change callback can never fire into
        # a destroyed window after quit.
        for m in list(getattr(self, "_monitors", ()) or ()):
            try:
                m.cancel()
            except Exception:            # noqa: BLE001 — already gone
                pass
        self._monitors = []
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
        title = Gtk.Label(label="GreyWatch", xalign=0)
        title.add_css_class("gw-title")
        sub = Gtk.Label(label="Linux endpoint security", xalign=0)
        sub.add_css_class("gw-subtitle")
        left.append(title)
        left.append(sub)
        bar.append(left)
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        bar.append(spacer)
        # The setup wizard keeps its launcher in the shell (constraint, plan
        # T2): a quiet header button, the hub itself unchanged.
        self.setup_btn = Gtk.Button(label="Setup")
        self.setup_btn.add_css_class("gw-mini")
        self.setup_btn.set_valign(Gtk.Align.CENTER)
        self.setup_btn.set_tooltip_text("Guided setup: pick one task")
        self.setup_btn.connect("clicked", lambda *_b: self._open_wizard())
        bar.append(self.setup_btn)
        self.header_pill = Gtk.Button(label="Checking…")
        self.header_pill.add_css_class("gw-pill")
        # A label stretches to the bar height by default; with a 999px
        # radius that painted a CIRCLE around the words instead of a chip.
        self.header_pill.set_valign(Gtk.Align.CENTER)
        # : the pill announced counts ("29 decisions waiting") with
        # nothing to click. A button now, and the count gets a surface.
        self.header_pill.set_tooltip_text(
            "decisions waiting for your answer; click to see them")
        self.header_pill.connect("clicked", self._open_decisions)
        bar.append(self.header_pill)
        # Every later activation hands the window manager the timestamp of
        # the last real pointer/keyboard event, not CurrentTime.
        clock_attach(self)
        parent.append(bar)

    def _apply_saved_theme(self):
        picked = load_setting()
        name = picked if picked in THEME_CHOICES.values() \
            else dark_default(self._theme_store.names())
        self._theme_store.apply(name)

    def _tab_bar(self, parent):
        """The main window shell, redrawn for :
        six symbol plates across the top — each tab shows its drawn symbol
        over the name, the active plate tints in the voice's accent, and
        Threat Hunter keeps the unread badge."""
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        bar.add_css_class("gw-tabs")
        parent.append(bar)
        self.tab_bar = bar
        self._tabs = {}
        self._badges = {}
        self._symbols = {}
        for key, label in TABS:
            b = Gtk.Button()
            plate = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            plate.set_halign(Gtk.Align.CENTER)
            sym = tab_symbol(key)
            sym.set_halign(Gtk.Align.CENTER)
            sym.set_valign(Gtk.Align.CENTER)
            plate.append(sym)
            self._symbols[key] = sym
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            lb = Gtk.Label(label=label)
            lb.xalign = 0.5
            lb.add_css_class("gw-tab-label")
            row.append(lb)
            badge = Gtk.Label(label="0")
            badge.add_css_class("gw-badge")
            badge.set_visible(False)
            badge.set_valign(Gtk.Align.CENTER)
            row.append(badge)
            plate.append(row)
            b.set_child(plate)
            b.set_tooltip_text(label)
            b.connect("clicked", self._tab_pick, key)
            bar.append(b)
            self._tabs[key] = b
            self._badges[key] = badge

    def _tab_pick(self, _b, key):
        self._show(key)

    def set_badge(self, key: str, count: int) -> None:
        """Unread count on a tab: a red pill with the number, hidden at
        zero. Nothing else may paint over the tab area."""
        badge = self._badges.get(key)
        if badge is None:
            return
        badge.set_text(str(int(count or 0)))
        badge.set_visible(bool(int(count or 0)))

    def _show(self, key):
        # Retired rail keys land where their content went; one map so every
        # caller (assistant words, wizard, tick code) resolves the same way.
        key = _LEGACY_PAGE.get(key, key)
        if key not in self._builders:
            key = "home"
        if key not in self._views:
            self._add_view(key, self._builders[key]())
        self.stack.set_visible_child_name(key)
        for k, b in self._tabs.items():
            on = k == key
            if on:
                b.add_css_class("gw-tab-on")
            else:
                b.remove_css_class("gw-tab-on")
            tab_symbol_active(self._symbols.get(k), on)
        # A page built on demand starts with placeholder text ("checking…")
        # and the periodic refresh is up to five seconds away, so the user
        # saw empty cards right after switching. Paint the real snapshot the
        # moment the page is shown.
        self.refresh()
        if key == "thunter":
            # The hunter feed redraws only on the one-second tick, so the
            # tab could open on its empty state for up to a second.
            self._hunter_tick()

    def _build_all(self):
        self._views = {}
        # The six tabs, plus the three old
        # rail pages (harden/logs/help) that stay reachable from Tools and
        # from the assistant. Pages build on demand — _show adds them —
        # so a tab click only pays for the page it opens; Home builds
        # eagerly because it is what launches.
        self._builders = {"home": self._home_view,
                          "thunter": self._thunter_view,
                          "scans": self._scans_view,
                          "protect": self._protect_view,
                          "tools": self._tools_view,
                          "settings": self._settings_view,
                          "harden": self._harden_view,
                          "logs": self._logs_view,
                          "help": self._help_view}
        self._add_view("home", self._builders["home"]())

    def _add_view(self, key, widget):
        # One cap and one center for every page (ui/desk.aperture): with
        # the window maximized on a 4K panel the raw content used to
        # stretch rows and paragraphs edge to edge, which read as
        # distortion.
        shown = aperture(widget)
        self.stack.add_named(shown, key)
        self._views[key] = shown

    @staticmethod
    def _page_box(spacing=None):
        """Every top-level page uses this inset so the app reads as one."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                      spacing=metrics.PAGE_SPACING if spacing is None
                      else spacing)
        box.set_margin_top(metrics.PAGE_TOP)
        box.set_margin_bottom(metrics.PAGE_BOTTOM)
        box.set_margin_start(metrics.PAGE_X)
        box.set_margin_end(metrics.PAGE_X)
        return box

    def _ensure_view(self, key):
        if key not in self._views:
            self._add_view(key, self._builders[key]())

    def _home_view(self):
        """Home: the AI main screen. The assistant
        conversation is the page and the recent-activity glance sits under
        it at its old fixed size; unread hunter notes pin on top.
        (suite first,: a plain-language protections verdict
        card leads the page — this is a full security suite before it is
        a threat hunter."""
        box = self._page_box(12)
        box.set_vexpand(True)

        # Suite lead: one verdict line over status.json, above
        # everything — suite state first, hunter notes after.
        self.suite_card = SuiteCard(self.data_dir,
                                    on_open=lambda *_a: self._show("protect"))
        box.append(self.suite_card)

        # Pinned digest next (unread
        # hunter notes pin until they are read; after that the
        # conversation carries them as report bubbles. Nothing here but
        # hunter-written files rendered.
        self.digest = HomeDigest(
            self.data_dir, on_explain=self._ask_assistant,
            on_open=lambda *_a: self._show("thunter"))
        self.digest.set_visible(False)
        box.append(self.digest)

        # Chat centre: the assistant IS the page, and a
        # visible restart affordance covers a failed model wake (a fresh Llm
        # restarts — start is one-shot per instance).
        self.assistant_panel = AssistantPanel(
            self.registry, self._get_status, self._get_recent,
            lambda: self.chat_llm, self._assistant_intent)
        self.assistant_panel.add_css_class("gw-chat")
        self.chat_retry = Gtk.Button(label="Retry model")
        self.chat_retry.set_visible(False)
        self.chat_retry.connect(
            "clicked", lambda *_a: self._start_chat_llm())
        self.assistant_panel.append(self.chat_retry)
        # The chat is the point of the page: it takes the spare height.
        self.assistant_panel.set_vexpand(True)
        self.assistant_panel.set_valign(Gtk.Align.FILL)
        # A floor, not a height: 280 keeps the composer and two answers
        # usable inside the 720px minimum window without forcing a page
        # scroll.
        self.assistant_panel.set_size_request(-1, 280)
        box.append(self.assistant_panel)
        # A theme switch rebuilds this page — and the panel with it. Hand
        # back the conversation and the anchors the previous panel carried,
        # then re-apply the model state to the banner (the test watched the
        # whole chat vanish after 'change theme to light mode',.
        snap = getattr(self, "_chat_snapshot", None)
        if snap:
            self.assistant_panel.restore_transcript(snap)
            self._chat_snapshot = None
        if getattr(self, "_chat_state", None) is not None:
            ok, err = self._chat_state
            self.assistant_panel.note_state(ok, err)
            if getattr(self, "chat_retry", None) is not None:
                self.chat_retry.set_visible(not ok)

        box.append(self._h2("Recent activity"))
        # [tool icon name, severity dot, time, sentence]
        # 4 = severity ink for the state dot in column 1.
        self.recent_store = Gtk.ListStore(str, str, str, str, str)
        # A fresh store must always be filled: the seen-guard belongs to this
        # store, and a rebuild from another page (theme switch) left the new
        # feed blank because the guard carried the old event list.
        self._recent_seen = None
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
        box.append(rf)
        # No page scroller: Home is one viewport. The chat absorbs the spare
        # height and the activity feed keeps a fixed glance size, so the
        # page fits the window at its 1100x720 minimum instead of hiding the
        # newest activity below the fold.
        return box

    def _sync_selection_buttons(self):
        """The dossier's Pause/Resume/Details act on the selection: dim them
        until a protection is selected, so a click can't end in a
        "Select a protection first." surprise (bug sweep B5). With a
        selection, the desk re-renders the dossier's decide-here row, so
        the per-selection dimming and the Resume/Pause labels stay true."""
        sel = bool(self._selected_tool)
        # Guard-safe: the segmented lives on the Protections desk, which
        # builds on demand - whichever page composes first must not
        # depend on the other having been built.
        for b in (getattr(self, "pause_btn", None),
                  getattr(self, "resume_btn", None),
                  getattr(self, "details_btn", None)):
            if b is not None:
                b.set_sensitive(sel)
        desk = getattr(self, "protect_desk", None)
        if desk is not None and sel and desk._facts \
                and self._selected_from == "protect":
            desk.fill_dossier(self._selected_tool)
        tools = getattr(self, "tools_desk", None)
        if tools is not None and sel and tools._facts \
                and self._selected_from == "tools":
            tools.fill_dossier(self._selected_tool)

    def _details_selected(self, name=None):
        """The protect desk's Details button rides the selection; the
        Tools desk's Tail button hands one record to open."""
        name = name or self._selected_tool
        if name:
            self._open_detail(name)

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
            self._selected_from = "protect"
            self._sync_selection_buttons()
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
            self._selected_from = "protect"
            self._sync_selection_buttons()
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
            # Widget-free before Settings builds: the learning
            # switch is born with the Settings pane, so the first learning
            # confirm from chat crashed with AttributeError. The direct
            # store start/stop is the same thing the switch's handler does.
            if getattr(self, "learn_check", None) is None:
                if want_on:
                    self._learn_store.start(60)
                else:
                    self._learn_store.stop()
                self._refresh_fw()
                audit.record("learning", value, True)
                return
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
            # crashed before recording.
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
            # The value arrives lowercased in its validate and its
            # description, so the executor reads the same contract: the
            # model echoing a user's capitalised page word must open
            # the page, not silently do nothing after the confirm dialog.
            key = PAGES.get(str(value or "").lower())
            if key:
                self._show(key)
                audit.record("open_page", value, True)
            return
        # "theme" was here; the assistant does not change the look any
        # more. Unknown actions fall through: the
        # model's wording gets answered with the deterministic reply and
        # nothing acts on it. Appearance stays in Settings.

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
        start is one-shot per instance (assistant/llm.py contract)."""
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

    def _harden_view(self):
        """Endpoint Hardening: the baseline pass, as its own page.

        The same checks the wizard runs, with the controls visible: run
        the checks, read every card, apply with one password prompt,
        verify, undo. It used to exist only inside the setup wizard, and
        its doorway was a card at the bottom of the protection list —
        reached by scrolling past everything else.
        """
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        self.harden_view = HardenView(win=self)
        scroller.set_child(self.harden_view)
        return scroller

    def _protect_view(self):
        """Protections: the protections desk (depth
        mockup, tasks #27/#29). The verdict chip leads the
        command strip, the stat band tallies what the rows carry, the
        coverage strip groups the registry into its protection classes,
        and the rows share the page with the picked row's side-by-side
        dossier (facts, the scanner's own units, the next step). Nothing
        the old rail did is lost: pause/resume/details ride the dossier
        per selection, the show-all switch stays the filter, and every
        row keeps its own Scan and Pause as control, never suggestion.
        """
        page = self._page_box(8)
        # Per-scanner names the dossier's Run scan grows (whole-session
        # keys like "full" and "scan-all" never appear per protection);
        # yara-watch's run routes to its Quick scan sibling.
        runset = {"clamav", "rkhunter", "lynis", "aide",
                  "yara-tmp-scan", "yara-watch"}
        desk = ProtectDesk(
            self.registry,
            on_select=self._protect_picked,
            on_scan=self._run_protection,
            on_wizard=self._open_wizard_for,
            on_refresh=self.refresh,
            on_filter=lambda: self._show_filter(
                self.protect_desk.show_all_btn),
            enable_all=lambda: self._on_panic(None),
            on_pause_selected=self._pause_selected,
            on_resume_selected=self._resume_selected,
            on_details_selected=self._details_selected,
            on_navigate=self._show,
            runset=runset,
            wizard_for=WIZARD_FOR)
        self.protect_desk = desk
        self.status_words = desk.status_words
        self.counts = desk.counts
        self.show_all_btn = desk.show_all_btn
        self.panic_btn = desk.enable_all
        self.pause_btn = desk.pause_btn
        self.resume_btn = desk.resume_btn
        self.details_btn = desk.details_btn
        page.append(desk)
        # No selection yet at build time: Pause/Resume/Details open dimmed
        # until a row is picked (carried contract).
        self.sel_note = Gtk.Label(xalign=1)
        self.sel_note.set_xalign(1)
        self.sel_note.set_text("Select a protection.")
        self.sel_note.add_css_class("gw-page-meta")
        page.append(self.sel_note)
        self._sync_selection_buttons()

        # Rows build whole at page build (they already did); refresh
        # paints them in place and hands them to the desk to mount under
        # their groups. Row frames keep their shipped paint contract.
        self.card_widgets = {}
        self._card_order = self._protection_order()
        for name in self._card_order:
            tool = self.by_name.get(name) or {"name": name}
            self.card_widgets[name] = self._tool_card(tool)
        return page

    def _show_filter(self, switch):
        """One show-all filter for both desks: whichever switch the
        a toggle becomes the page's filter (tests and refresh()
        read the one name), and the other desk's switch body is synced
        silently so the filter never drifts across pages."""
        if getattr(self, "_show_syncing", False):
            return
        self._show_syncing = True
        self.show_all_btn = switch
        show = switch.get_active()
        for desk_key in ("protect_desk", "tools_desk"):
            other = getattr(getattr(self, desk_key, None),
                            "show_all_btn", None)
            if other is not None and other is not switch \
                    and other.get_active() != show:
                other.set_active(show)
        self._show_syncing = False
        self.refresh()

    def _tools_picked(self, key):
        """The registry desk's pick: the same selection state the tree
        set on click, then the record fills (facts from the last
        refresh)."""
        self._selected_tool = key
        self._selected_from = "tools"
        if key:
            self.sel_note.set_text(f"Selected: {friendly_name(key)}")
        else:
            self.sel_note.set_text("Select a tool.")
        self._sync_selection_buttons()
        tools = getattr(self, "tools_desk", None)
        if tools is not None:
            if key and tools._facts:
                tools.fill_dossier(key)
            else:
                tools._fill_empty()

    def _protect_picked(self, key):
        """The desk's pick: the same selection state the cards used to set
        on click, then the dossier fills (facts from the last refresh)."""
        self._selected_tool = key
        self._selected_from = "protect"
        if key:
            self.sel_note.set_text(f"Selected: {friendly_name(key)}")
        else:
            self.sel_note.set_text("Select a protection.")
        self.protect_desk.select(key)
        self._sync_selection_buttons()
        if self.protect_desk._facts:
            self.protect_desk.fill_dossier(key)
        else:
            self.protect_desk._fill_empty()

    def _run_protection(self, name):
        """Run one protection's own scan: the same runner the Scans page's
        buttons and the row cards use, so no new power appears."""
        key = "yara-tmp-scan" if name == "yara-watch" else name
        mode = next((m for m in SCAN_MODES if m["key"] == key), None)
        if mode:
            self._start_scan(None, mode)

    def _scans_view(self):
        """Scans: the mode strip and the scan console on one page (the
 split; now on the approved desk shape, ). The
        console's feed lists the selected run scanner by scanner in their
        own units, findings keep their dialogs, and the dossier carries
        the picked scanner's record."""
        page = self._page_box(8)
        page.append(self._h1("Scans"))
        page.append(self._scan_strip())
        self.scanconsole = ScanConsole(self.data_dir,
                                       on_explain=self._ask_assistant,
                                       on_scan=self._rescan_tool,
                                       on_show=self._show_folder,
                                       on_navigate=self._show)
        page.append(self.scanconsole)
        return page

    def _thunter_view(self):
        """Threat Hunter: the hunter desk (. The panel mounts whole — command strip, stat band,
        coverage, feed and side-by-side dossier — and its "related in the
        suite" rows hand the finding back to the other pages."""
        page = self._page_box(8)
        self.hunter_panel = HunterPanel(self.data_dir,
                                        on_ask=self._ask_assistant,
                                        on_navigate=self._show)
        page.append(self.hunter_panel)
        return page

    def _tools_view(self):
        """Tools: the registry as a desk (depth mockup
, ). Rows keep their dot, name and real name,
        and the tool's own last activity becomes the row's fact; the
        picked row's record opens beside the feed. Nothing the old rail
        did is lost: the Refresh and show-all controls stay on the
        strip (one shared filter, see _show_filter), and the Elsewhere
        pointers keep their chips plus the per-record hand-offs."""
        page = self._page_box(8)
        page.append(self._h1("Tools"))
        desk = ToolsDesk(
            self.registry,
            on_select=self._tools_picked,
            on_refresh=self.refresh,
            on_filter=lambda: self._show_filter(
                self.tools_desk.show_all_btn),
            on_details=self._details_selected,
            on_navigate=self._show)
        self.tools_desk = desk
        self.status_words = desk.status_words
        self.counts = desk.counts
        self.show_all_btn = desk.show_all_btn
        page.append(desk)
        self.sel_note = Gtk.Label(xalign=1)
        self.sel_note.set_xalign(1)
        self.sel_note.set_text("Select a tool.")
        self.sel_note.add_css_class("gw-page-meta")
        page.append(self.sel_note)
        self._sync_selection_buttons()

        sec = Gtk.Label(xalign=0)
        sec.set_xalign(0)
        sec.add_css_class("gw-eyebrow")
        sec.set_text("ELSEWHERE")
        page.append(sec)
        links = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for key, label in (("harden", "Endpoint hardening"),
                           ("thunter", "Threat Hunter"),
                           ("logs", "Raw log"),
                           ("help", "Reference card")):
            b = Gtk.Button(label=label)
            b.add_css_class("gw-chip")
            b.connect("clicked", self._tab_pick, key)
            links.append(b)
        page.append(links)
        return page

    def _protection_order(self):
        """Scanners first, in the order a scan runs them; then the rest."""
        names = [t["name"] for t in self.registry]
        head = [k for k in SCANNER_ORDER if k in names]
        return head + [n for n in names if n not in head]

    def _scan_tick(self):
        """Redraw the live scan half while a page that can show it is up;
        the hunter tick only matters on its own tab (and its panel is a
        no-op until that tab has been opened)."""
        vis = self.stack.get_visible_child_name()
        if vis not in ("scans", "protect", "thunter"):
            return True
        console = getattr(self, "scanconsole", None)
        if vis in ("scans", "protect") and console is not None \
                and console.get_root() is not None:
            console.refresh()
            self._scan_live = read_live(self.data_dir)
            self._paint_scan_rows()
        self._hunter_tick()
        return True

    def _hunter_tick(self):
        """Keep the hunter feed current while its tab is shown; seeing it
        is reading it, so the unread badge clears the moment it renders."""
        try:
            panel = getattr(self, "hunter_panel", None)
            # Only the tab being up counts as seeing it: the same tick
            # rides the scans/protect pages too, and without this check
            # it marked hunter notes read while the user was elsewhere
            # (the badge cleared without a single glance at the feed).
            if panel is None or panel.get_root() is None \
                    or self.stack.get_visible_child_name() != "thunter":
                return
            # Capture the pointer BEFORE the paint: a note that lands
            # between the paint and the mark is marked by the next tick,
            # not born read (the mark reads what the desk actually showed).
            pointer = None
            try:
                notes = hunter_store.read_defender(
                    self.data_dir, limit=hunter_store.DEFENDER_KEEP)
                pointer = max((str(n.get("ts") or "") for n in notes),
                              default="")
            except OSError:
                pointer = None
            panel.refresh()
            if hunter_unread(self.data_dir):
                panel.mark_seen(pointer or None)
                panel.refresh(force=True)
        except Exception:  # noqa: BLE001 — a malformed field must not
            return         # kill the tick source that re-runs each minute

    def _refresh_home_hybrid(self) -> None:
        """The Home hybrid: the pinned digest tops the
        page while notes are unread; once they are read, each becomes one
        report bubble in the conversation below — exactly once, and only
        for notes a digest of this window actually pinned. History nobody
        saw pinned reports nothing back."""
        dig = getattr(self, "digest", None)
        if dig is None:
            return
        # The digest follows the window's data dir: tests and tools may
        # re-point it after the page was built.
        dig.data_dir = self.data_dir
        prev = getattr(self, "_pinned_ids", None)
        if prev is None:
            prev = self._pinned_ids = set()
        handed = getattr(self, "_reports_shown", None)
        if handed is None:
            handed = self._reports_shown = set()
        dig.refresh()
        cur = set(getattr(dig, "last_ids", ()))
        from hunter import explain, store
        # Notes that were pinned last tick and are behind the read pointer
        # now: they left the pin — report them, oldest first, once. The
        # pointer check keeps an unpinned-by-overflow unread note from
        # reporting while it still belongs on the digest.
        since = explain.read_pointer(self.data_dir)
        leaving = sorted(
            t for t in prev - cur - handed if t and t <= since)
        self._pinned_ids = cur
        if not leaving:
            return
        panel = getattr(self, "assistant_panel", None)
        if panel is None:
            return
        from ui.homepage import report_text
        by_ts = {str(n.get("ts") or ""): n
                 for n in store.read_defender(
                     self.data_dir, limit=store.DEFENDER_KEEP)}
        notes = [by_ts[ts] for ts in leaving if ts in by_ts]
        handed.update(leaving)
        if not notes:
            return
        ids = {n.get("finding_id") for n in notes}
        findings = {f.get("id"): f
                    for f in store.read_findings(self.data_dir, 200)
                    if f.get("id") in ids}
        panel.report_findings(
            report_text(n, findings.get(n.get("finding_id")))
            for n in notes)

    def _ask_assistant(self, question: str, finding: dict | None = None):
        """Open Home and put a real question in the composer.

        When the question came from a finding, the row travels with it so
        the advice engine answers about that exact line instead of
        guessing from its words.
        """
        panel = getattr(self, "assistant_panel", None)
        if panel is None:
            return
        self._show("home")
        if finding:
            panel.ask(question, finding=finding)
        else:
            panel.ask(question)

    def _pulse_bars(self):
        """Step the indeterminate block on every bar whose scanner runs."""
        if self.stack.get_visible_child_name() not in ("scans", "protect"):
            return True
        for frame in (getattr(self, "card_widgets", {}) or {}).values():
            bar = getattr(frame, "_bar", None)
            if (bar is not None and bar.get_visible()
                    and bar.has_css_class("busy")):
                bar.pulse()
        return True

    def _paint_scan_rows(self):
        """Paint the per-scanner progress bar and log into each row."""
        live = getattr(self, "_scan_live", None)
        scanners = (live or {}).get("scanners") or {}
        total = len(scanners)
        for name, frame in (getattr(self, "card_widgets", {}) or {}).items():
            bar = getattr(frame, "_bar", None)
            if bar is None:
                continue
            sc = scanners.get(name)
            line = getattr(frame, "_scanline", None)
            log = getattr(frame, "_log", None)
            if not sc:
                for w in (bar, line, log):
                    if w is not None:
                        w.set_visible(False)
                for cls in ("scan-run", "scan-queued", "scan-ok",
                            "scan-fail"):
                    frame.remove_css_class(cls)
                continue
            st = sc.get("state") or "queued"
            for cls in ("ok", "fail", "idle", "busy"):
                bar.remove_css_class(cls)
            # A scanner row wears its scan state on the left edge, so the
            # page reads at a glance: accent = working now, grey = waiting,
            # green = finished, red = needs a look.
            for cls in ("scan-run", "scan-queued", "scan-ok", "scan-fail"):
                frame.remove_css_class(cls)
            frame.add_css_class({
                "running": "scan-run", "done": "scan-ok",
                "failed": "scan-fail", "interrupted": "scan-fail",
            }.get(st, "scan-queued"))
            if st == "running":
                # No scanner reports a total, so a pulse is the honest
                # glyph for "working"; the counter beside it is the fact.
                bar.set_fraction(0.0)
                bar.add_css_class("busy")
            elif st == "done":
                bar.set_fraction(1.0)
                bar.add_css_class("ok")
            elif st in ("failed", "interrupted"):
                bar.set_fraction(1.0)
                bar.add_css_class("fail")
            else:
                bar.set_fraction(0.0)
                bar.add_css_class("idle")
            position = ""
            if total > 1:
                position = f" · step {int(sc.get('order') or 0)} of {total}"
            text = card_text(name, live) or ""
            if st == "failed" and sc.get("detail"):
                text = f"Failed - {sc['detail']}"
            if st == "queued" and sc.get("waiting_for"):
                text = f"Queued - starts after {sc['waiting_for']}"
            line.set_text((text + position).strip(" ·"))
            lines = [str(x) for x in (sc.get("log") or []) if str(x).strip()]
            log.set_text("\n".join(lines[-3:]) if lines else "")
            # A queued scanner shows no bar at all: an empty trough reads
            # as "stuck at 0", which is not what happened.
            bar.set_visible(st in ("running", "done", "failed",
                                   "interrupted"))
            line.set_visible(True)
            log.set_visible(bool(lines))

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
            "Scans run in the background, throttled: CPU and memory are "
            "capped so you can keep working. Max speed removes the caps "
            "for one run. Results appear here.</span>")
        right.append(self.scan_status)
        btns = Gtk.FlowBox()
        # One compact row of actions at their natural width: a 3-wide
        # stretch made each scan button a 600px banner across the card.
        btns.set_max_children_per_line(6)
        btns.set_min_children_per_line(1)
        btns.set_homogeneous(False)
        btns.set_selection_mode(Gtk.SelectionMode.NONE)
        btns.set_halign(Gtk.Align.START)
        btns.set_row_spacing(8)
        btns.set_column_spacing(8)
        self._scan_btns = {}
        # STRIP_MODES, not SCAN_MODES: the per-tool keys the protection
        # rows still use are in SCAN_MODES too, but the strip shows one
        # Full scan, not a separate deep-ClamAV button beside it.
        for m in STRIP_MODES:
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
        # minimum instead of scrolling.
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

        # Live state only — "● service running" / "● service needs
        # attention". The extra detail sentence lives in the row's tooltip;
        # at a 400px column it used to truncate to "● runni…" and read as a
        # defect. The noun "service" is load-bearing: the row below carries
        # the scan's own sentence, and a bare "running" beside "Last scan
        # failed" read as a contradiction.
        sub = Gtk.Label(xalign=0)
        sub.set_xalign(0)
        sub.set_size_request(metrics.STATE_COLUMN_PX, -1)
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
            cfg.set_tooltip_text("Guided setup - no commands to type")
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
        # A dimmed Pause next to a green "running" row reads as broken: say
        # why it is dimmed (this protection has no service to pause) (B3).
        if not tool.get("unit"):
            pause.set_tooltip_text(
                "Nothing to pause - this protection has no service of "
                "its own")
        pause.connect("clicked", lambda *_b, n=name:
                      self._resume_tool(n) if self.paused.is_paused(n)
                      else self._pause_tool(n))
        box.append(pause)

        # The whole row opens the dossier — a row is the affordance, the
        # way a Finder/System Settings list row is. The desk fills the
        # dossier and keeps the row's selection paint; Pause/resume and
        # Details stay their own buttons in it.
        click = Gtk.GestureClick()

        def _row_clicked(_g, _n, _x, _y, n=name):
            self._protect_picked(n)

        click.connect("released", _row_clicked)
        frame.add_controller(click)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        outer.append(box)
        scanline = bar = log = None
        if name in SCANNER_ORDER:
            # The scan half of the row: one sentence, a horizontal bar, and
            # the last lines the scanner itself printed. Indented to the
            # name so the eye reads it as part of this protection.
            scanline = Gtk.Label(xalign=0)
            scanline.set_xalign(0)
            scanline.set_wrap(True)
            scanline.add_css_class("gw-scanline")
            scanline.set_margin_start(31)
            scanline.set_margin_end(8)
            scanline.set_margin_bottom(2)
            outer.append(scanline)
            bar = Gtk.ProgressBar()
            bar.add_css_class("gw-scanbar")
            bar.set_show_text(False)
            bar.set_size_request(-1, 6)
            bar.set_margin_start(31)
            bar.set_margin_end(8)
            bar.set_visible(False)
            outer.append(bar)
            log = Gtk.Label(xalign=0)
            log.set_xalign(0)
            log.set_wrap(True)
            log.set_lines(3)
            log.set_ellipsize(Pango.EllipsizeMode.END)
            log.add_css_class("gw-scanlog")
            log.set_margin_start(31)
            log.set_margin_end(8)
            log.set_margin_bottom(5)
            log.set_visible(False)
            outer.append(log)

        frame.set_child(outer)
        frame.set_tooltip_text(f"{friendly_name(name)} - {what_is(name)}")
        frame._sub = sub
        frame._tool = tool_name
        frame._pause_btn = pause
        frame._scanline = scanline
        frame._bar = bar
        frame._log = log
        return frame

    def _request_scan(self, mode) -> tuple[bool, str]:
        """Ask the daemon to scan by writing one validated key.

        No password, no helper, no command text: the daemon honours only
        the six fixed keys. The request is
        written to a temporary file and renamed, so the daemon never sees
        half a document.
        """
        key = mode.get("key")
        if key not in {m["key"] for m in SCAN_MODES}:
            return False, "unknown scan"
        doc = {"id": time.strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(2).hex(),
               "key": key,
               "requested_at": _dt.datetime.now(
                   _dt.timezone.utc).isoformat(timespec="seconds")}
        target = self.data_dir / "scan-request.json"
        tmp = self.data_dir / "scan-request.new"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(doc))
            os.replace(tmp, target)
        except OSError as e:
            return False, str(e)
        return True, key

    def _start_scan(self, _btn, mode, allowed: bool = False):
        # Max speed is the one uncapped run, so it asks first. The chat path
        # is the exception: the assistant panel has already shown its own
        # confirm dialog and left the pending marker behind.
        if mode.get("key") == "max-speed" and not allowed \
                and getattr(self, "_assistant_pending", None) \
                != ("scan", "max-speed"):
            self._confirm_max_speed(mode)
            return
        # The strip (ring + status line) lives on the Scans tab now; make
        # sure it exists so the note and the ring land even when the
        # request comes from Protections or the assistant.
        self._ensure_view("scans")
        ok, msg = self._request_scan(mode)
        pending = getattr(self, "_assistant_pending", None)
        if pending == ("scan", mode.get("key")):
            self._assistant_pending = None
        audit.record("scan", mode.get("key", ""), ok)
        if hasattr(self, "circle"):
            self.circle.start(mode["title"]) if ok else self.circle.stop()
        if hasattr(self, "scan_status"):
            if ok:
                note = mode.get("run_note", "")
                shown = f"{mode['title']}: asked for" + \
                    (f" - {note}" if note else "")
            else:
                shown = f"{mode['title']}: not started: {msg}"
            self.scan_status.set_markup(
                f"<span size='13000' font_family='Inter'>"
                f"{escape(shown)}. Progress below when it runs.</span>")
        if not ok:
            return
        self._show("scans")

    def _confirm_max_speed(self, mode):
        """One ask before the single uncapped run. The everyday Full scan
        stays throttled; this says what it costs before it starts."""
        dlg = Gtk.Dialog(title=mode["title"],
                         transient_for=self.get_root(), modal=False)
        dlg.set_default_size(*metrics.popup_size())
        dlg.add_css_class("gw-popup")
        ok = dlg.add_button("Start at max speed", Gtk.ResponseType.ACCEPT)
        ok.add_css_class("destructive-action")
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        heading = Gtk.Label(xalign=0)
        heading.set_xalign(0)
        heading.set_wrap(True)
        heading.set_max_width_chars(44)
        heading.set_markup(
            "<span size='13000' font_family='Inter' weight='600'>"
            "Run every scanner with no CPU or memory caps?</span>")
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        body.set_max_width_chars(60)
        # This desktop draws no title bar, so the question has to be in the
        # body or the box arrives asking nothing (same lesson as the
        # assistant confirm and the decision popup).
        body.set_text(
            "This is the one uncapped run: scanners take the CPU and memory "
            "they need, and the desktop may lag until the scan finishes. "
            "The everyday Full scan stays throttled. Cancel leaves "
            "everything as it is.")
        content = dlg.get_content_area()
        content.set_margin_top(14)
        content.set_margin_bottom(14)
        content.set_margin_start(20)
        content.set_margin_end(20)
        content.set_spacing(8)
        content.append(heading)
        content.append(body)
        dlg.connect("response", self._max_speed_response, mode)
        present_now(dlg)

    def _max_speed_response(self, dlg, resp, mode):
        dlg.destroy()
        if resp == Gtk.ResponseType.ACCEPT:
            self._start_scan(None, mode, allowed=True)

    def _rescan_tool(self, tool_name):
        """Queue one scanner again, from a finding or a tool row."""
        self._open_scan_for(None, tool_name)

    def _show_folder(self, path):
        """Open the folder that holds a file, in the desktop's own file
        manager. The app only asks; it never deletes or moves anything."""
        folder = str(pathlib.Path(str(path)).parent)
        subprocess.Popen(["xdg-open", folder], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)

    def _open_scan_for(self, _btn, tool_name):
        key = "yara-tmp-scan" if tool_name == "yara-watch" else tool_name
        mode = next((m for m in SCAN_MODES if m["key"] == key), None)
        if mode:
            self._start_scan(None, mode)
        else:
            self._show("scans")

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
            self._ensure_view("scans")
            self.scan_status.set_markup(
                f"<span size='13000' font_family='Inter'>"
                f"{escape(friendly_name(name))} has no service to pause.</span>")
            self._assistant_record_outcome(False)
            return
        # : every greywatch dialog is non-modal - a grab here locks
        # the desk and marco bounces the dashboard's own close clicks.
        dlg = Gtk.Dialog(title=f"Pause {friendly_name(name)}?",
                         transient_for=self, modal=False)
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
        present_now(dlg)

    def _resume_tool(self, name):
        self._toggle_tool(name, pause=False)

    def _reconcile_pause_markers(self, snap):
        # A pause may only be claimed while the protection is really
        # stopped. If the monitor reports it running, the marker lied —
        # it is dropped, and no row ever says paused over a live guard.
        tools = snap.get("tools", {})
        setter = getattr(self.paused, "set", None)
        if not callable(setter):
            return
        if self.paused.is_paused("appfw"):
            # The app firewall has its own switch and its own running
            # state; a pause record for it was the source of "app firewall
            # paused by itself". Never claim it again.
            setter("appfw", False)
        for t in self.registry:
            name = t["name"]
            if name == "appfw" or not self.paused.is_paused(name):
                continue
            if self._display_state(name, tools.get(name, {}),
                                   snap.get("updated")) == "GREEN":
                setter(name, False)

    def _on_panic(self, _btn):
        dlg = Gtk.Dialog(title="Panic lockdown",
                         transient_for=self, modal=False)
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
        present_now(dlg)

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
            if name != "appfw":
                # The firewall's switch lives in appfw/enable.json, and its
                # real state comes from status.json. Writing a pause record
                # too is what let the tile say "paused" over an armed engine
                # and vice versa.
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
            if rc == 0 and not pause:
                # Started, not stopped: a successful turn-off must keep
                # saying it was paused, never "started" afterwards.
                started = ("App firewall started. New connections pass "
                           "once without a pop-up.")
                recorded = "Learning mode records them. Strict stops unknown ones."
                self.fw_status.set_text(started + " " + recorded)
            # Keep the just-happened sentence visible for a moment; the
            # periodic refresh would otherwise replace it instantly.
            self._fw_status_hold = time.monotonic() + 6.0
            self._refresh_fw()
        self.refresh()
        return False

    def _open_detail(self, name):
        if self._detail_dialog:
            self._detail_dialog.destroy()
        dlg = Gtk.Dialog(title=friendly_name(name), transient_for=self,
                         modal=False)
        dlg.add_button("Close", Gtk.ResponseType.CLOSE)
        dlg.set_default_size(*metrics.dialog_size())
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

        # Manual controls belong here too: the row's own buttons are one
        # thing, but a person reading this protection's history should not
        # have to close the dialog to act on it.
        acts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        tool = self.by_name.get(name) or {}
        if tool.get("unit"):
            paused = self.paused.is_paused(name)
            toggle = Gtk.Button(label="Resume" if paused else "Pause")
            toggle.add_css_class("gw-quiet")
            toggle.connect(
                "clicked",
                lambda _b, n=name, p=paused: (
                    dlg.destroy(),
                    self._resume_tool(n) if p else self._pause_tool(n)))
            acts.append(toggle)
        scan_keys = {m["key"] for m in SCAN_MODES}
        if name in scan_keys or name == "yara-watch":
            run = Gtk.Button(label="Scan now")
            run.add_css_class("gw-quiet")
            run.connect("clicked",
                        lambda _b, n=name: (dlg.destroy(),
                                            self._rescan_tool(n)))
            acts.append(run)
        if acts.get_first_child() is not None:
            content.append(acts)

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
        present_now(dlg)

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
            # markup the view already renders (emoji removed.
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
        head.set_margin_top(metrics.PAGE_TOP)
        head.set_margin_start(metrics.PAGE_X)
        head.set_margin_end(metrics.PAGE_X)
        head.set_margin_bottom(14)
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
        index.set_margin_bottom(metrics.PAGE_BOTTOM)
        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.NONE)
        stack.set_hexpand(True); stack.set_vexpand(True)
        stack.set_margin_start(12)
        stack.set_margin_end(metrics.PAGE_X)
        stack.set_margin_bottom(metrics.PAGE_BOTTOM)

        self._help_stack = stack
        self._help_index = index
        for key, icon, label, builder in (
                ("start", "help-contents-symbolic", "Using it",
                 self._help_start),
                ("tools", "applications-system-symbolic", "Security Tools",
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
                ("Home", "The assistant, plus what just happened."),
                ("Protections", "One row per protection, every state."),
                ("Scans", "Every scan: buttons, progress, and the log."),
                ("Tools", "The whole tool table, with live status."),
                ("Threat Hunter", "The hunter's findings and what they mean."),
                ("Endpoint Hardening", "Baseline checks, apply, verify, undo."),
                ("Logs", "The raw record, newest first."),
                ("Settings", "Theme, app firewall, trusted items, updates."),
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
            "Six places, one job each. Nothing here needs a command.")
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
            cell.set_tooltip_text(f"{fname} ({name}) - {what}")
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
        """The ten questions users ask most, two columns of five."""
        faq_lines = [
            ("What does greywatch do?",
             "One dashboard for every protection already on this computer."),
            ("How do I run a scan?",
             "Scans: press a scan button; each scanner shows "
             "its own progress."),
            ("How do I pause a protection?",
             "Protections or the Tools table: press Pause on its row; "
             "Resume brings it back."),
            ("What does At risk mean?",
             "A protection that should be running is not. Not a detection."),
            ("A detection appeared - what now?",
             "Read the Recent line or Logs. Quarantine what you didn't cause."),
            ("How do I isolate my machine?",
             "No one-click panic. Keep the firewall on; unplug to disconnect."),
            ("How do I change the theme?",
             "Settings - Appearance - Dark or Light."),
            ("Why is my antivirus quiet?",
             "Its full scan runs daily. Quiet means nothing bad was found."),
            ("Is my disk encrypted - how do I check?",
             "Not checked today. Run lsblk in a terminal; LUKS shows crypto."),
            ("How do I undo a wizard change?",
             "Endpoint Hardening - Undo last change."),
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

        The About page lives here, next to the protections
        it explains, not in a separate dialog.
        """
        card, inner = self._settings_card(
            "About GreyWatch",
            "Linux endpoint security, with a local assistant.")
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
                        f"weight='700'>GreyWatch {escape(self._version())}"
                        "</span>")
        words.append(name)
        why = Gtk.Label(xalign=0)
        why.set_xalign(0)
        why.set_wrap(True)
        why.set_width_chars(24)          # measure minimum height at a width
        why.set_markup(
            f"<span size='12500' font_family='Inter' "
            f"color='{pc_muted()}'>GreyWatch's protections watch this machine, the "
            "event trail stays on this machine, and the assistant's "
            "answers are composed from your own logs by a model that "
            "runs on your own CPU.</span>")
        words.append(why)
        row.append(words)
        inner.append(row)
        for uri, label in (
                ("https://github.com/greyok00/greywatch",
                 "Source and releases - github.com/greyok00/greywatch"),
        ):
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

    def _render_fw_mode_note(self, mode: str | None = None):
        note = getattr(self, "fw_mode_note", None)
        if note is None:
            return
        if mode is None:
            combo = getattr(self, "fw_mode", None)
            mode = (combo.get_active_id() if combo is not None else None) \
                or "standard"
        if mode == "whitelist":
            text = ("Only allowed sites and programs connect. If the worker "
                    "stops, the app restores fail-open traffic for safety "
                    "and re-arms whitelist when the worker returns.")
        elif mode == "learning":
            text = ("Nothing is blocked. Every new connection is recorded "
                    "so you can approve it from the list below.")
        else:
            text = ("Unknown programs and sites ask once, and your answer "
                    "is remembered. An unanswered prompt falls back to your "
                    "headless choice; traffic keeps moving.")
        note.set_text(text)

    def _on_fw_mode_pick(self, combo):
        mode = combo.get_active_id() or "standard"
        from appfw import config as acfg
        try:
            cfg = acfg.load(DATA_DIR)
            cfg["learning_mode"] = (mode == "learning")
            cfg["strict_mode"] = (mode == "whitelist")
            cfg["fail_open"] = (mode != "whitelist")
            acfg.save(DATA_DIR, cfg)      # daemon mtime check re-arms
        except Exception:
            pass
        self._render_fw_mode_note(mode)
        if hasattr(self, "fw_status"):
            self._fw_status_hold = time.monotonic() + 3.0
            self.fw_status.set_text(
                "Mode saved. The firewall re-arms with it within a few "
                "seconds.")
        self._refresh_fw()

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
        rows.append(("Crash restart", raw.get("Restart") or "-",
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
        anywhere.
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
        head.set_margin_top(metrics.PAGE_TOP)
        head.set_margin_start(metrics.PAGE_X)
        head.set_margin_end(metrics.PAGE_X)
        head.set_margin_bottom(14)
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
        # 240, not the old 190: the rows carry a one-line what's-inside
        # under the group name now, and it must not wrap to three lines.
        index.set_size_request(240, -1)
        index.set_valign(Gtk.Align.START)
        index.set_margin_start(20); index.set_margin_end(12)
        index.set_margin_bottom(metrics.PAGE_BOTTOM)

        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.NONE)
        stack.set_hexpand(True); stack.set_vexpand(True)
        stack.set_margin_start(12)
        stack.set_margin_end(metrics.PAGE_X)
        stack.set_margin_bottom(metrics.PAGE_BOTTOM)

        self._settings_stack = stack
        self._index_meta = {}
        self._settings_rows = {}
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
            ic.set_valign(Gtk.Align.START)
            line.append(ic)
            right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            name = Gtk.Label(label=label, xalign=0)
            name.set_xalign(0)
            name.add_css_class("gw-index-label")
            right.append(name)
            # The one-line what's-inside under each group name (approved
            # depth; the trust lists carry their real counts instead of
            # invented ones).
            meta = Gtk.Label(xalign=0)
            meta.set_xalign(0)
            meta.set_wrap(True)
            meta.add_css_class("gw-fmeta")
            meta.set_text(self._index_meta_text(key))
            right.append(meta)
            line.append(right)
            row.set_child(line)
            index.append(row)
            self._index_meta[key] = meta
            self._settings_rows[key] = row
            pane = builder()
            pane.append(related_box(self._settings_related(key),
                                    self._settings_open))
            stack.add_named(pane, key)

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

    # The index's one-line what's-inside per group (approved depth; the
    # mockup's own wording). The two trust-list keys are the exception:
    # they carry a real count instead of a static line.
    _INDEX_METAS = {
        "look": "the two looks · workspace · the pick is remembered",
        "firewall": "on/off · its modes · per-program decisions",
        "connections": "trusted lists · learning mode · what the firewall "
                       "consults",
        "computer": "the host's real name, OS and where state lives",
        "diagnostics": "gw doctor · what the service last checked",
        "updates": "CVE checks for installed packages · on request, "
                   "never scheduled",
    }

    def _index_meta_text(self, key):
        # getattr, not bare reads: a test can swap in a lighter trust
        # stub, and a count line must never be what breaks the swap
        if key == "sites":
            sites = getattr(self.trust, "allow", set())
            blocks = getattr(self.trust, "block", set())
            n = len(sites) + len(blocks)
            return f"{n} on file · the firewall consults them first"
        if key == "programs":
            n = len(getattr(self.trust, "apps_allow", set()))
            return f"{n} on file · decided by a prompt you answered"
        return self._INDEX_METAS[key]

    def _refresh_index_counts(self):
        """The index's two count lines re-read the store only, so an
        entry added on a pane updates the index instead of going stale."""
        meta = getattr(self, "_index_meta", None)
        if not meta:
            return
        for key in ("sites", "programs"):
            label = meta.get(key)
            if label is not None:
                label.set_text(self._index_meta_text(key))

    def _settings_related(self, key):
        return _SETTINGS_RELATED[key]

    def _settings_open(self, _btn, key):
        """One handler for every footer's Open: a pane key selects its
        index row; a page key moves across the shell."""
        row = self._settings_rows.get(key)
        if row is not None:
            self._settings_index.select_row(row)
            return
        self._show(key)

    def _settings_look(self):
        app_frame, app_inner = self._settings_card(
            "Appearance and placement",
            "Changes are remembered on this computer.")
        theme_row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        radio_agency = Gtk.CheckButton(label="Agency plate, light")
        radio_aperture = Gtk.CheckButton(label="Aperture graphite, dark")
        radio_aperture.set_group(radio_agency)
        picked = load_setting() or dark_default(self._theme_store.names())
        shown = picked if picked in THEME_CHOICES.values() \
            else dark_default(self._theme_store.names())
        (radio_agency if shown == "agency" else radio_aperture).set_active(True)
        radio_agency.connect("toggled", self._on_radio_theme, "agency")
        radio_aperture.connect("toggled", self._on_radio_theme, "aperture")
        self._radio_agency = radio_agency
        self._radio_aperture = radio_aperture
        theme_row.append(radio_agency)
        theme_row.append(radio_aperture)
        app_inner.append(self._settings_row(
            "Theme", theme_row, "Two looks; the pick is remembered."))
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

        from appfw import config as acfg
        self.fw_mode = Gtk.ComboBoxText()
        for ident, label in (
                ("learning", "Learning (record new connections, allow once)"),
                ("standard", "Standard (ask, then remember; fail-open)"),
                ("whitelist", "Whitelist only (deny everything unknown)")):
            self.fw_mode.append(ident, label)
        self.fw_mode.set_active_id(acfg.mode_of(acfg.load(DATA_DIR)))
        self.fw_mode.connect("changed", self._on_fw_mode_pick)
        fw_inner.append(self._settings_row(
            "Mode", self.fw_mode,
            "One setting behind three names. Learning records and allows. "
            "Standard asks, remembers, and keeps traffic moving if the "
            "helper stalls. Whitelist only lets through what you approved."))
        self.fw_mode_note = Gtk.Label(xalign=0)
        self.fw_mode_note.set_xalign(0)
        self.fw_mode_note.set_wrap(True)
        self.fw_mode_note.add_css_class("gw-sub")
        fw_inner.append(self.fw_mode_note)
        self._render_fw_mode_note()

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
            "On by default: IPv6 traffic follows the same rules as IPv4. "
            "Turning it off lets apps reach the internet over IPv6 "
            "unfiltered - keep it on unless you have a reason."))
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
        from ui.sitesview import SitesView
        trust_frame, trust_inner = self._settings_card(
            "Websites",
            "Click a site to select it, then trust it, block it, or remove "
            "it from both lists. Subdomains are included. Names come from "
            "the network; an address with no public name says so.")
        self.sites_view = SitesView(lambda: self.trust, self.data_dir)
        self.sites_view.reload()
        trust_inner.append(self.sites_view)
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
        self._refresh_index_counts()
        view = getattr(self, "sites_view", None)
        if view is None:
            return      # Settings has not built its widgets yet; the page
                        # reloads the list when it opens. The exec path runs
                        # before that build and must not crash here.
        view.reload()

    def _refresh_apps(self):
        self._refresh_index_counts()
        store = getattr(self, "app_store", None)
        if store is None:
            return      # same pre-Settings guard as _refresh_trust
        self.app_store.clear()
        if not self.trust.apps_allow:
            self.app_store.append(["Nothing trusted yet. Programs you "
                                   "trust appear here."])
        for e in sorted(self.trust.apps_allow):
            self.app_store.append([e])

    def _app_selected(self, view):
        path, _col = view.get_cursor()
        name = self.app_store[path[0]][0] if path else None
        self._app_sel = name if name in self.trust.apps_allow else None

    def _fw_is_on(self) -> bool:
        try:
            snap = daemon_mod.load_status(str(DATA_DIR / "status.json"))
            # "running (bypassing: queue full)" is still on: the queue's
            # bypass flag only skips the worker, never the user's switch.
            return str(snap.get("appfw_engine") or "").startswith("running")
        except (OSError, ValueError):
            return False

    def _on_fw_toggle(self, _btn):
        was_on = self._fw_is_on()
        # Widget-free before Settings builds: the chat's firewall intent
        # reaches this handler before any of the Settings pane widgets
        # exist (— every touch is now guarded).
        settings_ready = getattr(self, "fw_btn", None) is not None \
            and getattr(self, "fw_status", None) is not None
        if settings_ready:
            self.fw_btn.set_sensitive(False)
            self.fw_btn.set_label("Stopping…" if was_on else "Starting…")
            self.fw_status.set_text(
                "Waiting for the admin password…" if not was_on else
                "Stopping the firewall…")
            self._fw_status_hold = time.monotonic() + 6.0
        try:
            from appfw.engine import write_enabled
            # appfw's own writer: atomic (temp+rename). A torn enable.json
            # here reads as "firewall off" at the next daemon start.
            write_enabled(DATA_DIR, not was_on)
            self._after_toggle("appfw", was_on, 0)
        except OSError as e:
            if settings_ready:
                self.fw_btn.set_sensitive(True)
                self.fw_status.set_text(
                    f"could not switch the engine: {e}")
            else:
                self._assistant_record_outcome(False)
                self.refresh()
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

    def _render_appfw_state(self, snap):
        """Write the engine's own sentence into the tile, verbatim.

        The status file says exactly what the engine is doing — running,
        bypassing a full queue, re-arming, off (switch), off (failed: …),
        or suspended by the whitelist safety valve. The last three history
        entries say how it got there, so "why did it turn off?" has an
        answer on screen instead of in a root-only log.
        """
        text = str(snap.get("appfw_engine") or "").strip()
        if not text:
            return
        if time.monotonic() < getattr(self, "_fw_status_hold", 0.0):
            return
        lines = [text]
        for entry in snap.get("appfw_history") or []:
            if not isinstance(entry, dict):
                continue
            ts = str(entry.get("ts") or "")
            when = ts[11:16] if len(ts) >= 16 else ""
            reason = str(entry.get("reason") or "").strip()
            line = f"{when} {entry.get('event', '')}".strip()
            lines.append(line + (f" - {reason}" if reason else ""))
        status = getattr(self, "fw_status", None)
        if status is not None:
            status.set_text("\n".join(lines))

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
        # this meaning is gone (design pass.
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
        # Widget-free before Settings builds: the chat's
        # update_lists intent reaches this before update_btn/update_note
        # exist, so the pane widgets are guarded and the outcome still
        # lands in the assistant card and the audit ledger.
        updates_ready = getattr(self, "update_btn", None) is not None \
            and getattr(self, "update_note", None) is not None
        if updates_ready:
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
        updates_ready = getattr(self, "update_btn", None) is not None \
            and getattr(self, "update_note", None) is not None
        if updates_ready:
            self.update_btn.set_sensitive(True)
        self._refresh_updates()
        parts = []
        parts.append("security list up to date" if rc == 0
                     else f"security list failed ({msg or 'no answer'})")
        parts.append(f"block list up to date ({bl_count} domains)" if bl_ok
                     else f"block list failed ({bl_msg or 'no answer'})")
        if updates_ready:
            self.update_note.set_text(" · ".join(parts))
        else:
            self._assistant_record_outcome(bool(rc == 0 and bl_ok))
            self.refresh()
        return False

    def _on_app_browse(self, _btn):
        dlg = Gtk.FileChooserNative(
            title="Choose the program to trust", transient_for=self,
            action=Gtk.FileChooserAction.OPEN)
        try:
            dlg.set_current_folder(Gio.File.new_for_path("/usr/bin"))
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

    def _on_radio_theme(self, btn, kit):
        if not btn.get_active():
            return            # the toggle also fires on the partner's uncheck
        if self._theme_store.apply(kit):
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
        # blank after a theme switch,.
        self._recent_seen = None
        for key, widget in list(self._views.items()):
            self.stack.remove(widget)
            del self._views[key]
        # The tab bar is built once, so its glyphs keep the OLD voice's
        # colours after a switch unless they are told to repaint.
        for sym in getattr(self, "_symbols", {}).values():
            sym.queue_draw()
        self._show(visible or "home")
        self.refresh()
        return False

    def _reload_trust(self, *_a):
        # self.trust is the settings-side reference (swap-injectable); the
        # boot store covers the window before Settings has ever built — the
        # wizard-close hook used to read the raw alias and crash with
        # AttributeError (bug-sweep wave 3, part B harness).
        store = getattr(self, "trust", None) or self._trust
        store.load()
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

        seen = {"prev": -1, "w": -1}

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
        #  (shake): the wizard's own column ran this exact shape and
        # refit on every width change, and each margin change returned as a
        # different width the next frame - a ~1 Hz flip loop. The margins
        # here settle once on a stable allocation and move only on real
        # resizes, past the wobble band a scrollbar adds or removes.
        def on_tick(_widget, _clock):
            width = sc.get_width()
            if width <= 0:
                return True
            if seen["w"] < 0:
                if width == seen["prev"]:
                    seen["w"] = width
                    fit()
                else:
                    seen["prev"] = width
                return True
            if abs(width - seen["w"]) > 80:
                seen["w"] = width
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
        self._scan_live = read_live(self.data_dir)
        # The assistant facts source: the very snapshots refresh already
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
        self._render_appfw_state(snap)
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
        pending = int(snap.get("pending_decisions") or 0)
        alerts = recent_alerts(events)
        pill_state = "ok"
        if known == 0 and not self._state_override:
            lead = "No status yet"
            pill = "Waiting for monitor"
            pill_state = "warn"
        else:
            # Tool health is not the whole answer: 18 unanswered decisions
            # and a fresh CRITICAL event both mean the user has work.
            lead, pill, pill_state = verdict_words(
                attention, paused_n, pending, alerts)
        # Plain text: the headline is a theme class now, and the running
        # tally lives in the meta line below it rather than shrinking into
        # the same sentence. The Protections page builds on demand, so its
        # headline may not exist until the tab is first opened.
        if getattr(self, "status_words", None) is not None:
            self.status_words.set_text(lead)
        if getattr(self, "header_pill", None) is not None:
            if isinstance(self.header_pill, Gtk.Button):
                self.header_pill.set_label(pill)
            else:
                self.header_pill.set_text(pill)
            for cls in ("ok", "warn", "fail"):
                self.header_pill.remove_css_class(cls)
            self.header_pill.add_css_class(pill_state)
        # Counts header: green count, pauses and the attention tail, in the
        # monitor's own words when it has not reported yet.
        if getattr(self, "counts", None) is not None:
            if known == 0 and not self._state_override:
                self.counts.set_text("waiting for the monitor")
            else:
                # : the decision count rides the verdict line above
                # (verdict_words); repeating it in this tally put the same
                # figure inside one chip twice.
                self.counts.set_text(
                    f"{running} running · {paused_n} paused · "
                    f"{attention} {'needs' if attention == 1 else 'need'}"
                    " attention")

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

        # One shared run-history read for whichever desk needs it (the
        # protections desk's last scans, the registry's run facts). Every
        # field here comes from the reads this refresh already made
        # (the status snapshot, this refresh's event list, one history
        # read); nothing new is invented and nothing new starts.
        history_docs: dict = {}
        if getattr(self, "tools_desk", None) is not None or (
                getattr(self, "protect_desk", None) is not None
                and self.card_widgets):
            for doc in read_history(self.data_dir):
                for key, val in (doc.get("scanners") or {}).items():
                    history_docs.setdefault(key, val or {})
            if "yara-tmp-scan" in history_docs \
                    and "yara-watch" not in history_docs:
                history_docs["yara-watch"] = \
                    history_docs["yara-tmp-scan"]

        # The Tools table builds on demand like every page now, so the
        # whole table pass is conditional.
        tools_desk = getattr(self, "tools_desk", None)
        if tools_desk is not None:
            unknown_n = sum(
                1 for t in self.registry
                if self._display_state(t["name"],
                                       tools.get(t["name"], {}),
                                       updated) == "UNKNOWN")
            reg_facts = {}
            # Facts build over the WHOLE registry (the ON FILE flag and
            # the dossier describe the machine), while only `ordered`
            # decides what the feed mounts — the same contract the
            # protections desk runs, so the two counters on one screen
            # never disagree.
            for t in sorted(self.registry, key=_urgency):
                name = t["name"]
                info = tools.get(name, {})
                state = self._display_state(name, info, updated)
                paused = self.paused.is_paused(name)
                unit = t.get("unit")
                quiet = (unit or "").endswith(".timer") or not unit
                ev = next((e for e in reversed(events)
                           if e.get("from_tool") == name
                           and not str(e.get("text", "")).startswith(
                               "check-in:")), None)
                sc_key = "yara-tmp-scan" if name == "yara-watch" else name
                sc = history_docs.get(sc_key) or {}
                # : same live row as the protections desk - the
                # tools feed buckets the current run, not the last
                # finished one.
                live_sc = (((self._scan_live or {}).get("scanners"))
                           or {}).get(sc_key) or {}
                reg_facts[name] = {
                    "name": name,
                    "state": state,
                    "paused": paused,
                    "quiet": quiet,
                    "unit": unit,
                    "installed": info.get("installed"),
                    "label": friendly_name(name),
                    "event": ev,
                    "last_scan": sc,
                    "live_scan": live_sc or None,
                    "last_detail": self._update_detail(name) or "",
                    "logs": t.get("logs") or (),
                }
            tools_desk.paint(reg_facts, events, updated=updated,
                             visible={t["name"] for t in ordered})
            tools_desk.band_paint(
                len(self.registry), running, attention, paused_n,
                unknown_n, len(self.registry), len(events),
                sum(int(x) for x in (snap.get("failures") or {}).values()),
                snap.get("degraded") or (),
                dropped=int(snap.get("dropped") or 0))
            stamp_u = _dt.datetime.fromisoformat(
                str(updated or "")).astimezone() if updated else None
            tools_desk.update_clock(
                stamp_u.strftime("SNAPSHOT %H:%M") if stamp_u
                else "SNAPSHOT -")
            if self._selected_tool and self._selected_from == "tools" \
                    and tools_desk.selected is None:
                # The registry desk dropped the selection (the filter
                # now hides that row); the window keeps its pointer only
                # while the desk that holds it still shows it.
                self._selected_tool = None
                self._selected_from = None
                self.sel_note.set_text("Select a tool.")
                self._sync_selection_buttons()
            elif self._selected_tool and self._selected_from == "tools":
                tools_desk.fill_dossier(self._selected_tool)
        # The Threat Hunter tab shows its unread count before it is
        # opened. The badge and the pinned digest must agree, so both
        # count the same pointer-relative list (home_unread, homepage.py).
        if getattr(self, "_badges", None):
            self.set_badge("thunter", len(home_unread(self.data_dir)))
        # The suite verdict leads Home; it repaints on the same
        # cycle as the digest so neither can drift from status.json.
        if getattr(self, "suite_card", None) is not None:
            self.suite_card.refresh()
        self._refresh_home_hybrid()
        if hasattr(self, "card_widgets"):
            for t in self.registry:
                frame = self.card_widgets.get(t["name"])
                if not frame:
                    continue
                name = t["name"]
                info = tools.get(name, {})
                state = self._display_state(name, info, updated)
                paused = self.paused.is_paused(name)
                for cls in ("red", "warn", "ok"):
                    frame.remove_css_class(cls)
                stripe = {"RED": "red", "YELLOW": "warn",
                          "GREEN": "ok"}.get(state)
                if stripe is None and paused:
                    stripe = "warn"
                if stripe:
                    frame.add_css_class(stripe)
                ev = next((e for e in reversed(events)
                           if e.get("from_tool") == name
                           and not str(e.get("text", "")).startswith(
                               "check-in:")), None)
                state_color = pc_state_colour(state, paused)
                words = service_words(state, info.get("installed"), paused)
                # : a baseline-less integrity scanner must not read
                # "service running" — the monitor's own note takes the
                # state line first (status.py writes it when the db is
                # absent), because one green word over a row that can
                # never run was the original defect.
                if info.get("note") and not paused:
                    words = info["note"]
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
                # The sub-line describes the service. The scan's own
                # sentence, bar and log sit beneath it, painted by
                # _paint_scan_rows from the same live document.
                frame._sub.set_markup(head)
                frame.set_tooltip_text(
                    f"{friendly_name(name)} - {what_is(name)}"
                    f"{(' · ' + detail) if detail else ''}")
                frame._pause_btn.set_label("Resume" if paused else "Pause")
                if hasattr(frame, "_pause_btn") and t.get("unit"):
                    frame._pause_btn.set_sensitive(True)
                # The show-all switch (the old rail filter) drives the
                # protection rows too now: unticked, the page lists only
                # what needs attention.
                show = True
                if getattr(self, "show_all_btn", None) is not None:
                    show = self.show_all_btn.get_active()
                frame.set_visible(show or paused or state != "GREEN")
            self._paint_scan_rows()

        desk = getattr(self, "protect_desk", None)
        if desk is not None and self.card_widgets:
            # The desk's per-row facts: every field comes from the reads
            # this refresh already made (the status snapshot, this
            # refresh's event list, and one run-history read). Nothing new
            # is invented here and nothing new starts.
            docs_by_scanner = history_docs
            unknown_n = sum(
                1 for t in self.registry
                if self._display_state(t["name"], tools.get(t["name"], {}),
                                       updated) == "UNKNOWN")
            facts = {}
            # Every registry row builds facts, whatever the show-all
            # filter says: the coverage strip and the dossier describe the
            # machine, while only `ordered` decides what the FEED mounts —
            # a filter may hide healthy rows, never erase their class.
            for t in sorted(self.registry, key=_urgency):
                name = t["name"]
                info = tools.get(name, {})
                state = self._display_state(name, info, updated)
                paused = self.paused.is_paused(name)
                unit = t.get("unit")
                quiet = (unit or "").endswith(".timer") or not unit
                ev = next((e for e in reversed(events)
                           if e.get("from_tool") == name
                           and not str(e.get("text", "")).startswith(
                               "check-in:")), None)
                sc_key = "yara-tmp-scan" if name == "yara-watch" else name
                sc = docs_by_scanner.get(sc_key) or {}
                # : the card's fail rail reads the LIVE run (the
                # scan session's own document), while history keeps the
                # older finished runs; the desk's bucketing needs the
                # live row too or a green protection whose scan just
                # failed reads under "Running clean".
                live_sc = (((self._scan_live or {}).get("scanners"))
                           or {}).get(sc_key) or {}
                facts[name] = {
                    "name": name,
                    "state": state,
                    "paused": paused,
                    "quiet": quiet,
                    "unit": unit,
                    "installed": info.get("installed"),
                    "label": friendly_name(name),
                    "event": ev,
                    "last_scan": sc,
                    "live_scan": live_sc or None,
                    "last_scan_ts": sc.get("started_at"),
                }
            desk.paint(facts, updated, rows=self.card_widgets,
                       visible={t["name"] for t in ordered})
            desk.band_paint(running, attention, pending, paused_n,
                            unknown_n, len(self.registry))
            desk.cover_paint()
            stamp = _dt.datetime.fromisoformat(str(updated or "")).astimezone() \
                if updated else None
            clock = stamp.strftime("SNAPSHOT %H:%M") if stamp \
                else "SNAPSHOT -"
            desk.update_clock(clock)
            if self._selected_tool and self._selected_from == "protect" \
                    and desk.selected is None:
                # The protections desk dropped the selection (the filter
                # now hides that row): the window keeps its pointer only
                # while the desk that holds it still shows it, or every
                # refresh re-opens a dossier for an unmounted row.
                self._selected_tool = None
                self._selected_from = None
                self.sel_note.set_text("Select a protection.")
                self._sync_selection_buttons()
            if self._selected_tool and self._selected_from == "protect":
                desk.fill_dossier(self._selected_tool)
            elif not self._state_override:
                desk._fill_empty()

        if self._views.get("logs") and self.stack.get_visible_child_name() == "logs":
            self._refresh_logs()
        if hasattr(self, "scan_status"):
            self._scan_status_line()
        self._refresh_fw()
        self._refresh_updates()

    def _scan_status_line(self):
        """The Tools strip says what the daemon is scanning right now.

        The same label carries pause/resume and panic messages, so this only
        takes the line over when the scan itself changes state; a message a
        person's action just wrote is left alone until then.
        """
        live = self._scan_live
        state = (live or {}).get("state")
        prior = getattr(self, "_scan_status_state", None)
        self._scan_status_state = state
        if state is None:
            return
        # On the page itself, "below" tells the reader to go where they
        # already are; from Protections it names the Scans tab.
        where = ("below" if self.stack.get_visible_child_name()
                 in ("scans", "protect")
                 else "on the Scans page")
        msg = status_line(live, where, lambda k: SCAN_NAMES.get(k, k))
        if not msg:
            return
        owned = self.scan_status.get_text() == getattr(
            self, "_scan_status_text", None)
        if not owned and prior == state:
            return            # keep a pause/panic message that just landed
        self._scan_status_text = msg
        self.scan_status.set_markup(
            f"<span size='13000' font_family='Inter'>{escape(msg)}</span>")
        if state != "running" and hasattr(self, "circle"):
            self.circle.stop()

    def _open_setup_wizard(self):
        from wizard.ui_pages import SetupWizardWindow

        if self._setup_win is not None:      # one setup window, not many
            try:
                if not self._setup_win.get_mapped():
                    self._setup_win = None   # destroyed shell
                else:
                    present_now(self._setup_win)
            except Exception:
                self._setup_win = None
            else:
                if self._setup_win is not None:
                    return

        def open_dashboard():
            present_now(self)
            self._show("home")

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
        present_now(self._setup_win)
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

    def _open_decisions(self, *_a):
        """: the pill said "29 decisions waiting" and nothing was
        clickable; the count now opens its own list. One window,
        not many: re-open rebuilds the rows and presents again."""
        existing = getattr(self, "_decisions_win", None)
        if existing is not None and not existing.get_mapped():
            self._decisions_win = None   # destroyed shell
        elif existing is not None:
            try:
                existing.build_rows()
                present_now(existing)
            except Exception:
                self._decisions_win = None
            else:
                return
        from ui.decisionlist import DecisionsWindow
        self._decisions_win = DecisionsWindow(
            parent=self,
            on_change=lambda: self.refresh())
        self._decisions_win.connect(
            "destroy", lambda _w: setattr(self, "_decisions_win", None))
        present_now(self._decisions_win)

    def _open_wizard(self):
        from ui.wizard import ToolChooser

        existing = getattr(self, "_chooser", None)
        if existing is not None and not existing.get_mapped():
            #  (visual lane): a picked chooser is unmapped well
            # before GTK will call it destroyed, so reopening presented a
            # body-destroyed shell - an empty window that also swallowed
            # the Setup button. An unmapped previous chooser is dead, no
            # matter what GTK still thinks.
            self._chooser = None
        elif existing is not None:          # one hub, never a stack of them
            try:
                present_now(existing)
                return
            except Exception:
                self._chooser = None

        def picked(key):
            self._open_wizard_for(key)

        self._chooser = ToolChooser(on_pick=picked, parent=self)
        self._chooser.connect(
            "destroy", lambda _w: setattr(self, "_chooser", None))
        present_now(self._chooser)
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
        elif self.get_parent() is None:
            # A retheme builds the next theme's circle and unparents this
            # one; GTK4 does not promise the unparented copy disposes with
            # its signal, so the pulse stops itself the moment nothing
            # holds it and nothing is animating.
            self._pulse_id = None
            return False
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
