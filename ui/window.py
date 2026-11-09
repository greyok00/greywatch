import datetime as _dt
import json
import os
import pathlib
import time

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gtk, GLib, Gio    # noqa: E402

from assistant import audit
from registry import load_registry
from ui.models import local_clock, recent_alerts, verdict_words
from ui.plain import (sentence as plain_sentence, friendly_name, severity_colour as pc_severity_colour)
from ui.themes import (ThemeStore, dark_default, load_setting,
                       tab_symbol_active, THEME_CHOICES)
from ui.cards import SCAN_MODES
from ui.scanview import read_live, read_history
from ui.desk import aperture
from ui.eventclock import attach as clock_attach, present_now
from ui.homepage import unread_notes as home_unread
from ui.toolicons import icon_name as tool_icon
from ui.settings import (TrustList, PausedStore, LearningStore,
                         FirewallModeStore)
from ui import metrics
from ui.blocklist import BlockList
from ui.logsdesk import LogsDeskMixin
from ui.helpdesk import HelpDeskMixin
from ui.settingsdesk import SettingsDeskMixin
from ui.toolctl import ToolCtlMixin
import greywatch_daemon as daemon_mod

DATA_DIR = daemon_mod.DATA_DIR
PAINT_MERGE_MS = 250

# Recent-activity table geometry. The header row in `_security_view` draws
# plain labels over these widths, so they are shared rather than guessed in
# two places (a centred stock header never lines up with the cells).
ICON_W = 18      # tool glyph column
DOT_W = 22       # severity dot column
TIME_W = 104     # "18:35:39" plus breathing room

# The rail lives in ui/shell.py since wave D; old callers that named any
# retired page key keep working through _LEGACY_PAGE below and the pane
# stack. The rebuild (Phase 4) folds the ten-row rail into four pages, so
# every retired key resolves once, centrally, to the page that absorbed it
# (the fold-in map: Threat Hunter to Firewall, Scans/Protections/Tools/
# Harden to Services, logs to Activity Log, Home to Overview; 'security'
# and 'deep' were pre-wave-D names for the same Protections page).
_LEGACY_PAGE = {"home": "overview", "thunter": "defense",
                "scans": "services", "protect": "services",
                "tools": "services", "harden": "services",
                "logs": "auditlog",
                "security": "services", "deep": "services"}

# The settings panes' related-in-suite footers (approved mockup):
# where/what/Open hand-offs to pages that genuinely hold the subject.
# Open moves inside Settings when the key is a pane, else across pages.

class MainWindow(LogsDeskMixin, HelpDeskMixin, SettingsDeskMixin,
                 ToolCtlMixin, Gtk.Window):
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
        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        body.set_hexpand(True)
        body.set_vexpand(True)
        outer.append(body)
        self._rail(body)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)
        body.append(self.stack)

        self._views = {}
        self._theme_store = ThemeStore(self)
        self._apply_saved_theme()
        self._build_all()
        self._show("overview")
        self._tabs["overview"].grab_focus()
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

    def _rail(self, parent):
        """The sidebar shell, redrawn for wave D: grouped pages down the
        left edge (Watch, Defense, Care, System) instead of a plate bar
        across the top. Rows keep the shell's per-key API _tabs/_badges/
        _symbols, so unread counts and activation styling stay the same
        code the tab shell used."""
        from ui import shell
        self.rail_collapsed = False
        shell.build_rail(self)
        parent.append(self.rail_bar)
        self.rail_bar.set_size_request(shell.rail_size(self), -1)

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
            key = "overview"
        if key not in self._views:
            self._add_view(key, self._builders[key]())
        self.stack.set_visible_child_name(key)
        for k, b in self._tabs.items():
            on = k == key
            if on:
                b.add_css_class("gw-active")
            else:
                b.remove_css_class("gw-active")
            tab_symbol_active(self._symbols.get(k), on)
        # A page built on demand starts with placeholder text ("checking…")
        # and the periodic refresh is up to five seconds away, so the user
        # saw empty cards right after switching. Paint the real snapshot the
        # moment the page is shown.
        self.refresh()

    def _overview_view(self):
        """Overview (rebuild Phase 3): the anchor desk - ribbon, advisory
        strip, two-lane feed, assistant terminal, action gate rows.
        Reads only the daemon's published digest."""
        from ui.console import OverviewPage
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        self.overview_page = OverviewPage(win=self)
        scroller.set_child(self.overview_page)
        return scroller

    def _services_view(self):
        """Services (rebuild Phase 3): lane two - scan actions, the scan
        console, the tool grid, Service Healer rows. Lifecycle only."""
        from ui.toolhealth import ServicesPage
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        page = ServicesPage(win=self)
        scroller.set_child(page)
        self.services_page = page
        return scroller

    def _auditlog_view(self):
        """The Activity Log page (rebuild Phase 4): three tabs over the
        suite's history, sharing one filter."""
        from ui.auditlog import ActivityLogPage
        page = ActivityLogPage(win=self)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        scroller.set_child(page)
        self.auditlog_page = page
        return scroller

    def _defense_view(self):
        """The network defense desk (wave D): blocked addresses, Block Reviewer
        questions and the wave-A armor chain, fed by the daemon's public
        status digest since the ledger and event store stay root-only."""
        from ui.defense import DefenseView
        self.defense_view = DefenseView(win=self)
        return self.defense_view

    def _build_all(self):
        self._views = {}
        # The four rail pages, plus the panes Settings' related-open and
        # the footer reach (logs, diagnostics, help). Pages build on
        # demand — _show adds them — so a rail click only pays for the
        # page it opens; Overview builds eagerly because it is what
        # launches.
        self._builders = {"overview": self._overview_view,
                          "services": self._services_view,
                          "auditlog": self._auditlog_view,
                          "defense": self._defense_view,
                          "settings": self._settings_view,
                          "logs": self._logs_view,
                          "help": self._help_view}
        self._add_view("overview", self._builders["overview"]())

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
        tools = getattr(self, "tools_desk", None)
        if tools is None:
            spage = getattr(self, "services_page", None)
            tools = getattr(spage, "tools_desk", None) if spage else None
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
            self._selected_from = "tools"
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
            self._selected_from = "tools"
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

    def _panel(self):
        """The assistant conversation lives on the Overview page (rebuild
        Phase 4); resolve it wherever the window needs the panel."""
        opage = getattr(self, "overview_page", None)
        return getattr(opage, "_assistant", None) if opage else None

    def _start_chat_llm(self):
        """Wake the assistant model in-process (the installer drops the
        gguf under $DATA/models). A retry builds a NEW Llm instance, since
        start is one-shot per instance (assistant/llm.py contract)."""
        from assistant.llm import Llm
        from assistant.model import MODEL_FILENAME
        import gwpaths
        model = gwpaths.data_dir() / "models" / MODEL_FILENAME
        panel = self._panel()
        if panel is not None:
            panel.banner.set_text(
                "Assistant loading…"
                + ("" if getattr(self, "chat_llm", None) is None
                   else " retrying"))
        self.chat_llm = Llm(model_path=str(model))
        self.chat_llm.start(
            lambda ok, err: GLib.idle_add(self._on_llm_ready, ok, err))

    def _on_llm_ready(self, ok, err):
        self._chat_state = (ok, err)
        panel = self._panel()
        if panel is not None:
            panel.note_state(ok, err)
        return False

    def _show_filter(self, switch):
        """One show-all filter for both desks: whichever switch the
        a toggle becomes the page's filter (tests and refresh()
        read the one name), and the other desk's switch body is synced
        silently so the filter never drifts across pages."""
        if getattr(self, "_show_syncing", False):
            return
        self._show_syncing = True
        self.show_all_btn = switch
        self._show_syncing = False
        self.refresh()

    def _tools_picked(self, key):
        """The registry desk's pick: the same selection state the tree
        set on click, then the record fills (facts from the last
        refresh)."""
        self._selected_tool = key
        self._selected_from = "tools"
        if getattr(self, "sel_note", None) is not None:
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

    def _run_protection(self, name):
        """Run one protection's own scan: the same runner the Scans page's
        buttons and the row cards use, so no new power appears."""
        key = "yara-tmp-scan" if name == "yara-watch" else name
        mode = next((m for m in SCAN_MODES if m["key"] == key), None)
        if mode:
            self._start_scan(None, mode)

    def _scan_tick(self):
        """Redraw the live scan console (rebuild Phase 4: the Services
        page) while that page is up."""
        vis = self.stack.get_visible_child_name()
        spage = getattr(self, "services_page", None)
        console = getattr(spage, "scanconsole", None) if spage else None
        if vis == "services" and console is not None \
                and console.get_root() is not None:
            console.refresh()
            self._scan_live = read_live(self.data_dir)
        return True

    def _ask_assistant(self, question: str, finding: dict | None = None):
        """Open Overview and put a real question in the composer.

        When the question came from a finding, the row travels with it so
        the advice engine answers about that exact line instead of
        guessing from its words.
        """
        self._show("overview")
        panel = self._panel()
        if panel is None:
            return
        if finding:
            panel.ask(question, finding=finding)
        else:
            panel.ask(question)

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
        ok, msg = self._request_scan(mode)
        pending = getattr(self, "_assistant_pending", None)
        if pending == ("scan", mode.get("key")):
            self._assistant_pending = None
        audit.record("scan", mode.get("key", ""), ok)
        if not ok:
            # The request never reached disk: say why where the scan
            # buttons live, never just return (a click that does nothing
            # is the one failure mode this window refuses).
            page = getattr(self, "services_page", None)
            console = getattr(page, "scanconsole", None)
            note = f"the scan could not start: {msg}"
            if console is not None and hasattr(console, "show_scan_note"):
                console.show_scan_note(note)
            else:
                print("greywatch:", note, flush=True)
            return
        # The request file is written; the console is where the run shows.
        self._show("services")

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

    def _retheme(self):
        visible = self.stack.get_visible_child_name()
        panel = self._panel()
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
        self._show(visible or "overview")
        panel = self._panel()
        if panel is not None:
            if self._chat_snapshot is not None:
                panel.restore_transcript(self._chat_snapshot)
            self._chat_snapshot = None
            if self._chat_state is not None:
                panel.note_state(*self._chat_state)
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
        from ui import shell
        shell.collapse_rail(self, not shell.rail_pinned(self))
        self.rail_bar.set_size_request(shell.rail_size(self), -1)
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
        # The Defense page repaints only while shown: its armor probes run
        # subprocesses and must not cost every 5-second cycle.
        if self.stack.get_visible_child_name() == "defense" \
                and getattr(self, "defense_view", None) is not None:
            self.defense_view.refresh(snap)
        # rebuild Phase 3: the anchor pages feed off the same digest, and
        # only while they are shown (same cost rule as Defense)
        shown = self.stack.get_visible_child_name()
        if shown == "overview" \
                and getattr(self, "overview_page", None) is not None:
            self.overview_page.refresh(snap)
        if shown == "services" \
                and getattr(self, "services_page", None) is not None:
            self.services_page.refresh(snap)
        if shown == "auditlog" \
                and getattr(self, "auditlog_page", None) is not None:
            self.auditlog_page.refresh(snap)
        self._scan_live = read_live(self.data_dir)
        # The assistant facts source: the very snapshots refresh already
        # loaded — _get_status/_get_recent hand these over, no new reads.
        self._status_snapshot = snap
        self._recent_snapshot = events
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
        if getattr(self, "header_pill", None) is not None:
            if isinstance(self.header_pill, Gtk.Button):
                self.header_pill.set_label(pill)
            else:
                self.header_pill.set_text(pill)
            for cls in ("ok", "warn", "fail"):
                self.header_pill.remove_css_class(cls)
            self.header_pill.add_css_class(pill_state)
        # Rank by what needs a human, not by registry order: anything failed
        # or unverified sits at the top, paused next, healthy last. A flat
        # alphabetical table makes the one broken tool the 14th row.
        _rank = {"RED": 0, "YELLOW": 1, "UNKNOWN": 1}
        def tools_desk_any():
            """The one registry desk in play: the retired Tools page's or
            the Services page's (Phase 4) — whichever is mounted."""
            desk = getattr(self, "tools_desk", None)
            if desk is None:
                desk = getattr(getattr(self, "services_page", None),
                               "tools_desk", None)
            return desk
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
        if tools_desk_any() is not None:
            for doc in read_history(self.data_dir):
                for key, val in (doc.get("scanners") or {}).items():
                    history_docs.setdefault(key, val or {})
            if "yara-tmp-scan" in history_docs \
                    and "yara-watch" not in history_docs:
                history_docs["yara-watch"] = \
                    history_docs["yara-tmp-scan"]

        # The Tools table builds on demand like every page now, so the
        # whole table pass is conditional. Phase 4: the Services page
        # carries the same desk, so whichever instance is mounted wins.
        tools_desk = tools_desk_any()
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
                dropped=int(snap.get("dropped") or 0),
                outbox_dropped=int(snap.get("outbox_dropped") or 0))
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
                if getattr(self, "sel_note", None) is not None:
                    self.sel_note.set_text("Select a tool.")
                self._sync_selection_buttons()
            elif self._selected_tool and self._selected_from == "tools":
                tools_desk.fill_dossier(self._selected_tool)
        # The Firewall rail row shows its unread count before it is
        # opened. The badge and the pinned digest must agree, so both
        # count the same pointer-relative list (home_unread, homepage.py);
        # the hunter's unread now rides the Firewall page's badge (Phase 4).
        if getattr(self, "_badges", None):
            from ui.defense import ptp_high_count
            # additive: unread notes plus any HIGH findings the watchlist
            # is carrying; no watch run contributes nothing
            self.set_badge("defense", len(home_unread(self.data_dir))
                           + ptp_high_count(self.data_dir))
        # The suite verdict leads Home; it repaints on the same
        # cycle as the digest so neither can drift from status.json.
        self._refresh_fw()
        self._refresh_updates()

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
            self._show("overview")

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
        # the drawer reads the ONE published list, so the pill's count and
        # its rows can never disagree again (rebuild Phase 1)
        from ui.actiongate import ActionGateWindow
        self._decisions_win = ActionGateWindow(
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
