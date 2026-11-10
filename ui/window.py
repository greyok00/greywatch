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
from decisions_factory import snapshot_pending
from registry import load_registry
from ui.models import local_clock, recent_alerts, verdict_words
from ui.plain import (sentence as plain_sentence, friendly_name, severity_colour as pc_severity_colour)
from ui.themes import (ThemeStore, load_setting, resolve_pick,
                       tab_symbol_active)
from ui.cards import SCAN_MODES
from ui.scanview import read_live, read_history
from ui.desk import aperture
from ui.eventclock import attach as clock_attach, present_now
from ui.dock import DockHost
from ui import guided
from ui.homepage import STALE_S, unread_notes as home_unread
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

# The stale-snapshot guard's stack page (the one centered waiting panel)
# and its dock side.
WAITING_KEY = "_waiting"


def snapshot_stale(updated) -> bool:
    """True when no digest is on file, or the one on file is older than
    the 90 s staleness law ui.homepage already carries for the Home
    verdict. One clock, two surfaces, no drift.

    The daemon publishes a parseable ISO stamp in every snapshot it
    writes, so a stamp that cannot be parsed is a broken digest and waits
    like a missing one. GUI tests disarm the guard window-wide (conftest's
    `_hermetic_stale_guard`) because a test run must not depend on the
    live daemon's heartbeat age; the pins in tests/test_dock_host.py
    restore this predicate and cover both branches."""
    if updated is None:
        return True
    try:
        stamp = _dt.datetime.fromisoformat(str(updated))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=_dt.timezone.utc)
        return (_dt.datetime.now(_dt.timezone.utc)
                - stamp).total_seconds() > STALE_S
    except ValueError:
        return True


def dock_width(content_w, override=None) -> int:
    """The control dock's fixed width: about a quarter of the page area,
    floored at 220 (the groups must hold a control) and capped at 320 (a
    4K panel never balloons the dock into a second page). A stored pick
    from the UI settings file wins, clamped to a sane band; the pure law
    is what the tests pin."""
    if override is not None:
        return max(200, min(400, int(override)))
    return max(220, min(320, round(content_w * 0.26)))

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
# (the fold-in map: Scans/Protections/Harden to Services, logs to
# Activity Log, Home to Overview; 'security' and 'deep' were pre-wave-D
# names for the same Protections page). The round-2 rebuild gives pages
# back from the fold-in as their variants land: task 8 un-retired the
# Threat Hunter ("thunter"), task 9 gave the Tools page its cards back,
# task 10 gave Scans and Protections their own pages (the old
# "security"/"deep" aliases now land on Protections, p1), and task 11
# gave Harden its own page again (h1: score band + flat checklist), so
# the only remaining folds are the real absorbers (Home, logs, aliases).
_LEGACY_PAGE = {"home": "overview", "logs": "auditlog",
                "security": "protect", "deep": "protect"}

# The settings panes' related-in-suite footers (approved mockup):
# where/what/Open hand-offs to pages that genuinely hold the subject.
# Open moves inside Settings when the key is a pane, else across pages.

def saved_apply_pick(picked: str, names: list) -> str:
    """The theme the startup apply paints for a raw saved pick: the same
    shared resolver every theme read honors (themes.resolve_pick), so a
    retired pick (agency, aperture, obsidian, swiss) applies the voice
    that keeps its light/dark intent and is never overwritten by the
    dark default; only an absent or unknown pick falls to the dark
    default, floored by the store's actual sheets."""
    return resolve_pick(picked, names)


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
        self.chat_llm = None             # assistant brain, loaded ONLY by
                                         # the panel's GPU toggle (task 13)
        self.chat_retry = None
        self._trust = TrustList()
        self.paused = PausedStore()
        self._learn_store = LearningStore()
        self._fw_mode_store = FirewallModeStore()
        self._blocklist = BlockList()   # mtime-cached; never re-parsed per tick
        self._learn_sel = None
        self._learn_guard = False
        self._fw_mode_guard = False
        # Guided attention (rebuild round 2, task 4): the auto_jump
        # toggle is read ONCE here through the settings seam (guided
        # .load_toggle; the Settings desk writes through guided
        # .persist_toggle), and the router's seen-set counts it.
        self._toggles = {"auto_jump": guided.load_toggle()}
        self._handoff_seen: set = set()
        # The Help walkthrough (he1, task 12): state lives on the window
        # so the tour survives page switches; the Help page builds the
        # Stop control. Nothing walks until _tour_autorun says a first
        # launch.
        self._tour = None
        self._tour_stop_btn = None
        self._digest_viewer = None

        # The float layer (rebuild round 2, task 4): the pointer arrow of
        # the guided-attention layer rides this overlay above every page,
        # never taking input. The pages themselves are inner children.
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._float = Gtk.Overlay()
        self._float.set_child(outer)
        self.set_child(self._float)
        self._guided_overlay = self._float
        self._guided_point = None
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

        # The frame (rebuild round 2, task 3): rail | page feed | dock.
        self.dock = DockHost(self)
        body.append(self.dock)
        self._size_dock()
        self._dock_groups: dict = {}
        self._stale = False
        self._stale_prior = None
        self._waiting = None

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
        # he1: a first launch takes the walkthrough once the boot has
        # settled; the flag the loop honours ("tour_done") lives in the
        # same settings file every tunable writes.
        self._glib_ids.append(GLib.timeout_add(1600, self._tour_autorun))

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
        self._header_bar = bar
        parent.append(bar)

    def _apply_saved_theme(self):
        self._theme_store.apply(
            saved_apply_pick(load_setting(), self._theme_store.names()))

    def _toggle_voice(self):
        """The rail's sun/moon: flip between the two shipped voices
        (graphite dark, paper light) through the one theme seam -
        set_active_theme applies through the store, which repaints the
        CSS provider and persists the pick."""
        from ui.themes import THEMES, active_theme, set_active_theme
        names = [n for n in THEMES if n in self._theme_store.names()]
        if not names:
            return False
        try:
            i = names.index(active_theme())
        except ValueError:               # unknown/absent pick: go dark->light
            i = 0
        nxt = names[(i + 1) % len(names)]
        if not set_active_theme(nxt, store=self._theme_store):
            return False
        # The pages read the voice's tokens through the rebuild; the rail's
        # drawn glyphs keep the old colours until they are told to repaint.
        self._retheme()
        from ui import shell
        shell.voice_toggle_sync(self)
        return True

    def _rail(self, parent):
        """The sidebar shell, redrawn for rebuild round 2: the owner's
        ten-page menu - Overview as the large clickable home title, then
        the Care / Defense / System groups - with the sun/moon voice
        toggle pinned at the rail's bottom-left. Rows keep the shell's
        per-key API _tabs/_badges/_symbols, so unread counts and
        activation styling stay the same code the tab shell used."""
        from ui import shell
        shell.build_rail(self)
        shell.set_theme_toggle(self)
        parent.append(self.rail_bar)
        width = self.get_allocated_width() or metrics.window_size()[0]
        self.rail_bar.set_size_request(
            shell.rail_size(width, self._rail_pref()), -1)

    def _tab_pick(self, _b, key):
        # A click arrival clears the hand-off breadcrumb: the "came from"
        # line belongs to the auto-route that set it, not to the page.
        dock = getattr(self, "dock", None)
        if dock is not None:
            try:
                dock.clear_note()
            except (RuntimeError, TypeError, AttributeError):
                pass
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
        self._mount(key)
        if self._stale:
            # The waiting panel keeps the stack; the click is remembered
            # so the recovery lands on the page the user picked.
            self._stale_prior = key
        else:
            self.stack.set_visible_child_name(key)
        self.dock.set_page(key, self._dock_groups.get(key, []))
        # The greeting (rebuild round 2, task 4): the page's declared
        # entry target pulses its dock group title. While stale the stack
        # still shows the waiting panel, so the entry lookup is quiet by
        # itself (no entry declared for the waiting page).
        guided.entry(self)
        for k, b in self._tabs.items():
            # The ten-page menu: after the round-2 variants every Care row
            # opens its OWN page again (task 11 re-rooted Harden last), so
            # a row is active when the page it opens is the page now shown.
            on = _LEGACY_PAGE.get(k, k) == key
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

    def handoff(self, page_key, dock_group=None, row=None) -> bool:
        """The guided-attention router (rebuild round 2, task 4), bound
        to this window: open the page with the right dock open, greet its
        dock group and highlight the row - routed once per item."""
        return guided.handoff(self, page_key,
                              dock_group=dock_group, row=row)

    def _overview_view(self):
        """Overview (round 2, variant 3): the verdict strip over the
        published digest, one health card per rail group, the trend
        chart and the Needs-you rows. The builder returns the dock
        groups (Snapshot / Trend / Ask about) with the page; the fit law
        (2026-11-10) keeps the page whole and its lists inner-scrolled."""
        from ui.console import build_overview
        page, groups = build_overview(self)
        self.overview_page = page
        return page, groups

    def _services_view(self):
        """Services (rebuild Phase 3): lane two - the tool grid and the
        Service Healer rows. Lifecycle only; the scan actions and the
        console moved back to the Scans page (rebuild round 2, task 10).
        The fit law (2026-11-10): the page lays out to the window; its
        tool grid scrolls inside the desk, not here."""
        from ui.toolhealth import ServicesPage
        page = ServicesPage(win=self)
        self.services_page = page
        return page, []

    def _scans_view(self):
        """The Scans page (rebuild round 2, task 10, owner s2): the three
        mode cards (Quick sweep / Full suite / Deep audit) with their Run
        buttons through the validated-key request seam, the ScanConsole
        below (its inner scroll stays), and the dock's Schedule /
        Throttle groups. The page never scrolls as a whole."""
        from ui.scanview import ScansPage
        page = ScansPage(win=self)
        self.scan_page = page
        return page, page.dock_groups()

    def _protect_view(self):
        """The Protections page (rebuild round 2, task 10, owner p1):
        the "between this box and threats" strip with the run lane, the
        PATCH ADVISORIES wall (the CVE rows moved here from the Firewall
        page with the patch-the-planet coverage line), the recent
        protection-run cards, and the dock's Advisory filter / Runs
        groups."""
        from ui.protectdesk import ProtectionsPage
        page = ProtectionsPage(win=self)
        self.protect_page = page
        return page, page.dock_groups()

    def _harden_view(self):
        """The Harden page (rebuild round 2, task 11, owner h1): the
        hardening-score band over ONE flat checklist whose open rows
        apply themselves in place through the existing harden changeset
        lane (verby planfile -> polkit harden.sh), resolved rows
        collapsed to one line, and the dock's Profile / Recheck groups.
        The page never scrolls as a whole: the checklist is its one
        inner-scrolled container."""
        from ui.harden import HardenPage
        page = HardenPage(win=self)
        self.harden_page = page
        return page, page.dock_groups()

    def _auditlog_view(self):
        """The Activity Log page (rebuild round 2, task 6, variant 1):
        ONE chronology table with the Everything/Decisions/Blocks/
        Findings tab strip in the feed, the blocks-per-hour strip under
        it and the waiting/glitch row that glows. The controls live in
        the dock: Filter (search, severity, tool, time range), Sources
        (per-tool toggles) and Actions (follow, export, clear) - so a
        long history never scrolls its own levers away."""
        from ui.auditlog import ActivityLogPage
        page = ActivityLogPage(win=self)
        self.auditlog_page = page
        return page, [("Filter", [page._search, page._sev_pick,
                                  page._tool_pick, page._range_pick]),
                          ("Sources", [page._sources]),
                          ("Actions", [page._follow, page._export,
                                       page._clear])]

    def _defense_view(self):
        """The Firewall desk (rebuild round 2, task 7, owner fw-A): the
        wall verdict strip, the one decisions card, the blocked-address
        table with Unblock on the row and the armor chip line, fed by
        the daemon's public status digest (the ledger and event store
        stay root-only) plus the dock's Rules / psad / Open config
        groups."""
        from ui.defense import DefenseView
        self.defense_view = DefenseView(win=self)
        return self.defense_view, self.defense_view.dock_groups()

    def _thunter_view(self):
        """The Threat Hunter page (rebuild round 2, task 8, owner th-A):
        one finding card per open lead with its rule's REAL buttons
        wired (the quarantine-lane delete, the baseline-update lane, the
        full-scan request), resolved findings collapsed to one honest
        line each, and the dock's Filter / Suppressions / Watcher
        groups. The Ask button rides the same chat seam, the scan
        hand-off the same validated-key request the Scans page writes."""
        from ui.hunterview import HunterPanel
        self.thunter_view = panel = HunterPanel(
            self.data_dir, on_ask=self._ask_assistant,
            on_navigate=self._show, on_scan=self._hunter_scan)
        return panel, panel.dock_groups()

    def _tools_view(self):
        """The Tools page (rebuild round 2, task 9, owner t2): one
        full-width self-contained card per registered tool - lifecycle
        through the lanes that exist (disabled with the honest reason
        where none does), its schedule named where it really lives (the
        systemd unit), and Open config expanding the RAW file INSIDE the
        card with validate/apply through the config-write lane, then the
        baseline permafix offer (rkhunter --propupd / aide --update).
        The dock's Show group carries the all/live-only card filter."""
        from ui.toolcontrol import ToolControlPage
        page = ToolControlPage(win=self)
        self.tools_page = page
        return page, page.dock_groups()

    def _hunter_scan(self, scan_key: str = "full") -> None:
        """The hunter card's scan hand-off: the same validated-key
        request the Scans page's own buttons make - a mode key, never
        finding text, so the daemon only ever honours fixed requests."""
        mode = next((m for m in SCAN_MODES
                     if m.get("key") == str(scan_key)), None)
        if mode is None:
            return
        self._start_scan(None, mode, allowed=True)

    def _build_all(self):
        self._views = {}
        self._dock_groups = {}
        # The four rail pages, plus the panes Settings' related-open and
        # the footer reach (logs, diagnostics, help). Pages build on
        # demand — _show adds them — so a rail click only pays for the
        # page it opens; Overview builds eagerly because it is what
        # launches.
        self._builders = {"overview": self._overview_view,
                          "services": self._services_view,
                          "scans": self._scans_view,
                          "protect": self._protect_view,
                          "harden": self._harden_view,
                          "auditlog": self._auditlog_view,
                          "defense": self._defense_view,
                          "thunter": self._thunter_view,
                          "tools": self._tools_view,
                          "settings": self._settings_view,
                          "logs": self._logs_view,
                          "help": self._help_view}
        self._mount("overview")

    def _add_view(self, key, widget):
        # One cap and one center for every page (ui/desk.aperture): with
        # the window maximized on a 4K panel the raw content used to
        # stretch rows and paragraphs edge to edge, which read as
        # distortion.
        shown = aperture(widget)
        self.stack.add_named(shown, key)
        self._views[key] = shown

    def _mount(self, key):
        """Build one page unless it already stands. The builder returns
        (content, dock_groups): the content becomes the pane stack's page,
        the groups wait for _show to hand them to the dock, so a page's
        controls live in the dock and only its feed scrolls."""
        if key in self._views:
            return
        built = self._builders[key]()
        if isinstance(built, tuple):
            content, groups = built
        else:
            content, groups = built, []   # a builder not yet docked
        self._add_view(key, content)
        self._dock_groups[key] = groups

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
        self._mount(key)

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

    def _assistant_gpu_enable(self, on_stage, on_ready):
        """The owner clicked the panel's toggle: bring the local GPU model
        up on a worker thread and report the real loading stages back.

        This is the ONLY call site in the app that may load the model
        (assistant/tiers.py is the guard; ui/app.py wakes nothing). The
        installer drops the gguf under $DATA/models; the layer count comes
        from the owner's constant."""
        from assistant.llm import Llm
        from assistant.model import GPU_LAYERS, MODEL_FILENAME
        import gwpaths
        model = gwpaths.data_dir() / "models" / MODEL_FILENAME

        def settled(ok, err):
            # The loader thread runs this: touch facts only here, and hop
            # the GTK repaint to the main loop (widgets are not thread-
            # safe; the same hop the pre-togggle loader always made).
            self._chat_state = (ok, err or "")
            GLib.idle_add(self._assistant_paint_seams)
            on_ready(ok, err)

        self.chat_llm = Llm(model_path=str(model), n_gpu_layers=GPU_LAYERS)
        self.chat_llm.start(settled, on_stage=on_stage)
        self._assistant_paint_seams()

    def _assistant_gpu_disable(self):
        """The owner clicked the toggle off: free the model now (del +
        collect inside the loader) and fall back to the pure heuristic
        tier. Residency is the owner's rule, so nothing unloads the model
        except this handler - no timer, no refresh, no close."""
        llm = getattr(self, "chat_llm", None)
        self.chat_llm = None
        if llm is not None:
            llm.unload()
        self._chat_state = (True, "")
        self._assistant_paint_seams()

    def _assistant_state(self):
        """The task-13 seam: Settings and the Help About row read the
        assistant's tier state through here ('heuristics on - GPU model
        off/loading/on'), never a static promise."""
        panel = self._panel()
        gpu = getattr(panel, "gpu", None)
        if gpu is None:
            return ("heuristics on - GPU model off",)
        return gpu.state_line()

    def _assistant_paint_seams(self):
        """Repaint the seams that hold a tier-state row (the Settings GPU
        row and the Help About brain line); only the toggle calls this."""
        line = " ".join(str(x) for x in self._assistant_state()
                        if str(x).strip())
        for attr in ("_gpu_note", "_help_brain"):
            lbl = getattr(self, attr, None)
            if lbl is not None:
                try:
                    lbl.set_text(line)
                except Exception:            # noqa: BLE001 - paint only
                    pass

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
        """Redraw the live scan console (rebuild round 2 task 10: the
        Scans page) while that page is up."""
        vis = self.stack.get_visible_child_name()
        spage = getattr(self, "scan_page", None)
        console = getattr(spage, "scanconsole", None) if spage else None
        if vis == "scans" and console is not None \
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
            # is the one failure mode this window refuses). Whichever
            # page carries the console shows the note.
            for owner in ("scan_page", "services_page"):
                page = getattr(self, owner, None)
                console = getattr(page, "scanconsole", None) \
                    if page is not None else None
                if console is not None and \
                        hasattr(console, "show_scan_note"):
                    console.show_scan_note(f"the scan could not start: "
                                           f"{msg}")
                    return
            print("greywatch: the scan could not start:", msg, flush=True)
            return
        # The request file is written; the console is where the run shows.
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
        # The rebuild recreates every page; the pages' dock groups describe
        # the OLD widgets, so they drop with the views.
        self._dock_groups = {}
        # While stale the stack shows the waiting panel; the voice flip
        # must come back to the page the user was on, not to "_waiting".
        if getattr(self, "_stale", False):
            visible = getattr(self, "_stale_prior", None) or "overview"
            if visible not in self._builders:
                visible = "overview"
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

    def _pill(self, pill, pill_state):
        """The header pill carries one truth per cycle: the verdict, or
        the guard's wait. Warn styling travels with the words."""
        if getattr(self, "header_pill", None) is None:
            return
        if isinstance(self.header_pill, Gtk.Button):
            self.header_pill.set_label(pill)
        else:
            self.header_pill.set_text(pill)
        for cls in ("ok", "warn", "fail"):
            self.header_pill.remove_css_class(cls)
        self.header_pill.add_css_class(pill_state)

    def _waiting_enter(self):
        """The stale-snapshot surface: while the daemon's digest is
        missing or older than the 90 s law, the page stack IS one centered
        waiting panel — the header keeps the rail, the pill says what is
        being waited for. The page the user was on (and any page picked
        while waiting) is remembered, because refresh paints straight
        through the instant a fresh snapshot lands."""
        self._stale = True
        prev = self.stack.get_visible_child_name()
        if prev and prev != WAITING_KEY and prev in self._views:
            self._stale_prior = prev
        if self._waiting is None:
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            big = Gtk.Label(label="Waiting for the daemon")
            big.add_css_class("gw-headline")
            meta = Gtk.Label(
                wrap=True,
                label=("the last snapshot is older than "
                       f"{int(STALE_S)} seconds - this screen comes "
                       "back the moment the daemon reports"))
            meta.add_css_class("gw-page-meta")
            box.append(big)
            box.append(meta)
            box.set_halign(Gtk.Align.CENTER)
            box.set_valign(Gtk.Align.CENTER)
            box.set_margin_start(metrics.PAGE_X)
            box.set_margin_end(metrics.PAGE_X)
            self._waiting = box
            self.stack.add_named(box, WAITING_KEY)
        self.stack.set_visible_child_name(WAITING_KEY)
        self._pill("Waiting for the daemon", "warn")

    def _waiting_leave(self):
        """A fresh digest arrived: the stack is the user's pages again,
        on the page that was shown before the wait — or the one they
        picked while waiting."""
        self._stale = False
        child = self.stack.get_child_by_name(WAITING_KEY)
        if child is not None:
            self.stack.remove(child)
        self._waiting = None
        prior = self._stale_prior or "overview"
        self._stale_prior = None
        if self.stack.get_child_by_name(prior) is None:
            prior = "overview"
        self.stack.set_visible_child_name(prior)

    def _size_dock(self):
        """The dock is fixed at its quarter law (never collapsed), the
        same shape of law as the rail's five percent. Re-derived on the
        tick, so a user-resized window keeps the share."""
        width = self.get_allocated_width() or metrics.window_size()[0]
        self.dock.set_size_request(dock_width(width, self._dock_pref()), -1)

    def _dock_pref(self):
        """The stored dock-width pick from the UI settings file. Absent,
        unreadable or zero falls to the pure law (dock_width)."""
        try:
            from ui.themes import SETTINGS_PATH
            cfg = json.loads(pathlib.Path(SETTINGS_PATH).read_text())
            return int(cfg.get("dock_width") or 0) or None
        except (OSError, ValueError, TypeError):
            return None

    def _rail_pref(self):
        """The stored rail-width percentage pick from the UI settings file
        (the Settings rail slider writes it). Absent or unreadable falls
        to the pure five-percent law (ui.shell.rail_size)."""
        try:
            from ui.themes import SETTINGS_PATH
            cfg = json.loads(pathlib.Path(SETTINGS_PATH).read_text())
            return int(cfg.get("rail") or 0) or None
        except (OSError, ValueError, TypeError):
            return None

    def _periodic_refresh(self):
        from ui import shell
        # The rail is fixed at its width law (the stored percentage pick
        # when Settings set one, else five percent), never collapsed; the
        # width re-derives on this tick so a user-resized window keeps its
        # share without any collapse step. The dock carries the same law
        # at its quarter width.
        self.rail_bar.set_size_request(
            shell.rail_size(self.get_allocated_width(), self._rail_pref()),
            -1)
        self._size_dock()
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
        # The stale-snapshot guard (rebuild round 2, task 3): the app
        # never paints a verdict over a dead snapshot. Older than the
        # 90 s law — or no digest at all — every page gives way to the
        # one centered waiting panel; a fresh snapshot paints straight
        # through again, file monitor or 5 s tick whichever lands first.
        if snapshot_stale(snap.get("updated")):
            self._waiting_enter()
            return
        if self._stale:
            self._waiting_leave()
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
        if shown == "scans" \
                and getattr(self, "scan_page", None) is not None:
            self.scan_page.refresh(snap)
        if shown == "protect" \
                and getattr(self, "protect_page", None) is not None:
            self.protect_page.refresh(snap)
        if shown == "tools" \
                and getattr(self, "tools_page", None) is not None:
            # The Tools cards paint only while shown (the cost rule the
            # Defense page runs): dot, status and the live-only filter.
            self.tools_page.refresh(snap)
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
        pending = snapshot_pending(snap)   # gw215: the ONE published list
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
        self._pill(pill, pill_state)
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
        # The rail rows show their counts before they are opened (round
        # 2 moved the hunter's unread back to the hunter row): the
        # Firewall badge carries the watchlist's HIGH findings, the
        # Threat Hunter badge the hunter's unread notes - badge and
        # pinned digest keep counting the same pointer-relative list
        # (home_unread, homepage.py).
        if getattr(self, "_badges", None):
            from ui.defense import ptp_high_count
            self.set_badge("defense", ptp_high_count(self.data_dir))
            self.set_badge("thunter", len(home_unread(self.data_dir)))
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
