"""GreyWatch GUI, rebuilt 2026-11-15 on information architecture v4.

The shell: one window, one flat rail, one stack of pages. The rail is
the four screens plus the tail (Security Center, Network, Tools,
Timeline, then Assistant, Help), followed by an inline Advanced submenu
with one row per tool. The Security Center carries the Findings and
Baseline detail tabs. Appearance is a small header menu, not a page. No
label in this app carries a parenthetical. The GUI is a skin over the
CLI; the CLI is the product.

The page registry is honest: a rail row exists only when its module
exists, so pages appear as they land and nothing is promised twice.
"""

import fcntl
import os
import pathlib
import signal
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Pango

import json

from ui import themes

_LOCK = None

# rail order: the five surfaces, then the tail. Label = the page's rail
# name, verbatim, no parentheticals anywhere.
REGISTRY = (
    ("Security Center", "security"),
    ("Network", "network"),
    ("Tools", "tools"),
    ("Timeline", "timeline"),
    ("Assistant", "assistant_page"),
    ("Help", "helpdesk"),
)


def _is_dup(parts) -> bool:
    for p in parts:
        if p.endswith("ui/app.py") or p.endswith("ui/tray_helper.py") \
                or p == "ui.app":
            return True
    return False


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _kill_duplicates() -> None:
    """Kill every other greywatch GUI instance so a new launch always
    ends with exactly one running - launching again is a restart, never
    a stack-up."""
    me = os.getpid()
    dups = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == me:
            continue
        try:
            parts = (entry / "cmdline").read_bytes().decode(
                "utf-8", "replace").split("\0")
        except OSError:
            continue
        if _is_dup(parts):
            dups.append(pid)
    if not dups:
        return
    for pid in dups:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    for _ in range(30):
        if not any(_alive(p) for p in dups):
            break
        time.sleep(0.1)


def _lock_path() -> str:
    """The single-instance lock the app holds (the tray's click handler
    resolves the same path, never a second one)."""
    if pathlib.Path("/var/lib/greywatch/.greywatch-ui.lock").parent.exists():
        return "/var/lib/greywatch/.greywatch-ui.lock"
    return str(ROOT / "data" / ".greywatch-ui.lock")


def _acquire_single_instance_lock() -> bool:
    global _LOCK
    try:
        _LOCK = open("/var/lib/greywatch/.greywatch-ui.lock", "w")
    except OSError:
        try:
            _LOCK = open(str(ROOT / "data" / ".greywatch-ui.lock"), "w")
        except OSError:
            return True                  # lock unavailable: never block
    try:
        fcntl.flock(_LOCK, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def read_prefs(path=None) -> dict:
    # the path resolves through the theme module at call time, so a
    # test (and any staging) that moves the settings file moves it for
    # every reader
    import ui.themes as themes
    p = pathlib.Path(path if path is not None else themes.SETTINGS_PATH)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


class Window(Gtk.ApplicationWindow):
    """The one window: rail + pages."""

    def __init__(self, app):
        super().__init__(application=app)
        self._store = themes.ThemeStore(self)
        self._store.apply(themes.active_theme(picked=_raw_saved_pick()))
        self.set_title("GreyWatch")
        # The capture harness needs the real geometry; Xvfb has no window
        # manager to honor maximize(), so the size is set at construction.
        try:
            width = int(os.environ.get("GW_UI_WIDTH") or 1280)
            height = int(os.environ.get("GW_UI_HEIGHT") or 800)
        except ValueError:
            width, height = 1280, 800
        self.set_default_size(width, height)
        self.set_size_request(960, 600)

        header = Gtk.HeaderBar()
        title = Gtk.Label(label="GreyWatch")
        title.add_css_class("gw-title")
        header.set_title_widget(title)
        # The live instrument is a navigator, not a label: a running job's
        # status is also the way to the controls that own it. Idle is
        # insensitive so nothing clickable ever leads nowhere.
        self._header_status = Gtk.Button(label="Idle")
        self._header_status.add_css_class("gw-header-status")
        self._header_status.set_sensitive(False)
        self._header_status.connect("clicked", self._open_job_surface)
        header.pack_end(self._header_status)

        # Appearance lives in a small header popover, not on a Settings
        # page. The two shipped voices only, one checked, in one group.
        popover = Gtk.Popover()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(10)
        box.set_margin_end(10)
        group = []
        for label, voice in (("Dark", "graphite"), ("Light", "paper")):
            check = Gtk.CheckButton(label=label)
            if group:
                check.set_group(group[0])
            else:
                group.append(check)
            check.set_active(themes.active_theme() == voice)
            check.connect(
                "toggled",
                lambda button, v=voice:
                self._set_theme(v) if button.get_active() else None)
            box.append(check)
        popover.set_child(box)
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_popover(popover)
        menu_button.set_tooltip_text("Appearance")
        header.pack_start(menu_button)
        self._appearance_button = menu_button
        self.set_titlebar(header)

        self._pages = {}          # stack child (a centered wrapper)
        self._page_widgets = {}   # the page module's own widget
        self._page_modules = {}
        self._rail_rows = {}
        # The scan tracker lives on the window, above the page stack
        # (owner 2026-11-19): it keeps reading the daemon's live document
        # while another screen shows, so returning to the scan desk never
        # loses the run.
        from ui.scanmonitor import ScanMonitor
        self.scan_monitor = ScanMonitor(self)
        self.scan_monitor.start()

        root = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.set_child(root)

        # the rail: brand, then one flat list
        rail_holder = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        rail_holder.set_size_request(208, -1)
        # The rail rows' labels expand, and GTK4 derives a widget's expand
        # from its children unless it is set. Without this the rail took a
        # share of the free width at 4K and the page never got the rest.
        rail_holder.set_hexpand(False)
        self._rail_holder = rail_holder
        brand = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        brand.add_css_class("gw-brand")
        brand_title = Gtk.Label(label="GREYWATCH")
        brand_title.add_css_class("gw-brand-title")
        brand_title.set_xalign(0.0)
        brand_sub = Gtk.Label(label="SECURITY SUITE")
        brand_sub.add_css_class("gw-brand-sub")
        brand_sub.set_xalign(0.0)
        brand.append(brand_title)
        brand.append(brand_sub)
        rail_holder.append(brand)
        scroller = Gtk.ScrolledWindow()
        scroller.add_css_class("gw-rail-scroll")
        scroller.set_policy(Gtk.PolicyType.NEVER,
                            Gtk.PolicyType.AUTOMATIC)
        # The rail is a fixed measure. Without this, the child's natural
        # width (the advanced list) widened the whole rail at 4K.
        scroller.set_propagate_natural_width(False)
        scroller.set_vexpand(True)
        self._rail_scroll = scroller
        rail_holder.append(scroller)
        self._rail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                             spacing=2)
        self._rail.add_css_class("gw-rail")
        scroller.set_child(self._rail)
        root.append(rail_holder)

        # the pages, with a notice toast over the content instead of a
        # line of text at the bottom of the rail
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self._stack.set_vexpand(True)
        self._stack.set_hexpand(True)
        content = Gtk.Overlay()
        content.set_vexpand(True)
        content.set_hexpand(True)
        content.set_child(self._stack)
        self._note = Gtk.Label(label="")
        self._note.add_css_class("gw-toast")
        self._note.set_ellipsize(Pango.EllipsizeMode.END)
        self._note.set_max_width_chars(72)
        self._toast = Gtk.Revealer()
        self._toast.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
        self._toast.set_halign(Gtk.Align.END)
        self._toast.set_valign(Gtk.Align.START)
        self._toast.set_margin_top(16)
        self._toast.set_margin_end(18)
        self._toast.set_child(self._note)
        self._toast.set_reveal_child(False)
        content.add_overlay(self._toast)
        root.append(content)
        self._note_seq = 0

        self._build_pages()
        self._build_rail()
        self.scan_monitor.subscribe(self._update_header_status)
        GLib.timeout_add(400, self._fit_beat)

    # -- page plumbing ------------------------------------------------

    def _importable(self, mod: str) -> bool:
        return (ROOT / "ui" / f"{mod}.py").exists()

    def _import(self, mod: str):
        import importlib
        try:
            return importlib.import_module(f"ui.{mod}")
        except Exception as e:                # noqa: BLE001
            print(f"greywatch ui: page module ui/{mod}.py failed to "
                  f"load: {e}", file=sys.stderr)
            return None

    def _build_pages(self) -> None:
        """Import every page's module up front (cheap), BUILD only the
        pages that are already built. A page's widgets are made the
        first time its label is shown (owner 2026-11-16: the app used to
        assemble all nine pages before its window could exist, and a
        regular launch waited on the whole build; the landing page
        alone paints first now, everything else arrives on its first
        click). A theme re-pick calls this again with pages already
        built: those rebuild in place."""
        for label, mod in REGISTRY:
            if label in self._page_modules or not self._importable(mod):
                continue
            module = self._import(mod)
            if module is None:
                continue
            self._page_modules[label] = module
        for label, page in list(self._pages.items()):
            module = self._page_modules.get(label)
            if module is None or not hasattr(module, "build"):
                continue
            try:
                rebuilt = module.build(self)
            except Exception as e:            # noqa: BLE001
                print(f"greywatch ui: page {label} failed to rebuild: {e}",
                      file=sys.stderr)
                continue
            self._mount_page(label, rebuilt)
            self._stack.remove(page)
        self._fit_beat()

    def _mount_page(self, label: str, page) -> Gtk.Widget:
        """Put one page in the stack. The stack hands its child the whole
        area; the page fills it, and the fit beat hands it the width."""
        wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        wrapper.set_hexpand(True)
        wrapper.set_vexpand(True)
        # Every page and every future page fills the stack. A scroller
        # whose root never expands collapses to its minimum height once
        # the window has settled (Network and Tools did exactly that).
        page.set_hexpand(True)
        page.set_vexpand(True)
        wrapper.append(page)
        wrapper._gw_body = getattr(page, "_gw_body", page)
        wrapper._gw_window = self
        self._pages[label] = wrapper
        self._page_widgets[label] = page
        self._stack.add_named(wrapper, label)
        return wrapper

    def _ensure_page(self, label: str):
        """The page for one rail label, built on first show. None when
        the module never loaded or its build raised; the rail says so."""
        page = self._pages.get(label)
        if page is not None:
            return page
        module = self._page_modules.get(label)
        if module is None or not hasattr(module, "build"):
            return None
        try:
            page = module.build(self)
        except Exception as e:            # noqa: BLE001
            print(f"greywatch ui: page {label} failed to build: {e}",
                  file=sys.stderr)
            self.note(f"The {label}: it did not open (its build "
                      "raised an error).")
            return None
        wrapper = self._mount_page(label, page)
        self._fit_beat()
        return wrapper

    def _build_rail(self) -> None:
        child = self._rail.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._rail.remove(child)
            child = nxt
        self._rail_rows = {}

        surfaces = [label for label, _mod in REGISTRY
                    if label in self._page_modules and label not in
                    ("Assistant", "Help")]
        tail = [label for label, _mod in REGISTRY
                if label in self._page_modules and label in
                ("Assistant", "Help")]
        if surfaces:
            cap = Gtk.Label(label="Screens")
            cap.add_css_class("gw-side-cap")
            cap.set_xalign(0.0)
            self._rail.append(cap)
            for label in surfaces:
                self._rail.append(self._rail_row(label))
        if tail:
            cap2 = Gtk.Label(label="Application")
            cap2.add_css_class("gw-side-cap")
            cap2.set_xalign(0.0)
            self._rail.append(cap2)
            for label in tail:
                self._rail.append(self._rail_row(label))
        # Advanced is an inline expander in the rail, not a popover and
        # not a Settings switch. The full tool menu sits in a Revealer
        # under the row.
        if self._importable("advanced"):
            self._rail.append(self._rail_row("Advanced"))
            module = self._page_modules.get("Advanced")
            if module is None:
                module = self._import("advanced")
                if module is not None:
                    self._page_modules["Advanced"] = module
            if module is not None:
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                              spacing=2)
                box.add_css_class("gw-advanced")
                rows = module.build_rows(self)
                self._advanced_rows = {
                    row.get_label(): row for row in rows
                    if row.get_label()}
                for caption, labels in getattr(module, "GROUPS", ()):
                    cap = Gtk.Label(label=caption)
                    cap.add_css_class("gw-side-cap")
                    cap.set_xalign(0.0)
                    box.append(cap)
                    for label in labels:
                        row = self._advanced_rows.get(label)
                        if row is None:
                            continue
                        row.add_css_class("gw-advanced-row")
                        box.append(row)
                revealer = Gtk.Revealer()
                revealer.set_transition_type(
                    Gtk.RevealerTransitionType.SLIDE_DOWN)
                revealer.set_child(box)
                revealer.set_reveal_child(False)
                self._rail.append(revealer)
                self._advanced_revealer = revealer
                self._advanced_open = False

    def _rail_row(self, label: str) -> Gtk.Button:
        b = Gtk.Button()
        inner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                        spacing=8)
        from ui import kit
        image = kit.rail_icon(label)
        if image is not None:
            inner.append(image)
        lab = Gtk.Label(label=label)
        lab.set_hexpand(True)
        lab.set_xalign(0.0)
        inner.append(lab)
        b.set_child(inner)
        b.set_halign(Gtk.Align.FILL)
        if label == "Advanced":
            chevron = Gtk.Label(label="▸")
            chevron.add_css_class("gw-chevron")
            inner.append(chevron)
            b._gw_chevron = chevron
            b.connect("clicked", self._toggle_advanced)
        else:
            b.connect("clicked", lambda _b, n=label: self.show_page(n))
        self._rail_rows[label] = b
        return b

    def _toggle_advanced(self, button) -> None:
        """Expand or collapse the inline tool menu in the rail."""
        revealer = getattr(self, "_advanced_revealer", None)
        if revealer is None:
            self.note("The Advanced menu arrives with the tool screens.")
            return
        self._advanced_open = not getattr(self, "_advanced_open", False)
        revealer.set_reveal_child(self._advanced_open)
        scroll = getattr(self, "_rail_scroll", None)
        if scroll is not None:
            if self._advanced_open:
                scroll.add_css_class("gw-advanced-open")
            else:
                scroll.remove_css_class("gw-advanced-open")
        chevron = getattr(button, "_gw_chevron", None)
        if chevron is not None:
            chevron.set_label("▾" if self._advanced_open else "▸")

    def _set_theme(self, voice: str) -> None:
        if themes.set_active_theme(voice, store=self._store):
            self.note(f"Theme set to {voice}.")
            self.queue_draw()

    def open_tool_page(self, label: str, tool_ids: tuple,
                       digest: str) -> None:
        """An advanced tool opens as a page in this window, not a popup."""
        if label not in self._page_modules:
            from ui import tooldesk

            class _ToolPage:
                def build(self, window):
                    return tooldesk.build(window, title=label,
                                          tool_ids=tool_ids,
                                          digest_name=digest)

                def refresh(self, page):
                    tooldesk.refresh(page)

            self._page_modules[label] = _ToolPage()
        self.show_page(label)

    def has_page(self, label: str) -> bool:
        """The page is reachable: its module loaded. With lazy builds
        the page may not hold widgets yet - show_page builds it on the
        first request, so every rail jump and pointer stays true."""
        return label in self._page_modules

    def show_page(self, label: str, *, again_ok: bool = False) -> None:
        page = self._ensure_page(label)
        if page is None:
            return
        self._stack.set_visible_child(page)
        for name, row in self._rail_rows.items():
            if name == label:
                row.add_css_class("gw-active")
            else:
                row.remove_css_class("gw-active")
        for name, row in (getattr(self, "_advanced_rows", {}) or {}).items():
            if name == label:
                row.add_css_class("gw-active")
            else:
                row.remove_css_class("gw-active")
        module = self._page_modules.get(label)
        original = self._page_widgets.get(label, page)
        if module is not None and hasattr(module, "refresh"):
            try:
                module.refresh(original)
            except Exception as e:             # noqa: BLE001
                print(f"greywatch ui: refresh {module.__name__} failed: {e}",
                      file=sys.stderr)

    def _open_job_surface(self, _button) -> None:
        """The header status opens the surface that owns the running job:
        the scan desk for the antivirus and external scans, or the tool's
        own desk for the four named jobs."""
        key = str((self.scan_monitor.live or {}).get("key") or "")
        if key in ("rkhunter", "lynis", "aide", "yara-tmp-scan"):
            from ui import advanced
            try:
                target = advanced.desk_for(key)
            except KeyError:
                self.show_page("Security Center")
                return
            self.open_tool_page(*target)
            return
        self.show_page("Security Center")
        self._open_overview()

    def _open_overview(self) -> None:
        """A running antivirus or external scan lives on Overview: open
        that tab and put the scan block at the top of the page."""
        page = self._pages.get("Security Center")
        body = getattr(page, "_gw_body", page)
        stack = getattr(body, "_gw_tab_stack", None)
        if stack is not None:
            stack.set_visible_child_name("overview")
        scroll = self._page_widgets.get("Security Center")
        adjustment = (scroll.get_vadjustment()
                      if hasattr(scroll, "get_vadjustment") else None)
        if adjustment is not None:
            adjustment.set_value(0.0)

    def _update_header_status(self, doc) -> None:
        """The live instrument in the header: idle, scanning with a
        percent, paused, or a scan the service did not start. Only a
        running job makes it sensitive, so the button is inert when it
        has nowhere to go."""
        doc = doc or {}
        state = str(doc.get("state") or "")
        scanners = doc.get("scanners") or {}
        external = doc.get("external") or []
        # A finished scanner reports percent 1.0, and only some parsers
        # carry a total at all, so a terminal row must never speak for a
        # job that is still working: take a running row's percent, then a
        # paused one, and otherwise show no percentage.
        percent = None
        for wanted in ("running", "paused"):
            for row in scanners.values():
                if row.get("percent") is None:
                    continue
                if str(row.get("state") or "") == wanted:
                    percent = row["percent"]
                    break
            if percent is not None:
                break
        level, word = "", "Idle"
        if external and not scanners:
            level = "warn"
            word = "EXTERNAL SCAN"
        elif state == "paused":
            level, word = "warn", "PAUSED"
        elif state == "running":
            level = "warn"
            word = "SCANNING" + (f" {int(round(percent * 100))}%"
                                 if percent is not None else "")
        elif state == "failed":
            level, word = "fail", "SCAN FAILED"
        self._header_status.set_label(word)
        self._header_status.set_sensitive(word != "Idle")
        for name in ("ok", "warn", "fail"):
            self._header_status.remove_css_class(f"gw-status-{name}")
        if level:
            self._header_status.add_css_class(f"gw-status-{level}")

    def _fit_beat(self) -> bool:
        """The page takes the width it is given: no fixed measure, no
        centring. The rail keeps its law, the wide class still scales the
        type, and a page that knows how reflows its own content."""
        width = self.get_width()
        wide = width >= 2400
        if wide:
            self.add_css_class("gw-wide")
        else:
            self.remove_css_class("gw-wide")
        rail_w = 260 if wide else (232 if width >= 1600 else 208)
        if self._rail_holder.get_size_request()[0] != rail_w:
            self._rail_holder.set_size_request(rail_w, -1)
        for page in self._page_widgets.values():
            page.set_hexpand(True)
            page.set_halign(Gtk.Align.FILL)
            if page.get_size_request()[0] != -1:
                page.set_size_request(-1, -1)
            relayout = getattr(page, "_gw_relayout", None)
            if relayout is not None:
                relayout(width)
        return True

    def note(self, text: str) -> None:
        """A short notice at the top right, never a line under the rail."""
        self._note_seq += 1
        seq = self._note_seq
        self._note.set_label(text)
        self._toast.set_reveal_child(True)
        GLib.timeout_add_seconds(7, lambda: self._clear_note(seq))

    def _clear_note(self, seq: int) -> bool:
        if seq == self._note_seq:
            self._toast.set_reveal_child(False)
        return False


def _raw_saved_pick() -> str:
    prefs = read_prefs()
    return str(prefs.get("theme", ""))


class App(Gtk.Application):

    def __init__(self):
        super().__init__(application_id="org.greywatch.GUI")
        self._win = None

    def do_activate(self):
        if self._win is not None:
            self._win.present()
            return
        win = Window(self)
        self._win = win
        win.present()
        self._install_tray(win)
        landing = ("Security Center" if "Security Center" in win._page_modules
                   else next(iter(win._page_modules), None))
        if landing:
            win.show_page(landing)
            self._ask_elevated_once(win)
        else:
            win.note("No screens are available yet.")
        self.hold()

    def _install_tray(self, win) -> None:
        """The system tray again (owner 2026-11-19: 'theres no system
        tray anymore either'): the wolf icon owns show/quit through the
        window; a minute beat keeps the pending + alert badge fresh.
        A dead tray is non-fatal - the window close path keeps working."""
        try:
            from ui.tray import Tray
            import gi
            from gi.repository import GLib

            def on_show():
                win.present()

            def on_quit():
                app = self
                GLib.idle_add(app.quit)

            tray = Tray(on_show=on_show, on_quit=on_quit,
                        item_id="greywatch")
            self._tray = tray
            GLib.timeout_add_seconds(60, self._tray_beat, tray)
            tray.refresh_badge()
        except Exception as e:                  # noqa: BLE001
            self._tray = None
            print(f"tray unavailable (window close will exit): {e}",
                  file=sys.stderr)

    def _tray_beat(self, tray) -> bool:
        try:
            tray.refresh_badge()
        except Exception:                       # noqa: BLE001
            pass
        return True

    def _ask_elevated_once(self, win) -> None:
        """The one launch-time ask (owner 2026-11-16): when the posture
        report still lacks root inputs, request the elevated re-read as
        the app opens. The polkit dialog asks for the password; a cancel
        is honored and nothing re-prompts."""
        try:
            from ui import cliapi, security
            report = cliapi.read_state("posture.json") or {}
            need = security.root_need(report, security.get_status_mtime())
            page = win._pages.get("Security Center")
            if need and page is not None:
                security.request_root_once(win, page, from_launch=True)
                win.note("The Security Center asked for one root read: "
                         "approve it in the dialog for the full score.")
        except Exception as e:              # noqa: BLE001
            print(f"greywatch ui: launch elevate ask skipped: {e}",
                  file=sys.stderr)


def main() -> int:
    _kill_duplicates()
    if not _acquire_single_instance_lock():
        print("greywatch ui: another instance holds the lock - "
              "launching again is a restart, not a stack-up",
              file=sys.stderr)
        return 1
    app = App()
    try:
        return app.run(None)
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            if _LOCK is not None:
                fcntl.flock(_LOCK, fcntl.LOCK_UN)
                _LOCK.close()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
