"""The Settings page panes (rebuild Phase 4c): every pane builder, the
firewall and learning wiring, and the trusted-lists editors live here;
MainWindow composes this mixin for its panes, so window.py keeps the
stack, activation, badges, and the header."""
import datetime as _dt
import json
import os
import pathlib
import subprocess
import threading
import time

from gi.repository import Gtk, GLib, Gio

from assistant import audit
import greywatch_daemon as daemon_mod

from ui import discover, metrics
from ui.models import local_clock
from ui.desk import related_box
from ui.plain import escape, muted as pc_muted, ok as pc_ok
from ui.themes import dark_default, load_setting, THEME_CHOICES

_SETTINGS_RELATED = {
    "look": (("Connections", "The lists the firewall consults", "connections"),
             ("Tools", "Every protection, its row in the suite", "tools"),
             ("Browser Watch", "The findings desk", "thunter")),
    "firewall": (("Connections", "Add trusted sites or programs", "connections"),
                 ("Notifications", "Snooze popups or quiet a lane",
                  "alerts"),
                 ("Protections", "Its row in the suite, with its last events",
                  "protect"),
                 ("Logs", "Decisions recorded as events via=appfw", "logs")),
    "alerts": (("App firewall", "The decisions that raise a deny popup",
                "firewall"),
               ("Logs", "The deny rows the popups came from", "logs")),
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



def _data_dir():
    """The one data dir: the app window module owns DATA_DIR (tests
    patch it there), so the panes read through it instead of freezing
    this module's own import-time value."""
    from ui import window as _win
    return _win.DATA_DIR


class SettingsDeskMixin:
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
            cfg = acfg.load(_data_dir())
            cfg["learning_mode"] = (mode == "learning")
            cfg["strict_mode"] = (mode == "whitelist")
            cfg["fail_open"] = (mode != "whitelist")
            acfg.save(_data_dir(), cfg)      # daemon mtime check re-arms
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
            cfg = acfg.load(_data_dir())
            cfg["ipv6_enabled"] = bool(check.get_active())
            acfg.save(_data_dir(), cfg)
        except Exception:
            pass

    def _ws_pref(self) -> int:
        from ui.settings import ws_pref
        return ws_pref(_data_dir())

    def _on_ws_pick(self, combo):
        from ui.settings import ws_set
        try:
            ws_set(_data_dir(), int(combo.get_active_id() or 3))
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
        snap = pathlib.Path(_data_dir()) / "status.json"
        try:
            age = time.time() - snap.stat().st_mtime
            verdict = "fresh" if age < 90 else \
                "STALE: the daemon pipeline may be wedged (restart it)"
            lines.append(f"status snapshot age: {age:.0f} s · {verdict}")
        except OSError:
            lines.append("status snapshot: missing (daemon has not written yet)")
        try:
            tail = (pathlib.Path(_data_dir()) / "appfw" / "events.jsonl") \
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

    def _paint_doctor_rows(self):
        """The daemon's own health snapshot, verbatim: one line per lane
        from status["doctor"] (GW-D3). The key's absence renders nothing,
        so this stays invisible until Wave D turns it on."""
        label = getattr(self, "_doctor_label", None)
        if label is None:
            return
        rows = None
        try:
            raw = json.loads(
                (pathlib.Path(_data_dir()) / "status.json").read_text(
                    encoding="utf-8"))
            got = raw.get("doctor")
            rows = got if isinstance(got, list) else None
        except (OSError, ValueError):
            rows = None
        if not rows:
            label.set_visible(False)
            return
        lines = ["the daemon's last self-check:"]
        for r in rows:
            if isinstance(r, dict):
                lines.append(f"{r.get('lane', '?')} · "
                             f"{r.get('verdict', '?')} · "
                             f"{str(r.get('text', ''))[:160]}")
        label.set_text("\n".join(lines))
        label.set_visible(len(lines) > 1)

    def _on_diag_refresh(self, btn):
        btn.set_sensitive(False)
        def run():
            text = self._diag_truth()
            def done():
                self._diag_label.set_text(text)
                self._paint_doctor_rows()
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

    def _settings_alerts(self):
        """Desktop notifications: the master silence, the 30-minute
        snooze and a permanent switch per lane (GW-189). Quieting is a
        chosen state, so the controls write the keys the notify lane
        reads; a file it cannot read fails open and popups keep showing."""
        from ui.notify_alert import read_alert_prefs
        prefs = read_alert_prefs()
        card, inner = self._settings_card(
            "Desktop notifications",
            "What may pop up on screen while the tools work. Scans and "
            "events stay recorded even when their popups are quiet.")

        master = Gtk.Switch()
        master.set_active(prefs["alerts"])
        master.connect("notify::active",
                       lambda w, _p: self._on_alerts_master(w))
        inner.append(self._settings_row(
            "All desktop notifications", master,
            "The total switch: off silences every lane at once."))

        snooze_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                             spacing=12)
        snooze_btn = Gtk.Button(label="Snooze 30 minutes")
        snooze_btn.connect("clicked", self._on_alerts_snooze)
        snooze_btn.set_valign(Gtk.Align.CENTER)
        self._alerts_snooze_status = Gtk.Label(xalign=0)
        self._alerts_snooze_status.set_xalign(0)
        self._alerts_snooze_status.set_markup(
            self._alerts_snooze_words(prefs["alerts_snooze_until"]))
        snooze_box.append(snooze_btn)
        snooze_box.append(self._alerts_snooze_status)
        snooze_row = self._settings_row(
            "Snooze", snooze_box,
            "Thirty minutes without popups, then they come back by "
            "themselves.")
        inner.append(snooze_row)

        for label, key, hint in (
                ("Firewall deny popups", "deny_popups",
                 "The ⛔ square that names what a blocked connection "
                 "tried."),
                ("Critical event popups", "critical_popups",
                 "The ⚠ square for HIGH and CRITICAL tool findings.")):
            lane = Gtk.Switch()
            lane._alerts_key = key
            lane.set_active(prefs[key])
            lane.connect("notify::active",
                         lambda w, _p: self._on_alerts_lane(w))
            inner.append(self._settings_row(label, lane, hint))
        return self._settings_section(card)

    @staticmethod
    def _alerts_snooze_words(stamp) -> str:
        """What the snooze row says right now, in plain words."""
        stamp = float(stamp or 0.0)
        if stamp <= time.time():
            return "<span size='12000' font_family='Inter' " \
                   f"color='{pc_muted()}'>Popups are showing.</span>"
        when = time.strftime("%H:%M", time.localtime(stamp))
        return ("<span size='12000' font_family='Inter' "
                f"color='{pc_muted()}'>Quiet until {when}, then popups "
                "come back.</span>")

    def _on_alerts_master(self, switch):
        """The master silence switch: one key, every lane obeys."""
        from ui.notify_alert import write_alert_prefs
        write_alert_prefs(alerts=bool(switch.get_active()))
        return True

    def _on_alerts_lane(self, switch):
        """A per-lane switch: deny popups and critical popups quiet
        independently."""
        from ui.notify_alert import write_alert_prefs
        key = getattr(switch, "_alerts_key", "")
        if key:
            write_alert_prefs(**{key: bool(switch.get_active())})
        return True

    def _on_alerts_snooze(self, _btn):
        """The one-click 30-minute snooze; the row says when it ends."""
        from ui.notify_alert import snooze_alerts
        stamp = snooze_alerts(30)
        self._alerts_snooze_status.set_markup(
            self._alerts_snooze_words(stamp))
        return True

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
            ("alerts", "preferences-desktop-notification-symbolic",
             "Notifications", self._settings_alerts),
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
        "alerts": "snooze 30 minutes · per-lane switches · master silence",
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
        radio_paper = Gtk.CheckButton(label="Paper, light")
        radio_graphite = Gtk.CheckButton(label="Graphite, dark")
        radio_graphite.set_group(radio_paper)
        picked = load_setting() or dark_default(self._theme_store.names())
        shown = picked if picked in THEME_CHOICES.values() \
            else dark_default(self._theme_store.names())
        (radio_paper if shown == "paper" else radio_graphite).set_active(True)
        radio_paper.connect("toggled", self._on_radio_theme, "paper")
        radio_graphite.connect("toggled", self._on_radio_theme, "graphite")
        self._radio_paper = radio_paper
        self._radio_graphite = radio_graphite
        theme_row.append(radio_paper)
        theme_row.append(radio_graphite)
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
        self.fw_mode.set_active_id(acfg.mode_of(acfg.load(_data_dir())))
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
        # GW-D3 forward-compat: when the daemon publishes the doctor
        # snapshot (status["doctor"]), Diagnostics paints its rows under
        # the probe lines; the absent key renders nothing.
        self._doctor_label = Gtk.Label(xalign=0)
        self._doctor_label.set_xalign(0)
        self._doctor_label.set_wrap(True)
        self._doctor_label.add_css_class("gw-meta")
        self._doctor_label.set_visible(False)
        diag_inner.append(self._doctor_label)
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
            snap = daemon_mod.load_status(str(_data_dir() / "status.json"))
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
            write_enabled(_data_dir(), not was_on)
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
                (_data_dir() / "learning-clear.json").read_text()).get("since") or 0)
        except (OSError, ValueError, TypeError):
            return 0.0

    def _on_learn_clear(self, _btn):
        try:
            (_data_dir() / "learning-clear.json").write_text(
                json.dumps({"since": time.time()}))
        except OSError:
            pass
        self._refresh_fw()

    def _learned(self) -> list:
        path = _data_dir() / "learning-seen.jsonl"
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

