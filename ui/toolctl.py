import datetime as _dt
import pathlib
import subprocess
import threading
import time

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk    # noqa: E402

from ui.models import local_clock
from ui.plain import (friendly_name, what_is, escape, sentence as plain_sentence,
                      severity_colour as pc_severity_colour)
from ui.cards import SCAN_MODES
from ui.eventclock import present_now
from wiz.common import helper_detail
from ui import metrics
import greywatch_daemon as daemon_mod

# Which guided task configures a given protection. Shared by the Details
# dialog and the Services page so a tool offers the SAME entry point in
# both places (it used to differ: Details offered seven, the card none).
WIZARD_FOR = {"appfw": "appfw", "ufw": "ufw", "fail2ban": "fail2ban",
              "tetragon": "tetragon", "arpwatch": "arpwatch",
              "yara-watch": "yara", "yara-tmp-scan": "yara"}


class ToolCtlMixin:
    """Tool lifecycle, from dialog to unit, on the MainWindow.

    Pausing and resuming, the panic sweep, the manual scan triggers,
    the per-tool detail dialog. Reads and writes everything it touches
    through self (the window) so the state stays in one place; nothing
    here edits a config file directly.
    """

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
            self._show("services")

    def _pause_selected(self):
        if self._selected_tool:
            self._pause_tool(self._selected_tool)

    def _resume_selected(self):
        if self._selected_tool:
            self._resume_tool(self._selected_tool)

    def _pause_tool(self, name):
        tool = self.by_name.get(name) or {}
        if not tool.get("unit"):
            print(f"{friendly_name(name)} has no service to pause.",
                  flush=True)
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
            snap = daemon_mod.load_status(str(self.data_dir / "status.json"))
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
        print(msg, flush=True)
        self.refresh()
        return False

    def _ensure_appfw_enabled(self):
        try:
            from appfw.engine import read_enabled, write_enabled
            if not read_enabled(self.data_dir):
                write_enabled(self.data_dir, True)
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
            snap = daemon_mod.load_status(str(self.data_dir / "status.json"))
            info = (snap.get("tools") or {}).get("responderd") or {}
            if info.get("state") != "GREEN":
                self._resume_tool("responderd")
        except Exception:
            pass
        return None

    SCAN_RUN = {"rkhunter": "rkhunter", "lynis": "lynis"}

    def _control_requested(self, name: str) -> None:
        """The registry record's control row. Same levers the strip rows
        carry, now where the tool's own story is read: resume a paused
        tool, start a down one, and for the unit-less scanners (rkhunter,
        lynis: their verdict lives in their logs) run the scan now."""
        tool = self.by_name.get(name) or {}
        if not tool.get("unit") and name in self.SCAN_RUN:
            self._scan_pressed(name)
            return
        self._toggle_tool(name, pause=False)

    def _scan_pressed(self, name: str) -> None:
        def worker():
            try:
                from wiz import common
                rc, err = common.run_helper_out(
                    "scan-now", [self.SCAN_RUN[name]], timeout=120)
            except Exception:
                rc, err = -1, ""
            GLib.idle_add(self._after_scan, name, rc, err)

        threading.Thread(target=worker, daemon=True).start()

    def _after_scan(self, name: str, rc: int, err: str = "") -> None:
        self._assistant_record_outcome(rc == 0)
        msg = (f"{friendly_name(name)} scan started; its row turns "
               "green when the log speaks." if rc == 0 else
               f"Could not start the {friendly_name(name)} scan "
               f"({helper_detail(rc, err)}).")
        print(f"scan {name}: {msg}", flush=True)
        if rc != 0:
            console = getattr(getattr(self, "services_page", None),
                              "scanconsole", None)
            if console is not None and hasattr(console, "show_scan_note"):
                console.show_scan_note(f"the scan could not start: "
                                       f"{friendly_name(name)} - "
                                       f"{helper_detail(rc, err)}.")
        self.refresh()

    def _toggle_tool(self, name, pause: bool):
        tool = self.by_name.get(name) or {}
        unit = tool.get("unit")
        action = "stop" if pause else "start"

        if name == "appfw":
            try:
                from appfw.engine import write_enabled
                write_enabled(self.data_dir, not pause)
                rc = 0
            except Exception:
                rc = -1
            self._after_toggle("appfw", pause, rc)
            self._refresh_fw()
            return

        def worker():
            try:
                if not unit:
                    # No unit, no lever here: rkhunter and lynis run
                    # through the scan runner; anything else refuses.
                    if name in self.SCAN_RUN:
                        from wiz import common
                        rc, _err = common.run_helper_out(
                            "scan-now", [self.SCAN_RUN[name]], timeout=120)
                    else:
                        rc = -1
                    state = None
                elif tool.get("scope") == "user":
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
            events = daemon_mod.read_events(self.data_dir / "events.jsonl", 8000)
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
