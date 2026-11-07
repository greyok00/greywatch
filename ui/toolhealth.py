"""The Services page (rebuild Phase 3): lane two, service lifecycle only.

Header scan actions (the Scans page folds in here), the scan console
feed below them, the tool grid with lifecycle-only controls, and the
Service Healer's suggestion rows on failed components. TEST-PINNED
hard line (amendment C4): no quarantine, block, or threat control may
ever appear on this page - the classifier (events.lane_for) stays the
enforcement point and the test that pins one-control-per-lane survives
the rebuild.
"""
from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from ui.scanview import ScanConsole, SCANNER_ORDER
from ui.toolsdesk import ToolsDesk
from ui import metrics

# the manual passes that lead the page, in the order a scan runs them
_SCAN_ACTIONS = [n for n in SCANNER_ORDER]


class ServicesPage(Gtk.Box):
    """Services: scans, the tool grid, and the Service Healer's rows."""

    def __init__(self, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self.set_vexpand(True)
        self._win = win

        head = Gtk.Label(label="Scans", xalign=0)
        head.add_css_class("gw-page-title")
        acts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for name in _SCAN_ACTIONS:
            b = Gtk.Button(label="Run " + name)
            b.add_css_class("gw-primary")
            b.connect("clicked", self._scan_clicked, name)
            acts.append(b)
        scans = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        scans.append(head)
        scans.append(acts)

        self.scanconsole = ScanConsole(
            win.data_dir, on_explain=win._ask_assistant,
            on_scan=win._rescan_tool, on_show=win._show_folder,
            on_navigate=win._show)
        scans.append(self.scanconsole)
        self.append(scans)

        heal_head = Gtk.Label(label="Service Healer", xalign=0)
        heal_head.add_css_class("gw-page-title")
        self.append(heal_head)
        self._healer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                               spacing=6)
        self.append(self._healer)

        grid_head = Gtk.Label(label="Tools", xalign=0)
        grid_head.add_css_class("gw-page-title")
        self.append(grid_head)
        desk = ToolsDesk(win.registry,
                         on_select=win._tools_picked,
                         on_refresh=win.refresh,
                         on_filter=lambda: win._show_filter(
                             desk.show_all_btn),
                         on_details=win._details_selected,
                         on_navigate=win._show,
                         on_control=win._control_requested)
        self.tools_desk = desk
        # The one show-all filter lives on this desk; window.py reads it.
        win.show_all_btn = desk.show_all_btn
        self.append(desk)

    def _scan_clicked(self, _btn, name):
        if self._win is not None and hasattr(self._win, "_run_protection"):
            self._win._run_protection(name)

    # -- paint -------------------------------------------------------------
    def refresh(self, snap=None):
        snap = snap or self._win._get_status() if self._win else {}
        self._paint_healer()
        # Forward-compat (GW-C1): the daemon's scan_request digest, when
        # it appears, is said in the scan console's own note line; the
        # absent key renders nothing.
        cons = getattr(self, "scanconsole", None)
        if cons is not None and hasattr(cons, "show_request"):
            cons.show_request((snap or {}).get("scan_request"))

    def _paint_healer(self):
        from ui.decisionlist import _clear
        _clear(self._healer)
        snap = self._win._get_status() if self._win else {}
        comps = (snap or {}).get("components") or {}
        rows = [(name, str(info.get("state")), int(info.get("restarts", 0)))
                for name, info in comps.items() if isinstance(info, dict)]
        bad = [(n, s, r) for n, s, r in rows if s not in ("running",)]
        if not bad:
            ok = Gtk.Label(
                xalign=0, wrap=True,
                label="every component the healer watches is running")
            ok.add_css_class("gw-meta")
            self._healer.append(ok)
            return
        for name, state, restarts in bad:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            lbl = Gtk.Label(xalign=0, wrap=True)
            lbl.set_markup(
                f"<b>{name}</b> is <i>{state}</i>"
                f"{f' after {restarts} restart(s)' if restarts else ''} -")
            lbl.add_css_class("gw-meta")
            lbl.set_xalign(0)
            row.append(lbl)
            b = Gtk.Button(label=f"Restart {name}")
            b.add_css_class("gw-primary")
            b.connect("clicked", self._restart_clicked, name)
            row.append(b)
            self._healer.append(row)

    def _restart_clicked(self, _btn, name):
        """Proposed restart via the Service Healer: keeper-initiated, so
        it runs the standard confirm dialog naming the helper and args;
        the supervisor circuit breaker stays untouched. tool-control.sh
        takes <action> <unit>; a unit-less scanner routes to the window's
        own control path (it runs the scan instead)."""
        w = self._win
        tool = (w.by_name.get(name) or {} if w is not None else {})
        unit = str(tool.get("unit") or "")
        if not unit:
            if w is not None and hasattr(w, "_control_requested"):
                w._control_requested(str(name))
            return
        opt = {"id": "restart", "label": f"Restart {name}", "tone":
               "primary", "helper": "tool-control",
               "args": ["restart", unit]}
        if w is not None and hasattr(w, "_run_log_option"):
            w._run_log_option(_btn, dict(opt))
