"""The Scans page: what the background service is doing, as it happens.

Read-only by design. The daemon writes scan-live.json, scan-findings.jsonl
and scans/<id>.json; this module renders them and holds no scan state, so
closing the window loses nothing.
"""
from __future__ import annotations

import json
import pathlib

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango  # noqa: E402

SCANNER_ORDER = ("clamav", "rkhunter", "lynis", "aide", "yara-tmp-scan")
NAMES = {"clamav": "Antivirus", "rkhunter": "Rootkit", "lynis": "Audit",
         "aide": "File integrity", "yara-tmp-scan": "Quick scan"}
TITLES = {"scan-all": "Scan everything", "yara-tmp-scan": "Quick scan",
          "clamav": "Full antivirus scan", "rkhunter": "Rootkit scan",
          "lynis": "Security audit", "aide": "File-integrity check"}

STATE_WORDS = {"queued": "Queued", "running": "Scanning", "done": "Done",
               "failed": "Failed", "interrupted": "Interrupted"}
STATE_INK = {"queued": "#8b9bb0", "running": "#5b8def", "done": "#4dd07a",
             "failed": "#ff5a52", "interrupted": "#ffc940"}
MUTED = "#8b9bb0"


def read_live(data_dir):
    """The latest live document, or None when no scan has ever run."""
    try:
        return json.loads(
            (pathlib.Path(data_dir) / "scan-live.json").read_text())
    except (OSError, ValueError):
        return None


def read_findings(data_dir, limit=200, scan_id=None):
    try:
        lines = (pathlib.Path(data_dir) / "scan-findings.jsonl").read_text(
            errors="replace").splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and (scan_id is None
                                      or row.get("scan_id") == scan_id):
            out.append(row)
    return out


def read_history(data_dir, limit=8):
    d = pathlib.Path(data_dir) / "scans"
    try:
        files = sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime,
                       reverse=True)[:limit]
    except OSError:
        return []
    out = []
    for p in files:
        try:
            out.append(json.loads(p.read_text()))
        except (OSError, ValueError):
            continue
    return out


# The Tools grid gives each protection a narrow status cell, so the counter
# label is shortened there ("12,844 files", not "12,844 files scanned …").
# The Scans page keeps the full label.
_GRID_WORD = {"files scanned": "files", "checks completed": "checks",
              "tests completed": "tests", "differences listed": "diffs",
              "temp folders swept": "folders"}


def card_text(tool: str, live) -> str:
    """One plain sentence about this protection's scan, or ""."""
    if not live:
        return ""
    key = "yara-tmp-scan" if tool == "yara-watch" else tool
    sc = (live.get("scanners") or {}).get(key)
    if not sc:
        return ""
    state = sc.get("state")
    n = int(sc.get("count") or 0)
    finds = int(sc.get("findings") or 0)
    label = _GRID_WORD.get(sc.get("counter_label") or "checks",
                           sc.get("counter_label") or "checks")
    if state == "queued":
        return "Queued"
    if state == "running":
        out = f"Scanning · {n:,} {label}"
        return out + (f" · {finds} finding{'s' if finds != 1 else ''}"
                      if finds else "")
    if state == "failed":
        return "Last scan failed" + (f": {sc['detail']}"
                                     if sc.get("detail") else "")
    if state == "interrupted":
        return "Last scan interrupted"
    return f"Last scan done · {n:,} {label}" + \
        (f" · {finds} found" if finds else " · clean")


class ScanView(Gtk.Box):
    """Per-scanner rows, a growing findings list, and the last scans."""

    def __init__(self, data_dir):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.data_dir = pathlib.Path(data_dir)
        self._pinned = None
        self._find_key = None
        self._history_key = None
        self.painted_live = None

        self.headline = Gtk.Label(xalign=0)
        self.headline.set_xalign(0)
        self.headline.set_wrap(True)
        self.append(self.headline)

        self.rows_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                spacing=4)
        self.row_widgets = {}
        for key in SCANNER_ORDER:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            row.set_margin_top(2)
            row.set_margin_bottom(2)
            name = Gtk.Label(label=NAMES[key], xalign=0)
            name.set_xalign(0)
            name.set_size_request(116, -1)
            state = Gtk.Label(xalign=0)
            state.set_xalign(0)
            state.set_size_request(86, -1)
            count = Gtk.Label(xalign=0)
            count.set_xalign(0)
            count.set_size_request(200, -1)
            current = Gtk.Label(xalign=0)
            current.set_xalign(0)
            current.set_hexpand(True)
            current.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
            for w in (name, state, count, current):
                row.append(w)
            self.rows_box.append(row)
            self.row_widgets[key] = {"state": state, "count": count,
                                     "current": current}
        self.append(self.rows_box)

        self.routine_expander = Gtk.Expander()
        self.routine_expander.set_visible(False)
        self.routine_body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                    spacing=2)
        self.routine_expander.set_child(self.routine_body)
        self.append(self.routine_expander)

        self.findings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                    spacing=4)
        # The findings list is as tall as it needs to be, up to a cap: a
        # fixed 170px pane left a dead gap between the last finding and
        # "Recent scans" on a short scan.
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_propagate_natural_height(True)
        scroll.set_max_content_height(240)
        scroll.set_child(self.findings_box)
        self.append(scroll)

        hist_head = Gtk.Label(xalign=0)
        hist_head.set_xalign(0)
        hist_head.set_markup(
            f"<span size='12000' font_family='Inter' color='{MUTED}'>"
            "Recent scans</span>")
        self.append(hist_head)
        self.history = Gtk.FlowBox()
        self.history.set_selection_mode(Gtk.SelectionMode.NONE)
        self.history.set_max_children_per_line(4)
        self.history.set_homogeneous(False)
        self.append(self.history)
        self.refresh()

    # ---- data -------------------------------------------------------
    def _findings_for(self, live):
        if self._pinned:
            return read_findings(self.data_dir, limit=400,
                                 scan_id=self._pinned)
        return read_findings(self.data_dir, limit=200)

    def pin(self, scan_id):
        """Show one finished scan instead of the live state."""
        self._pinned = scan_id
        self._find_key = None
        self._history_key = None
        self.refresh()

    def show_live(self):
        self._pinned = None
        self._find_key = None
        self._history_key = None
        self.refresh()

    def refresh(self):
        live = read_live(self.data_dir)
        if self._pinned:
            for doc in read_history(self.data_dir, limit=20):
                if doc.get("scan_id") == self._pinned:
                    live = doc
                    break
        self.paint(live, self._findings_for(live or {}))

    # ---- rendering --------------------------------------------------
    def paint(self, live, findings):
        self.painted_live = live
        if not live:
            self.headline.set_markup(
                f"<span size='13000' font_family='Inter' color='{MUTED}'>"
                "No scan yet. Press a scan button above; progress appears "
                "here as each program works.</span>")
            for w in self.row_widgets.values():
                w["state"].set_text("—")
                w["count"].set_text("")
                w["current"].set_text("")
            self._paint_findings([])
            self._paint_history()
            return
        state = live.get("state") or "done"
        finds = int(live.get("real_findings") or 0)
        title = TITLES.get(live.get("key"), "Scan")
        line = {"running": f"{title}: scanning now",
                "done": f"{title}: finished",
                "failed": f"{title}: failed",
                "interrupted": f"{title}: interrupted"}.get(state, title)
        extra = ""
        if finds:
            extra += f" · {finds} finding{'s' if finds != 1 else ''}"
        if live.get("note"):
            extra += f" · {live['note']}"
        self.headline.set_markup(
            f"<span size='14000' font_family='Inter' weight='600'>{line}"
            f"</span><span size='12000' font_family='Inter' "
            f"color='{MUTED}'>{extra}</span>")
        scanners = live.get("scanners") or {}
        for key, w in self.row_widgets.items():
            sc = scanners.get(key)
            if not sc:
                w["state"].set_text("—")
                w["count"].set_text("")
                w["current"].set_text("")
                continue
            st = sc.get("state") or "queued"
            w["state"].set_markup(
                f"<span color='{STATE_INK.get(st, MUTED)}'>"
                f"{STATE_WORDS.get(st, st)}</span>")
            w["count"].set_text(
                f"{int(sc.get('count') or 0):,} "
                f"{sc.get('counter_label', '')}".strip())
            w["current"].set_text(sc.get("detail") or sc.get("current") or "")
        self._paint_findings(findings)
        self._paint_history()

    def _paint_findings(self, findings):
        key = (self._pinned, tuple((f.get("tool"), f.get("text"))
                                   for f in findings))
        if key == self._find_key:
            return
        self._find_key = key
        for box in (self.findings_box, self.routine_body):
            while (c := box.get_first_child()) is not None:
                box.remove(c)
        real = [f for f in findings if not f.get("routine")]
        routine = [f for f in findings if f.get("routine")]
        if not real:
            quiet = Gtk.Label(label="Nothing to report yet.", xalign=0)
            quiet.set_xalign(0)
            quiet.set_markup(f"<span color='{MUTED}'>Nothing to report "
                             f"yet.</span>")
            self.findings_box.append(quiet)
        for f in real:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            chip = Gtk.Label()
            sev = str(f.get("severity", "INFO"))
            ink = {"HIGH": "#ff5a52", "CRITICAL": "#ff5a52",
                   "MEDIUM": "#ffc940"}.get(sev, MUTED)
            chip.set_markup(f"<span color='{ink}'>{sev}</span>")
            chip.set_size_request(76, -1)
            who = Gtk.Label(label=NAMES.get(f.get("tool"), f.get("tool", "")),
                            xalign=0)
            who.set_xalign(0)
            who.set_size_request(96, -1)
            text = Gtk.Label(label=str(f.get("text", "")), xalign=0)
            text.set_xalign(0)
            text.set_hexpand(True)
            text.set_ellipsize(Pango.EllipsizeMode.END)
            text.set_tooltip_text(str(f.get("text", "")))
            for w in (chip, who, text):
                row.append(w)
            self.findings_box.append(row)
        for f in routine:
            row = Gtk.Label(label=f"· {f.get('text', '')}", xalign=0)
            row.set_xalign(0)
            row.set_ellipsize(Pango.EllipsizeMode.END)
            row.set_tooltip_text(str(f.get("text", "")))
            self.routine_body.append(row)
        self.routine_expander.set_label(
            f"{len(routine)} routine notice{'s' if len(routine) != 1 else ''}")
        self.routine_expander.set_visible(bool(routine))

    def _paint_history(self):
        docs = read_history(self.data_dir, limit=8)
        key = (self._pinned, tuple(d.get("scan_id") for d in docs))
        if key == self._history_key:
            return
        self._history_key = key
        while (c := self.history.get_first_child()) is not None:
            self.history.remove(c)
        if not docs:
            return
        live_b = Gtk.Button(label="Live")
        live_b.connect("clicked", lambda *_a: self.show_live())
        self.history.append(live_b)
        for doc in docs:
            when = (doc.get("ended_at") or doc.get("started_at") or "")[:16]
            label = f"{TITLES.get(doc.get('key'), 'Scan')} · {when}"
            b = Gtk.Button(label=label)
            b.connect("clicked",
                      lambda _b, sid=doc.get("scan_id"): self.pin(sid))
            self.history.append(b)
