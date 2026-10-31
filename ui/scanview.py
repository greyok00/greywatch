"""Scan results: findings with their fixes, and the last scans.

The daemon writes scan-live.json, scan-findings.jsonl and scans/<id>.json;
this module only renders them. It holds no scan state, so closing the
window loses nothing.

The per-scanner progress rows that used to live here moved into the
Protections page (2026-10-30): the owner saw the same scan twice — once
bare on a Scans page and once as "0" on the Tools page — and asked for one
page with full-width rows, a progress bar each, and a small log beneath.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk, Pango  # noqa: E402

from ui.plain import muted as theme_muted  # noqa: E402
from ui.plain import severity_colour  # noqa: E402

SCANNER_ORDER = ("clamav", "rkhunter", "lynis", "aide", "yara-tmp-scan")
NAMES = {"clamav": "Antivirus", "rkhunter": "Rootkit", "lynis": "Audit",
         "aide": "File integrity", "yara-tmp-scan": "Quick scan"}
TITLES = {"scan-all": "Scan everything", "yara-tmp-scan": "Quick scan",
          "clamav": "Full antivirus scan", "rkhunter": "Rootkit scan",
          "lynis": "Security audit", "aide": "File-integrity check"}

STATE_WORDS = {"queued": "Queued", "running": "Scanning", "done": "Done",
               "failed": "Failed", "interrupted": "Interrupted"}
# Colours come from the active theme at paint time (ui.plain), never from
# literals: the hardcoded dark-theme hexes read as washed-out blue-grey on
# the light cream theme (2026-10-31).

# Severity words mean nothing without a sentence beside them; the owner
# read a lone red "HIGH" and asked what it was for (2026-10-30).
SEVERITY_MEANING = {
    "HIGH": "needs your attention now",
    "CRITICAL": "needs your attention now",
    "MEDIUM": "review when you have a moment",
    "LOW": "noted, usually nothing to do",
    "INFO": "for the record",
}

# Tools whose findings name a file that the user may actually act on.
_FILE_TOOLS = ("clamav", "yara-tmp-scan")
_PATH_RE = re.compile(r"(?<![\w:.])(/[^\s()\[\],;'\"]+)")


def finding_path(text: str) -> str | None:
    """The absolute file a finding talks about, or None."""
    for m in _PATH_RE.finditer(str(text or "")):
        path = m.group(1).rstrip(".")
        if 1 < len(path) <= 400:
            return path
    return None


def when_label(raw: str) -> str:
    """A history chip reads as a local moment, not raw ISO text."""
    try:
        when = _dt.datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return (raw or "")[:16]
    if when.tzinfo is not None:
        when = when.astimezone()
    return when.strftime("%b %d, %H:%M")


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


# The protection row gives each scan a short status line, so the counter
# label is shortened there ("12,844 files", not "12,844 files scanned …").
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
        wait = sc.get("waiting_for")
        return f"Queued — starts after {wait}" if wait else "Queued"
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


class ScanConsole(Gtk.Box):
    """The findings list, its legend, and recent scans — the actionable half
    of the merged Protections page."""

    def __init__(self, data_dir, on_explain=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.data_dir = pathlib.Path(data_dir)
        self.on_explain = on_explain
        self._pinned = None
        self._find_key = None
        self._history_key = None
        self.painted_live = None

        self.headline = Gtk.Label(xalign=0)
        self.headline.set_xalign(0)
        self.headline.set_wrap(True)
        self.headline.add_css_class("gw-h2")
        self.append(self.headline)

        self.legend = Gtk.Label(xalign=0)
        self.legend.set_xalign(0)
        self.legend.set_wrap(True)
        self.legend.add_css_class("gw-page-meta")
        self.legend.set_markup(
            "High findings need a decision now; medium findings are worth a "
            "look. Click any finding to read what it means and quarantine, "
            "delete or ask the assistant about it.")
        self.append(self.legend)

        self.findings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                    spacing=4)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_propagate_natural_height(True)
        scroll.set_max_content_height(260)
        scroll.set_child(self.findings_box)
        self.append(scroll)

        self.routine_expander = Gtk.Expander()
        self.routine_expander.set_visible(False)
        self.routine_body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                    spacing=2)
        self.routine_expander.set_child(self.routine_body)
        self.append(self.routine_expander)

        hist_head = Gtk.Label(xalign=0)
        hist_head.set_xalign(0)
        hist_head.add_css_class("gw-eyebrow")
        hist_head.set_text("RECENT SCANS")
        self.append(hist_head)
        self.history = Gtk.FlowBox()
        self.history.set_selection_mode(Gtk.SelectionMode.NONE)
        self.history.set_max_children_per_line(5)
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
                f"<span size='13000' font_family='Inter' color='{theme_muted()}'>"
                "No scan yet. Press a scan button above — each protection "
                "below shows its own progress and log while it runs."
                "</span>")
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
            f"<span size='15000' font_family='Inter' weight='650'>{line}"
            f"</span><span size='12000' font_family='Inter' "
            f"color='{theme_muted()}'>{extra}</span>")
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
            said = ("Nothing needs attention." if routine
                    else "Nothing to report yet.")
            quiet = Gtk.Label(label=said, xalign=0)
            quiet.set_xalign(0)
            quiet.set_markup(f"<span color='{theme_muted()}'>{said}</span>")
            self.findings_box.append(quiet)
        for f in real:
            self.findings_box.append(self._finding_row(f))
        for f in routine:
            row = Gtk.Label(label=f"· {f.get('text', '')}", xalign=0)
            row.set_xalign(0)
            row.set_ellipsize(Pango.EllipsizeMode.END)
            row.set_tooltip_text(str(f.get("text", "")))
            self.routine_body.append(row)
        count = len(routine)
        self.routine_expander.set_label(
            f"{count} routine notice{'s' if count != 1 else ''} "
            f"— expected, not errors")
        self.routine_expander.set_tooltip_text(
            "Background noise the app recognises: baseline drift, package "
            "debris, and tool suggestions. Nothing to act on. Open to read "
            "the exact files.")
        self.routine_expander.set_visible(bool(routine))

    def _finding_row(self, f) -> Gtk.Button:
        sev = str(f.get("severity", "INFO")).upper()
        ink = severity_colour(sev)
        btn = Gtk.Button()
        btn.add_css_class("gw-finding")
        btn.add_css_class("sev-" + sev.lower())
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        chip = Gtk.Label(label=sev)
        chip.add_css_class("gw-sev")
        chip.set_markup(f"<span color='{ink}' weight='700'>{sev}</span>")
        chip.set_size_request(64, -1)
        who = Gtk.Label(label=NAMES.get(f.get("tool"), f.get("tool", "")),
                        xalign=0)
        who.set_xalign(0)
        who.set_size_request(92, -1)
        text = Gtk.Label(label=str(f.get("text", "")), xalign=0)
        text.set_xalign(0)
        text.set_hexpand(True)
        text.set_ellipsize(Pango.EllipsizeMode.END)
        meaning = SEVERITY_MEANING.get(sev, "")
        hint = Gtk.Label(label="Review and fix →", xalign=1)
        hint.set_xalign(1)
        hint.add_css_class("gw-fixhint")
        for w in (chip, who, text, hint):
            row.append(w)
        btn.set_child(row)
        btn.set_tooltip_text(f"{sev} — {meaning}\n{f.get('text', '')}")
        btn.connect("clicked", lambda *_a, row=f: self._open_finding(row))
        return btn

    # ---- one finding: meaning + real actions -------------------------
    def _open_finding(self, f):
        sev = str(f.get("severity", "INFO")).upper()
        tool = str(f.get("tool", ""))
        text = str(f.get("text", ""))
        dialog = Gtk.Dialog(title=f"{sev} finding — {NAMES.get(tool, tool)}",
                            transient_for=self.get_root(), modal=True)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        body = dialog.get_content_area()
        body.set_margin_top(14)
        body.set_margin_bottom(14)
        body.set_margin_start(18)
        body.set_margin_end(18)
        body.set_spacing(10)

        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_wrap(True)
        head.set_markup(
            f"<span size='15000' weight='650'>{sev}</span> "
            f"<span color='{severity_colour(sev)}'>"
            f"{SEVERITY_MEANING.get(sev, '')}</span>")
        body.append(head)
        what = Gtk.Label(label=text, xalign=0)
        what.set_xalign(0)
        what.set_wrap(True)
        what.set_selectable(True)
        body.append(what)

        advice = Gtk.Label(xalign=0)
        advice.set_xalign(0)
        advice.set_wrap(True)
        advice.set_selectable(True)
        advice.add_css_class("gw-advice")
        try:
            from assistant.advice import advise_event
            advice.set_text(advise_event({"tool": tool, "severity": sev,
                                          "text": text}))
        except Exception:
            advice.set_text("")
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_propagate_natural_height(True)
        scroller.set_max_content_height(300)
        scroller.set_child(advice)
        body.append(scroller)

        status = Gtk.Label(xalign=0)
        status.set_xalign(0)
        status.set_wrap(True)
        body.append(status)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        path = finding_path(text) if tool in _FILE_TOOLS else None
        if path:
            for label, action in (("Quarantine file", "quarantine"),
                                  ("Delete file", "delete")):
                b = Gtk.Button(label=label)
                b.add_css_class("gw-quiet")
                b.connect("clicked", self._file_action, action, path,
                          dialog, status)
                actions.append(b)
        ask = Gtk.Button(label="Ask the assistant")
        ask.add_css_class("gw-primary")
        ask.connect("clicked", self._explain, text, dialog)
        actions.append(ask)
        body.append(actions)
        dialog.present()

    def _explain(self, _btn, text, dialog):
        dialog.destroy()
        if callable(self.on_explain):
            self.on_explain(
                f"How do I fix this scan finding? {text}")

    def _file_action(self, btn, action, path, dialog, status):
        warn = ("Quarantine" if action == "quarantine" else "Delete")
        confirm = Gtk.Dialog(title=f"{warn} this file?",
                             transient_for=dialog, modal=True)
        confirm.add_button("Cancel", Gtk.ResponseType.CANCEL)
        confirm.add_button(warn, Gtk.ResponseType.OK)
        box = confirm.get_content_area()
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(18)
        box.set_margin_end(18)
        lbl = Gtk.Label(xalign=0)
        lbl.set_xalign(0)
        lbl.set_wrap(True)
        verb = ("moved into the greywatch quarantine" if action ==
                "quarantine" else "deleted permanently")
        lbl.set_text(f"{path}\n\nThis file will be {verb}. "
                     "You will be asked for your password.")
        box.append(lbl)

        def _go(dlg, rid, *_a):
            dlg.destroy()
            if rid != Gtk.ResponseType.OK:
                return
            status.set_text(f"{warn}ing {path}…")
            btn.set_sensitive(False)

            def work():
                from wiz import common
                try:
                    rc = common.run_helper("file-action", [action, path],
                                           timeout=120)
                    msg = (f"{warn}: done." if rc == 0
                           else f"{warn}: the helper exited {rc}.")
                except Exception as e:
                    msg = f"{warn}: failed ({type(e).__name__})."
                GLib.idle_add(status.set_text, msg)

            import threading
            threading.Thread(target=work, daemon=True,
                             name="gw-file-action").start()

        confirm.connect("response", _go)
        confirm.present()

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
        live_b.add_css_class("gw-chip")
        live_b.connect("clicked", lambda *_a: self.show_live())
        self.history.append(live_b)
        for doc in docs:
            when = when_label(doc.get("ended_at") or doc.get("started_at")
                              or "")
            label = f"{TITLES.get(doc.get('key'), 'Scan')} · {when}"
            b = Gtk.Button(label=label)
            b.add_css_class("gw-chip")
            b.connect("clicked",
                      lambda _b, sid=doc.get("scan_id"): self.pin(sid))
            self.history.append(b)
