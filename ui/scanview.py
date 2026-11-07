"""Scan results: findings with their fixes, and the last scans.

The daemon writes scan-live.json, scan-findings.jsonl and scans/<id>.json;
this module only renders them. It holds no scan state, so closing the
window loses nothing.

The per-scanner progress rows that used to live here moved into the
Protections page: the same scan used to show twice — once bare on a Scans
page and once as "0" on the Tools page — so the rows moved to one page with
full-width rows, a progress bar each, and a small log beneath.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402

from ui import metrics
from ui.plain import muted as theme_muted  # noqa: E402
from ui.plain import severity_colour  # noqa: E402
from ui.desk import DeskBand, DeskCoverage, DeskDossier, DeskFeed, \
    DeskStrip  # noqa: E402

SCANNER_ORDER = ("clamav", "rkhunter", "lynis", "aide", "yara-tmp-scan")
NAMES = {"clamav": "Antivirus", "rkhunter": "Rootkit", "lynis": "Audit",
         "aide": "File integrity", "yara-tmp-scan": "Quick scan"}
TITLES = {"full": "Full scan", "max-speed": "Full scan at max speed",
          "scan-all": "Full scan", "yara-tmp-scan": "Quick scan",
          "clamav": "Deep antivirus scan", "rkhunter": "Rootkit scan",
          "lynis": "Security audit", "aide": "File-integrity check"}

STATE_WORDS = {"queued": "Queued", "running": "Scanning", "done": "Done",
               "failed": "Failed", "interrupted": "Interrupted"}

# The desk's stat band and coverage strip (approved mockup):
# every tile reads the run document's own fields, never a guess.
SCAN_BAND_KEYS = (("finds", "Findings · newest run"),
                  ("runs", "Runs on file"),
                  ("fails", "Scanners failed"),
                  ("files", "Files swept"),
                  ("now", "Running now"))
# The four scanners a full run carries, plus the scan-logs doorway tile.
SCAN_CHANNELS = (("clamav", "Antivirus"), ("rkhunter", "Rootkit"),
                 ("lynis", "Audit"), ("aide", "File integrity"),
                 ("yara-tmp-scan", "Quick scan"))

# Standard exit-code names worth saying in raw facts (128 + signal). The
# scanner's own detail text always carries the real words; this only
# names the code in the code's own terms.
EXIT_NAMES = {137: "= killed (SIGKILL)", 124: "= timed out (SIGTERM)",
              1: "= the scanner reported an error"}
# Colours come from the active theme at paint time (ui.plain), never from
# literals: the hardcoded dark-theme hexes read as washed-out blue-grey on
# the light cream theme.

# Severity words mean nothing without a sentence beside them.
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


def when_label(raw) -> str:
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


def short_label(counter_label: str | None) -> str:
    """The counter in its short grid word ("files", never "files scanned")."""
    if not counter_label:
        return "checks"
    return _GRID_WORD.get(counter_label, counter_label)


def duration_words(seconds) -> str:
    """A run length in the desk's honest words ("6 h 12 m", "21.4 s")."""
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return ""
    if s <= 0:
        return ""
    if s >= 3600:
        return f"{int(s // 3600)} h {int(s % 3600 // 60)} m"
    if s >= 120:
        return f"{int(s // 60)} m"
    return f"{s:.1f} s"


def sev_counts(findings) -> tuple[int, int, int]:
    """High / medium / routine counts from a run's finding rows."""
    high = sum(1 for f in findings
               if str(f.get("severity", "")).upper() in ("HIGH", "CRITICAL")
               and not f.get("routine"))
    med = sum(1 for f in findings
              if str(f.get("severity", "")).upper() == "MEDIUM"
              and not f.get("routine"))
    routine = sum(1 for f in findings
                  if f.get("routine")
                  or str(f.get("severity", "INFO")).upper()
                  in ("LOW", "INFO"))
    return high, med, routine


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
        return f"Queued - starts after {wait}" if wait else "Queued"
    if state == "running":
        out = f"Scanning · {n:,} {label}"
        return out + (f" · {finds} finding{'s' if finds != 1 else ''}"
                      if finds else "")
    if state == "failed":
        return "Last scan failed" + (f": {sc['detail']}"
                                     if sc.get("detail") else "")
    if state == "interrupted":
        return "Last scan interrupted"
    tail = " · clean"
    if finds:
        tail = f" · {finds} found"
    elif sc.get("warned"):
        # rkhunter's own closing line says warnings were found even when
        # none of them matched a "Warning:" line, so the honest word is
        # "warnings logged", never "clean".
        tail = " · warnings logged"
    return f"Last scan done · {n:,} {label}" + tail


SCAN_STALE_S = 30.0     # scan-live refreshes at ~1 Hz while a session runs


def _live_age(stamp) -> float | None:
    try:
        when = _dt.datetime.fromisoformat(str(stamp))
        delta = _dt.datetime.now(_dt.timezone.utc) - when
    except (TypeError, ValueError, OSError):
        return None
    return delta.total_seconds()


def status_line(live, where: str, name_of=None) -> str:
    """One sentence about the scan for the strip above the page, or "".

    A finished scan is only "clean" when every scanner actually finished. A
    scanner that failed reported nothing, which is not the same as reporting
    no problem, and saying "clean" over it hides the failure.
    """
    live = live or {}
    state = live.get("state")
    rows = live.get("scanners") or {}
    finds = int(live.get("real_findings") or 0)
    if state == "running":
        # A running claim nobody has refreshed for SCAN_STALE_S is a dead
        # writer, not a running scan (audit SM3): before this, a crashed
        # session left the strip saying "Scanning:..." forever.
        age = _live_age(live.get("updated"))
        if age is not None and age > SCAN_STALE_S:
            return (f"Scan update is {age:,.0f} s old - the session looks "
                    f"stopped. Details {where}.")
        name_of = name_of or (lambda key: key)
        running = [name_of(key) for key, v in rows.items()
                   if (v or {}).get("state") == "running"]
        msg = ("Scanning: " + ", ".join(running)) if running \
            else "Finishing the scan…"
        if finds:
            msg += f" · {finds} finding{'s' if finds != 1 else ''}"
        return msg + f". Details {where}."
    if state == "done":
        failed = sum(1 for v in rows.values()
                     if (v or {}).get("state") == "failed")
        bits = [f"{finds} finding{'s' if finds != 1 else ''}"] if finds else []
        if not finds and not failed:
            bits.append("clean")
        if failed:
            bits.append(f"{failed} scanner{'s' if failed != 1 else ''} "
                        "did not finish")
        return ("Last scan finished · " + " · ".join(bits)
                + f". Details {where}.")
    if state in ("failed", "interrupted"):
        return f"Last scan {state}. Details {where}."
    return ""


class ScanConsole(Gtk.Box):
    """The findings list, its legend, and recent scans — the actionable half
    of the merged Protections page."""

    def __init__(self, data_dir, on_explain=None, on_scan=None,
                 on_show=None, on_navigate=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.data_dir = pathlib.Path(data_dir)
        self.on_explain = on_explain
        self.on_scan = on_scan        # (tool) -> run that scanner again
        self.on_show = on_show        # (path) -> open its folder
        self.on_navigate = on_navigate  # (page key) -> jump within the app
        self._pinned = None
        self._find_key = None
        self._history_key = None
        self._run_key = None
        self._run_paint = None
        self.painted_live = None

        # The desk: the headline rides the command strip's
        # chip, the stat band and coverage strip count what the run
        # carries, and the run's own feed shares the page with the
        # selected row's dossier.
        self._strip = DeskStrip()
        self.headline = Gtk.Label(xalign=0)
        self.headline.set_xalign(0)
        self.headline.set_wrap(True)
        self.headline.add_css_class("gw-h2")
        self._strip.chip(self.headline)
        self._strip.finish()
        self.append(self._strip)

        self.legend = Gtk.Label(xalign=0)
        self.legend.set_xalign(0)
        self.legend.set_wrap(True)
        # Same single-line minimum rule as desk.py's foot/empty caps: this
        # wrap was demanding ~1170px and the desk never reached the page.
        self.legend.set_max_width_chars(96)
        self.legend.add_css_class("gw-page-meta")
        self.legend.set_markup(
            "High findings need a decision now; medium findings are worth a "
            "look. Click any finding to read what it means, re-run the "
            "scanner, show the file, quarantine or delete it, or ask the "
            "assistant.")
        self.append(self.legend)

        self.band = DeskBand(SCAN_BAND_KEYS)
        self.append(self.band)
        self.cover = DeskCoverage(
            SCAN_CHANNELS, gap=("Scan logs",
                                "per-scanner folders under scan-logs/"))
        self.append(self.cover)

        split = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        split.set_vexpand(True)
        self.history = Gtk.FlowBox()
        self.history.set_selection_mode(Gtk.SelectionMode.NONE)
        self.history.set_max_children_per_line(5)
        self.history.set_homogeneous(False)
        self._feed = DeskFeed(
            eyebrow="RECENT SCANS", on_select=self._on_run_pick,
            foot="Expected, not errors: the temp-folder sweep's routine "
                 "notices fold into their expander, never counted as "
                 "findings · every finished scanner keeps its log under "
                 "scan-logs/ · a run takes findings from its own run id, "
                 "never the last one's.")
        self._feed.headrow(self.history)      # the run chips
        split.append(self._feed)
        self.dossier = DeskDossier("SCANNER DOSSIER",
                                   on_navigate=self.on_navigate)
        self.dossier.related(self._related_rows())
        split.append(self.dossier)
        self.append(split)
        self.dossier.fill_empty(
            "Pick a scanner row to open its dossier here: its outcome in "
            "raw facts (state, exit code, the counters in its own units), "
            "the last lines it printed, and the same Run again and Show "
            "the log powers the finding dialogs carry.")

        # The findings pane carries its own eyebrow so the muted lines
        # under the feed's list never read as a scanner row's body
        # (: at the list's fold the last group heading is cut
        # mid-glyph, and an unlabelled pane invited that misreading).
        self.findings_label = Gtk.Label(xalign=0)
        self.findings_label.add_css_class("gw-eyebrow")
        self.findings_label.set_text("FINDINGS")
        self._feed.bodyrow(self.findings_label)
        self.findings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                    spacing=4)
        # The findings list keeps its shipped pane inside the feed:
        # shrink-to-content with the 260px cap (test contract.
        self.findings_scroll = Gtk.ScrolledWindow()
        self.findings_scroll.set_policy(Gtk.PolicyType.NEVER,
                                        Gtk.PolicyType.AUTOMATIC)
        self.findings_scroll.set_propagate_natural_height(True)
        self.findings_scroll.set_max_content_height(260)
        self.findings_scroll.set_child(self.findings_box)
        self._feed.bodyrow(self.findings_scroll)
        # The list is capped at about six rows so the row feed stays the
        # page's entry point; the count and this doorway make it explicit
        # (shipped.
        self.more_btn = Gtk.Button(label="Show all findings")
        self.more_btn.add_css_class("gw-mini")
        self.more_btn.set_halign(Gtk.Align.START)
        self.more_btn.set_visible(False)
        self.more_btn.connect("clicked", self._show_all_findings)
        self._feed.bodyrow(self.more_btn)
        # the record is one click away: a finding here also lives in the
        # Activity Log with its fix card, so the same event is resolvable
        # from either surface
        self.record_btn = Gtk.Button(label="Open the Activity Log")
        self.record_btn.add_css_class("gw-mini")
        self.record_btn.set_halign(Gtk.Align.START)
        self.record_btn.set_tooltip_text(
            "Every scan event, with a fix card per row.")
        self.record_btn.connect("clicked", self._open_record)
        self._feed.bodyrow(self.record_btn)
        self._last_findings = []

        self.routine_expander = Gtk.Expander()
        self.routine_expander.set_visible(False)
        self.routine_body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                    spacing=2)
        self.routine_expander.set_child(self.routine_body)
        self._feed.bodyrow(self.routine_expander)

        self.refresh()

    # ---- desk side helpers --------------------------------
    def _open_record(self, _btn):
        if callable(self.on_navigate):
            self.on_navigate("auditlog")

    def _on_run_pick(self, key: str) -> None:
        """Dossier fill for the picked feed row ("s:<scanner key>")."""
        self._run_key = str(key)
        self._paint_dossier()

    def _related_rows(self):
        """The scanner dossier's fixed related hand-offs."""
        return (
            ("Protections", "The protection rows and their last-run "
             "sentences", "protect"),
            ("Logs", "Events the suite recorded from these scanners",
             "logs"),
            ("Browser Watch",
             "The hunter's detections channel watching these tools",
             "thunter"),
        )

    # ---- data -------------------------------------------------------
    def _findings_for(self, live):
        if self._pinned:
            return read_findings(self.data_dir, limit=400,
                                 scan_id=self._pinned)
        # The findings file is appended to by every scan and trimmed in
        # place, so an unfiltered read mixed a finished scan's rows into the
        # one on screen: a "clean" headline sat over six HIGH rows left by
        # an earlier run.
        sid = (live or {}).get("scan_id")
        return read_findings(self.data_dir, limit=200, scan_id=sid)

    def pin(self, scan_id):
        self._pinned = scan_id
        self._find_key = None
        self._history_key = None
        self._run_key = None               # the pinned run's feed re-paints
        self.refresh()

    def show_live(self):
        self._pinned = None
        self._find_key = None
        self._history_key = None
        self._run_key = None
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
        # The desk paints before the words: band, coverage and the run's
        # feed rows read the same document the headline reads.
        self._paint_band(live or {}, findings)
        self._paint_cover(live or {})
        self._paint_feed(live or {})
        self._paint_strip_meta(live or {})
        if not live:
            self.headline.set_markup(
                f"<span size='13000' font_family='Inter' color='{theme_muted()}'>"
                "No scan yet. Press a scan button above - each protection "
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
        # : notes are for live moments (a refused request while a
        # scan runs); a session note beside a final state is stale by
        # definition, so the desk renders it only while something moves.
        if live.get("note") and state not in ("done", "failed", "interrupted"):
            extra += f" · {live['note']}"
        self.headline.set_markup(
            f"<span size='15000' font_family='Inter' weight='650'>{line}"
            f"</span><span size='12000' font_family='Inter' "
            f"color='{theme_muted()}'>{extra}</span>")
        self._paint_findings(findings)
        self._paint_history()

    # ---- desk band / coverage / feed / dossier ------------
    @staticmethod
    def _run_row_key(key: str) -> str:
        return f"s:{key}"

    def _paint_strip_meta(self, live: dict) -> None:
        """The strip's right-edge words: the selected run's own record
        (state, local moment, the longest scanner's own run length)."""
        if not live:
            self._strip.meta("no run on file")
            return
        title = TITLES.get(live.get("key"), "Scan").upper()
        state = (live.get("state") or "done").upper()
        parts = [f"{title}: {state}"]
        finished = state not in ("RUNNING", "QUEUED")
        if finished:
            parts.append(when_label(
                live.get("ended_at") or live.get("started_at")))
            longest = max([float((sc or {}).get("duration_s") or 0)
                           for sc in (live.get("scanners") or {}).values()]
                          or [0.0])
            if longest > 0:
                parts.append(f"longest scanner {duration_words(longest)}")
        cap = " · CPU AND MEMORY CAPPED" \
            if live.get("throttle") and finished else ""
        self._strip.meta(" · ".join(parts) + cap)

    def _paint_band(self, live: dict, findings) -> None:
        """Five tallies from the selected run plus the store of runs."""
        docs = read_history(self.data_dir, limit=20)
        finds = live.get("real_findings") or 0
        high, med, routine = sev_counts(findings)
        sub = (f"{med} medium · {routine} routine · "
               f"{high} {'needs' if high == 1 else 'need'} a decision now")
        self.band.set("finds", f"{int(finds):,}", sub)
        self.band.set("runs", f"{len(docs)}",
                      " · ".join(when_label(
                          d.get("ended_at") or d.get("started_at"))[0:6]
                          for d in docs[:3]) or "nothing on file")
        rows = live.get("scanners") or {}
        failed = [(k, v) for k, v in rows.items()
                  if (v or {}).get("state") in ("failed", "interrupted")]
        self.band.set(
            "fails", f"{len(failed)}/{len(SCANNER_ORDER)}",
            (f"{NAMES.get(failed[-1][0], failed[-1][0])}: "
             f"{str(failed[-1][1].get('detail') or 'did not finish')}"
             + (f", exit {failed[-1][1].get('exit_code')}"
                if failed[-1][1].get("exit_code") is not None else "")
             if failed else "every scanner finished, nothing swallowed"))
        best, best_n, best_k = None, 0, ""
        for key, sc in rows.items():
            n = int((sc or {}).get("count") or 0)
            if "files" in str((sc or {}).get("counter_label") or "") \
                    and n > best_n:
                best, best_n, best_k = sc, n, key
        self.band.set(
            "files", f"{best_n:,}" if best_n else "0",
            f"the {NAMES.get(best_k, best_k).lower()} alone, "
            f"last {TITLES.get(live.get('key'), 'run')}" if best
            else "files counted only when a run carries them")
        running = [(k, v) for k, v in rows.items()
                   if (v or {}).get("state") == "running"]
        self.band.set(
            "now", f"{len(running)}/{len(SCANNER_ORDER)}",
            ", ".join(NAMES.get(k, k) for k, _v in running) + " scanning now"
            if running else "nothing scanning - the desktop is quiet")

    def _paint_cover(self, live: dict) -> None:
        """The run scanner by scanner, in each scanner's own units."""
        rows = live.get("scanners") or {}
        for key, _label in SCAN_CHANNELS:
            sc = rows.get(key) or {}
            state = sc.get("state")
            n = int(sc.get("count") or 0)
            label = short_label(sc.get("counter_label"))
            finds = int(sc.get("findings") or 0)
            if state == "done":
                tail = f" · {finds} found" if finds else (
                    " · clean" if not sc.get("warned")
                    else " · warnings logged")
                self.cover.set(key, f"{state} · {n:,} {label}{tail}")
            elif state == "failed":
                code = sc.get("exit_code")
                note = f" · exit {code}" if code is not None else ""
                self.cover.set(key, f"{state}{note} · {n:,} {label}")
            elif state == "interrupted":
                self.cover.set(key, f"{state} · {n:,} {label}")
            elif state == "queued":
                wait = sc.get("waiting_for")
                self.cover.set(key,
                               f"queued · starts after {wait}" if wait
                               else "queued")
            elif state == "running":
                self.cover.set(key, f"scanning · {n:,} {label}")
            else:
                self.cover.set(key, "no run on file")

    def _scanner_row(self, key: str, sc: dict) -> Gtk.Box:
        """One feed row per scanner: its own verdict line and units."""
        state = sc.get("state") or "done"
        n = int(sc.get("count") or 0)
        label = short_label(sc.get("counter_label"))
        finds = int(sc.get("findings") or 0)
        if state == "running":
            title = f"Scanning · {n:,} {label}"
            meta_bits = ["running now"]
            colour = severity_colour("MEDIUM")
        elif state == "queued":
            wait = sc.get("waiting_for")
            title = f"Queued - starts after {wait}" if wait else "Queued"
            meta_bits = []
            colour = severity_colour("MEDIUM")
        elif state == "failed":
            code = sc.get("exit_code")
            detail = str(sc.get("detail") or "did not finish")
            title = f"Finished with exit {code} - {detail}"
            meta_bits = [f"exit {code} {EXIT_NAMES.get(code, '')}".strip()]
            colour = severity_colour("HIGH")
        elif state == "interrupted":
            title = f"Interrupted - {sc.get('detail') or 'mid-run'}"
            meta_bits = []
            colour = severity_colour("HIGH")
        else:
            tail = "clean"
            if finds:
                tail = f"{finds} found"
            elif sc.get("warned"):
                tail = "warnings logged"
            title = f"{n:,} {label} - {tail}"
            meta_bits = []
            colour = severity_colour("LOW")
        when = when_label(sc.get("ended_at") or sc.get("started_at"))
        meta_bits = [f"{key}"] + meta_bits + [
            STATE_WORDS.get(state, state).lower()] + (
            [when] if state not in ("running", "queued") else [])
        return self._feed.row(
            self._run_row_key(key), title, " · ".join(meta_bits),
            dot_colour=colour)

    def _paint_feed(self, live: dict) -> None:
        """The selected run's feed: one row per scanner, its units."""
        self._feed.clear()
        rows = live.get("scanners") or {}
        sequence = live.get("sequence") or SCANNER_ORDER
        built = 0
        for key in sequence:
            sc = rows.get(key)
            if not sc:
                continue
            self._feed.group(f"{NAMES.get(key, key)} · {key}")
            self._feed.append_row(self._run_row_key(key),
                                  self._scanner_row(key, sc))
            built += 1
        self._feed.set_empty("" if built
                             else ("No run on file yet. Press a scan "
                                   "button on the strip above."))
        if self._run_key and self._run_key in self._feed.rows():
            self._feed.mark_selected(self._run_key)
        self._paint_dossier()

    def _paint_dossier(self) -> None:
        """Dossier fill for the picked scanner row; never a finding row's
        pick (findings open their own dialogs as shipped)."""
        if self._run_key is None:
            return
        if self._run_key not in self._feed.rows():
            return
        key = self._run_key[2:] if self._run_key.startswith("s:") else \
            self._run_key
        live = self.painted_live or {}
        sc = (live.get("scanners") or {}).get(key)
        if not sc:
            self._run_key = None
            self.dossier.fill_empty(
                "That scanner is not part of this run.")
            return
        self._fill_scanner_dossier(key, sc)

    def _fill_scanner_dossier(self, key: str, sc: dict) -> None:
        """The scanner's own record: state, exit code, its units, the
        last lines it printed, next step, and the run/show powers."""
        live = self.painted_live or {}
        state = sc.get("state") or "done"
        n = int(sc.get("count") or 0)
        label = short_label(sc.get("counter_label"))
        finds = int(sc.get("findings") or 0)
        sev = "HIGH" if state in ("failed", "interrupted") else (
            "MEDIUM" if finds else "LOW")
        d = self.dossier
        d.clear()
        d.title().set_text(f"{NAMES.get(key, key)} - {key}")
        d.pill(STATE_WORDS.get(state, state).lower(),
               "gw-pill-fail" if state in ("failed", "interrupted")
               else "gw-pill-warn" if state in ("running", "queued")
               else "gw-pill-neutral",
               severity_colour(sev))
        code = sc.get("exit_code")
        if code not in (0, None):
            d.pill(f"exit code {code}", "gw-pill-neutral",
                   severity_colour(sev))
        if n:
            d.pill(f"{n:,} {label}")
        if finds:
            d.pill(f"{finds} found", "gw-pill-warn",
                   severity_colour("MEDIUM"))
        dur = duration_words(sc.get("duration_s"))
        if dur:
            d.pill(f"{dur} {('capped run' if live.get('throttle')
                   else 'uncapped run')}")
        means = ""
        if state == "done":
            found = (f"{finds} finding{'s' if finds != 1 else ''}"
                     if finds else
                     ("the scanner's own closing line said warnings were "
                      "logged" if sc.get("warned") else "nothing found"))
            means = f"Finished with {n:,} {label} - {found}"
        elif state == "failed":
            detail = str(sc.get("detail") or "Did not finish")
            means = f"{detail} - exit {code} " \
                    f"{EXIT_NAMES.get(code, '')}".strip()
        elif state == "interrupted":
            means = ("The scanner was interrupted mid-run; its own log "
                     "says where it stopped.")
        elif state == "running":
            means = "Scanning now; its counts move while it runs."
        else:
            wait = sc.get("waiting_for")
            tail = f" ({wait})" if wait else ""
            means = (f"Queued behind another scanner{tail}; it runs "
                     "after that one finishes.")
        d.label("What this means")
        d.prose(means)
        d.label("Raw facts")
        raw_bits = []
        raw_bits.append(f"exit code: {code} "
                        f"{EXIT_NAMES.get(code, '')}".strip())
        raw_bits.append(f"counter: {n:,} - {label}")
        raw_bits.append(f"findings: {finds:,}")
        if sc.get("warned"):
            raw_bits.append("the scanner's own closing line said warnings "
                            "were logged")
        if dur:
            raw_bits.append(f"duration: {sc.get('duration_s')} s"
                            f"{' · capped run' if live.get('throttle')
                             else ' · uncapped run'}")
        scan_id = live.get("scan_id")
        log_dir = self.data_dir / "scan-logs" / str(scan_id or "") / key
        if scan_id and log_dir.exists():
            raw_bits.append(f"log folder: {log_dir}")
        d.facts(raw_bits)
        if sc.get("log"):
            d.label("Last lines it printed")
            d.facts([str(line) for line in sc["log"]])
        d.label("Suggested next step")
        if state in ("failed", "interrupted"):
            d.prose(f"Run {NAMES.get(key, key)} again from this dossier; "
                    "the same scanner runs after anything already queued.")
        elif state == "running":
            d.prose("Let it run; nothing here stops a scanner by itself.")
        else:
            found = (f"Open its {finds} finding{'s' if finds != 1 else ''}"
                     " above to act on it" if finds else
                     "Keep the protection on; nothing here acts by "
                     "itself")
            d.prose(f"Nothing to act on from this run. {found}.")
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        if callable(self.on_scan):
            again = Gtk.Button(label=f"Run {NAMES.get(key, key)} again")
            again.add_css_class("gw-mini")
            again.set_tooltip_text(
                "Queue the same scanner; it runs after anything already "
                "in the queue")
            again.connect("clicked", self._scan_again, key, None)
            actions.append(again)
        log_dir = self.data_dir / "scan-logs" / str(scan_id or "") / key
        if callable(self.on_show) and scan_id and log_dir.exists():
            show = Gtk.Button(label="Show the log")
            show.add_css_class("gw-mini")
            show.set_tooltip_text(str(log_dir))
            show.connect("clicked", self._show_finding, str(log_dir),
                         None)
            actions.append(show)
        if actions.observe_children():
            d.detail().append(actions)

    def _paint_findings(self, findings):
        # The key includes the run's state: a run can go from scanning
        # to finished without a single finding arriving, and the empty
        # state must follow it out of the still-running voice.
        key = (self._pinned, (self.painted_live or {}).get("state") or "",
               tuple((f.get("tool"), f.get("text")) for f in findings))
        if key == self._find_key:
            return
        self._find_key = key
        self._last_findings = list(findings)
        for box in (self.findings_box, self.routine_body):
            while (c := box.get_first_child()) is not None:
                box.remove(c)
        real = [f for f in findings if not f.get("routine")]
        routine = [f for f in findings if f.get("routine")]
        if not real:
            state = str((self.painted_live or {}).get("state") or "")
            said = "Nothing needs attention." if routine else (
                "Nothing to report yet."
                if state in ("running", "queued", "")
                else "Nothing to report from this run.")
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
            f"- expected, not errors")
        self.routine_expander.set_tooltip_text(
            "Background noise the app recognises: baseline drift, package "
            "debris, and tool suggestions. Nothing to act on. Open to read "
            "the exact files.")
        self.routine_expander.set_visible(bool(routine))
        shown = len(real)
        self.more_btn.set_visible(shown > 6)
        self.more_btn.set_label(
            f"Show all {shown} findings" if shown > 6 else "Show all")

    def _show_all_findings(self, *_a):
        """Every finding, in a dialog with its own scroll — the list on the
        page stays short so the protections underneath stay reachable."""
        findings = self._last_findings or []
        # : non-modal - the scan page stays closable under it.
        dialog = Gtk.Dialog(title="All findings",
                            transient_for=self.get_root(), modal=False)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        dialog.set_default_size(*metrics.dialog_size())
        body = dialog.get_content_area()
        body.set_margin_top(12)
        body.set_margin_bottom(12)
        body.set_margin_start(18)
        body.set_margin_end(18)
        body.set_spacing(8)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_wrap(True)
        head.set_text(f"Every finding from this scan, newest first - "
                      f"{len(findings)} in total. Click one to act on it.")
        head.add_css_class("gw-page-meta")
        body.append(head)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        for f in findings:
            box.append(self._finding_row(f, parent=dialog))
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        scroll.set_child(box)
        body.append(scroll)
        dialog.connect("response", lambda d, _r: d.destroy())
        dialog.present()

    def _finding_row(self, f, parent=None) -> Gtk.Button:
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
        btn.set_tooltip_text(f"{sev} - {meaning}\n{f.get('text', '')}")
        btn.connect("clicked", lambda *_a, row=f:
                    self._open_finding(row, parent=parent))
        return btn

    # ---- one finding: meaning + real actions -------------------------
    def _open_finding(self, f, parent=None):
        sev = str(f.get("severity", "INFO")).upper()
        tool = str(f.get("tool", ""))
        text = str(f.get("text", ""))
        dialog = Gtk.Dialog(title=f"{sev} finding - {NAMES.get(tool, tool)}",
                            transient_for=parent or self.get_root(),
                            modal=False)
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

        actions = Gtk.FlowBox()
        actions.set_selection_mode(Gtk.SelectionMode.NONE)
        actions.set_column_spacing(8)
        actions.set_row_spacing(6)
        actions.set_max_children_per_line(4)
        actions.set_homogeneous(False)

        # Manual control first. The dialog used to offer only Close or
        # "ask the assistant", so a person could not do anything about a
        # finding themselves.
        copy = Gtk.Button(label="Copy details")
        copy.add_css_class("gw-quiet")
        copy.set_tooltip_text("Copy the severity, tool and raw line")
        copy.connect("clicked", self._copy_finding, tool, sev, text, status)
        actions.append(copy)

        path = finding_path(text) if tool in _FILE_TOOLS else None
        if path and pathlib.Path(path).exists():
            show = Gtk.Button(label="Show in folder")
            show.add_css_class("gw-quiet")
            show.set_tooltip_text(path)
            show.connect("clicked", self._show_finding, path, status)
            actions.append(show)

        if tool in SCANNER_ORDER and callable(self.on_scan):
            again = Gtk.Button(label=f"Run {NAMES.get(tool, tool)} again")
            again.add_css_class("gw-quiet")
            again.set_tooltip_text(
                "Queue the same scanner; it runs after anything already "
                "in the queue")
            again.connect("clicked", self._scan_again, tool, dialog)
            actions.append(again)

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
        ask.connect("clicked", self._explain, tool, sev, text, dialog)
        actions.append(ask)
        body.append(actions)
        dialog.present()

    def _copy_finding(self, _btn, tool, sev, text, status):
        detail = (f"{sev} - {NAMES.get(tool, tool)} ({tool})\n{text}")
        try:
            clip = Gdk.Display.get_default().get_clipboard()
            clip.set(detail)
            status.set_text("Copied. Paste it into a note or a bug report.")
        except Exception:
            status.set_text(f"Could not reach the clipboard. The line is:\n"
                            f"{detail}")

    def _show_finding(self, _btn, path, status=None):
        if callable(self.on_show):
            try:
                self.on_show(path)
                if status is not None:
                    status.set_text(f"Opened the folder holding {path}.")
                return
            except Exception as exc:            # noqa: BLE001
                if status is not None:
                    status.set_text(f"Could not open the folder: {exc}")
                return
        if status is not None:
            status.set_text(f"The file is at {path}.")

    def _scan_again(self, _btn, tool, dialog=None):
        if dialog is not None:
            dialog.destroy()
        if callable(self.on_scan):
            self.on_scan(tool)

    def _explain(self, _btn, tool, sev, text, dialog=None):
        if dialog is not None:
            dialog.destroy()
        if callable(self.on_explain):
            # Tool and severity travel with the question: without them the
            # assistant matched the text alone and answered an infected-
            # file finding with "the scan is clean".
            question = (f"How do I fix this {sev} finding from "
                        f"{NAMES.get(tool, tool)} ({tool})? {text}")
            row = {"tool": tool, "severity": sev, "text": text}
            try:
                self.on_explain(question, row)
            except TypeError:          # an older one-argument callback
                self.on_explain(question)

    def _file_action(self, btn, action, path, dialog, status):
        warn = ("Quarantine" if action == "quarantine" else "Delete")
        # : destroy-with-parent instead of modal - the scan view
        # keeps its close button working while the confirm is up.
        confirm = Gtk.Dialog(title=f"{warn} this file?",
                             transient_for=dialog, modal=False)
        confirm.set_destroy_with_parent(True)
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
