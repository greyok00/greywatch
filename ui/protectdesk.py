"""The Protections desk, and the Protections page (owner p1, round 2).

The page (rebuild round 2, task 10) answers "between this box and
threats, what is pending": the strip with the Run-protections-now lane,
PATCH ADVISORIES - the CVE wall moved here from the Firewall page
(severity + affected tool per row, and the patch-the-planet machinery's
coverage line) - and the recent protection-run cards below. The dock
carries the advisory filter and the Runs facts. Nothing here invents a
patch lane: where none exists the control sits disabled and says so.

The desk class below (the Protections *desk* from the approved depth
mockup) is kept for the tests that pin its dossier and narrowing laws.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import threading

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402

from cverules import active_rules  # noqa: E402
from ptp import cross_join as ptp_cross_join, watch_rows as ptp_watch_rows, \
    DASH_PROSE  # noqa: E402
from ui import metrics  # noqa: E402
from ui.plain import escape  # noqa: E402
from ui.desk import (DeskBand, DeskCoverage, DeskDossier, DeskFeed,
                     DeskStrip)  # noqa: E402
from ui.plain import (sentence as plain_sentence, muted as _muted,
                      severity_colour, without_mark, what_is)  # noqa: E402
from ui.models import age_words, status_words  # noqa: E402

# ------------------------------------------------------- the wall readers
# The CVE rule reader MOVED here from ui/defense.py (rebuild task 10):
# the Firewall page no longer renders these rows, this page does, and
# defense re-exports the names for the pins that monkeypatch through it.

_TOOL_LABEL = {
    "appfw": "the app firewall's netfilter stack",
    "clamav": "the antivirus",
    "fail2ban": "the login blocker",
    "psad": "the scan watcher",
    "kernel": "the running Linux kernel",
}


def _tool_words(tool: str) -> str:
    return _TOOL_LABEL.get(str(tool or ""), f"tool '{tool or 'unknown'}'")


def _rule_tone(score: float) -> str:
    """The wall's own tone words: HIGH at the top of the scale, MEDIUM
    for the rest of the active band."""
    return "HIGH" if float(score) >= 9.0 else "MEDIUM"


def cve_rows(data_dir):
    """Active CVE rules for the managed tools, or None when this box has
    never fetched a cache (the reader says so rather than 'nothing')."""
    cache = pathlib.Path(data_dir) / "cve-cache.json"
    if not cache.exists():
        return None
    try:
        return active_rules(cache)
    except Exception:
        return []


def ptp_rows(data_dir):
    """The Patch the Planet watchlist coverage the daemon wrote for this
    machine, or None when no watch file exists yet (the page says so
    rather than guessing; unreadable never reads as safe)."""
    rows = ptp_watch_rows(pathlib.Path(data_dir))
    if rows is None:
        return None
    return rows.get("projects") if isinstance(rows, dict) else []


def ptp_probe_failed(data_dir):
    """Which package channels could not be read on the last watch run
    (GW-B2), or [] - old watch files without the key read as all-ok."""
    path = pathlib.Path(data_dir) / "ptp-watch.json"
    try:
        got = json.loads(path.read_text(encoding="utf-8")).get(
            "probe_failed")
    except (OSError, ValueError, AttributeError):
        return []
    return got if isinstance(got, list) else []


def ptp_high_count(data_dir):
    """How many HIGH findings the covered projects carry, for the rail
    badge riding the Defense count. Never fetched reads as 0: the badge
    counts defense news, and no watch run is no defense news."""
    rows = ptp_rows(data_dir)
    if not isinstance(rows, list):
        return 0
    return sum(int(r.get("high") or 0) for r in rows
               if isinstance(r, dict))


def ptp_watch_stamp(data_dir) -> str:
    """When coverage was last matched, in human words ('today 14:52');
    empty when no watch run has arrived."""
    path = pathlib.Path(data_dir) / "ptp-watch.json"
    try:
        ts = json.loads(path.read_text(encoding="utf-8")).get("ts")
    except (OSError, ValueError, AttributeError):
        return ""
    try:
        when = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    local = when.astimezone()
    if local.date() == _dt.datetime.now().astimezone().date():
        return "today " + local.strftime("%H:%M")
    return local.strftime("%b %d %H:%M")


def coverage_line(data_dir, rows) -> str:
    """The wall's coverage sentence: how much of what the advisories
    name the program's reviewers already cover, plus the watch stamp."""
    if not isinstance(rows, list) or not rows:
        return ""
    stamp = ptp_watch_stamp(data_dir)
    if stamp == "":
        return "the watchlist has never been read - coverage is not claimed"
    covered = sum(1 for r in rows if isinstance(r, dict)
                  and ptp_cross_join(pathlib.Path(data_dir),
                                     r.get("tool")) is not None)
    pct = round(100.0 * covered / max(1, len(rows)))
    return (f"Patch the Planet: {pct}% of the advisory tools are on the "
            f"review map - watchlist read {stamp}")


# The registry's classes on the coverage strip (approved mockup). Members
# are counted by class from the registry the desk receives, never read by
# name here.
CLASSES = (
    ("antivirus", "Antivirus"),
    ("rootkit", "Rootkit scanner"),
    ("integrity", "File integrity"),
    ("firewall", "Firewall"),
    ("runtime", "Runtime and events"),
)

# Which coverage channel a registry key counts into (registry name).
CLASS_OF = {
    "clamav": "antivirus", "freshclam": "antivirus",
    "rkhunter": "rootkit",
    "aide": "integrity", "yara-watch": "integrity",
    "yara-tmp-scan": "integrity",
    "ufw": "firewall", "appfw": "firewall", "fail2ban": "firewall",
    "net-watch": "firewall",
    "apparmor": "runtime", "tetragon": "runtime", "arpwatch": "runtime",
    "responderd": "runtime", "auditd": "runtime", "lynis": "runtime",
}

_BAND_KEYS = (
    ("up", "UP AND GREEN"), ("att", "NEED ATTENTION"),
    ("wait", "DECISIONS WAITING"), ("paused", "PAUSED BY YOU"),
    ("unknown", "COULD NOT CHECK"),
)

_GROUP_ORDER = ("att", "flunked", "paused", "clean", "quiet", "unknown")

_GROUP_LABELS = {
    "att": "Needs attention",
    "flunked": "Last scan did not finish",
    "paused": "Paused by you",
    "clean": "Running clean",
    "quiet": "Runs when asked",
    "unknown": "Could not check",
}


def _when(ts) -> _dt.datetime | None:
    try:
        return _dt.datetime.fromisoformat(str(ts or "")).astimezone()
    except ValueError:
        return None


def _fmt_clock(ts) -> str:
    when = _when(ts)
    return when.strftime("%b %d, %H:%M") if when else "unknown"


def _clock_hm(ts) -> str:
    when = _when(ts)
    return when.strftime("%H:%M") if when else "unknown"


def _scan_words(state: str) -> str:
    """The scanner's state in the row's own words, never raw jargon."""
    return {"running": "running", "done": "finished", "failed": "failed",
            "interrupted": "interrupted", "queued": "waiting"}.get(
        state or "", state or "")


def _scan_pill_css(state: str) -> str:
    return {"failed": "gw-pill-fail", "interrupted": "gw-pill-fail",
            "running": "gw-pill-warn"}.get(state or "",
                                           "gw-pill-neutral")


def _scan_sev_word(state: str) -> str:
    return {"failed": "HIGH", "interrupted": "HIGH"}.get(state or "",
                                                         "LOW")


class ProtectDesk(Gtk.Box):
    """The protections desk: strip, band, coverage, feed + dossier.

    The desk owns the widgets and computes words from the snapshots it
    receives; the window keeps every handler (selection state, pause/
    resume, wizard, scan, details, navigate, show-all filter, refresh).
    """

    def __init__(self, registry, on_select=None, on_scan=None,
                 on_pause_selected=None, on_resume_selected=None,
                 on_details_selected=None, on_navigate=None,
                 enable_all=None, on_refresh=None, on_filter=None,
                 runset=(), wizard_for=None, on_wizard=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.registry = registry
        self.on_select = on_select
        self.on_scan = on_scan
        self.on_wizard = on_wizard
        self.on_pause_selected = on_pause_selected
        self.on_resume_selected = on_resume_selected
        self.on_details_selected = on_details_selected
        self.on_navigate = on_navigate
        self.runset = set(runset)
        self.wizard_for = dict(wizard_for or {})
        self.selected: str | None = None
        self._facts: dict = {}
        self._row_widgets: dict = {}
        self._updated = None
        self._dossier_text = ""

        self._build_strip(enable_all, on_refresh, on_filter)
        self._build_band()
        self._build_cover()
        self._build_split()
        self._fill_empty()

    def _now(self):
        return _dt.datetime.now(_dt.timezone.utc)

    # ------------------------------------------------------------- build

    def _build_strip(self, enable_all, on_refresh, on_filter) -> None:
        strip = DeskStrip()
        self._strip = strip
        # The verdict chip carries the big words and the tally behind
        # them, exactly the two labels refresh already fills.
        verdict = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        verdict.set_valign(Gtk.Align.CENTER)
        self.status_words = Gtk.Label(xalign=0)
        self.status_words.set_xalign(0)
        self.status_words.add_css_class("gw-suite-verdict")
        self.status_words.set_ellipsize(3)
        self.status_words.set_hexpand(False)
        verdict.append(self.status_words)
        self.counts = Gtk.Label(xalign=0)
        self.counts.set_xalign(0)
        self.counts.add_css_class("gw-page-meta")
        self.counts.set_ellipsize(3)
        verdict.append(self.counts)
        strip.chip(verdict)
        if enable_all is not None:
            self.enable_all = Gtk.Button(label="Enable all")
            self.enable_all.add_css_class("gw-mini")
            self.enable_all.set_tooltip_text(
                "Starts what is stopped and turns the app firewall on.")
            self.enable_all.connect("clicked",
                                    lambda *_b: enable_all())
            strip.append(self.enable_all)
        if on_refresh is not None:
            refresh_btn = Gtk.Button(label="Refresh")
            refresh_btn.add_css_class("gw-mini")
            refresh_btn.set_tooltip_text(
                "Re-read the snapshots nothing here acts on")
            refresh_btn.connect("clicked", lambda *_b: on_refresh())
            strip.append(refresh_btn)
        show_label = Gtk.Label(xalign=0)
        show_label.set_text("Show all")
        show_label.add_css_class("gw-page-meta")
        strip.append(show_label)
        self.show_all_btn = Gtk.Switch()
        self.show_all_btn.set_active(True)
        self.show_all_btn.set_valign(Gtk.Align.CENTER)
        self.show_all_btn.set_tooltip_text(
            "List every protection. Turn off to see only the ones that "
            "need attention.")
        if on_filter is not None:
            self.show_all_btn.connect("notify::active",
                                      lambda *_a: on_filter())
        strip.append(self.show_all_btn)
        strip.finish()
        self.append(strip)
        self.append(strip.feedback_line())

    def _build_band(self) -> None:
        self.band = DeskBand(_BAND_KEYS)

    def _build_cover(self) -> None:
        self.cover = DeskCoverage(CLASSES,
                                  gap=("RAW LINES",
                                       "the Logs tab carries every event"))

    def _build_split(self) -> None:
        split = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        split.set_vexpand(True)
        feed = DeskFeed(
            eyebrow="ALL PROTECTIONS", on_select=self._on_pick,
            foot="Rows are the page's list; the dossier carries the "
                 "depth. Pause and Run stay the rail's buttons - nothing "
                 "here starts or stops itself.")
        split.append(feed)
        self.feed = feed
        self.dossier = DeskDossier("PROTECTION DOSSIER",
                                   on_navigate=self.on_navigate)
        split.append(self.dossier)
        self.append(split)
        self._build_split_append_segmented()

    def _fill_empty(self) -> None:
        self.feed.set_empty("")
        self.dossier.fill_empty(
            "Pick a row in the feed to open its dossier here. Everything "
            "the suite knows about that protection gathers there: what "
            "it does, its live state, its last run in the scanner's own "
            "units, and where it touches the rest of the suite.")

    # ------------------------------------------------------------ select

    def _on_pick(self, key: str) -> None:
        self.selected = key
        if self.on_select is not None:
            self.on_select(key)

    def select(self, key: str | None) -> None:
        """Selection + row paint without side effects: the window's own
        row (the card frame's click handler) routes here, while a feed-row
        click routes through _on_pick. Keeping the paint in the desk is
        what lets a picked row stay marked across refreshes."""
        self.selected = key
        self.feed.mark_selected(key)

    # ------------------------------------------------------------- paint

    def _build_split_append_segmented(self) -> None:
        """The desk's segmented: build once, mount in the
        dossier's decide-here row."""
        self.pause_btn = Gtk.Button(label="Pause")
        self.pause_btn.add_css_class("gw-mini")
        if self.on_pause_selected is not None:
            self.pause_btn.connect(
                "clicked",
                lambda *_b: self.on_pause_selected())
        self.resume_btn = Gtk.Button(label="Resume")
        self.resume_btn.add_css_class("gw-mini")
        if self.on_resume_selected is not None:
            self.resume_btn.connect(
                "clicked",
                lambda *_b: self.on_resume_selected())
        self.details_btn = Gtk.Button(label="Details")
        self.details_btn.add_css_class("gw-mini")
        if self.on_details_selected is not None:
            self.details_btn.connect(
                "clicked",
                lambda *_b: self.on_details_selected())

    def paint(self, facts: dict, updated=None, rows: dict | None = None,
              visible: set | None = None):
        """Paint the feed from the per-row facts the window computed.

        The rows are the old cards (`_tool_card` frames) mounted whole,
        so refresh() keeps painting in place and nothing about them
        changes shape. Groups mount only when they have rows ("Paused by
        you" absent on a never-paused machine, never an empty strip),
        and a previous selection keeps its paint across refreshes.
        `visible` narrows only what the feed mounts (the show-all
        filter's rows); the dossier and the coverage strip still read
        `facts` whole, so a filtered-out healthy member never makes its
        whole class read as absent from the machine.
        """
        self._facts = facts
        self._updated = updated
        self.feed.clear()
        rows = dict(rows) if rows is not None else {}
        rows_by_group: dict = {g: [] for g in _GROUP_ORDER}
        for name, f in facts.items():
            state, paused, quiet = f["state"], f["paused"], f["quiet"]
            # : "Running clean" speaks about SERVICE health, but a
            # green protection whose last scan stopped short needs a
            # human look, so it reads under its own outcome banner
            # instead of an all-clear that contradicts its red rail.
            # The live run outranks history: the card's fail rail
            # describes the live session's row (window.py passes it as
            # live_scan), and history may only hold older finished runs.
            scan_state = str((f.get("live_scan") or {}).get("state")
                             or (f.get("last_scan") or {}).get("state")
                             or "")
            group = ("paused" if paused and state != "UNKNOWN"
                     else "unknown" if state == "UNKNOWN"
                     else "quiet" if quiet
                     else "att" if state in ("RED", "YELLOW")
                     else "flunked" if scan_state in ("failed",
                                                      "interrupted")
                     else "clean")
            rows_by_group[group].append(name)
        self._row_widgets = {}
        for group in rows_by_group:
            names = rows_by_group[group] or []
            if not names:
                continue
            # The heading mounts with the group's FIRST mounted row: a
            # group whose every member the visible-set drops prints no
            # banner, or the narrowed feed reads as columns of empty
            # findings under a group name.
            mounted = False
            for name in names:
                if visible is not None and name not in visible:
                    continue
                row = rows.get(name)
                if row is None:
                    continue
                if not mounted:
                    mounted = True
                    self.feed.group(_GROUP_LABELS[group])
                self.feed.append_row(name, row)
                self._row_widgets[name] = row
        if self.selected and self.selected in self._row_widgets:
            self.feed.mark_selected(self.selected)
        # A selection the refresh dropped (the filter hides it, or the
        # tool left the registry) opens the feed's empty dossier again,
        # never a dossier for a row that is not on the feed.
        if self.selected and self.selected not in self._row_widgets:
            self.selected = None
            self._fill_empty()

    def _scan_outcome_words(self) -> str:
        """, verdict half: the att tile counts tool health, so
        when a protection's own last scan did not finish the tile's
        words carry that outcome instead of reading as an all-clear
        over a row that wears a fail rail."""
        failed = [n for n, f in self._facts.items()
                  if not f["paused"] and f["state"] not in ("RED", "YELLOW")
                  and ((f.get("live_scan") or {}).get("state")
                       or (f.get("last_scan") or {}).get("state"))
                  in ("failed", "interrupted")]
        if not failed:
            return ""
        n = len(failed)
        scan = "scan" if n == 1 else "scans"
        return f"{n} last {scan} did not finish"

    def band_paint(self, running: int, attention: int, pending: int,
                   paused_n: int, unknown_n: int, total: int) -> None:
        """The five tallies the window's refresh already computes, in
        the tiles' own words."""
        self.band.set("up", str(running), f"of {total} protections")
        self.band.set("att", str(attention),
                      "reasons in the dossier" if attention
                      else self._scan_outcome_words()
                      or "nothing needs it right now")
        self.band.set("wait", str(pending),
                      "yours to answer" if pending
                      else "no decisions on file")
        self.band.set("paused", str(paused_n),
                      "resume is one click" if paused_n
                      else "nothing paused right now")
        self.band.set("unknown", str(unknown_n),
                      "reads only; nothing acted on" if unknown_n
                      else "everything checked")

    def cover_paint(self) -> None:
        """One text per protection class: how many of its members carry
        their job, and the class's last run in the scanner's clock (the
        newest by real timestamps, never by how the words sort)."""
        for key, _label in CLASSES:
            members = [n for n, f in self._facts.items()
                       if CLASS_OF.get(n) == key]
            if not members:
                self.cover.set(key, "no member on this machine")
                continue
            green_n = sum(1 for n in members
                          if self._facts[n]["state"] == "GREEN")
            stamps = sorted(
                t for t in (_when(self._facts[n].get("last_scan_ts"))
                            for n in members) if t is not None)
            last = (_fmt_clock(stamps[-1]) if stamps else "no run on file")
            self.cover.set(key, f"{green_n} of {len(members)} running · "
                                f"last run {last}")

    def fill_dossier(self, name: str | None) -> None:
        """The selected row's dossier: title, pills, what it does, the
        honest reason, raw facts, the last run's own units, the next
        step and the decide-here row (always existing powers only)."""
        f = self._facts.get(name) if name else None
        if not f:
            self.dossier.clear()
            self.dossier.fill_empty(
                "Pick a row in the feed to open its dossier here. "
                "Everything the suite knows about that protection "
                "gathers there: what it does, its live state, its last "
                "run in the scanner's own units, and where it touches "
                "the rest of the suite.")
            return
        d = self.dossier
        # A refill is a rebuild, not an append: the window refills every
        # refresh tick, and without the clear the dossier stacks a whole
        # copy of itself under the old one each time.
        d.clear()
        d.title().set_text(f"{f['label']}")
        d.pills().set_visible(True)
        state, paused = f["state"], f["paused"]
        words = status_words(state, f["installed"], paused)
        d.pill(f"state: {words.lower()}",
               "gw-pill-fail" if state == "RED"
               else "gw-pill-warn" if state in ("YELLOW", "UNKNOWN")
               else "gw-pill-warn" if paused else "gw-pill-neutral",
               _muted())
        sc = f.get("last_scan") or {}
        if (sc or {}).get("detail"):
            d.pill(str(sc["detail"]), _scan_pill_css(sc.get("state")),
                   severity_colour(_scan_sev_word(sc.get("state"))))
        if sc.get("exit_code") not in (0, None):
            d.pill(f"exit code {sc['exit_code']}",
                   _scan_pill_css(sc.get("state")),
                   severity_colour(_scan_sev_word(sc.get("state"))))
        d.detail().append(d.prose(what_is(name)))
        wrong = self._wrong_line(state, paused, sc, f.get("event"))
        if wrong:
            d.detail().append(d.label("WHAT'S WRONG ON THIS MACHINE"))
            d.detail().append(d.prose(wrong))
        raw = [
            f"real tool: {name}",
            f"unit: {f['unit'] or 'none (checkers and scans run on demand)'}",
            f"snapshot: {_fmt_clock(self._updated) if self._updated else 'no status yet'}",
        ]
        ev = f.get("event") or {}
        if ev.get("ts"):
            raw.append(f"last event: {_fmt_clock(ev.get('ts'))} · "
                       f"age {age_words(ev.get('ts'), self._now())}")
        if sc:
            raw.append(
                f"last run: {_fmt_clock(sc.get('started_at'))} - "
                f"{_scan_words(sc.get('state'))}")
        if (sc or {}).get("detail"):
            raw.append(f"scanner detail: {sc['detail']}")
        if (sc or {}).get("exit_code") not in (0, None):
            raw.append(f"exit code {sc['exit_code']}")
        if sc.get("duration_s") is not None:
            raw.append(f"run length: {sc['duration_s']}s")
        d.detail().append(d.label("RAW FACTS"))
        d.detail().append(d.facts(raw))
        unit_line = None
        if sc.get("counter_label") is not None and \
                sc.get("count") is not None:
            d.detail().append(d.label("LAST RUN IN ITS OWN UNITS"))
            unit_line = (f"{int(sc.get('count') or 0):,} "
                         f"{sc.get('counter_label')} · "
                         f"{_fmt_clock(sc.get('ended_at') or sc.get('started_at'))}")
            d.detail().append(d.evline(unit_line))
        d.detail().append(d.label("SUGGESTED NEXT STEP"))
        d.detail().append(
            d.next_box(self._next_text(state, paused, name)))
        # The dossier's plain-text twin for "Copy details": the
        # same words the dossier paints, nothing summarised away.
        copy_lines = [f["label"], f"state: {words.lower()}"]
        if sc.get("detail"):
            copy_lines.append(f"last scan: {sc['detail']}")
        elif sc.get("exit_code") not in (0, None):
            copy_lines.append("last run: did not finish")
        if sc.get("exit_code") not in (0, None):
            copy_lines.append(f"exit code {sc['exit_code']}")
        copy_lines.append(str(what_is(name)))
        if wrong:
            copy_lines.extend(["WHAT'S WRONG ON THIS MACHINE", wrong])
        copy_lines.extend(["RAW FACTS", *raw])
        if unit_line is not None:
            copy_lines.extend(["LAST RUN IN ITS OWN UNITS", unit_line])
        copy_lines.extend(["SUGGESTED NEXT STEP",
                           self._next_text(state, paused, name)])
        self._dossier_text = "\n".join(copy_lines)
        self._decide_row(name, f)

    def _decide_row(self, name: str, f: dict) -> None:
        """The dossier's decide-here row: the desk owns the segmented
        (pause/resume/details, the old rail's same handlers, dimmed
        until a row is picked) and grows the run/guided-setup buttons
        the selection is actually able to grow. Existing powers only."""
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        for b in (self.pause_btn, self.resume_btn, self.details_btn):
            holder = b.get_parent()
            if holder is not None:
                holder.remove(b)  # these buttons are singletons: each
                # fill re-mounts them into this row's own box
            b.set_valign(Gtk.Align.CENTER)
            actions.append(b)
        # Per-selection dimming with the reason (B3's contract): a dimmed
        # Pause reads as broken, so it says why it is dimmed.
        pause_sensitive = bool(f["unit"])
        self.pause_btn.set_sensitive(pause_sensitive)
        if not pause_sensitive:
            self.pause_btn.set_tooltip_text(
                "Nothing to pause - this protection has no service of "
                "its own")
        self.pause_btn.set_label("Resume" if f["paused"] else "Pause")
        if self.on_scan is not None and name in self.runset:
            run = Gtk.Button(label="Run scan")
            run.add_css_class("gw-mini")
            run.set_tooltip_text("Run this protection's scan now")
            run.connect("clicked", lambda *_b: self.on_scan(name))
            actions.append(run)
        if self.on_wizard is not None and name in self.wizard_for:
            cfg = Gtk.Button(label="Guided setup")
            cfg.add_css_class("gw-mini")
            cfg.set_tooltip_text("Guided setup - no commands to type")
            cfg.connect("clicked",
                        lambda *_b, k=self.wizard_for[name]:
                        self.on_wizard(k))
            actions.append(cfg)
        # Fresh per refill, so the "Copied" feedback resets with the
        # dossier it copied.
        copy = Gtk.Button(label="Copy details")
        copy.add_css_class("gw-mini")
        copy.set_tooltip_text("Copy this dossier's text to the clipboard")
        copy.connect("clicked", self._on_copy_dossier)
        actions.append(copy)
        self.dossier.detail().append(actions)

    def _on_copy_dossier(self, btn) -> None:
        """Copy the selected dossier's plain-text twin: everything
        the dossier says, in the order it says it, onto the clipboard. A
        clipboard that refuses is said to the button, never swallowed."""
        clip = Gdk.Display.get_default().get_clipboard()
        try:
            clip.set_text(self._dossier_text)
            btn.set_label("Copied")
        except Exception:
            btn.set_label("Copy failed")

    def _next_text(self, state: str, paused: bool, name: str) -> str:
        if state == "UNKNOWN":
            return ("Give the monitor another cycle; reads only, so "
                    "nothing is being changed meanwhile.")
        if paused:
            return ("Resume it from this dossier when you want it "
                    "working again; until then pause is yours, nothing "
                    "resumes on its own.")
        if state in ("RED", "YELLOW"):
            wizard = self.wizard_for.get(name)
            if name in self.runset:
                return ("Run its scan from this dossier: with a run on "
                        "file the counters use the scanner's own units, "
                        "and exit codes surface here in full.")
            if wizard:
                return ("Open guided setup to turn it on as installed; "
                        "it asks before changing anything.")
        return ("Keep it on. Nothing here will start or stop a "
                "protection on its own; the suite reads only.")

    def _wrong_line(self, state: str, paused: bool, sc: dict,
                    event: dict | None) -> str:
        """The honest reason: real fields, never a canned claim."""
        if paused:
            return ("Paused by you; the readings stop moving until you "
                    "resume it.")
        if state in ("RED", "YELLOW"):
            bits = []
            if (sc or {}).get("detail"):
                bits.append(str(sc["detail"]))
            if sc.get("exit_code") not in (0, None):
                bits.append(f"its last run exited {sc['exit_code']}")
            if event:
                bits.append(without_mark(plain_sentence(event)))
            if bits:
                return " · ".join(str(b) for b in bits if b)
            return ("The service reports its job needs attention; its "
                    "own detail lists nothing more.")
        if state == "UNKNOWN":
            return ("The monitor could not check it yet; its reads only, "
                    "nothing acted on.")
        return ""

    def update_clock(self, text: str) -> None:
        """The strip's right-edge SNAPSHOT clock, filled from refresh."""
        self._strip.meta(str(text))
        self._strip.finish()


# ----------------------------------------------------------- the p1 page

_RUN_HISTORY_LIMIT = 5
_PATCH_TIP = ("no patch lane exists yet on this machine - packages move "
              "through your system's own update manager; the advisory "
              "list itself refreshes from the update lane beside the "
              "card title")
_RUNS_NOTE = ("Runs arrive when the keeper starts them; the suite runs "
              "one scanner per slot. The timers the tools already keep: "
              "yara-tmp-scan.timer, aide-check.timer, "
              "greywatch-cve.timer.")
_RUNS_EDIT_TIP = ("no lane writes a schedule from the app yet - these "
                  "timers keep their own time today: yara-tmp-scan."
                  "timer, aide-check.timer, greywatch-cve.timer")


def _sev_words(rule: dict) -> str:
    sev = str(rule.get("severity") or "").upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev
    try:
        return "CRITICAL" if float(rule.get("score") or 0) >= 9.0 \
            else "HIGH"
    except (TypeError, ValueError):
        return "HIGH"


class ProtectionsPage(Gtk.Box):
    """Protections p1: the strip, the PATCH ADVISORIES wall (the CVE
    rows that moved here from the Firewall page), recent run cards, and
    the dock's Advisory filter / Runs groups. The page never patches,
    never starts a scanner except through the run lane, and every
    control without a lane sits disabled with its reason."""

    def __init__(self, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self.add_css_class("gw-protect")
        self.set_vexpand(True)
        self._win = win
        self._advisories: list = []
        self._shown: list = []
        self._sev = None            # None = every severity
        self._tool = None
        self._fixable = False
        self._refreshing = False

        # 1. the strip: the lane in plain words + the one run button
        strip = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        strip.add_css_class("gw-card")
        face = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        glyph = Gtk.Label(label="●")
        glyph.add_css_class("gw-pill")
        glyph.add_css_class("ok")
        face.append(glyph)
        words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        title = Gtk.Label(label="Between this box and threats", xalign=0)
        title.add_css_class("gw-headline")
        words.append(title)
        self.strip_meta = Gtk.Label(xalign=0, wrap=True)
        self.strip_meta.add_css_class("gw-meta")
        words.append(self.strip_meta)
        face.append(words)
        face.set_hexpand(True)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        run_btn = Gtk.Button(label="Run protections now")
        run_btn.add_css_class("gw-primary")
        run_btn.set_tooltip_text(
            "Run the suite the existing protections lane runs - the run "
            "arrives on the Scans page's console.")
        run_btn.connect("clicked", self._on_run_protections)
        actions.append(run_btn)
        face.append(actions)
        strip.append(face)
        self.append(strip)

        # 2. the PATCH ADVISORIES wall: the CVE rows live here now
        wall = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        wall.add_css_class("gw-card")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        eyebrow = Gtk.Label(label="PATCH ADVISORIES", xalign=0)
        eyebrow.add_css_class("gw-eyebrow")
        eyebrow.set_hexpand(True)
        head.append(eyebrow)
        self.refresh_adv = Gtk.Button(label="Refresh advisories")
        self.refresh_adv.add_css_class("gw-mini")
        self.refresh_adv.set_tooltip_text(
            "Read the advisory cache again (the update lane the "
            "settings page uses); coverage matching catches up on the "
            "daemon's next cycle.")
        self.refresh_adv.connect("clicked", self._on_refresh_cve)
        head.append(self.refresh_adv)
        wall.append(head)
        self.coverage_lbl = Gtk.Label(xalign=0, wrap=True)
        self.coverage_lbl.add_css_class("gw-meta")
        self.coverage_lbl.set_max_width_chars(96)
        wall.append(self.coverage_lbl)
        # the rows scroll INSIDE the card (window-fit law: never a
        # whole-page scroller)
        self._wall_rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                  spacing=4)
        wall_scroll = Gtk.ScrolledWindow()
        wall_scroll.set_policy(Gtk.PolicyType.NEVER,
                               Gtk.PolicyType.AUTOMATIC)
        wall_scroll.set_propagate_natural_height(True)
        wall_scroll.set_max_content_height(260)
        wall_scroll.set_child(self._wall_rows)
        wall.append(wall_scroll)
        self.append(wall)

        # 3. the recent protection-run cards
        runs = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        runs.add_css_class("gw-card")
        runs_eyebrow = Gtk.Label(label="RECENT RUNS", xalign=0)
        runs_eyebrow.add_css_class("gw-eyebrow")
        runs.append(runs_eyebrow)
        self._runs_body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                  spacing=6)
        runs.append(self._runs_body)
        self.runs_card = runs
        self.append(runs)

        self._build_dock()

    # ------------------------------------------------------------- dock
    def _build_dock(self) -> None:
        """The dock controls p1 (built once; DockHost claims them). The
        advisory filter carries working picks and live counts; the Runs
        group stays honest where no lane exists."""
        model = Gtk.StringList()
        for word in ("All severities", "CRITICAL", "HIGH", "MEDIUM"):
            model.append(word)
        self._sev_pick = Gtk.DropDown(model=model)
        self._sev_pick.connect("notify::selected", self._on_sev_pick)
        self._adv_counts = Gtk.Label(xalign=0, wrap=True)
        self._adv_counts.add_css_class("gw-meta")
        self._fixable_pick = Gtk.CheckButton(
            label="Covered by the watch map")
        self._fixable_pick.set_tooltip_text(
            "Only advisories whose tool the Patch the Planet map covers: "
            "the flaw is fixed upstream, so the watch is to install it.")
        self._fixable_pick.connect("toggled", self._on_fixable)
        self._tool_pick = Gtk.DropDown(model=Gtk.StringList())
        self._tool_pick.connect("notify::selected", self._on_tool_pick)
        self._runs_note = Gtk.Label(xalign=0, wrap=True)
        self._runs_note.set_text(_RUNS_NOTE)
        self._runs_note.set_max_width_chars(60)
        self._runs_note.add_css_class("gw-meta")
        self._runs_edit = Gtk.Button(label="Edit run schedule",
                                     sensitive=False)
        self._runs_edit.set_tooltip_text(_RUNS_EDIT_TIP)

    def dock_groups(self):
        """("Title", [widgets]) groups for the fixed right dock."""
        return [("Advisories", [self._sev_pick, self._tool_pick,
                                self._fixable_pick, self._adv_counts]),
                ("Runs", [self._runs_note, self._runs_edit])]

    # ----------------------------------------------------------- lane
    def _on_run_protections(self, _btn):
        """The strip's run button through the EXISTING protections lane
        (one request, the full suite; the machinery staggers it)."""
        w = self._win
        if w is not None and hasattr(w, "_run_protection"):
            w._run_protection("full")

    def _on_refresh_cve(self, btn):
        """The advisory cache refresh through the EXISTING update lane
        (ui.updates.refresh_cve, the settings page's own worker)."""
        if self._refreshing:
            return
        self._refreshing = True
        btn.set_sensitive(False)

        def work():
            try:
                from ui.updates import refresh_cve
                rc, msg = refresh_cve()
            except Exception:
                rc, msg = -1, ""
            from gi.repository import GLib as _GLib
            _GLib.idle_add(self._after_cve_refresh, rc, msg)
            return False

        threading.Thread(target=work, daemon=True).start()

    def _after_cve_refresh(self, rc, msg=""):
        self._refreshing = False
        self.refresh_adv.set_sensitive(True)
        note = ("the advisory cache was read again"
                if rc == 0 else
                f"the advisory refresh did not finish ({msg or 'no answer'})")
        self.coverage_lbl.set_text(note)
        self.refresh()
        return False

    # -------------------------------------------------------- refresh
    def refresh(self, snap=None) -> None:
        """Paint from the files refresh already owns (the CVE cache, the
        watch file, run history and scan-live); no new reads invented."""
        dd = getattr(self._win, "data_dir", "") or "."
        raw = cve_rows(dd)
        self._advisories = list(raw or [])
        self._repaint_wall(dd)
        self._repaint_runs(dd)
        self._repaint_meta(dd)
        self._sync_filter_counts()

    # -------------------------------------------------------- the wall
    def _filtered(self, dd):
        rows = []
        for r in self._advisories:
            if not isinstance(r, dict):
                continue
            if self._sev and _sev_words(r) != self._sev:
                continue
            if self._tool and str(r.get("tool") or "") != self._tool:
                continue
            if self._fixable and ptp_cross_join(
                    pathlib.Path(dd), r.get("tool")) is None:
                continue
            rows.append(r)
        return rows

    def _repaint_wall(self, dd) -> None:
        while (c := self._wall_rows.get_first_child()) is not None:
            self._wall_rows.remove(c)
        raw = cve_rows(dd)
        if raw is None:
            self.coverage_lbl.set_text(
                "No advisory cache on file yet - the advisory list has "
                "never been fetched; the Refresh button reads it now.")
            return
        self.coverage_lbl.set_text(coverage_line(dd, raw))
        if not raw:
            quiet = Gtk.Label(xalign=0, wrap=True)
            quiet.set_text("no active advisory for this machine's tools")
            quiet.set_xalign(0)
            self._wall_rows.append(quiet)
            return
        for r in self._filtered(dd):
            self._wall_rows.append(self._advisory_row(r))

    def _advisory_row(self, rule: dict) -> Gtk.Box:
        """One wall row: severity tone, the affected tool in its own
        words, the flaw, and the Patch control. Disabled, because no
        apt lane exists - the tooltip says so instead of pretending."""
        sev = _sev_words(rule)
        ink = severity_colour(_rule_tone(float(rule.get("score") or 0)))
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        chip = Gtk.Label(label=sev)
        chip.add_css_class("gw-sev")
        chip.set_size_request(88, -1)
        chip.set_markup(
            f"<span color='{ink}' weight='700'>{sev}</span>")
        row.append(chip)
        text = Gtk.Label(xalign=0, wrap=True, selectable=True)
        text.set_hexpand(True)
        text.set_max_width_chars(96)
        head = (str(rule.get("cve") or "?")
                + f" (score {rule.get('score')} {sev}) "
                + f"affects {_tool_words(rule.get('tool'))}")
        summary = str(rule.get("summary") or "")
        text.set_markup(
            escape(head) + (": " + escape(summary) if summary else ""))
        row.append(text)
        patch = Gtk.Button(label="Patch")
        patch.add_css_class("gw-mini")
        patch.set_sensitive(False)
        patch.set_tooltip_text(_PATCH_TIP)
        row.append(patch)
        return row

    # ---------------------------------------------------- the run cards
    def _repaint_runs(self, dd) -> None:
        from ui.scanview import STATE_WORDS, TITLES, read_history, \
            read_live, when_label
        while (c := self._runs_body.get_first_child()) is not None:
            self._runs_body.remove(c)
        cards = []
        live = read_live(dd) or {}
        if live.get("state") in ("running",):
            finds = int(live.get("real_findings") or 0)
            cards.append((
                TITLES.get(live.get("key"), "Scan"),
                (f"{finds} finding{'s' if finds != 1 else ''} so far - "
                 "scanning now")))
        for doc in read_history(dd, limit=_RUN_HISTORY_LIMIT):
            state = str(doc.get("state") or "done")
            finds = int(doc.get("real_findings") or 0)
            failed = [k for k, v in (doc.get("scanners") or {}).items()
                      if isinstance(v, dict)
                      and v.get("state") in ("failed", "interrupted")]
            when = when_label(doc.get("ended_at") or doc.get("started_at")
                              or "")
            if state == "done":
                tail = (f"{finds} finding{'s' if finds != 1 else ''}"
                        if finds else "clean" if not failed
                        else "finished, some scanners did not")
            else:
                tail = STATE_WORDS.get(state, state)
            if failed:
                tail += f" - {', '.join(failed)} did not finish"
            cards.append(
                (f"{TITLES.get(doc.get('key'), 'Scan')} · {when}", tail))
        if not cards:
            quiet = Gtk.Label(xalign=0, wrap=True)
            quiet.set_text("No runs on file yet - run protections now, "
                           "or start a scan from the Scans page.")
            quiet.add_css_class("gw-meta")
            self._runs_body.append(quiet)
            self.runs_card.set_visible(False)   # bug-9: no empty card
            return
        self.runs_card.set_visible(True)
        for head_text, tail in cards:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            card.add_css_class("gw-run-card")
            head = Gtk.Label(label=head_text, xalign=0, wrap=True)
            head.add_css_class("gw-meta")
            head.set_xalign(0)
            card.append(head)
            meta = Gtk.Label(label=tail, xalign=0)
            meta.set_ellipsize(Pango.EllipsizeMode.END)
            meta.add_css_class("gw-page-meta")
            meta.set_xalign(0)
            card.append(meta)
            self._runs_body.append(card)

    def _repaint_meta(self, dd) -> None:
        n = len(self._advisories)
        if not n:
            self.strip_meta.set_text(
                "no active advisory now - the scans keep the word")
            return
        self.strip_meta.set_text(
            f"{n} active advisor"
            f"{'y' if n == 1 else 'ies'} named below - the wall carries "
            "the details")

    # ------------------------------------------------------ the filters
    def _sync_filter_counts(self) -> None:
        dd = getattr(self._win, "data_dir", "") or "."
        tool_model = self._tool_pick.get_model()
        tools = sorted({str(r.get("tool") or "") for r in self._advisories
                        if r.get("tool")})
        wanted = ["All tools"] + tools
        if tool_model is not None and tool_model.get_n_items() \
                != len(wanted):
            fresh = Gtk.StringList()
            for word in wanted:
                fresh.append(word)
            self._tool_pick.set_model(fresh)
            self._tool_pick.set_selected(0)
        shown = len(self._filtered(dd))
        self._adv_counts.set_text(f"{shown} of {len(self._advisories)} "
                                  "advisories shown")

    def advisory_count(self) -> int:
        dd = getattr(self._win, "data_dir", "") or "."
        return len(self._filtered(dd))

    def set_severity_filter(self, sev) -> None:
        self._sev = str(sev or "") or None
        self._repaint()
        self._sync_filter_counts()

    def set_tool_filter(self, tool) -> None:
        self._tool = str(tool or "") or None
        self._repaint()
        self._sync_filter_counts()

    def set_fixable_filter(self, want) -> None:
        self._fixable = bool(want)
        self._repaint()
        self._sync_filter_counts()

    def _repaint(self) -> None:
        dd = getattr(self._win, "data_dir", "") or "."
        self._repaint_wall(dd)

    def _on_sev_pick(self, _dd, _ps) -> None:
        try:
            model = self._sev_pick.get_model()
            idx = int(self._sev_pick.get_selected())
            word = str(model[idx]) if 0 <= idx < model.get_n_items() \
                else None
        except (TypeError, IndexError):
            word = None
        self._sev = None if not word or word.startswith("All ") else word
        self._repaint()
        self._sync_filter_counts()

    def _on_tool_pick(self, _dd, _ps) -> None:
        try:
            model = self._tool_pick.get_model()
            idx = int(self._tool_pick.get_selected())
            word = str(model[idx]) \
                if 0 < idx < model.get_n_items() else None
        except (TypeError, IndexError):
            word = None
        self._tool = word
        self._repaint()
        self._sync_filter_counts()

    def _on_fixable(self, _btn) -> None:
        self._fixable = bool(self._fixable_pick.get_active())
        self._repaint()
        self._sync_filter_counts()
