"""The Protections desk.

The page follows the approved depth mockup - the same treatment as the
other desks - so it is a desk, not a card: the verdict
chip on the command strip, a five-tile stat band, the registry grouped
into its protection classes on the coverage strip, the rows grouped the
way refresh() already ranks them, and the selected row's side-by-side
dossier. Every number reads only the snapshots the window's refresh()
already loads (status.json, the event store's public digest, scan-live
and the run history); nothing here invents a reason or starts a
scanner.

The reason rule (, recorded: when a scanner fails or
exits oddly, the desk surfaces the real reason fields whenever they are
present - exit code, the scanner's own detail text and its counts in its
own units. It never substitutes a canned sentence for them, so the words
change when the machine does.
"""
from __future__ import annotations

import datetime as _dt

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, Gtk  # noqa: E402

from ui.desk import (DeskBand, DeskCoverage, DeskDossier, DeskFeed,
                     DeskStrip)  # noqa: E402
from ui.plain import (sentence as plain_sentence, muted as _muted,
                      severity_colour, without_mark, what_is)  # noqa: E402
from ui.models import age_words, status_words  # noqa: E402

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