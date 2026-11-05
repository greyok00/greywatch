"""The Tools desk.

The registry the dashboard demoted comes back as a desk: rows keep their
dot, friendly name and real name, but the visible fact per tool is its
own last activity, rows group attention-first, and the picked row's
registry record sits beside the feed - identity pills, the recent
activity trail, how the daemon reads this source, and the next step.
The band tiles read the live status snapshot; the coverage strip names
the daemon's feeds. No new powers are created: a pick only selects, the
record's buttons use the handlers the window already had (the details
dialog and navigation), and everything reads only files the suite
itself writes.
"""
from __future__ import annotations

import datetime as _dt

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from ui.desk import (DeskBand, DeskCoverage, DeskDossier, DeskFeed,
                     DeskStrip)  # noqa: E402
from ui.models import age_words, status_words  # noqa: E402
from ui.plain import friendly_name, muted as _muted, sentence as \
    plain_sentence, state_colour, what_is, without_mark  # noqa: E402

_BAND_KEYS = (
    ("reg", "REGISTERED"), ("job", "RUNNING THEIR JOB"),
    ("tails", "EVENT TAILS"), ("boot", "EVENTS THIS BOOT"),
    ("fails", "DAEMON FAILURES"),
)

_COVER_CHANNELS = (
    ("journal", "JOURNAL UNITS"), ("logs", "SCAN LOGS"),
    ("appfw", "APP FIREWALL"), ("store", "EVENT STORE"),
)

# The registry's groups: attention first, then by activity, exactly the
# way refresh already ranks them and the way the approved mockup
# groups the feed.
_GROUP_ORDER = ("att", "flunked", "unknown", "paused", "clean", "quiet")

_GROUP_LABELS = {
    "att": "Needs attention",
    "flunked": "Last scan did not finish",
    "unknown": "Could not check",
    "paused": "Paused by you",
    "clean": "Running clean, by activity",
    "quiet": "Runs when asked",
}

# The Elsewhere pointers the old page carried as chips (the approved
# announce says they survive as related rows inside each record). They
# are the same four hand-offs the chips grow; no page is lost.
_RELATED_ROWS = (
    ("Logs", "This tool's raw lines beside their plain readings", "logs"),
    ("Reference", "The tool's reference card", "help"),
    ("Hardening", "Endpoint hardening hand-offs", "harden"),
    ("Hunter", "The hunter's detections channel on these tools", "thunter"),
)

_EMPTY_RECORD_TEXT = (
    "Pick a row in the registry to open its record here. Everything the "
    "suite knows about that tool gathers there: what it does, its last "
    "activity, how the daemon reads its source, and the hand-offs to the "
    "rest of the suite.")


def _clock(ts) -> str:
    import datetime as _d
    try:
        when = _d.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=_d.timezone.utc)
        return when.astimezone().strftime("%H:%M")
    except (ValueError, TypeError):
        return ""


def _scan_word(state: str) -> str:
    """A scan state in the record's own words, never raw jargon."""
    return {"running": "running", "done": "finished", "failed": "failed",
            "interrupted": "interrupted", "queued": "waiting"}.get(
        state or "", state or "unknown")


def _run_pill_css(state: str) -> str:
    return {"failed": "gw-pill-fail", "interrupted": "gw-pill-fail",
            "running": "gw-pill-warn"}.get(state or "",
                                           "gw-pill-neutral")


def _sev_word(state: str) -> str:
    return {"failed": "HIGH", "interrupted": "HIGH"}.get(state or "",
                                                         "LOW")


class ToolsDesk(Gtk.Box):
    """The tools desk: strip, band, coverage, registry feed + record.

    The desk owns the widgets and computes words from the snapshots it
    receives; the window keeps every handler (selection state, details,
    navigate, filter, refresh) exactly as protectdesk.py carries them.
    """

    def __init__(self, registry, on_select=None, on_refresh=None,
                 on_filter=None, on_details=None, on_navigate=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.registry = registry
        self.on_select = on_select
        self.on_details = on_details
        self.on_navigate = on_navigate
        self.selected: str | None = None
        self._facts: dict = {}
        self._events: list = []
        self._updated = None

        self._build_strip(on_refresh, on_filter)
        self._build_band()
        self._build_cover()
        self._build_split()
        self._fill_empty()

    def _now(self):
        return _dt.datetime.now(_dt.timezone.utc)

    # ------------------------------------------------------------- build

    def _strip_chip(self) -> None:
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
        self._strip.chip(verdict)

    def _build_strip(self, on_refresh, on_filter) -> None:
        strip = DeskStrip()
        self._strip = strip
        self._strip_chip()
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
            "List every tool. Turn off to see only the ones that need "
            "attention.")
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
        # Names for the daemon's feeds, the approved mockup's five
        # channels: structural facts of how the suite reads the machine,
        # so nothing here counts an invented number.
        self.cover = DeskCoverage(
            _COVER_CHANNELS,
            gap=("NO CLOUD", "no account, no telemetry, nothing leaves"))
        self.cover.set("journal",
                       "watched · every systemd unit the app manages")
        self.cover.set("logs", "kept · one folder per scanner, per run")
        self.cover.set("appfw", "history · every decision recorded")
        self.cover.set("store", "0600 · append-only, this machine only")

    def _build_split(self) -> None:
        split = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        split.set_vexpand(True)
        feed = DeskFeed(
            eyebrow="THE REGISTRY", on_select=self._on_pick,
            foot="This is the registry the dashboard demoted, with its "
                 "last activity promoted: a row is what the tool did, "
                 "not what to click. Select one and its record opens "
                 "beside it.")
        split.append(feed)
        self.feed = feed
        self.dossier = DeskDossier("REGISTRY RECORD",
                                   on_navigate=self.on_navigate)
        self.dossier.related(_RELATED_ROWS)
        split.append(self.dossier)
        self.append(split)

    def _fill_empty(self) -> None:
        self.feed.set_empty("")
        self.dossier.fill_empty(_EMPTY_RECORD_TEXT)

    # ------------------------------------------------------------ select

    def _on_pick(self, key: str) -> None:
        self.selected = key
        if self.on_select is not None:
            self.on_select(key)

    # ------------------------------------------------------------- paint

    def paint(self, facts: dict, events: list, updated=None,
              visible=None) -> None:
        """Paint the registry feed from the per-row facts the window
        computed. Every row is a desk row (dot, friendly name, own
        fact); groups mount only when they have rows, and a picked row
        keeps its selection across refreshes. `visible` narrows only
        what the feed mounts (the shared show-all filter); the ON FILE
        flag and the dossier still read `facts` whole, so the counter
        beside the band's REGISTERED tally never contradicts it."""
        self._facts = facts
        self._events = events
        self._updated = updated
        self.feed.set_flag(f"{len(facts)} ON FILE")
        rows_by_group: dict = {g: [] for g in _GROUP_ORDER}
        for name, f in facts.items():
            state, paused, quiet = f["state"], f["paused"], f["quiet"]
            # , same shape as the protections desk: a tool whose
            # service is green but whose last scan did not finish reads
            # under the outcome banner, not an all-clear. The live run
            # outranks history (window.py passes it as live_scan).
            scan_state = str((f.get("live_scan") or {}).get("state")
                             or (f.get("last_scan") or {}).get("state")
                             or "")
            group = ("paused" if paused and state != "UNKNOWN"
                     else "unknown" if state == "UNKNOWN"
                     else "att" if state in ("RED", "YELLOW")
                     else "flunked" if scan_state in ("failed",
                                                      "interrupted")
                     else "quiet" if quiet
                     else "clean")
            rows_by_group[group].append(name)
        self.feed.clear()
        for group in _GROUP_ORDER:
            names = rows_by_group[group] or []
            if not names:
                continue
            # The heading mounts with the group's FIRST mounted row (no
            # banner above an empty run of rows).
            mounted = False
            for name in names:
                if visible is not None and name not in visible:
                    continue
                if not mounted:
                    mounted = True
                    self.feed.group(_GROUP_LABELS[group])
                self.feed.append_row(name, self._row(name, facts[name]))
        if self.selected and self.selected in self.feed.rows():
            self.feed.mark_selected(self.selected)
        if self.selected and self.selected not in self.feed.rows():
            # A selection the refresh dropped (the filter hides it)
            # opens the empty record again, never a dossier for a row
            # that is not on the feed.
            self.selected = None
            self._fill_empty()

    def _row(self, name: str, f: dict) -> Gtk.Box:
        """One registry row (approved mockup): a dot, the friendly
        name, and the meta line packed in the tool's own facts - real
        name, state words, and the last activity (or the honest none on
        file). A failed last run carries its real fields whenever they
        are present: the scanner's detail and its exit code."""
        state, paused = f["state"], f["paused"]
        sc = f.get("last_scan") or {}
        dot = state_colour(state, paused)
        ev = f.get("event") or {}
        meta_bits = [name]
        if (sc or {}).get("detail"):
            meta_bits.append(str(sc["detail"]))
            if sc.get("state") in ("failed", "interrupted"):
                dot = state_colour("YELLOW", paused)
        elif f.get("last_detail"):
            meta_bits.append(str(f["last_detail"]))
        else:
            meta_bits.append(status_words(state, f.get("installed"),
                                          paused))
        if sc.get("exit_code") not in (0, None):
            meta_bits.append(f"exit code {sc['exit_code']}")
        if ev.get("ts"):
            meta_bits.append(f"last activity {_clock(ev.get('ts'))}")
        elif sc.get("started_at"):
            end = _clock(sc.get("ended_at")) or _clock(sc.get("started_at"))
            meta_bits.append(f"last run {end or 'unknown'}")
        else:
            meta_bits.append("last activity none on file")
        return self.feed.row(name, friendly_name(name),
                             " · ".join(str(b) for b in meta_bits),
                             dot_colour=dot)

    def _flunked_words(self) -> str:
        """, verdict half: the job tile reads tool health, so when
        a tool's own last scan did not finish the tile's words carry
        that outcome instead of reading as an all-clear over a tool
        wearing a fail rail."""
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

    def band_paint(self, total: int, running: int, attention: int,
                   paused_n: int, unknown_n: int, tails: int,
                   boot: int, fails: int, degraded=(), dropped: int = 0) \
            -> None:
        """The five tallies the window's refresh already computes, in
        the tiles' own words. Every number is a tally refresh() computes
        or the registry's own size; the band invents nothing. Dropped
        events (: 7.5 million parsed lines lost while a tail stalled
        behind a full queue) keep their own sentence rather than being
        summed into the failure tally, which would make every read fault
        look seven-million-strong."""
        self.band.set("reg", str(total), "one registry, the whole suite")
        quiet = max(0, total - running - attention - paused_n - unknown_n)
        flunked = self._flunked_words()
        self.band.set("job", f"{running}/{total}",
                      (f"{attention} "
                       f"need{'s' if attention == 1 else ''} attention"
                       f" · {quiet} quiet"
                       if attention else
                       (f"{quiet} quiet · {flunked}" if flunked
                        else f"{quiet} quiet, nothing needs it")
                       if quiet else
                       flunked or "nothing needs it right now"))
        self.band.set("tails", f"{tails}/{total}",
                      "every tool watched, journal or log"
                      if tails == total else "some reads not started")
        self.band.set("boot", f"{boot:,}",
                      "parsed into the 0600 store" if boot
                      else "nothing from this boot yet")
        note = (f"named by the reads: {', '.join(str(x) for x in degraded)}"
                if degraded else "reads only; writes staged + renamed")
        if dropped:
            note = f"{dropped:,} parsed events dropped, queue full · {note}"
        self.band.set("fails", f"{fails:,}", note)

    # ------------------------------------------------------------ record

    def fill_dossier(self, name: str | None) -> None:
        """The picked row's record: title, identity pills, what it
        does, its activity trail in its own words, how the daemon reads
        the source, and the next step. Existing powers only appear in
        the actions row."""
        f = self._facts.get(name) if name else None
        if not f:
            self.dossier.clear()
            self.dossier.fill_empty(_EMPTY_RECORD_TEXT)
            return
        d = self.dossier
        # A refill is a rebuild, not an append: the window refills every
        # refresh tick, and without the clear the record stacks a whole
        # copy of itself under the old one each time.
        d.clear()
        d.title().set_text(f"{f['label']} - {name}")
        d.pills().set_visible(True)
        state, paused = f["state"], f["paused"]
        sc = f.get("last_scan") or {}
        d.pill(f"state: {status_words(state, f.get('installed'), paused)}",
               "gw-pill-fail" if state == "RED"
               else "gw-pill-warn" if state in ("YELLOW", "UNKNOWN")
               else "gw-pill-warn" if paused else "gw-pill-neutral",
               _muted())
        if f.get("unit"):
            d.pill(f"unit: {f['unit']}", "gw-pill-neutral", _muted())
        if (sc or {}).get("detail"):
            d.pill(str(sc["detail"]), _run_pill_css(sc.get("state")),
                   )
        if sc.get("exit_code") not in (0, None):
            d.pill(f"exit code {sc['exit_code']}",
                   _run_pill_css(sc.get("state")),
                   )
        ev = f.get("event") or {}
        if ev.get("ts"):
            d.pill(f"last activity {age_words(ev.get('ts'), self._now())}",
                   "gw-pill-neutral", _muted())
        d.detail().append(d.prose(what_is(name)))
        self._fill_trail(name)
        self._fill_run(sc)
        self._fill_reads(f)
        d.detail().append(d.label("SUGGESTED NEXT STEP"))
        d.detail().append(d.next_box(self._next_text(f)))
        self._fill_actions(name)

    def _trail_line(self, e: dict) -> str:
        """One trail line in the tool's own words; the sentences are the
        feed's own, so the recorded data still reads whole."""
        sev = str(e.get("severity") or "INFO").upper()
        words = without_mark(plain_sentence(e))
        return f"{_clock(e.get('ts')) or 'unknown'} · {sev} · {words}"

    def _fill_trail(self, name: str) -> None:
        d = self.dossier
        trail = []
        for e in self._events:
            if e.get("from_tool") != name:
                continue
            if str(e.get("text", "")).startswith("check-in:"):
                continue
            trail.append(e)
            if len(trail) == 3:
                break
        d.detail().append(d.label("RECENT ACTIVITY"))
        if not trail:
            d.detail().append(
                d.evline("Nothing recorded from this tool yet."))
            return
        for e in trail:
            d.detail().append(d.evline(self._trail_line(e)))

    def _fill_run(self, sc: dict) -> None:
        """The selected tool's last run, in its own units. The
        counter's own label paints in plain text so no unit is ever
        escaped; every real field appears whenever present, never a
        canned sentence for it."""
        if not (sc or {}):
            return
        d = self.dossier
        d.detail().append(d.label("LAST RUN IN ITS OWN UNITS"))
        clock = _clock(sc.get("ended_at") or sc.get("started_at")) \
            or "unknown"
        if sc.get("counter_label") is not None and \
                sc.get("count") is not None:
            d.detail().append(d.evline(
                f"{int(sc.get('count') or 0):,} "
                f"{sc.get('counter_label')} · ended {clock}"))
        else:
            d.detail().append(d.evline(
                f"{_clock(sc.get('started_at')) or 'unknown'} - "
                f"{_scan_word(sc.get('state'))}"))
        bits = []
        if sc.get("duration_s") is not None:
            bits.append(f"run length: {sc['duration_s']}s")
        if sc.get("warned"):
            bits.append("warnings logged in its own words")
        if bits:
            d.detail().append(d.facts(bits))

    def _fill_reads(self, f: dict) -> None:
        """How the daemon reads this tool's source: real facts from the
        registry entry itself (journal or file tails), never a claim
        invented for the row."""
        d = self.dossier
        logs = [x for x in (f.get("logs") or ()) if isinstance(x, str)]
        journal = any(x.startswith("journal:") for x in logs)
        files = [x for x in logs if not x.startswith("journal:")]
        bits = []
        if journal:
            bits.append("source: journal follow (the kernel's stream)")
        if files:
            seen = files[0] if len(files) == 1 else f"{len(files)} logs"
            bits.append(f"source: file tail on {seen}")
        bits.append("parsing: one family per source, structured events"
                    " out")
        bits.append("pause: the tail pauses, nothing resumes itself")
        bits.append("events: land in the 0600 store, this machine only")
        d.detail().append(d.label("HOW THE APP READS IT"))
        d.detail().append(d.facts(bits))

    def _next_text(self, f: dict) -> str:
        """The next step grows from the row's own fact: a pick that has
        a failed last run opens it in the scans dossier; a decision
        waiting names where the answers go; otherwise the suite keeps
        reading. Nothing new is invented."""
        state, paused = f["state"], f["paused"]
        sc = f.get("last_scan") or {}
        if sc.get("state") in ("failed", "interrupted"):
            return ("Open the Scans tab: that run is pinned there by "
                    "name, with its detail, exit code and its own log "
                    "folder. Recorded data again - reading, not running.")
        if state == "UNKNOWN":
            return ("Give the monitor another cycle; reads only, so "
                    "nothing is being changed meanwhile.")
        if paused:
            return ("Resume it from the Protections desk's dossier when "
                    "you want it working again; until then pause is "
                    "yours, nothing resumes on its own.")
        if state in ("RED", "YELLOW"):
            return ("The row's own detail says what to look at next; "
                    "the Logs page carries the raw lines beside their "
                    "plain readings.")
        return ("Keep it on. Nothing here starts or stops a protection "
                "on its own; the suite reads only.")

    def _fill_actions(self, name: str) -> None:
        """The record's actions row (approved mockup): the shipped
        hand-offs only - the tool's raw log page and the details dialog
        the protect cards also grow. No new powers are created."""
        if self.on_navigate is None and self.on_details is None:
            return
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                          spacing=6)
        if self.on_navigate is not None:
            open_btn = Gtk.Button(label="Open in Logs")
            open_btn.add_css_class("gw-mini")
            open_btn.connect("clicked",
                             lambda *_b, k="logs":
                             self.on_navigate(k))
            actions.append(open_btn)
        if self.on_details is not None and name:
            tail_btn = Gtk.Button(label="Tail this journal")
            tail_btn.add_css_class("gw-mini")
            tail_btn.connect("clicked",
                             lambda *_b, k=name:
                             self.on_details(k))
            actions.append(tail_btn)
        self.dossier.detail().append(actions)

    # ------------------------------------------------------------- clock

    def update_clock(self, text: str) -> None:
        """The strip's right-edge SNAPSHOT clock, filled from refresh."""
        self._strip.meta(str(text))
        self._strip.finish()