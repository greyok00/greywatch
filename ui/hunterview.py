"""The Browser Watch desk (.

The hunter runs headless in its own user process (hunter.main); this page
only renders the files it writes — findings.jsonl, defender.jsonl,
live.json, state.json — and drops small requests into its request file and
inbox. It holds no hunt state, so closing the window loses nothing, and
nothing a hostile HAR contains can reach a privileged path: the import is
a plain file copy into the inbox directory, exactly like handing it over
by hand.

The page is an operational desk, not a card: a command strip (hunt now,
HAR import, the AI explainer meter, the suite's own verdict riding the
same row, and the hunt clock), a stat band over the hunt channels'
coverage, a day-grouped feed, and the selected finding's side-by-side
dossier — raw facts, evidence, the next step, the ask path, and a
"related in the suite" footer that hands the finding back to the
Protections, Scans or Logs pages.

Every finding already arrives with rule-written plain language (what it
is, what to do next), so the page explains itself even when the AI
explainer is off or cooling down. Findings are data, never commands:
nothing here executes on their suggestion.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import shutil
import time as _time

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from hunter import store, web  # noqa: E402
from ui.plain import ink as _ink  # noqa: E402
from ui.plain import muted as theme_muted  # noqa: E402
from ui.plain import severity_colour  # noqa: E402
from ui.homepage import suite_summary  # noqa: E402

MAX_ROWS = 24

# Severity chips (Task 5: label + the raw value they match.
# Info-level findings stay in view under All — they are rare and the page
# is the full record; the corpus the hunter writes is HIGH/MEDIUM anyway.
SEV_CHIPS = (("All", ""), ("High", "HIGH"), ("Medium", "MEDIUM"),
             ("Low", "LOW"))


def _bucket(sev) -> str:
    """The chip a finding's severity belongs to: Critical rides with High
    and Info with Low, so the tally and the filter agree on every row."""
    s = str(sev or "").upper()
    if s in ("HIGH", "CRITICAL"):
        return "HIGH"
    if s == "MEDIUM":
        return "MEDIUM"
    return "LOW"

# The strip under the stat band: the live hunt channels, plus the one the
# browser wave will land. Each tile reads only data the hunter already
# writes; nothing here pretends a channel exists.
_COVERAGE = (("detections", "Detections"),
             ("scans", "Finished scans"),
             ("files", "Files & startup"),
             ("browser", "Browser history"))

# A rule id's (feed label, coverage key) — the feed's one-line tag that
# says which hunter channel a finding came from.
_RULE_CHANNELS = {
    "malware-detected": ("antivirus", "detections"),
    "rootkit-warning": ("rootkit scanner", "detections"),
    "scan-positive": ("finished scans", "scans"),
}


def _channel_of(rule: str) -> tuple[str, str]:
    r = str(rule or "")
    if r in _RULE_CHANNELS:
        return _RULE_CHANNELS[r]
    if r.startswith("har-"):
        return "HAR capture", "har"
    if r.startswith("download-"):
        return "downloads", "files"
    if r.startswith("persistence-"):
        return "startup automation", "files"
    if r.startswith("browser-history"):
        return "browser history", "browser"
    if r.startswith("cfg-"):
        # : browser configuration rules are their own channel, not
        # the suite-events fallback.
        return "browser config", "browser"
    return "suite events", "detections"


def _ext_parts(f: dict) -> tuple[str, str]:
    """The extension a cfg-new-extension finding names: the id from the
    evidence row, the human label from the facts. Anything else returns
    ("", "") and never reads as an extension."""
    for e in f.get("evidence") or []:
        if isinstance(e, dict) and str(e.get("ext_id") or "").strip():
            ext = str(e["ext_id"])
            break
    else:
        for row in f.get("facts") or []:
            s = str(row)
            if s.startswith("ext=") and s[4:].strip():
                ext = s[4:]
                break
        else:
            return ("", "")
    name = ""
    for row in f.get("facts") or []:
        s = str(row)
        if s.startswith("name=") and s[5:].strip():
            name = s[5:]
            break
    return (ext[:120], name)


def latest_findings(data_dir, limit=MAX_ROWS) -> list[dict]:
    """Newest first by each finding's own time: a hunt cycle can
    append an older-evidence finding after a newer one, so append order is
    not reading order."""
    # Read at least the requested amount; a smaller card request still
    # gets a lookback buffer (the old 200) because a hunt cycle can
    # append an older-ts finding out of order and the newest window by
    # time has to see past append order.
    rows = store.read_findings(data_dir, limit=max(int(limit), 200))
    rows.sort(key=lambda f: str(f.get("ts") or ""), reverse=True)
    return rows[:limit]


def unread_notes(data_dir) -> int:
    since = ""
    try:
        cfg = json.loads(store.config_path(data_dir).read_text())
        since = str(cfg.get("read_until") or "")
    except (OSError, ValueError, AttributeError):
        since = ""
    notes = store.read_defender(data_dir, limit=store.DEFENDER_KEEP)
    return sum(1 for n in notes if str(n.get("ts") or "") > since)


def request_hunt(data_dir) -> None:
    """Presence is the whole message: the hunter's loop notices the file."""
    path = store.request_path(data_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n")
    except OSError:
        pass


def import_har(data_dir, src_path) -> str:
    """Copy a capture into the inbox; the hunter owns it from there.

    Returns a short verdict for the header label."""
    try:
        inbox = store.inbox_dir(data_dir)
        src = pathlib.Path(src_path)
        if not src.is_file():
            # A folder pick or a path that is not there is a different
            # conversation from "too big".
            return "That path is not a capture file we can read."
        if src.stat().st_size > web.HAR_MAX_BYTES:
            return "That file is too large to hunt (the cap is 25 MB)."
        # Land the copy atomically: the hunter's tick reads whatever is
        # in the inbox, and a capture read mid-copy is a truncated JSON
        # that gets retired as junk instead of hunted.
        tmp = inbox / (src.name + ".har.part")
        shutil.copyfile(src, tmp)
        os.replace(tmp, inbox / (src.name + ".har"))
        return "Imported - the hunter answers it within a minute."
    except OSError:
        return "The import could not be copied into the inbox."


def ai_enabled(data_dir) -> bool:
    try:
        cfg = json.loads(store.config_path(data_dir).read_text())
        return bool(cfg.get("enabled", True)) if isinstance(cfg, dict) \
            else True
    except (OSError, ValueError):
        return True


def set_ai_enabled(data_dir, enabled: bool) -> None:
    try:
        cfg = json.loads(store.config_path(data_dir).read_text())
    except (OSError, ValueError):
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    cfg["enabled"] = bool(enabled)
    store.write_config(data_dir, cfg)


# ------------------------------------------------------------- stamping

def _when(ts) -> _dt.datetime | None:
    """A stamp in the user's own clock; None when absent or unreadable
    (old writers could omit ts)."""
    try:
        return _dt.datetime.fromisoformat(str(ts or "")).astimezone()
    except ValueError:
        return None


def _fmt_ts(ts) -> str:
    when = _when(ts)
    return when.strftime("%b %d, %H:%M") if when else "-"


def _clock(ts) -> str:
    when = _when(ts)
    return when.strftime("%H:%M") if when else "-"


def _day_label(when: _dt.datetime | None) -> str:
    """The feed's day separators: Today, Yesterday, then the date."""
    if when is None:
        return "Earlier"
    # Tolerate a bare date: callers pass a datetime, tests pass both.
    day = when.date() if isinstance(when, _dt.datetime) else when
    delta = (_dt.datetime.now().astimezone().date() - day).days
    if delta <= 0:
        return "Today"
    if delta == 1:
        return "Yesterday"
    return day.strftime("%b %d")


def _next_hunt_text(live: dict) -> str:
    """The hunt clock on the command strip: when the last cycle ran and
    how far away the next one is."""
    ts = _when(live.get("ts"))
    interval = float(live.get("interval_s") or 300.0)
    if ts is None:
        return "FIRST HUNT SOON"
    elapsed = max(0.0, _time.time() - ts.timestamp())
    last = _clock(live.get("ts"))
    # A runner that died (crash, unit not enabled after an update - the
    # report of: the deb hunter had never run and the board
    # still read "NEXT ~1 SEC" forever) cannot be described with the
    # old clamp. Past a multiple of the interval, the only honest line
    # is that the clock is no longer running.
    if elapsed > max(60.0, interval * 2.5):
        return f"LAST {last} · HUNTER NOT RESPONDING"
    remaining = max(0.0, interval - elapsed)
    if remaining <= 60:
        return f"LAST {last} · NEXT ~{max(1, int(remaining))} SEC"
    return f"LAST {last} · NEXT IN ~{int(remaining // 60) + 1} MIN"


def _ai_meter(live: dict) -> str:
    """The explainer's use-count for the hour, plus a cooldown word."""
    ai = live.get("ai") or {}
    used = int(ai.get("used_hour") or 0)
    cap = int(ai.get("per_hour") or 3)
    words = [f"{used}/{cap} THIS HOUR"]
    if ai.get("cooling"):
        words.append("COOLING DOWN")
    return " · ".join(words)


_WATCHER_WORDS = {
    "off": "no browser port",
    "down": "port quiet",
    "watching": "watching live",
    "idle": "connected, idle",
}


def _watcher_line(live: dict) -> str:
    """The live-watcher cover tile: how the debug-port lane is doing and
    how fresh the intel feeds are, in words a person can read at a glance."""
    if "watcher" not in live and "intel" not in live:
        return "opens with the browser wave"
    state = str((live.get("watcher") or {}).get("state") or "off")
    word = _WATCHER_WORDS.get(state, state)
    intel = live.get("intel") or {}
    if not intel.get("enabled"):
        return word
    ages = intel.get("ages") or {}
    # An unparsable stamp reads as "waiting", never as a giant number,
    # and the two-part line still honors the chip's character budget.
    hours = sorted(h for h in (_age_hours(a) for a in ages.values())
                   if 0.0 <= h <= 87600.0)
    if not hours:
        return word
    text = f"{word} · intel {hours[0]:.0f}h fresh"
    return text if len(text) <= 31 else word


def _event_log_text(state: dict) -> tuple[str, str]:
    """The stat-band tile for the event log the hunter watches: how much
    of it this boot has parsed."""
    events = state.get("events") or {}
    try:
        offset = int(events.get("offset") or 0)
    except (TypeError, ValueError):
        offset = 0
    if offset <= 0:
        return "-", "nothing parsed this boot yet"
    mb = offset / (1024 * 1024)
    return (f"{mb:.1f}" if mb < 1000 else f"{mb / 1024:.1f}G"), \
        "parsed since last boot"


def _sev_tally(findings: list) -> str:
    high = med = low = 0
    for f in findings:
        sev = str(f.get("severity") or "").upper()
        if sev in ("HIGH", "CRITICAL"):
            high += 1
        elif sev == "MEDIUM":
            med += 1
        else:
            low += 1
    return (f"{high} high · {med} medium · {low} low" if findings
            else "none on file")


def _age_hours(ts: str) -> float:
    when = _when(ts)
    if when is None:
        return 1e9
    return max(0.0, (_dt.datetime.now().astimezone()
                     - when).total_seconds() / 3600.0)


def _esc(text) -> str:
    text = str(text or "")
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _pill_key(sev: str) -> str:
    return {"HIGH": "fail", "CRITICAL": "fail", "MEDIUM": "warn"
            }.get(sev, "neutral")


class HunterPanel(Gtk.Box):
    """The hunter desk: command strip, stat band and coverage, the feed,
    and the dossier of the selected finding."""

    def __init__(self, data_dir, on_ask=None, on_navigate=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.data_dir = data_dir
        self.on_ask = on_ask
        self.on_navigate = on_navigate
        self._findings: list = []
        self._row_widgets: dict = {}
        self._selected: str | None = None
        self._selected_finding: dict | None = None
        self._replies: dict = {}
        self._kept: list = []
        self._quiet: list = []
        self._sev = "ALL"

        self._build_cmd()
        self._build_band()
        self._build_cover()
        self._build_split()
        self.refresh(force=True)

    # ------------------------------------------------------------- build

    def _build_cmd(self) -> None:
        cmd = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cmd.add_css_class("gw-card")
        cmd.add_css_class("gw-desk-cmd")
        hunt = Gtk.Button(label="Hunt now")
        hunt.add_css_class("suggested-action")
        hunt.connect("clicked", self._on_hunt)
        cmd.append(hunt)
        har = Gtk.Button(label="Import HAR…")
        har.connect("clicked", self._on_import)
        cmd.append(har)
        # the same events live in the Activity Log with their fix cards:
        # one hop, no hunting (the hunter must not be a dead end)
        rec = Gtk.Button(label="Open the Activity Log")
        rec.add_css_class("gw-mini")
        rec.set_tooltip_text("Every hunter event, with a fix card per row.")
        rec.connect("clicked", self._open_record)
        cmd.append(rec)
        self._ai_switch = Gtk.Switch()
        self._ai_switch.set_valign(Gtk.Align.CENTER)
        self._ai_switch.connect("state-set", self._on_ai_toggle)
        ai_label = Gtk.Label(xalign=0)
        ai_label.set_text("AI explainer")
        self._ai_meter = Gtk.Label(xalign=0)
        self._ai_meter.add_css_class("gw-mono")
        ai_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        ai_row.add_css_class("gw-suite-chip")
        ai_row.append(self._ai_switch)
        ai_row.append(ai_label)
        ai_row.append(self._ai_meter)
        cmd.append(ai_row)
        self._suite_chip = Gtk.Label(xalign=0)
        self._suite_chip.add_css_class("gw-suite-chip")
        self._suite_chip.set_ellipsize(3)
        # The chip takes the strip's free width (and only ellipsizes when
        # the window is genuinely narrow); the clock keeps its natural
        # size and stays pinned to the right edge.
        self._suite_chip.set_hexpand(True)
        cmd.append(self._suite_chip)
        self._clock_label = Gtk.Label(xalign=1)
        self._clock_label.add_css_class("gw-mono")
        self._clock_label.set_justify(Gtk.Justification.RIGHT)
        cmd.append(self._clock_label)
        # One feedback line under the strip: a requested hunt or a HAR
        # verdict says so here instead of shouting anywhere louder.
        self._status = Gtk.Label(xalign=0)
        self._status.set_xalign(0)
        self._status.set_wrap(True)
        self._status.set_visible(False)
        self._cmd = cmd
        self.append(cmd)
        self.append(self._status)

    def _build_band(self) -> None:
        """Five stat tiles — every number reads only hunter-written files
        (live.json, state.json) plus the feed's own counts."""
        band = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._tiles: dict = {}
        for key, label in (("leads", "OPEN LEADS"),
                           ("cycle", "NEW THIS CYCLE"),
                           ("unread", "UNREAD NOTES"),
                           ("har", "HAR CAPTURES"),
                           ("events", "EVENT LOG WATCHED")):
            band.append(self._tile(key, label))
        self.append(band)

    def _tile(self, key: str, label: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        box.add_css_class("gw-tile")
        box.set_hexpand(True)
        name = Gtk.Label(xalign=0)
        name.add_css_class("gw-tile-k")
        name.set_text(label)
        value = Gtk.Label(xalign=0)
        value.add_css_class("gw-tile-v")
        value.set_ellipsize(3)
        sub = Gtk.Label(xalign=0)
        sub.add_css_class("gw-tile-s")
        sub.set_ellipsize(3)
        box.append(name)
        box.append(value)
        box.append(sub)
        self._tiles[key] = (value, sub)
        return box

    def _build_cover(self) -> None:
        """The hunt channels' coverage strip: last sweep plus the 24-hour
        match count, from data the hunter already writes."""
        cover = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._cover_tiles: dict = {}
        for key, label in _COVERAGE:
            cover.append(self._cover_tile(key, label))
        gap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        gap.add_css_class("gw-tile")
        gap.add_css_class("gw-tile-gap")
        gap.set_hexpand(True)
        name = Gtk.Label(xalign=0)
        name.add_css_class("gw-tile-k")
        name.set_text("Live watcher")
        text = Gtk.Label(xalign=0)
        text.add_css_class("gw-tile-s")
        text.add_css_class("gw-mono")
        self._watcher_tile = text
        text.set_text("opens with the browser wave")
        gap.append(name)
        gap.append(text)
        cover.append(gap)
        self.append(cover)

    def _cover_tile(self, key: str, label: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        box.add_css_class("gw-tile")
        box.add_css_class("gw-cchan")
        box.set_hexpand(True)
        name = Gtk.Label(xalign=0)
        name.add_css_class("gw-tile-k")
        name.set_text(label)
        text = Gtk.Label(xalign=0)
        text.add_css_class("gw-tile-s")
        text.set_ellipsize(3)
        box.append(name)
        box.append(text)
        self._cover_tiles[key] = text
        return box

    def _build_split(self) -> None:
        split = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        split.set_vexpand(True)
        # --- feed column ------------------------------------------------
        feed = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        feed.add_css_class("gw-card")
        feed.add_css_class("gw-feed")
        feed.set_hexpand(True)
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        head.add_css_class("gw-feedhead")
        eyebrow = Gtk.Label(xalign=0)
        eyebrow.add_css_class("gw-eyebrow")
        eyebrow.set_text("FINDINGS")
        head.append(eyebrow)
        self._chip_btns: dict = {}
        for label, sev in SEV_CHIPS:
            chip = Gtk.Button(label=label)
            chip.add_css_class("gw-chip")
            chip.connect("clicked", self._on_filter, sev)
            head.append(chip)
            self._chip_btns[label] = chip
        self._chip_btns["All"].add_css_class("gw-chip-on")
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        head.append(spacer)
        # A quiet counter beside the chips: how many notes are still
        # unread — the badge on the tab reads the same number, so the page
        # never contradicts the shell.
        self._unread_flag = Gtk.Label(xalign=0)
        self._unread_flag.add_css_class("gw-mono")
        self._unread_flag.set_visible(False)
        head.append(self._unread_flag)
        feed.append(head)
        # The kept strip: one row per extension the user chose
        # to keep, each with a Warn-again way back. Mounted between the
        # chips and the feed; painted by refresh.
        self._kept_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                 spacing=4)
        self._kept_box.add_css_class("gw-feedbody")
        self._kept_box.set_visible(False)
        feed.append(self._kept_box)
        # The hidden strip: one row per dismissed finding, each
        # with the Show-again way back. Mounted under the kept strip.
        self._quiet_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                  spacing=4)
        self._quiet_box.add_css_class("gw-feedbody")
        self._quiet_box.set_visible(False)
        feed.append(self._quiet_box)
        # The rows scroll on their own so the dossier keeps its height.
        self._scroll = scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        self._list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._list.add_css_class("gw-feedbody")
        scroll.set_child(self._list)
        feed.append(scroll)
        self._empty = Gtk.Label(xalign=0)
        self._empty.set_xalign(0)
        self._empty.set_wrap(True)
        self._empty.add_css_class("gw-feed-empty")
        feed.append(self._empty)
        foot = Gtk.Label(xalign=0)
        foot.add_css_class("gw-feedfoot")
        # wrap + cap, same as desk.py's foot: an unwrapped label carries its
        # full sentence as its GTK minimum (875px here), which pushed the
        # findings column to 909 and the hunter page past a 1320px window
        foot.set_wrap(True)
        foot.set_max_width_chars(96)
        interval = int((store.read_live(self.data_dir)
                        .get("interval_s") or 300.0) // 60) or 1
        foot.set_text(f"""The hunter sweeps every {interval} minutes · the
feed keeps the newest {store.FINDINGS_KEEP:,} findings, then older ones rotate
out · suppressed repeats stay recorded in the hunter's seen map""".replace(
            "\n", " "))
        feed.append(foot)
        split.append(feed)
        # --- dossier column ---------------------------------------------
        dossier = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        dossier.add_css_class("gw-card")
        dossier.add_css_class("gw-dossier")
        dossier.set_size_request(440, -1)
        self._dhead = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._dhead.add_css_class("gw-dhead")
        d_eyebrow = Gtk.Label(xalign=0)
        d_eyebrow.add_css_class("gw-eyebrow")
        d_eyebrow.set_text("FINDING DOSSIER")
        self._dhead.append(d_eyebrow)
        self._dtitle = Gtk.Label(xalign=0)
        self._dtitle.set_xalign(0)
        self._dtitle.set_wrap(True)
        self._dtitle.add_css_class("gw-dtitle")
        self._dhead.append(self._dtitle)
        self._dpills = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                               spacing=5)
        self._dhead.append(self._dpills)
        dscroll = Gtk.ScrolledWindow()
        self._dscroll = dscroll
        dscroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        dscroll.set_vexpand(True)
        self._detail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                               spacing=8)
        self._detail.add_css_class("gw-dbody")
        dscroll.set_child(self._detail)
        dossier.append(self._dhead)
        dossier.append(dscroll)
        self._related = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                spacing=2)
        self._related.add_css_class("gw-related")
        self._build_related()
        dossier.append(self._related)
        split.append(dossier)
        self.append(split)
        self._fill_detail(None)

    def _build_related(self) -> None:
        """The suite hand-offs: the same tab keys the shell switches on.
        Buttons render only when a navigate handler was given, which is
        also how tests inject their spy."""
        self._related_rows: dict = {}
        for key, where, what in (
                ("protect", "PROTECTIONS",
                 "Every protection's state, last scan and dossier"),
                ("scans", "SCANS",
                 "The runs and their findings this hunter reads"),
                ("logs", "LOGS",
                 "Every event the suite recorded, newest first")):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            where_l = Gtk.Label(xalign=0)
            where_l.add_css_class("gw-rel-where")
            where_l.set_text(where)
            row.append(where_l)
            what_l = Gtk.Label(xalign=0)
            what_l.add_css_class("gw-rel-what")
            what_l.set_hexpand(True)
            what_l.set_wrap(True)
            what_l.set_text(what)
            row.append(what_l)
            if self.on_navigate is not None:
                btn = Gtk.Button(label="Open")
                btn.add_css_class("gw-mini")
                btn.connect("clicked", self._related_open, key)
                row.append(btn)
            self._related_rows[key] = row
            self._related.append(row)
        # The conditional Home row: unread notes pin on Home first.
        home_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        where_l = Gtk.Label(xalign=0)
        where_l.add_css_class("gw-rel-where")
        where_l.set_text("HOME")
        what_l = Gtk.Label(xalign=0)
        what_l.add_css_class("gw-rel-what")
        what_l.set_hexpand(True)
        what_l.set_wrap(True)
        what_l.set_text("Unread notes from the hunter pin on Home first")
        home_row.append(where_l)
        home_row.append(what_l)
        if self.on_navigate is not None:
            btn = Gtk.Button(label="Open")
            btn.add_css_class("gw-mini")
            btn.connect("clicked", self._related_open, "home")
            home_row.append(btn)
        self._related_rows["home"] = home_row
        self._related.append(home_row)

    def _related_open(self, _btn, key: str) -> None:
        if self.on_navigate is not None:
            self.on_navigate(key)

    def _open_record(self, _btn):
        if self.on_navigate is not None:
            self.on_navigate("auditlog")

    # ------------------------------------------------------------ actions

    def _on_hunt(self, _btn):
        request_hunt(self.data_dir)
        self._say("The hunter is on it - results land here when the "
                  "cycle finishes.")

    def _on_import(self, _btn):
        dlg = Gtk.FileChooserNative.new(
            "Choose a HAR capture", self.get_native(),
            Gtk.FileChooserAction.OPEN, "Import", "Cancel")
        flt = Gtk.FileFilter()
        flt.set_name("HAR captures (*.har)")
        flt.add_pattern("*.har")
        flt.add_pattern("*.json")
        dlg.add_filter(flt)
        # : file pickers sit beside the desk, not over it.
        dlg.set_modal(False)
        dlg.connect("response", self._har_response)
        dlg.show()

    def _har_response(self, dlg, resp):
        if resp == Gtk.ResponseType.ACCEPT and self.get_root() is not None:
            # The page can be torn down while a modal file choice sits
            # open; an unmounted view must neither import nor paint.
            chosen = dlg.get_file()
            if chosen is not None:
                verdict = import_har(self.data_dir, chosen.get_path())
                self.refresh()
                self._say(verdict)
        dlg.destroy()

    def _say(self, text: str) -> None:
        """The command strip's feedback line; hidden again on the next
        full paint so it never reads as a stuck state."""
        self._status.set_markup(
            f"<span size='12000' font_family='Inter' "
            f"color='{theme_muted()}'>{_esc(text)}</span>")
        self._status.set_visible(True)

    def _paint_kept(self) -> None:
        """The kept strip: one line per extension on the ledger with the
        Warn-again way back. Rebuilt per paint, like the feed rows."""
        for child in list(self._kept_box.observe_children()):
            self._kept_box.remove(child)
        self._kept_box.set_visible(bool(self._kept))
        if not self._kept:
            return
        n = len(self._kept)
        head = Gtk.Label(xalign=0)
        head.add_css_class("gw-eyebrow")
        head.set_text(f"KEPT · {n} extension{'s' if n != 1 else ''} "
                      "you chose to keep")
        self._kept_box.append(head)
        for row in self._kept:
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            name = Gtk.Label(xalign=0)
            name.add_css_class("gw-fmeta")
            name.set_xalign(0)
            name.set_wrap(True)
            name.set_hexpand(True)
            name.set_text(f"• {row['name'] or row['ext']}")
            line.append(name)
            btn = Gtk.Button(label="Warn again")
            btn.add_css_class("gw-mini")
            btn.connect("clicked", self._on_unkeep, row["ext"])
            line.append(btn)
            self._kept_box.append(line)

    def _on_keep_ext(self, _btn) -> None:
        """The dossier's Keep: this extension belongs here on purpose, so
        the ledger gains it and the hunter raises nothing more for it.
        Past records stay on the disk; the desk just stops painting them."""
        ext_id, name = _ext_parts(self._selected_finding or {})
        if not ext_id:
            return
        store.keep_extension(self.data_dir, ext_id, name)
        self.refresh(force=True)
        self._say(f"“{name or ext_id}” is kept. The hunter raises nothing "
                  "more for it, and Warn again beside the kept list "
                  "changes your mind.")

    def _on_unkeep(self, _btn, ext_id: str) -> None:
        store.unkeep_extension(self.data_dir, ext_id)
        self.refresh(force=True)
        self._say("Warned again: its past records show in the feed, and "
                  "next time the hunter sees it unkept, it raises.")

    def _paint_quiet(self) -> None:
        """The hidden strip: one line per dismissed finding with the
        Show-again way back."""
        for child in list(self._quiet_box.observe_children()):
            self._quiet_box.remove(child)
        self._quiet_box.set_visible(bool(self._quiet))
        if not self._quiet:
            return
        n = len(self._quiet)
        head = Gtk.Label(xalign=0)
        head.add_css_class("gw-eyebrow")
        head.set_text(f"HIDDEN · {n} finding{'s' if n != 1 else ''} "
                      "you dismissed")
        self._quiet_box.append(head)
        for row in self._quiet:
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            label = row["label"] or row["rule"] or row["id"]
            name = Gtk.Label(xalign=0)
            name.add_css_class("gw-fmeta")
            name.set_xalign(0)
            name.set_wrap(True)
            name.set_hexpand(True)
            name.set_text(f"• {str(label)[:70]} "
                          f"({row['rule'] or 'finding'})")
            line.append(name)
            btn = Gtk.Button(label="Show again")
            btn.add_css_class("gw-mini")
            btn.connect("clicked", self._on_unquiet, row["id"])
            line.append(btn)
            self._quiet_box.append(line)

    def _on_dismiss(self, _btn) -> None:
        """The dossier's Dismiss: this exact finding was seen and judged
        quiet, so the ledger gains its id and the hunter never appends
        that subject again. A changed subject is a new id and alerts."""
        f = self._selected_finding or {}
        if not str(f.get("id") or ""):
            return
        store.quiet_finding(self.data_dir, f)
        self.refresh(force=True)
        self._say("Dismissed: nothing more is raised for this exact "
                  "finding, and its records leave the feed. If the "
                  "underlying thing changes, it alerts as new. Show "
                  "again sits above the feed.")

    def _on_unquiet(self, _btn, fid: str) -> None:
        store.unquiet_finding(self.data_dir, fid)
        self.refresh(force=True)
        self._say("Shown again: its records return to the feed, and the "
                  "hunter raises it when it next fires.")


    def _on_ai_toggle(self, _switch, state):
        set_ai_enabled(self.data_dir, bool(state))
        self.refresh(force=True)
        return False

    def _on_copy(self, _btn) -> None:
        """Copy facts: the finding's what, raw facts and evidence, one
        per line, straight to the clipboard. Data leaves as text only."""
        f = self._selected_finding or {}
        lines = [str(f.get("what") or "")]
        lines.extend(str(x) for x in (f.get("facts") or []))
        for e in (f.get("evidence") or []):
            bits = [str(e.get("source") or ""),
                    str(e.get("path") or e.get("tool")
                        or e.get("scan_id") or ""),
                    str(e.get("ts") or "")]
            lines.append(" · ".join(b for b in bits if b))
        try:
            from gi.repository import Gdk  # noqa: PLC0415 — lazy: themes does

            self.get_clipboard().set_content(
                Gdk.ContentProvider.new_for_value("\n".join(lines)))
            self._say("Facts copied to the clipboard.")
        except Exception:  # noqa: BLE001 — a missing clipboard never breaks
            self._say("The clipboard is not reachable on this display.")

    def set_ai_switch(self, enabled: bool) -> None:
        self._ai_switch.handler_block_by_func(self._on_ai_toggle)
        self._ai_switch.set_active(bool(enabled))
        self._ai_switch.handler_unblock_by_func(self._on_ai_toggle)

    def mark_seen(self, newest: str | None = None) -> None:
        """The desk was seen: move the pointer to the newest note.

        The tick hands over the pointer it captured BEFORE painting - a
        note that lands between the paint and this mark never gets a
        pointer at or above its ts; the next tick shows it and marks it."""
        try:
            if not newest:
                notes = store.read_defender(self.data_dir,
                                            limit=store.DEFENDER_KEEP)
                newest = max((str(n.get("ts") or "") for n in notes),
                             default="")
            if newest:
                from hunter import explain
                explain.mark_read(self.data_dir, newest)
        except OSError:
            pass

    # ------------------------------------------------------------ render

    def refresh(self, force: bool = False) -> None:
        doc = store.read_live(self.data_dir)
        stamp = str(doc.get("ts") or "")
        if not force and stamp == getattr(self, "_shown_ts", None):
            return  # the hunter has written nothing new since the last paint
        self._shown_ts = stamp
        # Kept extensions read straight from the ledger:
        # their records stay on the disk, but the desk paints a feed
        # without the extensions the user chose to keep.
        self._kept = store.kept_extensions(self.data_dir)
        kept_ids = {row["ext"] for row in self._kept}
        # Dismissed findings leave the desk the same way: the
        # store keeps every record, the ledger decides what paints.
        self._quiet = store.quieted_findings(self.data_dir)
        quiet_ids = {row["id"] for row in self._quiet}
        findings = [f for f in
                    latest_findings(self.data_dir, limit=store.FINDINGS_KEEP)
                    if _ext_parts(f)[0] not in kept_ids
                    and str(f.get("id") or "") not in quiet_ids]
        self._findings = findings
        self._paint_kept()
        self._paint_quiet()
        unread = unread_notes(self.data_dir)
        # A status word (Hunt now, copy, import) says itself once and
        # leaves on the next full paint, as the desk's contract promises.
        self._status.set_visible(False)

        self._clock_label.set_markup(
            f"<span size='10500' font_family='IBM Plex Mono' weight='600' "
            f"color='{theme_muted()}'>{_esc(_next_hunt_text(doc))}</span>")
        verdict, subline = suite_summary(self.data_dir)
        # The chip keeps the decision part of the subline and leaves the
        # "when the snapshot was taken" half to Home, so the strip never
        # ellipsizes the part you act on.
        subline = subline.split(" · snapshot")[0]
        self._suite_chip.set_markup(
            f"<span size='11500' font_family='Inter' "
            f"color='{theme_muted()}'>Suite: <span color='{_ink()}'><b>"
            f"{_esc(verdict)}</b></span> · {_esc(subline)}</span>")
        # The switch follows the OWNER's config, not the last cycle's
        # snapshot: a doc written before the toggle flipped would else
        # snap the switch back for up to one hunt cycle.
        try:
            from hunter import explain
            self.set_ai_switch(
                bool(explain.load_config(self.data_dir).get("enabled")))
        except Exception:            # noqa: BLE001 - config unread: leave
            pass                     # the switch where the user set it
        self._ai_meter.set_markup(
            f"<span size='10000' font_family='IBM Plex Mono' weight='650' "
            f"color='{theme_muted()}'>{_esc(_ai_meter(doc))}</span>")
        self._paint_band(doc, findings, unread)
        self._paint_cover(doc, findings)
        self._watcher_tile.set_text(_watcher_line(doc))
        flag = self._unread_flag
        if unread:
            flag.set_markup(
                f"<span size='10000' font_family='IBM Plex Mono' "
                f"weight='650' color='{theme_muted()}'>{unread} NEW</span>")
            flag.set_visible(True)
        else:
            flag.set_text("")
            flag.set_visible(False)
        self._related_rows["home"].set_visible(bool(unread))

        for child in list(self._list.observe_children()):
            self._list.remove(child)
        self._row_widgets.clear()
        if not findings:
            if getattr(self, "_selected", None) is not None:
                self._clear_selection()
            self._chip_counts(findings)
            self._empty.set_markup(
                f"<span size='12000' font_family='Inter' "
                f"color='{theme_muted()}'>Nothing needs hunting yet. The "
                "hunter watches downloads, browser history, startup "
                "automation, and event telemetry; import a HAR capture "
                "with the button to have it analysed too.</span>")
            # A previous filtered render may have hidden the label; the
            # empty state owns it again here, or it never shows twice.
            self._empty.set_visible(True)
            return
        self._empty.set_visible(False)
        self._render()
        # If the pane is open on a finding, keep its notes current (a new
        # defender note IS the in-place answer arriving) — and when that
        # finding has left the latest window (rotated out, or its capture
        # was retired) the dossier would be showing a ghost: close it.
        sel = next((f for f in findings
                    if str(f.get("id") or "") == self._selected), None)
        if sel is not None:
            self._selected_finding = dict(sel)
            self._fill_detail(sel)
        elif getattr(self, "_selected", None) is not None:
            self._clear_selection()

    def _paint_band(self, doc: dict, findings: list, unread: int) -> None:
        values, subs = self._tiles["leads"]
        values.set_text(str(len(findings)))
        subs.set_text(_sev_tally(findings))
        values, subs = self._tiles["cycle"]
        values.set_text(str(int(doc.get("new_this_cycle") or 0)))
        # A burst larger than the read window is declared, not silent
        # (recovery audit A6): rows beyond the window were never hunted
        # over, and only the cycle that dropped them says so.
        overflow = int(doc.get("events_overflow") or 0)
        tail = f"last cycle {_clock(doc.get('ts'))}"
        if overflow:
            tail += f" · {overflow:,} older skipped"
        subs.set_text(tail)
        values, subs = self._tiles["unread"]
        values.set_text(str(int(unread)))
        subs.set_text("pinned on Home" if unread else "all read")
        # Every capture ever answered, not the last cycle's numbers: a
        # one-capture read (imported a file this cycle) that fell back to
        # "0 processed" a minute later read as if the import vanished.
        total = doc.get("har_total") or {}
        processed = int(total.get("processed")
                        or (doc.get("har") or {}).get("processed") or 0)
        rejected = int(total.get("rejected")
                       or (doc.get("har") or {}).get("rejected") or 0)
        values, subs = self._tiles["har"]
        values.set_text(str(processed + rejected))
        subs.set_text(f"{processed} processed · "
                      f"{rejected} rejected")
        events = store.read_state(self.data_dir)
        values, subs = self._tiles["events"]
        value, sub_text = _event_log_text(events)
        values.set_text(value)
        subs.set_text(sub_text)

    def _paint_cover(self, doc: dict, findings: list) -> None:
        """Every live channel sweeps each cycle, so its last sweep is the
        last hunt's clock and its 24-hour match count reads the findings."""
        for key, _label in _COVERAGE:
            swept_24h = sum(1 for f in findings
                            if _channel_of(f.get("rule"))[1] == key
                            and _age_hours(f.get("ts")) < 24.0)
            self._cover_tiles[key].set_text(
                f"last sweep {_clock(doc.get('ts'))} · {swept_24h} / 24 h")

    def _on_filter(self, _btn, sev: str) -> None:
        """A click on one severity chip: swap the active fill, keep the
        feed at the chosen severity, and drop a selection it excludes."""
        self._sev = (sev or "ALL").upper()
        for label, val in SEV_CHIPS:
            chip = self._chip_btns[label]
            if (val.upper() or "ALL") == self._sev:
                chip.add_css_class("gw-chip-on")
            else:
                chip.remove_css_class("gw-chip-on")
        selected_ok = any(
            str(f.get("id") or "") == self._selected
            for f in self._findings
            if self._sev == "ALL"
            or _bucket(f.get("severity")) == self._sev)
        if not selected_ok:
            self._clear_selection()
        self._render()

    def _render(self) -> None:
        """Paint the feed from the pool behind the current filter, grouped
        into the days the findings themselves span."""
        pool = [f for f in self._findings
                if self._sev == "ALL"
                or _bucket(f.get("severity")) == self._sev]
        pool = pool[:MAX_ROWS]
        # The chips tally the whole pool on file, not the narrowed view —
        # the mockup's "ALL 3 / HIGH 2" reads as an inventory, whatever the
        # feed is showing right now.
        self._chip_counts(self._findings)
        # Diffs clear and re-append rows, and the cleared list clamps the
        # scroll to the top; hold the reading position and set it back at
        # the close of the rebuild so a refresh never yanks the user to
        # the top mid-read.
        vadj = self._scroll.get_vadjustment()
        pos = vadj.get_value()
        for child in list(self._list.observe_children()):
            self._list.remove(child)
        self._row_widgets.clear()
        last_day = None
        for f in pool:
            day = _day_label(_when(f.get("ts")))
            if day != last_day:
                last_day = day
                strip = Gtk.Label(xalign=0)
                strip.add_css_class("gw-day")
                strip.set_text(day)
                self._list.append(strip)
            self._list.append(self._feed_row(f))
        vadj.set_value(max(0.0, min(pos,
                        vadj.get_upper() - vadj.get_page_size())))
        if not pool and self._findings:
            # A filter emptied the feed — not "nothing to hunt", which the
            # refresh path owns; say what the filter means.
            self._empty.set_markup(
                f"<span size='12000' font_family='Inter' "
                f"color='{theme_muted()}'>No findings at this severity."
                "</span>")
            self._empty.set_visible(True)
        else:
            # Coming back to a filter with rows must hide the label a
            # previous filtered render left showing.
            self._empty.set_visible(False)

    def _chip_counts(self, pool: list) -> None:
        """Counted chips: each chip names its severity and how
        many of the feed's rows carry it; All is the pool itself."""
        counts = {"All": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in pool:
            sev = _bucket(f.get("severity"))
            if sev == "HIGH":
                counts["High"] += 1
            elif sev == "MEDIUM":
                counts["Medium"] += 1
            else:
                counts["Low"] += 1
            counts["All"] += 1
        for label in self._chip_btns:
            self._chip_btns[label].set_label(f"{label} {counts[label]}")

    def _feed_row(self, f: dict) -> Gtk.Box:
        sev = str(f.get("severity") or "?")
        colour = severity_colour(sev)
        channel, _key = _channel_of(f.get("rule"))
        row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        row.add_css_class("gw-frow")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        dot = Gtk.Label(xalign=0)
        dot.set_markup(
            f"<span size='10000' font_family='Inter' weight='600' "
            f"color='{colour}'>●</span>")
        dot.set_valign(Gtk.Align.CENTER)
        head.append(dot)
        title = Gtk.Label(xalign=0)
        title.set_xalign(0)
        title.set_wrap(True)
        title.set_hexpand(True)
        title.set_markup(
            f"<span size='12000' font_family='Inter' weight='600' "
            f"color='{_ink()}'>{_esc(f.get('title'))}</span>")
        head.append(title)
        row.append(head)
        when = _when(f.get("ts"))
        stamp = (when.strftime("%H:%M") if when
                 and _day_label(when) == "Today" else _fmt_ts(f.get("ts")))
        meta = Gtk.Label(xalign=0)
        meta.add_css_class("gw-fmeta")
        meta.set_xalign(0)
        meta.set_wrap(True)
        meta.set_markup(
            f"<span size='10500' font_family='IBM Plex Mono' "
            f"color='{theme_muted()}'>{_esc(channel)} · "
            f"{_esc(f.get('rule'))} · {_esc(stamp)}</span>")
        row.append(meta)
        fid = str(f.get("id") or "")
        row._gw_finding_id = fid
        click = Gtk.GestureClick()
        click.connect("released", self._on_row_gesture)
        row.add_controller(click)
        if fid == self._selected:
            row.add_css_class("gw-row-on")
        self._row_widgets[fid] = row
        return row

    def _on_row_gesture(self, gesture, n_press, x, y) -> None:
        row = gesture.get_widget()
        fid = getattr(row, "_gw_finding_id", None)
        if fid:
            self._select_finding(str(fid))

    def _select_finding(self, fid: str) -> None:
        f = next((x for x in self._findings
                  if str(x.get("id") or "") == fid), None)
        if f is None:
            return
        self._selected = fid
        self._selected_finding = dict(f)
        for row in self._row_widgets.values():
            row.remove_css_class("gw-row-on")
        row = self._row_widgets.get(fid)
        if row:
            row.add_css_class("gw-row-on")
        self._fill_detail(dict(f))

    def _clear_selection(self) -> None:
        self._selected = None
        self._selected_finding = None
        self._fill_detail(None)

    def _on_detail_ask(self, _btn) -> None:
        """The dossier's Ask: the same on_ask path the rows use. When the
        handler returns a reply (injected handlers in tests; the window
        handler during live use), it renders in the dossier at once."""
        f = self._selected_finding
        if not f or self.on_ask is None:
            return
        question = (f"Explain this hunter finding: {f.get('title', '')}. "
                    f"What it found: {f.get('what', '')}"
                    " - what should I do about it?")
        replies = self._replies.setdefault(str(f.get("id") or ""), [])
        reply = self.on_ask(question, f)
        if isinstance(reply, str) and reply.strip():
            replies.append(str(reply))
            # The dossier repaints the answers block itself — it mounts
            # the ANSWERS heading only when there is something under it.
            self._fill_detail(f)

    def _fill_detail(self, f: dict | None) -> None:
        """The dossier: pills, what it saw, raw facts, evidence, next
        step, the ask row, the finding's own answers — the related footer
        is fixed above and always mounted."""
        # The rebuild clears the body and clamps the scroll to the top;
        # hold the reading position and set it back after, the way the
        # feed does, so a note arriving mid-read never yanks the page.
        vadj = self._dscroll.get_vadjustment()
        pos = vadj.get_value()
        for child in list(self._detail.observe_children()):
            self._detail.remove(child)
        for child in list(self._dpills.observe_children()):
            self._dpills.remove(child)
        if f is None:
            self._dtitle.set_text("")
            self._dpills.set_visible(False)
            self._detail.append(self._lead(
                "Pick a finding in the feed to open its dossier here. "
                "Everything the hunter recorded about it gathers there: "
                "what it saw, the raw facts, the evidence, the next step, "
                "and the ask path - plus where it touches the rest of the "
                "suite."))
            return
        self._dpills.set_visible(True)
        self._dtitle.set_text(str(f.get("title") or ""))
        sev = (str(f.get("severity") or "?") or "?").upper()
        self._pill(sev, f"gw-pill-{_pill_key(sev)}", severity_colour(sev))
        conf = str(f.get("confidence") or "").lower()
        if conf:
            self._pill(f"confidence {conf}", "gw-pill-neutral", None)
        status = str(f.get("status") or "").lower()
        self._pill(f"status: {status or 'lead'}", "gw-pill-neutral", None)
        asset = str(f.get("asset") or "").lower()
        if asset:
            self._pill(f"asset: {asset}", "gw-pill-neutral", None)
        what = Gtk.Label(xalign=0)
        what.set_xalign(0)
        what.set_wrap(True)
        what.add_css_class("gw-prose")
        what.set_text(str(f.get("what") or ""))
        self._detail.append(what)
        facts = list(f.get("facts") or [])
        if facts:
            self._detail.append(self._label("RAW FACTS"))
            facts_l = Gtk.Label(xalign=0)
            facts_l.set_xalign(0)
            facts_l.set_wrap(True)
            facts_l.add_css_class("gw-facts")
            facts_l.set_text("\n".join(str(x) for x in facts))
            self._detail.append(facts_l)
        ev_rows = list(f.get("evidence") or [])
        if ev_rows:
            self._detail.append(self._label("EVIDENCE"))
            for e in ev_rows[:6]:
                self._detail.append(self._evidence_row(e))
            if len(ev_rows) > 6:
                more = Gtk.Label(xalign=0)
                more.set_xalign(0)
                more.add_css_class("gw-fmeta")
                more.set_text(
                    f"… and {len(ev_rows) - 6} more piece(s) held in the "
                    "hunter's inbox folder.")
                self._detail.append(more)
        nxt = str(f.get("next") or "")
        if nxt:
            self._detail.append(self._label("SUGGESTED NEXT STEP"))
            self._detail.append(self._next_box(nxt))
        ask_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        if self.on_ask is not None:
            ask = Gtk.Button(label="Ask about this")
            ask.add_css_class("gw-mini")
            ask.connect("clicked", self._on_detail_ask)
            ask_row.append(ask)
        # A browser-extension lead offers its own answer first:
        # keep it, once, and the hunter never raises it again.
        if str(f.get("rule") or "") == "cfg-new-extension" \
                and _ext_parts(f)[0]:
            keep_btn = Gtk.Button(label="Keep this extension")
            keep_btn.add_css_class("gw-mini")
            keep_btn.add_css_class("suggested-action")
            keep_btn.connect("clicked", self._on_keep_ext)
            ask_row.append(keep_btn)
        # Every finding carries its own answer: seen
        # and quiet — dismissed permanently by id, records hidden, the
        # way back on the hidden strip above the feed.
        fid = str((f or {}).get("id") or "")
        if fid:
            dis = Gtk.Button(label="Dismiss this finding")
            dis.add_css_class("gw-mini")
            dis.connect("clicked", self._on_dismiss)
            ask_row.append(dis)
        copy_btn = Gtk.Button(label="Copy facts")
        copy_btn.add_css_class("gw-mini")
        copy_btn.connect("clicked", self._on_copy)
        ask_row.append(copy_btn)
        self._detail.append(ask_row)
        # The finding's own defender notes, then this session's replies:
        # chronological reading order, so an answer asked for just now
        # lands at the bottom instead of above the older notes. The
        # ANSWERS heading appears only when one of the two has rows.
        fid = str(f.get("id") or "")
        self._replies.setdefault(fid, [])
        self._answers = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                spacing=6)
        for n in notes_for(self.data_dir, fid):
            row = _answer_note_row(n)
            if row is not None:
                self._answers.append(row)
        for reply in self._replies[fid]:
            self._answers.append(_answer_row(reply))
        if self._answers.get_first_child() is not None:
            self._detail.append(self._label("ANSWERS"))
            self._detail.append(self._answers)
        vadj.set_value(max(0.0, min(pos,
                        vadj.get_upper() - vadj.get_page_size())))

    def _lead(self, text: str) -> Gtk.Label:
        lead = Gtk.Label(xalign=0)
        lead.set_xalign(0)
        lead.set_wrap(True)
        lead.add_css_class("gw-dlead")
        lead.set_text(text)
        return lead

    def _label(self, text: str) -> Gtk.Label:
        label = Gtk.Label(xalign=0)
        label.set_xalign(0)
        label.add_css_class("gw-dlabel")
        label.set_text(text)
        return label

    def _pill(self, text: str, css: str, colour: str | None) -> None:
        pill = Gtk.Label(xalign=0)
        pill.set_xalign(0)
        pill.add_css_class("gw-pill")
        pill.add_css_class(css)
        if colour:
            pill.set_markup(
                f"<span size='9500' font_family='IBM Plex Mono' "
                f"weight='700' color='{colour}'>{_esc(text)}</span>")
        else:
            pill.set_text(str(text).upper())
        self._dpills.append(pill)

    def _evidence_row(self, e: dict) -> Gtk.Box:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        where = str(e.get("path") or e.get("tool") or e.get("scan_id")
                    or e.get("text") or "")[:120]
        key = Gtk.Label(xalign=0)
        key.add_css_class("gw-mono")
        key.set_text(str(e.get("source") or "-"))
        row.append(key)
        val = Gtk.Label(xalign=0)
        val.set_xalign(0)
        val.set_wrap(True)
        val.set_hexpand(True)
        val.add_css_class("gw-facts-line")
        val.set_text(where or "-")
        row.append(val)
        when = Gtk.Label(xalign=1)
        when.add_css_class("gw-mono")
        when.set_text(_fmt_ts(e.get("ts")))
        row.append(when)
        return row

    def _next_box(self, text: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.add_css_class("gw-next")
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        body.set_text(str(text))
        box.append(body)
        return box


def _answer_row(text: str) -> Gtk.Box:
    row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    row.add_css_class("gw-reply")
    body = Gtk.Label(xalign=0)
    body.set_xalign(0)
    body.set_wrap(True)
    body.add_css_class("gw-prose")
    body.set_text(text)
    row.append(body)
    return row


def _answer_note_row(note: dict) -> Gtk.Box | None:
    text = str(note.get("text") or "")
    if not text:
        return None
    row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    body = Gtk.Label(xalign=0)
    body.set_xalign(0)
    body.set_wrap(True)
    body.add_css_class("gw-prose")
    hint = str(note.get("hint") or "")
    body.set_text(f"{text} {hint}".strip())
    row.append(body)
    return row


def notes_for(data_dir, finding_id: str) -> list:
    """The finding's own defender notes (rule wording and, when the
    bounded explainer ran, its AI note) — the in-place answer list."""
    return [n for n in store.read_defender(data_dir,
                                           limit=store.DEFENDER_KEEP)
            if str(n.get("finding_id") or "") == finding_id
            and str(n.get("text") or "")]