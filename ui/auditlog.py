"""The Activity Log page (rebuild round 2, task 6 - owner variant 1):
ONE chronology table with a tab strip on top, fed by the suite's
existing records only.

- Everything: the event store's chronology (what the tools saw, said
  and did), grouped like the raw-logs desk always grouped it.
- Decisions: the one answer ledger (decisions.jsonl).
- Blocks: the chronology filtered to block verdicts - the same rows
  the blocks-per-hour strip under the table draws.
- Findings: the quarantine ledger, each row still offering exactly the
  three stored answers through the confirm pipeline.

Rows carry the producing tool's own enforcement options, every one
through an existing lane and nothing new: psad rows block (block-ip)
and unblock (lift-block); appfw rows answer a still-live ask through
the ask-answer bridge the ask dialogs use; rkhunter rows refresh the
checker baseline through baseline-update.sh (rkhunter --propupd); aide
rows open the page's own diff read. After any action the page says
plainly what happened - or honestly what did not finish.

The waiting/glitch row (the newest unanswered ask) glows with the
guided pulse style class, because it IS the hand-off target: the app
sends you here when something needs you, and this row is the thing
that needed you.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import pathlib
import re
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk, Pango  # noqa: E402

import greywatch_daemon as daemon_mod      # noqa: E402
from decisions_factory import pending_spec_pairs  # noqa: E402
from ui.plain import (friendly_name, severity_colour as pc_severity_colour,
                      severity_word)       # noqa: E402
from ui.threatcards import (_fixed, log_row_values,   # noqa: E402
                            threat_card_options)
from ui.eventclock import present_now      # noqa: E402
from ui.models import local_clock          # noqa: E402
from ui import guided                      # noqa: E402
from ui import metrics                     # noqa: E402
from gwpaths import data_dir as _data_dir  # noqa: E402

# The variant-1 tab strip, in the owner's own order. Each tab reads one
# record the page already read before the rebuild.
TAB_ORDER = ("Everything", "Decisions", "Blocks", "Findings")

RANGES = {"24h": dt.timedelta(hours=24),
          "7d": dt.timedelta(days=7),
          "all": None}

# A block verdict for the Blocks tab and the strip: the words the
# suite's own block writers put in their rows (psad's auto-block,
# fail2ban's ban, the firewall's drop/deny lines).
BLOCK_MARKERS = ("block", "ban", "drop", "deny")

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_ts(text) -> "dt.datetime | None":
    """The one timestamp reader for every record shape on this page:
    ISO events with their zone, and the ledgers' space-separated stamp
    without one (naive stamps read in the machine's own zone)."""
    raw = str(text or "").strip().replace("Z", "+00:00")
    if not raw:
        return None
    try:
        stamp = dt.datetime.fromisoformat(raw)
    except ValueError:
        try:
            stamp = dt.datetime.fromisoformat(raw.split(".")[0].replace(
                " ", "T", 1))
        except ValueError:
            return None
    if stamp.tzinfo is None:
        stamp = stamp.astimezone()
    return stamp


def _first_ip(text: str) -> str:
    """The first valid IPv4 in a row, or nothing: the address is the
    block lane's whole subject, and a wrong one blocks the wrong host."""
    for cand in _IPV4.findall(text):
        try:
            octets = [int(o) for o in cand.split(".")]
            if all(0 <= o <= 255 for o in octets):
                return cand
        except ValueError:
            continue
    return ""


def _is_block(event: dict) -> bool:
    low = str(event.get("text", "")).lower()
    return any(m in low for m in BLOCK_MARKERS)


def block_buckets(rows, now=None) -> list:
    """24 hourly buckets of block verdicts ending at the runner's own
    hour: the strip's one data shape (label, count), the same record
    the table reads. Rows outside the window are never invented as
    bars; an empty window honestly holds twenty-four zeros."""
    if now is None:
        now = dt.datetime.now().astimezone()
    start = (now.replace(minute=0, second=0, microsecond=0)
             - dt.timedelta(hours=23))
    counts = [0] * 24
    for row in rows:
        if not _is_block(row):
            continue
        stamp = parse_ts(row.get("ts"))
        if stamp is None or stamp < start:
            continue
        try:
            hour = int((stamp - start).total_seconds() // 3600)
        except (TypeError, ValueError):
            continue
        if 0 <= hour < 24:
            counts[hour] += 1
    return [((start + dt.timedelta(hours=i)).strftime("%H:00"), count)
            for i, count in enumerate(counts)]


def _ask_request_path(spec_id: str):
    """The ask bridge's request file for one spec id - the same
    sha16 name the daemon and the ask dialogs already share."""
    key = hashlib.sha256(str(spec_id or "").encode()).hexdigest()[:16]
    return _data_dir() / "appfw" / "asks" / f"{key}.json"


def _appfw_options(ev) -> list:
    """Allow rule / Block rule for an appfw row, through the ask-answer
    bridge and nothing else. A live ask (its request file still on
    disk) is answerable; anything else is history, so the buttons ship
    disabled and say so - never a control that pretends to work."""
    spec = ev.get("interaction")
    spec_id = str(spec.get("id", "")) if isinstance(spec, dict) else ""
    why = ("This firewall ask is closed: a rule is written only while the"
           " ask is live - the firewall asks again the next time this app"
           " connects.")
    opts = [{"id": "appfw-allow", "label": "Allow rule", "tone": "primary",
             "kind": "appfw-answer", "args": ["allow", "always"],
             "disabled": True, "why": why},
            {"id": "appfw-block", "label": "Block rule", "tone": "danger",
             "kind": "appfw-answer", "args": ["deny", "always"],
             "disabled": True, "why": why}]
    if not spec_id:
        return opts
    req = _ask_request_path(spec_id)
    if not req.exists():
        return opts
    stored = spec.get("options") or []

    def _stored(prefixes, fallback):
        for pref in prefixes:
            for o in stored:
                if str(o.get("id", "")).startswith(pref):
                    return o
        return fallback

    allow = _stored(("allow-always", "allow-once"),
                    {"args": ["allow", "always"]})
    deny = _stored(("block-always", "deny-once"),
                   {"args": ["deny", "always"]})

    def _mk(stored_opt, oid, label, tone, fallback):
        args = list(stored_opt.get("args") or fallback)[:2]
        out = {"id": oid, "label": label, "tone": tone,
               "kind": "appfw-answer", "args": args,
               "spec_id": spec_id, "req": str(req)}
        if any("trust" in str(a) for a in stored_opt.get("args") or []):
            out["host_op"] = str(spec.get("host", "") or "")
        return out

    return [_mk(allow, "appfw-allow", "Allow rule", "primary",
                ["allow", "always"]),
            _mk(deny, "appfw-block", "Block rule", "danger",
                ["deny", "always"])]


def row_options(ev) -> list:
    """The producing tool's own enforcement options, existing lanes
    only: psad blocks/unblocks real addresses, appfw answers the ask
    bridge, rkhunter blesses a reviewed state through baseline-update,
    aide opens the page's diff read. Every other tool row stays plain."""
    tool = str(ev.get("from_tool", ""))
    text = str(ev.get("text", ""))
    if text.startswith("check-in:"):
        return []                      # tool chatter: nothing to enforce
    if tool == "psad":
        ip = _first_ip(text)
        if not ip:
            return []
        return [{"id": "block", "label": f"Block {ip}", "tone": "primary",
                 "helper": "block-ip", "args": [ip], "kind": "helper"},
                {"id": "unblock", "label": f"Unblock {ip}",
                 "tone": "danger", "helper": "lift-block", "args": [ip],
                 "kind": "helper"}]
    if tool == "appfw":
        return _appfw_options(ev)
    if tool == "rkhunter":
        # the reviewer's own blessing: --propupd keeps the previous
        # baseline beside the new one (baseline-update.sh, untracked
        # helper reviewed in tree)
        return [{"id": "baseline", "label": "Update baseline",
                 "tone": "primary", "helper": "baseline-update",
                 "args": ["rkhunter"], "kind": "helper"}]
    if tool == "aide":
        return [{"id": "aide-review", "label": "Review diff",
                 "tone": "primary", "kind": "aide-diff"}]
    return []


def _tone(name, fallback):
    """One theme token as RGBA for the strip's bars - the same lookup
    the trend card paints with."""
    from ui.themes import CURRENT, _hex_rgba
    return _hex_rgba(CURRENT.get(name), fallback)


class _BlockStrip(Gtk.Box):
    """The blocks-per-hour strip under the table: one DrawingArea, 24
    thin bars from the same rows the table reads, the peak bar in the
    warn tone and labelled with its hour, an honest empty note when no
    block is on record - never fake bars."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._empty = Gtk.Label(
            xalign=0, wrap=True,
            label="no blocks in the last day - the strip fills from the "
                  "same record the table reads")
        self._empty.add_css_class("gw-meta")
        self.append(self._empty)
        self._area = Gtk.DrawingArea()
        self._area._gw_strip = True
        self._area.set_size_request(-1, 64)
        self.append(self._area)
        self._area.set_draw_func(self._draw)
        self._buckets = []

    def repaint(self, buckets):
        self._buckets = list(buckets or [])
        total = sum(c for _l, c in self._buckets)
        self._empty.set_visible(total == 0)
        if total == 0:
            tip = "no blocks in the last day"
        else:
            label, count = self._peak()
            tip = (f"{total} block{'s' if total != 1 else ''} in the last"
                   f" day - peak {count} around {label}")
        self._area.set_tooltip_text(tip)
        self._area.queue_draw()

    def _peak(self):
        label, count = max(self._buckets, key=lambda b: b[1])
        return label, count

    def _draw(self, _area, cr, width, height):
        buckets = self._buckets
        if not buckets or sum(c for _l, c in buckets) == 0 \
                or width <= 8 or height <= 8:
            return
        n = len(buckets)
        peak = max(c for _l, c in buckets) or 1
        slot = width / n
        bar_w = max(3.0, min(11.0, slot * 0.36))
        axis_y = height - 1.0
        rest = _tone("mute", (0.5, 0.5, 0.5, 1.0))
        warn = _tone("warn", (0.7, 0.5, 0.2, 1.0))
        accent = _tone("accent", rest)
        peak_label, peak_count = self._peak()
        for i, (label, count) in enumerate(buckets):
            is_peak = count == peak_count and count > 0
            colour = warn if is_peak else (
                accent if i == n - 1 else rest)
            bar_h = max(2.0, (height - 18.0) * (count / peak)) if count \
                else 2.0
            x = i * slot + (slot - bar_w) / 2
            cr.set_source_rgba(*colour)
            cr.rectangle(x, axis_y - bar_h, bar_w, bar_h)
            cr.fill()
            if is_peak:
                # the peak bar carries its own hour, in the warn tone
                cr.set_font_size(10.0)
                cr.move_to(max(2.0, min(width - 46.0, x - 12.0)),
                           max(10.0, axis_y - bar_h - 4.0))
                cr.show_text(label)


class ActivityLogPage(Gtk.Box):
    """One chronology, four reads of it, and the dock's controls."""

    def __init__(self, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self.set_margin_top(metrics.PAGE_TOP)
        self.set_margin_bottom(metrics.PAGE_BOTTOM)
        self.set_margin_start(metrics.PAGE_X)
        self.set_margin_end(metrics.PAGE_X)
        self._win = win
        self._now = dt.datetime.now().astimezone   # test seam: honest clock
        self._tab = "Everything"
        self._events = []
        self._quar_records = []
        self._needs = None

        title = Gtk.Label(label="Activity log", xalign=0)
        title.add_css_class("gw-page-title")
        self.append(title)
        meta = Gtk.Label(xalign=0, wrap=True,
                         label="One chronology of what the tools saw, said "
                               "and did. Click a row to resolve it; "
                               "identical consecutive lines are grouped, "
                               "newest first.")
        meta.add_css_class("gw-meta")
        self.append(meta)
        self._status = Gtk.Label(xalign=0, wrap=True)
        self._status.set_xalign(0)
        self._status.add_css_class("gw-meta")
        self.append(self._status)

        # the attention row: rebuilt on refresh, glowing when it stands
        self._needs_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                  spacing=6)
        self.append(self._needs_box)

        # the tab strip above the one table
        strip_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                            spacing=6)
        self._tabs = {}
        for name in TAB_ORDER:
            btn = Gtk.ToggleButton(label=name)
            btn.connect("toggled", self._tab_toggled, name)
            self._tabs[name] = btn
            strip_row.append(btn)
        self.append(strip_row)

        # the one chronology table (the raw-logs desk's shape, reused)
        self._store = Gtk.ListStore(str, str, str, str, str, object, str)
        view = Gtk.TreeView(model=self._store, headers_visible=False)
        icon = Gtk.CellRendererPixbuf()
        icon.set_property("width", 22)
        view.append_column(_fixed(
            Gtk.TreeViewColumn(None, icon, icon_name=0), 44))
        sev = Gtk.CellRendererText()
        view.append_column(_fixed(
            Gtk.TreeViewColumn(None, sev, text=1, foreground=2), 86))
        view.append_column(_fixed(
            Gtk.TreeViewColumn(None, Gtk.CellRendererText(), text=3), 300))
        event_cell = Gtk.CellRendererText()
        event_cell.set_property("ellipsize", Pango.EllipsizeMode.END)
        last = Gtk.TreeViewColumn(None, event_cell, text=4)
        last.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        last.set_fixed_width(200)
        last.set_expand(True)
        view.append_column(last)
        view.connect("row-activated", self._activated)
        view.set_has_tooltip(True)
        view.connect("query-tooltip", self._row_tooltip)
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        head.add_css_class("gw-th-row")
        pad = Gtk.Box()
        pad.set_size_request(44, -1)
        head.append(pad)
        for label, width in (("State", 86), ("Time / tool", 300),
                             ("Event", 0)):
            lbl = Gtk.Label(label=label, xalign=0)
            lbl.set_xalign(0)
            lbl.add_css_class("gw-th")
            if width:
                lbl.set_size_request(width, -1)
            else:
                lbl.set_hexpand(True)
            head.append(lbl)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        body.append(head)
        # The fit law (2026-11-10): the chronology is the one inner
        # scrolled container on this page - the table grows inside its
        # card, the page never scrolls whole. The wrap is the raw-logs
        # desk's shape (a box child inside the scroller); the height
        # request bounds the page's minimum so the window never lays out
        # a scrolled table taller than itself, and the card above keeps
        # the flex.
        wrap = Gtk.ScrolledWindow()
        wrap.set_name("audit-table")
        wrap.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        wrap.set_size_request(-1, 220)
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        inner.append(view)
        wrap.set_child(inner)
        body.append(wrap)
        card = Gtk.Frame()
        card.add_css_class("gw-card")
        card.set_child(body)
        card.set_vexpand(True)
        self.append(card)
        self._view = view

        # the honest empty state: a tab that holds nothing says so
        self._empty = Gtk.Label(xalign=0, wrap=True)
        self._empty.set_xalign(0)
        self._empty.add_css_class("gw-meta")
        self._empty.set_visible(False)
        self.append(self._empty)

        # the blocks-per-hour strip, under the table, same data
        self._strip = _BlockStrip()
        self.append(self._strip)

        # -- the dock's widgets (built unattached: the dock claims them)
        self._search = Gtk.SearchEntry()
        self._search.set_placeholder_text("search the record")
        self._search.connect("search-changed", self._refilter)
        self._sev_pick = Gtk.ComboBoxText()
        self._sev_pick.append("", "Any severity")
        for word in ("Critical", "High", "Medium", "Low", "Info"):
            self._sev_pick.append(word, word)
        self._sev_pick.set_active_id("")
        self._sev_pick.connect("changed", lambda _c: self._refilter())
        self._tool_pick = Gtk.ComboBoxText()
        self._tool_pick.append("", "All tools")
        for t in (getattr(win, "registry", None) or []):
            self._tool_pick.append(t["name"], friendly_name(t["name"]))
        self._tool_pick.set_active_id("")
        self._tool_pick.set_size_request(240, -1)
        self._tool_pick.connect("changed", lambda _c: self._refilter())
        self._range_pick = Gtk.ComboBoxText()
        for rid, label in (("24h", "Last 24 hours"), ("7d", "Last 7 days"),
                           ("all", "All time")):
            self._range_pick.append(rid, label)
        self._range_pick.set_active_id("7d")
        self._range_pick.connect("changed", lambda _c: self._refilter())

        self._sources = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                spacing=2)
        self._source_buttons = {}
        for t in (getattr(win, "registry", None) or []):
            chk = Gtk.CheckButton(label=friendly_name(t["name"]),
                                  active=True)
            chk.connect("toggled", self._refilter)
            self._source_buttons[t["name"]] = chk
            self._sources.append(chk)

        self._follow = Gtk.CheckButton(
            label="Follow the feed",
            active=guided.load_toggle(key="log_follow", default=True))
        self._follow.add_css_class("gw-quiet")
        self._follow.set_tooltip_text(
            "When on, new rows appear as the tick lands; when off, the "
            "table changes only when you pick a tab or act.")
        self._follow.connect("toggled", self._follow_toggled)

        self._export = Gtk.Button(label="Export view")
        self._export.add_css_class("gw-quiet")
        self._export.set_tooltip_text(
            "Puts the rows on screen into the clipboard as text - the "
            "suite's one export lane.")
        self._export.connect("clicked", self._export_view)

        self._clear = Gtk.Button(label="Clear the log")
        self._clear.add_css_class("gw-quiet")
        self._clear.set_tooltip_text(
            "Empties this event log through the same clear helper. Answers, "
            "scan results and quarantine records are not touched.")
        self._clear.connect("clicked", self._clear_pressed)

        # one tab is always on; the strip only fires _refill once the
        # table it speaks to exists
        self._tabs[self._tab].set_active(True)

        self.refresh()

    # ---------------------------------------------------------- refresh
    def refresh(self, *_a, **_k):
        """The window's 5 s tick lands here while the page is shown. With
        follow off the store keeps its rows (a reader is never scrolled
        out from under) - the attention row and strip still track."""
        if self._follow.get_active() or not len(self._store):
            self._load()
            self._refill()
        self._paint_needs()
        self._strip.repaint(block_buckets(self._events, now=self._now()))

    def _load(self):
        try:
            self._events = daemon_mod.read_events(
                _data_dir() / "events.jsonl", 4000)
        except OSError:
            snap = getattr(self._win, "_status_snapshot", None)
            self._events = list((snap or {}).get("recent") or [])
        try:
            raw = (_data_dir() / "quarantine.jsonl").read_text(
                errors="replace")
        except OSError:
            self._quar_records = []
        else:
            import json
            recs = []
            for line in raw.splitlines()[-500:]:
                try:
                    recs.append(json.loads(line))
                except ValueError:
                    continue
            self._quar_records = recs

    def _follow_toggled(self, btn):
        guided.persist_toggle(btn.get_active(), key="log_follow")
        if btn.get_active():
            self.refresh()

    def _tab_toggled(self, btn, name):
        if btn.get_active():
            self._tab = name
            for other, other_btn in self._tabs.items():
                if other != name and other_btn.get_active():
                    other_btn.set_active(False)
            self._refill()
        elif self._tab == name:
            btn.set_active(True)          # one tab is always on

    def _set_tab(self, name):
        self._tab = name
        switched = False
        for other, other_btn in self._tabs.items():
            want = other == name
            if other_btn.get_active() != want:
                other_btn.set_active(want)
                switched = True
        if not switched:
            self._refill()                # actives already match

    def _refilter(self, *_a):
        self._refill()

    # ------------------------------------------------------- filtering
    def _cutoff(self):
        span = RANGES.get(self._range_pick.get_active_id() or "7d")
        if span is None:
            return None
        return self._now().replace(minute=0, second=0, microsecond=0) - span

    def _needle(self):
        return self._search.get_text().lower()

    def _want_tool(self, tool):
        pick = self._tool_pick.get_active_id()
        if pick and tool != pick:
            return False
        chk = self._source_buttons.get(tool)
        return True if chk is None else chk.get_active()

    def _want_sev(self, ev):
        pick = self._sev_pick.get_active_id()
        if not pick:
            return True
        return str(ev.get("severity", "")).upper() == pick.upper()

    def _in_window(self, stamp_text, cutoff):
        if cutoff is None:
            return True
        stamp = parse_ts(stamp_text)
        return stamp is not None and stamp >= cutoff

    # ---------------------------------------------------------- filling
    _EMPTY_WORDS = {"Everything": "no events in the record for this view",
                    "Blocks": "no blocks in this view",
                    "Decisions": "no answers recorded yet",
                    "Findings": "nothing quarantined on file - the ledger"
                                " on file is empty"}

    def _refill(self):
        self._store.clear()
        cutoff = self._cutoff()
        needle = self._needle()
        if self._tab == "Everything":
            shown = self._fill_events(False, cutoff, needle)
        elif self._tab == "Blocks":
            shown = self._fill_events(True, cutoff, needle)
        elif self._tab == "Decisions":
            shown = self._fill_decisions(cutoff, needle)
        else:
            shown = self._fill_quarantine(cutoff, needle)
        self._empty.set_text(self._EMPTY_WORDS.get(self._tab, ""))
        self._empty.set_visible(shown == 0)

    def _fill_events(self, blocks_only, cutoff, needle) -> int:
        ordered = sorted(self._events, key=lambda e: str(e.get("ts", "")),
                         reverse=True)
        grouped = []
        for e in ordered:
            if not self._want_tool(str(e.get("from_tool", ""))):
                continue
            if not self._want_sev(e):
                continue
            if blocks_only and not _is_block(e):
                continue              # the Blocks tab shows verdicts only
            if not self._in_window(e.get("ts"), cutoff):
                continue
            if needle:
                hay = " ".join((str(e.get("text", "")),
                                str(e.get("from_tool", "")),
                                friendly_name(str(e.get("from_tool", ""))),
                                str(e.get("severity", "")))).lower()
                if needle not in hay:
                    continue
            key = (e.get("from_tool"), e.get("text", ""))
            if grouped and grouped[-1]["key"] == key:
                grouped[-1]["count"] += 1
                continue
            grouped.append({"key": key, "count": 1, "ev": e})
            if len(grouped) >= 500:
                break
        for g in grouped:
            e = g["ev"]
            suffix = f"   ×{g['count']}" if g["count"] > 1 else ""
            values, raw, _lane = log_row_values(
                e, f"{local_clock(e.get('ts', ''))} "
                   f"{friendly_name(e.get('from_tool', ''))}",
                str(e.get("text", ""))[:400] + suffix,
                pc_severity_colour(str(e.get("severity", ""))))
            self._store.append([*values, raw, "event"])
        return len(grouped)

    def _fill_decisions(self, cutoff, needle) -> int:
        try:
            import json
            raw = (_data_dir() / "decisions.jsonl").read_text(
                errors="replace")
            rows = []
            for line in raw.splitlines()[-500:]:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
        except OSError:
            rows = []
        shown = 0
        for r in reversed(rows[-120:]):
            if needle and needle not in str(r).lower():
                continue
            if not self._in_window(r.get("ts"), cutoff):
                continue
            src = str(r.get("source") or
                      friendly_name(str(r.get("id", "")).split(":")[0]))
            text = f"{src} - {r.get('option', '')}"
            values, _raw, _lane = log_row_values(
                r, str(r.get("ts", ""))[:19] + " Decision ledger", text,
                pc_severity_colour("INFO"))
            self._store.append([*values, r, "decision"])
            shown += 1
        return shown

    def _fill_quarantine(self, cutoff, needle) -> int:
        shown = 0
        for rec in reversed(self._quar_records):
            if needle and needle not in str(rec).lower():
                continue
            if not self._in_window(rec.get("ts"), cutoff):
                continue
            orig = str(rec.get("orig") or "?")
            values, _raw, _lane = log_row_values(
                rec, f"{local_clock(rec.get('ts', ''))} Quarantine",
                f"{rec.get('tag', '')} - {orig}",
                pc_severity_colour("HIGH"))
            self._store.append([*values, rec, "quarantine"])
            shown += 1
        return shown

    _quarantine_opts = (
        ("keep", "Keep quarantined", "primary", "keep-quarantine"),
        ("restore", "Put it back", "primary", "restore-quarantine"),
        ("wipe", "Secure-wipe", "danger", "delete-quarantine"))

    @staticmethod
    def _quar_opts(rec) -> list:
        orig = str(rec.get("orig") or "")
        return [{"id": oid, "label": label, "tone": tone,
                 "helper": helper, "args": [orig], "kind": "helper"}
                for oid, label, tone, helper in
                ActivityLogPage._quarantine_opts]

    # ------------------------------------------------- the attention row
    def _pending_spec(self):
        """The ONE published pending list (the same two sources the
        Overview's needs-you rows read), newest ask first."""
        from ui.actiongate import _status_path_rows
        rows = _status_path_rows(_data_dir())
        if rows is None:
            try:
                rows = pending_spec_pairs(_data_dir())
            except Exception:
                rows = []
        rows = [(spec, ts) for spec, ts in (rows or [])
                if isinstance(spec, dict) and spec.get("id")]
        return rows[-1][0] if rows else None

    def _paint_needs(self):
        spec = self._pending_spec()
        if spec is None:
            if self._needs is not None:
                self._needs_box.remove(self._needs)
                self._needs = None
            return
        sid = str(spec.get("id"))
        if self._needs is not None and \
                getattr(self._needs, "_spec_id", None) == sid:
            return
        if self._needs is not None:
            self._needs_box.remove(self._needs)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row.add_css_class("gw-card")
        row.add_css_class(guided._PULSE)   # the row that needs you glows
        row._spec_id = sid
        subject = str(spec.get("subject") or spec.get("question")
                      or spec.get("eyebrow") or "a decision")
        glow = Gtk.Label(label="●", xalign=0)
        glow.add_css_class("gw-pill")
        row.append(glow)
        words = Gtk.Label(xalign=0,
                          wrap=True,
                          label=f"Waiting for you: {subject}")
        words.add_css_class("gw-meta")
        words.set_hexpand(True)
        row.append(words)
        if hasattr(self._win, "_open_decisions"):
            decide = Gtk.Button(label="Decide")
            decide.add_css_class("gw-primary")
            decide.connect("clicked", lambda *_a: self._win._open_decisions())
            row.append(decide)
        self._needs = row
        self._needs_box.append(row)

    def attention_row(self):
        """The hand-off target: the waiting/glitch row that glows, or
        nothing when no unanswered ask stands."""
        return self._needs

    # ------------------------------------------------------------ cards
    def _row_tooltip(self, view, x, y, kb, tip):
        try:
            path, _col, _cx, _cy = view.get_path_at_pos(x, y)
        except Exception:
            return False
        if path is None or tip is None:
            return False
        tip.set_text(
            "Click to open this row's card - it carries that lane's "
            "controls.")
        return True

    def _activated(self, _view, path, _col):
        self._row_card(self._store[path][5], self._store[path][6])

    def _row_card(self, ev, kind):
        """One row, one card: the heading is the tool's own name, the
        actions are the producing tool's lanes only, and every press
        says plainly what happened."""
        ev = ev if isinstance(ev, dict) else {}
        parent = self._win if isinstance(self._win, Gtk.Window) else None
        dlg = Gtk.Dialog(title="Resolve this row", transient_for=parent,
                         modal=False)
        dlg.set_destroy_with_parent(True)
        body = dlg.get_content_area()
        body.set_margin_top(12)
        body.set_margin_bottom(12)
        body.set_margin_start(18)
        body.set_margin_end(18)
        tool = str(ev.get("from_tool") or
                   ("Quarantine" if kind == "quarantine" else "Record"))
        what = Gtk.Label(xalign=0, wrap=True)
        what.set_xalign(0)
        what.set_text(f"{friendly_name(tool)} · "
                      f"{severity_word(str(ev.get('severity', ''))) or '-'}"
                      f"\n{str(ev.get('text', ''))[:400]}")
        what.set_selectable(True)
        body.append(what)
        acts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        acts.set_margin_top(10)
        opts = self._quar_opts(ev) if kind == "quarantine" else \
            (row_options(ev) + self._threat_opts(ev))
        for opt in opts:
            acts.append(self._opt_button(opt, ev))
        if not opts:
            quiet = Gtk.Label(xalign=0, wrap=True)
            quiet.set_text("This row is a record - its lane offers no "
                           "control here.")
            quiet.add_css_class("gw-meta")
            acts.append(quiet)
        copy = Gtk.Button(label="Copy details")
        copy.add_css_class("gw-quiet")
        copy.connect("clicked", self._copy_row, ev)
        acts.append(copy)
        body.append(acts)
        dlg.connect("response", lambda d, _r: d.destroy())
        present_now(dlg)

    def _threat_opts(self, ev) -> list:
        """A non-appfw ask's own stored options (the confirm pipeline's
        records); appfw asks answer through the bridge above only."""
        spec = ev.get("interaction")
        if not (isinstance(spec, dict) and str(spec.get("id", "")).startswith(
                ("appfw",))):
            return [o for o in threat_card_options(ev) if o.get("helper")]
        return []

    def _opt_button(self, opt, ev):
        b = Gtk.Button(label=str(opt.get("label") or opt.get("id")))
        tone = str(opt.get("tone") or "")
        b.add_css_class({"primary": "gw-primary", "danger": "gw-danger"}
                        .get(tone, "gw-quiet"))
        if opt.get("disabled"):
            b.set_sensitive(False)
            b.set_tooltip_text(str(opt.get("why") or ""))
            return b
        what = opt.get("kind")
        if what == "appfw-answer":
            b.set_tooltip_text("Answers the firewall's ask through the "
                               "same bridge the ask dialogs use.")
            b.connect("clicked", self._answer_appfw, opt)
        elif what == "aide-diff":
            b.set_tooltip_text("Opens the record of this path - a read, "
                               "never a write.")
            b.connect("clicked", self._open_aide_review, ev)
        else:
            helper = str(opt.get("helper") or "")
            args = ", ".join(str(a) for a in (opt.get("args") or []))
            b.set_tooltip_text((f"Runs {helper} {args} through polkit - "
                                "you will be asked for your password.")
                               if helper else "Records your answer.")
            b.connect("clicked", self._fire_option, opt)
        return b

    # --------------------------------------------------------- actions
    def _fire_option(self, _btn, opt):
        self._confirm_and_run(opt)

    def _confirm(self, label, words) -> Gtk.Dialog:
        d = Gtk.Dialog(title=f"{label} : are you sure?",
                       transient_for=self._win
                       if isinstance(self._win, Gtk.Window) else None,
                       modal=False)
        d.set_destroy_with_parent(True)
        body = d.get_content_area()
        body.set_margin_start(18)
        body.set_margin_end(18)
        body.set_margin_top(12)
        body.set_margin_bottom(12)
        ask = Gtk.Label(xalign=0, wrap=True)
        ask.set_xalign(0)
        ask.set_text(words)
        body.append(ask)
        d.add_button("Cancel", Gtk.ResponseType.CANCEL)
        d.add_button(label, Gtk.ResponseType.OK)
        present_now(d)
        return d

    def _confirm_and_run(self, opt):
        helper = str(opt.get("helper") or "")
        args = " ".join(str(a) for a in (opt.get("args") or []))
        words = (f"{helper} {args}\n\nYou will be asked for your password."
                 if helper else "Record this answer.")
        d = self._confirm(str(opt.get("label") or "Run"), words)
        d.connect("response", lambda dialog, rid, o=dict(opt):
                  self._on_confirm_response(dialog, rid, o))

    def _on_confirm_response(self, d, rid, opt):
        d.destroy()
        if rid != Gtk.ResponseType.OK:
            return
        self._run_now(opt)

    def _run_now(self, opt):
        def worker():
            from ui.decisionlist import _helper_exec
            try:
                rc, err = _helper_exec(opt.get("helper"),
                                       list(opt.get("args", [])))
            except Exception:
                rc, err = -1, ""
            GLib.idle_add(self._after_run,
                          str(opt.get("label") or ""), rc, err)
        threading.Thread(target=worker, daemon=True).start()

    def _after_run(self, label, rc, err=""):
        from wiz.common import helper_detail
        self._status.set_text(
            f"{label}: done." if rc == 0 else
            f"{label}: did not finish ({helper_detail(rc, err)}).")
        self.refresh()
        return False

    def _answer_appfw(self, _btn, opt):
        """Hand the verdict back through the ask bridge's own writer."""
        req = pathlib.Path(str(opt.get("req") or ""))
        if not req.exists():
            self._status.set_text(
                "The firewall's ask closed before an answer could ride "
                "back - nothing was changed.")
            return

        def worker():
            try:
                from ui.decisions import DecisionBroker
                broker = DecisionBroker()
                broker._answers_dir = req.parent.parent / "answers"
                args = list(opt.get("args") or [])
                action = args[0] if args and args[0] in ("allow", "deny") \
                    else "deny"
                duration = args[1] if len(args) > 1 and args[1] in \
                    ("once", "always") else "once"
                broker._write_answer(str(req), action, duration,
                                     opt.get("host_op"))
                rc = 0
            except (OSError, ValueError, TypeError) as exc:
                err, rc = str(exc), -1
            else:
                err = ""
            GLib.idle_add(self._after_run, str(opt.get("label") or ""),
                          rc, err)
        threading.Thread(target=worker, daemon=True).start()

    def _open_aide_review(self, _btn, ev):
        """The file-integrity read lane: what the record holds for the
        changed path, straight from the store the page already reads."""
        text = str(ev.get("text", ""))
        path = text.split(":", 1)[1].strip() if ":" in text else text
        lines = [str(e.get("text", "")) for e in self._events
                 if e.get("from_tool") == "aide" and path and
                 path in str(e.get("text", ""))]
        if not lines:
            lines = [text]
        parent = self._win if isinstance(self._win, Gtk.Window) else None
        dlg = Gtk.Dialog(title="File-integrity diff", transient_for=parent,
                         modal=False)
        dlg.set_destroy_with_parent(True)
        body = dlg.get_content_area()
        body.set_margin_top(12)
        body.set_margin_bottom(12)
        body.set_margin_start(18)
        body.set_margin_end(18)
        head = Gtk.Label(xalign=0, wrap=True)
        head.set_text("The integrity record for this path:\n"
                      + "\n".join(lines[-20:]))
        head.set_selectable(True)
        body.append(head)
        note = Gtk.Label(xalign=0, wrap=True)
        note.set_text("The stored baseline still blesses the previous "
                      "state; this read shows the record only.")
        note.add_css_class("gw-meta")
        note.set_margin_top(8)
        body.append(note)
        dlg.connect("response", lambda d, _r: d.destroy())
        present_now(dlg)

    def _copy_row(self, _btn, ev):
        from ui.plain import friendly_name as fn
        detail = (f"{ev.get('severity', '')} - {fn(ev.get('from_tool', ''))}"
                  f"\n{ev.get('text', '')}")
        try:
            from gi.repository import Gdk
            Gdk.Display.get_default().get_clipboard().set(detail)
            self._status.set_text("Copied. Paste it into a note.")
        except Exception:
            self._status.set_text("Could not reach the clipboard.")

    def _export_view(self, _btn):
        rows = [f"{r[3]} | {r[4]}" for r in self._store]
        try:
            from gi.repository import Gdk
            Gdk.Display.get_default().get_clipboard().set(
                "\n".join(rows))
            self._status.set_text(f"Exported {len(rows)} row(s) to the "
                                  "clipboard as text.")
        except Exception:
            self._status.set_text("Could not reach the clipboard.")

    def _clear_pressed(self, _btn):
        d = self._confirm(
            "Clear the log",
            "Just the log. Your answers, scan results and quarantine "
            "records stay.")
        d.connect("response", self._on_clear_response)

    def _on_clear_response(self, d, rid):
        d.destroy()
        if rid != Gtk.ResponseType.OK:
            return
        self._run_now({"label": "Clear the log", "helper": "clear-events",
                       "args": []})
