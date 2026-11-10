"""The Overview page (rebuild round 2, task 5 - variant 3).

One page that answers "am I OK right now" and hands off everything
else: the verdict strip over the published digest, one health card per
rail group (Care / Defense / System) whose whole face is a button into
the group's primary page through the guided handoff, the 7-day trend
bars over the digest's recent list, and a Needs-you section that lists
ONLY the published decisions that carry real answer buttons - and, per
the bug-9 law, hides its card and its title completely when nothing
waits.

The page reads the daemon's published status digest and nothing else;
the one published pending-list source (status.json's pending_list,
ui.actiongate._status_path_rows, with the decisions-store fallback)
drives both the waiting count and the answer rows, so a chip and a row
can never disagree.
"""
from __future__ import annotations

import datetime as dt
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ui.decisionlist import (_clear, _helper_exec, card_widget)
from ui.assistant import AssistantPanel
from ui.homepage import STALE_S
from ui.models import recent_alerts
from ui import metrics
from ui.themes import CURRENT, _hex_rgba
from wiz.common import helper_detail

# The rail groups, their primary page and their card copy. The handoff
# row identity is the stable string key - never a widget (widget reprs
# dedupe wrongly across rebuilds).
GROUPS = (
    ("care", "Care", "tools", None),
    ("defense", "Defense", "defense", None),
    ("system", "System", "logs", "Search"),
)

TREND_RANGES = ("7d", "24h")


def _when(ts):
    """The event's UTC datetime, or None for junk stamps."""
    try:
        t = dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t


def _stamp_hhmm(snap):
    """'12:04' from the digest's own ISO stamp, '-' when unreadable."""
    raw = str((snap or {}).get("updated") or "")
    return raw[11:16] if len(raw) >= 16 else "-"


def _age_s(snap):
    try:
        stamp = _when(snap.get("updated"))
        return None if stamp is None else max(
            0.0, (dt.datetime.now(dt.timezone.utc) - stamp).total_seconds())
    except (TypeError, AttributeError):
        return None


def _pending_of(snap):
    """The ONE published pending list, as a count (gw215: the shared
    rule in decisions_factory, the same one the pill and the count
    surfaces run, so a chip and a row can never disagree)."""
    from decisions_factory import snapshot_pending
    return snapshot_pending(snap)


def _chip(label, tone="quiet"):
    lbl = Gtk.Label(label=label)
    lbl.add_css_class("gw-pill")
    if tone != "quiet":
        lbl.add_css_class(tone)
    lbl.set_visible(False)
    lbl._gw_tone = tone
    lbl._gw_text = label
    return lbl


class _TrendCard(Gtk.Box):
    """The 7-day (or 24-hour) bar chart: thin bars over one axis, the
    peak bar in the warn tone, honest 'no data' when the digest's
    recent list is empty - never fake bars."""

    def __init__(self, page):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._page = page
        self._area = Gtk.DrawingArea()
        self._area.set_vexpand(True)
        self._area.set_size_request(-1, 72)
        self._area.set_tooltip_text("")
        self._empty = Gtk.Label(xalign=0, wrap=True,
                                label="no events published in this window "
                                      "yet - bars appear as the suite "
                                      "reports")
        self._empty.add_css_class("gw-meta")
        self._empty.set_visible(False)
        self.append(self._empty)
        self.append(self._area)
        self._area.set_draw_func(self._draw)

    def repaint(self):
        buckets = self._page.trend_buckets()
        self._empty.set_visible(not buckets)
        tip = self._tooltip(buckets)
        self.set_tooltip_text(tip)      # the card hover: the whole chart
        self._area.set_tooltip_text(tip)
        self._area.queue_draw()

    def _tooltip(self, buckets):
        if not buckets:
            return ""
        total = sum(c for _l, c in buckets)
        label, peak = max(buckets, key=lambda b: b[1])
        unit = "event" if total == 1 else "events"
        return f"{total} {unit} in this window - peak {peak} on {label}"

    def _draw(self, _area, cr, width, height):
        buckets = self._page.trend_buckets()
        if not buckets or width <= 8 or height <= 8:
            return
        n = len(buckets)
        peak = max(c for _l, c in buckets) or 1
        slot = width / n
        bar_w = max(3.0, min(11.0, slot * 0.36))
        axis_y = height - 1.0
        axis = _hex_rgba(CURRENT.get("mute"), (0.45, 0.45, 0.45, 1.0))
        cr.set_source_rgba(*axis)
        cr.set_line_width(1.0)
        cr.move_to(0.5, axis_y)
        cr.line_to(width - 0.5, axis_y)
        cr.stroke()
        rest = _hex_rgba(CURRENT.get("ink_soft"), (0.5, 0.5, 0.5, 1.0))
        accent = _hex_rgba(CURRENT.get("accent"), rest)
        warn = _hex_rgba(CURRENT.get("warn"), (0.7, 0.5, 0.2, 1.0))
        for i, (_label, count) in enumerate(buckets):
            colour = warn if count == peak and count > 0 else \
                (accent if i == n - 1 else rest)
            bar_h = max(2.0, (height - 6.0) * (count / peak)) if count else 2.0
            x = i * slot + (slot - bar_w) / 2
            cr.set_source_rgba(*colour)
            cr.rectangle(x, axis_y - bar_h, bar_w, bar_h)
            cr.fill()


class OverviewPage(Gtk.Box):
    """Variant 3: the verdict strip, the three group cards, the trend
    chart and the Needs-you rows - every element a button into the page
    that owns it, a pointer to the dock, never a re-display."""

    def __init__(self, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self.add_css_class("gw-console")
        self._win = win
        self._answering = set()
        self.set_vexpand(True)

        # 1. the verdict strip
        strip = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        strip.add_css_class("gw-card")
        face = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.status_glyph = Gtk.Label(label="●")
        self.status_glyph.add_css_class("gw-pill")
        self.status_glyph.set_valign(Gtk.Align.START)
        face.append(self.status_glyph)
        words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.verdict_head = Gtk.Label(xalign=0, wrap=True)
        self.verdict_head.add_css_class("gw-headline")
        words.append(self.verdict_head)
        chips = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        chips.set_halign(Gtk.Align.START)
        self._chips = [_chip("tools"), _chip("decisions"),
                       _chip("blocked"), _chip("findings")]
        for c in self._chips:
            chips.append(c)
        words.append(chips)
        face.append(words)
        face.set_hexpand(True)
        strip.append(face)
        self.age_label = Gtk.Label(xalign=0)
        self.age_label.add_css_class("gw-meta")
        strip.append(self.age_label)
        self.append(strip)

        # 2. one health card per rail group; the whole card is the button
        self.group_cards: dict = {}
        self._group_lines: dict = {}
        self._group_titles: dict = {}
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for key, title, page, dock_group in GROUPS:
            btn = Gtk.Button()
            btn.add_css_class("gw-card")
            btn.set_hexpand(True)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            head = Gtk.Label(label=title, xalign=0)
            head.add_css_class("gw-headline")
            body.append(head)
            self._group_titles[key] = head
            lines = []
            for _i in (0, 1):
                lbl = Gtk.Label(xalign=0, wrap=True)
                lbl.add_css_class("gw-meta")
                body.append(lbl)
                lines.append(lbl)
            self._group_lines[key] = lines
            btn.set_child(body)
            btn.connect("clicked", self._open_group, key, page, dock_group)
            self.group_cards[key] = btn
            row.append(btn)
        self.append(row)

        # 3. the trend chart
        trend_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        trend_card.add_css_class("gw-card")
        t_title = Gtk.Label(label="Last 7 days", xalign=0)
        t_title.add_css_class("gw-headline")
        trend_card.append(t_title)
        self._trend_head = t_title
        self._trend = _TrendCard(self)
        self._trend.set_vexpand(True)
        trend_card.append(self._trend)
        self._trend_empty = self._trend._empty
        self.append(trend_card)
        self._trend_range = "7d"
        self._trend_evs = None
        self._trend_card = trend_card

        # 4. Needs you: only the published decisions that carry buttons
        self.needs_you_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                     spacing=6)
        self.needs_you_title = Gtk.Label(label="Needs you", xalign=0)
        self.needs_you_title.add_css_class("gw-page-title")
        self.needs_you_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                      spacing=8)
        self.needs_you_box.append(self.needs_you_title)
        self.needs_you_box.append(self.needs_you_card)
        self.needs_you_box.set_visible(False)   # bug-9 law: quiet by default
        self.append(self.needs_you_box)

        # The assistant terminal rides this page (phase 4 kept it; the
        # window resolves the panel here and the dock's ask button
        # focuses it), so chat never needs a page of its own.
        self._assistant = self._make_assistant()
        self._assistant.set_vexpand(True)
        self.append(self._assistant)

    # -- wiring ------------------------------------------------------------
    def _make_assistant(self):
        """The assistant terminal: the same chat brain wired through the
        window's own callbacks, exactly as on the old anchor desk. The
        GPU toggle is part of the panel (task 13); the loader pair comes
        from the window when it can, guarded for the stub windows."""
        w = self._win
        pair = (getattr(w, "_assistant_gpu_enable", None),
                getattr(w, "_assistant_gpu_disable", None))
        gpu = pair if all(callable(x) for x in pair) else None
        panel = AssistantPanel(w.registry, w._get_status, w._get_recent,
                               lambda: w.chat_llm, w._assistant_intent,
                               get_gpu=gpu)
        panel.add_css_class("gw-chat")
        return panel

    def focus_assistant(self):
        """The dock's Ask-about button: put the cursor in the question
        box (the terminal itself never pops up - it lives on the page)."""
        self._assistant.entry.grab_focus()

    def _open_group(self, _btn, key, page_key, dock_group):
        """One click into the group's primary page. Click-to-jump always
        works: the guided route (pulse + pointer) when the auto_jump
        toggle allows it, the window's own show otherwise."""
        if not self._handoff(page_key, dock_group, key):
            self._show(page_key)

    def needs_you_row_open(self, decision_id):
        """A needs-you row also links its owning page: the decisions
        waiting desk. The row's identity is the decision id string."""
        if not self._handoff("defense", None, str(decision_id)):
            self._show("defense")

    def _handoff(self, page_key, dock_group, row_key):
        h = getattr(self._win, "handoff", None)
        if h is None:
            return False
        try:
            return bool(h(page_key, dock_group=dock_group, row=row_key))
        except (TypeError, RuntimeError):
            return False

    def _show(self, page_key):
        w = self._win
        if w is not None and hasattr(w, "_show"):
            w._show(page_key)

    # dock groups (build_overview hands these to the DockHost)
    def dock_groups(self):
        """("Title", [widgets]) groups for the fixed right dock."""
        refresh_btn = Gtk.Button(label="Refresh now")
        refresh_btn.set_tooltip_text("Repaint everything from the latest "
                                     "published digest now (the suite "
                                     "checks every 5 s on its own).")
        refresh_btn.connect("clicked", self._on_refresh_now)

        seven = Gtk.CheckButton(label="Last 7 days")
        seven.set_active(True)
        hours = Gtk.CheckButton(label="Last 24 hours")
        hours.set_group(seven)
        seven.connect("toggled", self._on_range_picked, "7d")
        hours.connect("toggled", self._on_range_picked, "24h")

        ask = Gtk.Button(label="Open the assistant")
        ask.set_tooltip_text("Jump to the assistant's question box below "
                             "and ask about this box.")
        ask.connect("clicked", self._on_ask)

        self._range_buttons = {"7d": seven, "24h": hours}
        return [("Snapshot", [refresh_btn]),
                ("Trend", [seven, hours]),
                ("Ask about", [ask])]

    def _on_refresh_now(self, _btn):
        w = self._win
        if w is not None and hasattr(w, "refresh"):
            w.refresh()

    def _on_range_picked(self, btn, key):
        if btn.get_active() and self._trend_range != key:
            self._set_range(key)

    def _set_range(self, key):
        if key not in TREND_RANGES:
            return
        self._trend_range = key
        self._trend_head.set_text(
            "Last 7 days" if key == "7d" else "Last 24 hours")
        self._trend.repaint()

    def _on_ask(self, _btn):
        self.focus_assistant()

    # -- data --------------------------------------------------------------
    def _data_dir(self):
        from ui.actiongate import _resolve_data_dir
        return _resolve_data_dir()

    # -- the answer pipeline (the gate's own bookkeeping: one recorded
    #    answer per id; kept whole from the previous anchor desk) --------
    def _on_answer(self, _btn, spec, opt, buttons, state):
        sid = str(spec["id"])
        if sid in self._answering:
            return
        self._answering.add(sid)
        for b in buttons:
            b.set_sensitive(False)
        state.set_visible(True)
        state.set_text(f"running {opt.get('helper')}…")

        def work():
            try:
                rc, err = _helper_exec(opt.get("helper"),
                                       list(opt.get("args", [])))
            except Exception:
                rc, err = -1, ""
            GLib.idle_add(self._after_answer, sid, opt, buttons, state,
                          rc, err, priority=GLib.PRIORITY_DEFAULT)

        threading.Thread(target=work, daemon=True).start()

    def _after_answer(self, sid, opt, buttons, state, rc, err=""):
        self._answering.discard(sid)
        if rc == 0:
            from ui.decisionlist import RECORD_NOTE, answer_record
            done = answer_record(self._data_dir() / "decisions.jsonl",
                                 sid, opt["id"])
            if not done:
                # The action ran; only the write-down failed. The row
                # stays pending and the sentence is the truth.
                state.set_text(f"{opt.get('helper')} did finish, but "
                               f"{RECORD_NOTE}.")
                return GLib.SOURCE_REMOVE
            if self._win is not None and hasattr(self._win, "_get_status"):
                self.refresh(self._win._get_status())
            if self._win is not None and getattr(self._win, "_on_change",
                                                 None) is not None:
                self._win._on_change()
        else:
            for b in buttons:
                b.set_sensitive(True)
            state.set_text(f"{opt.get('helper')} did not finish "
                           f"({helper_detail(rc, err)}). You can try "
                           "again.")
        return GLib.SOURCE_REMOVE

    # -- paint -------------------------------------------------------------
    def refresh(self, snap=None):
        snap = snap or {}
        self._trend_evs = list(snap.get("recent") or [])
        self._paint_verdict(snap)
        self._paint_groups(snap)
        self._set_range(self._trend_range)     # repaints the chart tooltip
        self._paint_needs_you()

    def _paint_verdict(self, snap):
        tools = snap.get("tools") or {}
        rows = list(tools.values()) if isinstance(tools, dict) else []
        online = sum(1 for t in rows if t.get("state") == "GREEN")
        bad = sum(1 for t in rows
                  if str(t.get("state") or "").upper()
                  in ("YELLOW", "RED", "ORANGE", "FAIL"))
        pending = _pending_of(snap)
        blocked = len((snap.get("defense") or {}).get("blocked") or [])
        highs = recent_alerts(self._trend_evs)
        need = bad + pending
        if need:
            self.verdict_head.set_text(
                "1 thing needs you" if need == 1
                else f"{need} things need you")
            self.status_glyph.remove_css_class("ok")
            self.status_glyph.add_css_class("warn")
        else:
            self.verdict_head.set_text("This box is OK right now")
            self.status_glyph.remove_css_class("warn")
            self.status_glyph.add_css_class("ok")
        # the chips: one pill per count, its subject named - the count
        # lives once, in its own pill (the tally-never-repeats law).
        for chip, text in zip(self._chips, (
                f"tools {online} / {len(rows)}",
                f"decisions {pending}",
                f"blocked {blocked}",
                f"findings {highs} HIGH")):
            chip._gw_text = text
            chip.set_text(text)
        # skip pills for honest zeros (a "decisions 0" chip is noise;
        # the tools pill always says how many protections are looked at)
        for chip in self._chips:
            chip.set_visible(True)
        # findings HIGH only names itself when there is one: the pill on
        # the end is the suite's alert, not a fourth daily number.
        self._chips[3].set_visible(bool(highs))
        self.status_glyph.set_visible(True)

        age = _age_s(snap)
        stamp = _stamp_hhmm(snap)
        if age is None:
            self.age_label.set_text(f"snapshot {stamp}")
        else:
            self.age_label.set_text(
                f"snapshot {stamp} · {int(age)} s ago")
        if age is not None and age > STALE_S:
            self.age_label.set_text(self.age_label.get_text()
                                    + " - waiting for the daemon")

    def _paint_groups(self, snap):
        tools = snap.get("tools") or {}
        rows = list(tools.values()) if isinstance(tools, dict) else []
        online = sum(1 for t in rows if t.get("state") == "GREEN")
        bad = sum(1 for t in rows
                  if str(t.get("state") or "").upper()
                  in ("YELLOW", "RED", "ORANGE", "FAIL"))
        care = self._group_lines["care"]
        care[0].set_text(f"{online} / {len(rows)} tools online")
        care[1].set_text(f"{bad} need attention" if bad
                         else "every checked tool is green")

        pending = _pending_of(snap)
        blocked = len((snap.get("defense") or {}).get("blocked") or [])
        defense = self._group_lines["defense"]
        defense[0].set_text("no decisions waiting" if not pending
                            else ("1 decision waiting" if pending == 1
                                  else f"{pending} decisions waiting"))
        defense[1].set_text("nothing is blocked" if not blocked
                            else ("1 address blocked" if blocked == 1
                                  else f"{blocked} addresses blocked"))

        sysl = self._group_lines["system"]
        sysl[0].set_text(f"daemon checked in {_stamp_hhmm(snap)}")
        flowing = bool(self._trend_evs)
        sysl[1].set_text("activity log is flowing" if flowing
                         else "activity log is quiet")

    # -- the trend buckets --------------------------------------------------
    def trend_buckets(self):
        """[(label, count)] for the picked range from the digest's own
        recent list (the only event source the page reads). [] = the
        source has nothing to say - the card says so, never fake bars."""
        evs = self._trend_evs or []
        stamps = []
        for ev in evs:
            t = _when(ev.get("ts")) if isinstance(ev, dict) else None
            if t is not None:
                stamps.append(t)
        if not stamps:
            return []
        now = dt.datetime.now(dt.timezone.utc)
        if self._trend_range == "24h":
            hour0 = now.replace(minute=0, second=0, microsecond=0)
            hours = [hour0 - dt.timedelta(hours=i)
                     for i in reversed(range(24))]
            counts = [0] * 24
            for t in stamps:
                idx = int((t - hours[0]).total_seconds() // 3600)
                if 0 <= idx < 24:
                    counts[idx] += 1
            return [(f"{h:%H}:00", c) for h, c in zip(hours, counts)]
        today = now.date()
        days = [today - dt.timedelta(days=i) for i in reversed(range(7))]
        counts = [0] * 7
        for t in stamps:
            d = t.date()
            idx = (d - days[0]).days
            if 0 <= idx < 7:
                counts[idx] += 1
        return [(f"{d:%b} {d.day}", c) for d, c in zip(days, counts)]

    # -- needs you ----------------------------------------------------------
    def _paint_needs_you(self):
        _clear(self.needs_you_card)
        from ui.actiongate import _status_path_rows
        rows = _status_path_rows(self._data_dir())
        if rows is None:
            try:
                from decisions_factory import pending_spec_pairs
                rows = pending_spec_pairs(self._data_dir())
            except Exception:
                rows = []
        rows = [(spec, ts) for spec, ts in (rows or [])
                if any(o.get("helper") for o in spec.get("options", []))]
        if not rows:
            # bug-9 law: an empty section hides its card AND its title;
            # an empty-looking card never ships.
            self.needs_you_box.set_visible(False)
            return
        self.needs_you_box.set_visible(True)
        for spec, ts in rows[:20]:
            row = self._needs_you_row(spec, ts)
            self.needs_you_card.append(row)

    def _needs_you_row(self, spec, ts):
        """The published decision's own card (the same buttons the gate
        rows carry), with a click-elsewhere handoff to its owning page
        keyed on the decision id string."""
        row = card_widget(spec, ts, self._on_answer)
        sid = str(spec["id"])
        gesture = Gtk.GestureClick()
        gesture.connect("pressed", self._row_pressed, sid)
        row.add_controller(gesture)
        return row

    def _row_pressed(self, _gesture, _n, _x, _y, sid):
        self.needs_you_row_open(sid)

    def action_buttons(self):
        """The option buttons the needs-you rows carry (what the bug-9
        pin counts: a visible section with real, working buttons)."""
        out = []

        def walk(w):
            c = w.get_first_child()
            while c is not None:
                if isinstance(c, Gtk.Button):
                    out.append(c)
                walk(c)
                c = c.get_next_sibling()
        walk(self.needs_you_card)
        return out


def build_overview(win):
    """The overview builder: (content, dock_groups) - the page plus the
    Snapshot / Trend / Ask-about groups for the fixed right dock."""
    scroller = Gtk.ScrolledWindow()
    scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroller.set_vexpand(True)
    page = OverviewPage(win=win)
    scroller.set_child(page)
    return scroller, page.dock_groups()
