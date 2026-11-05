"""The clickable surface for the pill's "decisions waiting" count.

The pill counted pending decisions and said so, but nothing on the screen
listed them - the pill was a label with no click handler. This window is the
list the pill was describing: every decision the event store is holding that
has not been answered into decisions.jsonl, each with the same answer buttons
the popups show.

The scan runs against the whole event file the way the daemon's status
counter counts it, so the pill and this list can never disagree on "29
decisions waiting".
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

import greywatch_daemon as dm  # noqa: F401  (patch target for older tests)
from decisions_factory import pending_ids, record_answer
from gwpaths import data_dir as _resolve_data_dir
from ui import metrics


def _helper_exec(helper, args_list):
    # Late import: cli is a root module; tests reroute it away from pkexec
    # through GREYWATCH_HELPER_CMD.
    import cli as _cli
    return _cli.helper_exec(helper, args_list)


def _batch_exec(items):
    # Same late import as _helper_exec: several answers under ONE
    # polkit prompt.
    import cli as _cli
    return _cli.helper_batch(items)


def _age_text(ts):
    """'38 min ago' from an event timestamp, None when the ts is junk."""
    try:
        when = _dt.datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    mins = int((_dt.datetime.now(_dt.timezone.utc) - when).total_seconds() // 60)
    if mins < 1:
        return "asked just now"
    if mins < 60:
        return f"asked {mins} min ago"
    if mins < 60 * 24:
        return f"asked {mins // 60} h ago"
    return f"asked {mins // (60 * 24)} d ago"


def _iter_interaction_events(data_dir):
    """Events carrying a decision spec: whole file, daemon's counting rule.

    The pill's count indexes every line of events.jsonl, not a capped tail;
    the cli reader caps its scan, so a long backlog would show fewer rows
    than the pill claims. Same fallback as the broker's pump: when
    events.jsonl is not readable by the desktop user, status.json's recent
    snapshot stands in instead of going blind.
    """
    try:
        raw = (data_dir / "events.jsonl").read_bytes().split(b"\n")
    except OSError:
        raw = []
    if not raw:
        try:
            snap = json.loads((data_dir / "status.json").read_text())
            events = snap.get("recent") or []
        except (OSError, ValueError):
            events = []
        raw = [json.dumps(ev).encode("utf-8", "replace") for ev in events]
    for line in raw:
        if b'"interaction"' not in line:
            continue
        try:
            ev = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(ev, dict):
            yield ev


def pending_rows(data_dir=None):
    """[(spec, ts)] of unanswered decisions, oldest asked first, one per id.

    Repeated detections of the same subject re-emit the same id (the id is
    keyed on the subject, not the moment); the newest occurrence wins so the
    age shown reads "still seeing this", not "first saw this on Tuesday".
    """
    # Resolved at call time, not import time: a module-global bound the
    # live store, so import order decided which store a widget read, and
    # one page could show facts from two stores at once.
    data_dir = _resolve_data_dir() if data_dir is None else data_dir
    answered = pending_ids(data_dir / "decisions.jsonl")
    by_id, order = {}, []
    for ev in _iter_interaction_events(data_dir):
        spec = ev.get("interaction")
        if not (isinstance(spec, dict) and spec.get("id")):
            continue
        sid = spec["id"]
        if sid not in by_id:
            order.append(sid)
        by_id[sid] = (spec, ev.get("ts", ""))
    return [(by_id[i][0], by_id[i][1]) for i in order if i not in answered]


def _tone(o):
    tone = o.get("tone")
    if tone in ("primary", "danger", "quiet"):
        return tone
    oid = str(o.get("id", "")).lower()
    if any(w in oid for w in ("deny", "block", "restore", "unban", "lift")):
        return "danger"
    return "quiet"


def _clear(box):
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


class DecisionsWindow(Gtk.Dialog):
    """Headline count, one card per pending decision, working answer buttons."""

    def __init__(self, parent=None, on_change=None):
        super().__init__(title="greywatch: decisions waiting")
        self.set_default_size(*metrics.dialog_size())
        self.add_css_class("gw-popup")
        parent = parent if parent is not None else _active_window()
        if parent is not None:
            self.set_transient_for(parent)
            self.set_destroy_with_parent(True)
        self._on_change = on_change
        self._answering = set()
        self._data_dir: pathlib.Path | None = None

        head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        head.add_css_class("gw-popup-header")
        self._cat = Gtk.Label(label="greywatch · decisions", xalign=0)
        self._cat.add_css_class("gw-eyebrow")
        self._headline = Gtk.Label(xalign=0, wrap=True, selectable=True)
        self._headline.add_css_class("gw-headline")
        self._meta = Gtk.Label(xalign=0, wrap=True)
        self._meta.add_css_class("gw-meta")
        head.append(self._cat)
        head.append(self._headline)
        head.append(self._meta)
        # : one password covers a whole backlog. The bulk row fills
        # wherever the same answer appears on two or more cards; buttons
        # live in a plain box so their labels stay inspectable and the
        # cards never reflow under the cursor.
        self._bulk = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                             spacing=8)
        self._bulk.set_margin_top(2)
        self._bulk.set_margin_bottom(4)
        head.append(self._bulk)
        self._bulk_state = None
        self.get_content_area().append(head)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        self._list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self._list.set_margin_top(10)
        self._list.set_margin_bottom(12)
        self._list.set_margin_start(14)
        self._list.set_margin_end(14)
        scroll.set_child(self._list)
        self.get_content_area().append(scroll)

        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.connect("response", self._on_response)

        self.build_rows()

    # -- data ------------------------------------------------------------

    def build_rows(self):
        rows = self._rows()
        n = len(rows)
        self._headline.set_text(f"{n} decision{'s' if n != 1 else ''} waiting"
                                if n else "No decisions waiting")
        self._meta.set_text(
            "decisions the suite is holding for your answer · every answer "
            "is recorded in data/decisions.jsonl and never asked again"
            if n else "nothing waits on you right now. decisions show up "
            "when the suite quarantines something or asks about a "
            "connection, and stay open until answered")
        self._build_bulk(rows)

        _clear(self._list)
        if not rows:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            empty.add_css_class("gw-card")
            self._list.append(empty)
            return
        for spec, ts in rows:
            self._list.append(self._card(spec, ts))

    def _build_bulk(self, rows):
        # : where the same answer shows up on two or more cards,
        # offer to apply it to all of them under ONE polkit password.
        # Singles keep their own buttons; nothing here executes quietly -
        # the count in the label is the count the helper will touch.
        _clear(self._bulk)
        self._bulk.set_sensitive(False)
        self._bulk_state = Gtk.Label(xalign=0)
        self._bulk_state.add_css_class("gw-meta")
        self._bulk.append(self._bulk_state)
        counts, labels = {}, {}
        for spec, ts in rows:
            seen = set()               # dedupe within one card only
            for o in spec.get("options", []):
                if not o.get("helper"):
                    continue
                oid = str(o.get("id"))
                if oid in seen:
                    continue
                seen.add(oid)
                counts[oid] = counts.get(oid, 0) + 1
                labels[oid] = str(o.get("label", oid))
        for oid in [o for o, c in counts.items() if c >= 2][:3]:
            btn = Gtk.Button(label=(f"Apply '{labels[oid]}' to {counts[oid]} "
                                    "(one password)"))
            btn.add_css_class("gw-primary")
            btn.connect("clicked", self._on_bulk, oid)
            self._bulk.append(btn)
            self._bulk.set_sensitive(True)
        self._bulk_state.set_text(
            "" if counts else "no shared answer to apply in one go")

    def _bulk_items(self, oid):
        items, sids = [], []
        for spec, ts in self._rows():
            opt = next((o for o in spec.get("options", [])
                        if str(o.get("id")) == oid and o.get("helper")), None)
            if opt is None:
                continue
            items.append((opt.get("helper"), list(opt.get("args", []))))
            sids.append(str(spec["id"]))
        return items, sids

    def _on_bulk(self, _btn, oid):
        btn = _btn
        btn.set_sensitive(False)
        self._bulk_state.set_text(f"running {oid} across the matching "
                                  "decisions…")

        def work():
            items, sids = self._bulk_items(oid)
            rcs = _batch_exec(items) if items else []
            GLib.idle_add(self._after_bulk, oid, sids, rcs, btn)

        threading.Thread(target=work, daemon=True).start()
        return None

    def _after_bulk(self, oid, sids, rcs, btn):
        store = self._store_dir() / "decisions.jsonl"
        if not isinstance(rcs, list) or len(rcs) != len(sids):
            # The batch never reported per-item results; nothing is
            # recorded, so everything stays open exactly as it was.
            rcs = [-1] * len(sids)
        done = sum(1 for r in rcs if r == 0)
        for sid, rc in zip(sids, rcs):
            if rc == 0:
                record_answer(store, sid, oid)
        if self._on_change is not None and done:
            try:
                self._on_change()
            except Exception:
                pass
        if done < len(sids):
            self._bulk_state.set_text(
                f"{done} of {len(sids)} applied ({oid}); the rest stayed "
                "open - try them again from their own buttons.")
        else:
            self._bulk_state.set_text(f"applied {oid} to {done}.")
        self.build_rows()
        return GLib.SOURCE_REMOVE

    def _rows(self):
        try:
            self._data_dir = _resolve_data_dir()
            return pending_rows(self._data_dir)
        except Exception:
            return []

    # -- rendering -------------------------------------------------------

    def _card(self, spec, ts):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        card.add_css_class("gw-card")

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cat = Gtk.Label(
            label=(spec.get("eyebrow") or str(spec["id"]).split(":")[0]
                   ).upper(), xalign=0)
        cat.add_css_class("gw-eyebrow")
        cat.set_hexpand(True)
        top.append(cat)
        age = _age_text(ts)
        if age:
            lbl = Gtk.Label(label=age, xalign=1)
            lbl.add_css_class("gw-meta")
            top.append(lbl)
        card.append(top)

        subject = (spec.get("subject")
                   or spec.get("question", "").split("\n", 1)[0]) or "?"
        title = Gtk.Label(xalign=0, wrap=True, selectable=True)
        title.set_markup("<b>" + GLib.markup_escape_text(str(subject))
                         + "</b>")
        card.append(title)

        detail = spec.get("detail")
        if detail:
            d = Gtk.Label(label=str(detail), xalign=0, wrap=True,
                          selectable=True)
            d.add_css_class("gw-meta")
            card.append(d)

        opts = [o for o in spec.get("options", []) if o.get("helper")]
        buttons, state = [], Gtk.Label(xalign=0)
        state.add_css_class("gw-meta")
        state.set_visible(False)
        if opts:
            buttons_box = Gtk.FlowBox()
            buttons_box.set_selection_mode(Gtk.SelectionMode.NONE)
            buttons_box.set_hexpand(True)
            buttons_box.set_max_children_per_line(2)
            buttons_box.set_min_children_per_line(1)
            buttons_box.set_column_spacing(8)
            buttons_box.set_row_spacing(6)
            buttons_box.set_homogeneous(False)
            for opt in opts:
                b = Gtk.Button(label=str(opt.get("label", opt.get("id"))))
                b.add_css_class("gw-" + _tone(opt))
                buttons_box.append(b)
                buttons.append(b)
                b.connect("clicked", self._on_answer, spec, opt, buttons,
                          state)
            card.append(buttons_box)
        card.append(state)
        return card

    # -- answering -------------------------------------------------------

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
                rc = _helper_exec(opt.get("helper"), list(opt.get("args", [])))
            except Exception:
                rc = -1
            GLib.idle_add(self._after_answer, sid, opt, buttons, state, rc)

        threading.Thread(target=work, daemon=True).start()

    def _store_dir(self):
        """The store the rows were read from, so a widget pointed at one
        store never writes into another."""
        return self._data_dir if isinstance(self._data_dir, pathlib.Path) \
            else _resolve_data_dir()

    def _after_answer(self, sid, opt, buttons, state, rc):
        self._answering.discard(sid)
        if rc == 0:
            record_answer(self._store_dir() / "decisions.jsonl", sid,
                          opt["id"])
            self.build_rows()
            if self._on_change is not None:
                try:
                    self._on_change()
                except Exception:
                    pass
        else:
            for b in buttons:
                b.set_sensitive(True)
            state.set_text(f"{opt.get('helper')} did not finish "
                           f"(exit code {rc}). The decision stays open - "
                           "you can try again.")
        return GLib.SOURCE_REMOVE

    # -- lifecycle -------------------------------------------------------

    def _on_response(self, dlg, response_id, *_a):
        dlg.destroy()


def _active_window():
    app = Gtk.Application.get_default()
    return app.get_active_window() if app else None
