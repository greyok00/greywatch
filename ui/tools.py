"""The Tools page (architecture v4, its own page).

Every lane's live state ticking with the daemon's beat: one row per
tool from the daemon's one snapshot, mark, state word, the unit it
rides, and the newest event written. The page reads
`status.json` - the state file that is an app-owned surface - and
nothing else; lifecycle actions live on the per-tool pages in the
Advanced dropdown, never duplicated here.
"""

from __future__ import annotations

import datetime

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import charts, cliapi, kit, labels, pageutil
from ui.widgets import (card, count_word, eyebrow, headline, meta,
                        state_pill)

_LEVEL = {"GREEN": "ok", "YELLOW": "warn", "RED": "fail"}
_STALE_S = 90          # the snapshot's own freshness law


def build(window) -> Gtk.Widget:
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroll.set_vexpand(True)
    scroll.set_hexpand(True)
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page.set_hexpand(True)
    page.set_vexpand(True)
    scroll.set_child(page)
    scroll._gw_body = page
    page._gw_scroll = scroll
    _refresh_into(page)
    page._gw_sig = _sig()
    return scroll


def _sig() -> str:
    return pageutil.signature("status.json", "events.jsonl")


def refresh(page: Gtk.Widget) -> None:
    """A return visit repaints only when the snapshot or the ledger
    changed, and it keeps the reader's place."""
    body = getattr(page, "_gw_body", None) or page
    sig = _sig()
    if sig == getattr(body, "_gw_sig", None):
        return
    scroll = getattr(body, "_gw_scroll", None) or page
    if hasattr(scroll, "get_vadjustment"):
        pageutil.restore_scroll(scroll)
    _refresh_into(body)
    body._gw_sig = sig


def _clear(box: Gtk.Box) -> None:
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


def _refresh_into(page: Gtk.Box) -> None:
    _clear(page)
    snap = cliapi.read_state("status.json") or {}
    tools = snap.get("tools") or {}
    level = "ok"
    if not tools:
        level = "empty"
    elif any(t.get("state") == "RED" for t in tools.values()):
        level = "fail"
    elif any(t.get("state") == "YELLOW" for t in tools.values()):
        level = "warn"

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    head.append(headline("Tools"))
    # GW-10: the attention pill navigates to the first yellow lane's desk
    first_yellow = next((name for name, row in tools.items()
                         if row.get("state") == "YELLOW"), None)
    page._gw_yellow_first = first_yellow
    head.append(state_pill(*_pill(level),
                           target=(_yellow_target(page, first_yellow)
                                   if first_yellow else None)))
    head.set_halign(Gtk.Align.START)
    page.append(head)
    page.append(meta(_snapshot_note(snap)))

    if not tools:
        page.append(card(
            eyebrow("Lanes"),
            meta("No snapshot yet. Start the greywatch unit or wait "
                 "one cycle.")))
        return

    rows = []
    names = []
    first_yellow = None
    for name, row in tools.items():
        names.append(name)
        rows.append([
            labels.clean_tool_label(str(row.get("label") or name)),
            labels.tool_state(row.get("state"))[0],
            _unit_word(row),
            _stamp(str(row.get("last_event") or "")),
            str((row.get("note") or ""))])
        if row.get("state") == "YELLOW" and first_yellow is None:
            first_yellow = name
    page._gw_yellow_first = first_yellow
    tree = card_tree(rows, names)
    view = tree.get_child()
    view.connect("row-activated", _open_row,
                 getattr(page, "_gw_window", None), names)
    page.append(card(
        eyebrow(f"Lanes - {count_word(len(tools), 'lane')} monitored"),
        meta("Status words and marks come from the daemon. Start and "
             "stop live on each tool's screen in the Advanced menu."),
        tree))

    # the cycle pulse: every lane's events by hour, the last 24 hours
    stamps = [str(ev.get("ts") or "")
              for ev in (cliapi.read_jsonl("events.jsonl", last=6000))]
    buckets = _hour_buckets(stamps, 24)
    if any(buckets):
        page.append(kit.section_card(
            "Events written, last 24 hours",
            charts.sparkline(buckets, w=520, h=56)))
    else:
        page.append(kit.section_card(
            "Events written, last 24 hours",
            meta("No events in the last 24 hours.")))


def _yellow_target(page, name: str):
    """Open the first yellow lane's desk — the pill's promise: click it,
    land where the problem is."""
    window = getattr(page, "_gw_window", None)

    def _go():
        try:
            from ui import advanced
            label, ids, digest = advanced.desk_for(name)
        except KeyError:
            return
        opener = getattr(window, "open_tool_page", None) if window else None
        if opener is not None:
            opener(label, ids, digest)
    return _go


def _open_row(view, path, column, window, names):
    from ui import advanced
    idx = path.get_indices()[0]
    try:
        label, ids, digest = advanced.desk_for(names[idx])
    except (IndexError, KeyError):
        note = getattr(window, "note", None)
        if note is not None:
            note("That lane has no desk yet.")
        return
    opener = getattr(window, "open_tool_page", None)
    if opener is not None:
        opener(label, ids, digest)


def card_tree(rows, names=None):
    """The lane table, one row per tool, in the snapshot's own order,
    each row with its tool's symbolic icon. Rows activate on a single
    click (GW-12: double-click-only navigation had no affordance)."""
    scroll, _store = kit.table(columns=(
        ("Tool", 150), ("State", 90), ("Unit", 140),
        ("Last event", 165), ("Note", 160)), rows=rows,
        height=None, tool_icons=names, activate_single=True)
    return scroll


def _hour_buckets(stamps, buckets: int) -> list:
    """The last `buckets` hours as counts, oldest left."""
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    out = [0] * buckets
    for stamp in stamps:
        try:
            when = dt.datetime.fromisoformat(str(stamp).replace(" ", "T"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=dt.timezone.utc)
        except (ValueError, AttributeError):
            continue
        age_h = (now - when).total_seconds() / 3600.0
        try:
            out[max(0, buckets - 1 - int(age_h))] += 1
        except IndexError:
            continue
    return out


def _pill(level: str) -> tuple[str, str]:
    word = {"ok": "All green", "warn": "Attention needed",
            "fail": "A lane is down", "empty": "Waiting"}[level]
    return word, (level if level in ("ok", "warn", "fail") else "warn")


def _snapshot_note(snap) -> str:
    updated = str(snap.get("updated") or "")
    n_tools = len(snap.get("tools") or {})
    if not updated or not n_tools:
        return ("The daemon has not written a snapshot yet. Start the "
                "greywatch unit or wait one cycle.")
    age = _age_s(updated)
    if age is None:
        return f"snapshot from {updated}"
    if age > _STALE_S:
        return (f"Snapshot is {count_word(age // 60, 'minute')} old. The "
                "service may be paused; rows stand until the next cycle.")
    return f"Snapshot is {count_word(age, 'second')} old"


def _age_s(stamp: str):
    try:
        when = datetime.datetime.fromisoformat(stamp)
    except ValueError:
        return None
    try:
        return int((datetime.datetime.now(datetime.timezone.utc)
                    - when).total_seconds())
    except (TypeError, ValueError):
        return None


def _unit_word(row) -> str:
    unit = row.get("unit_state")
    if not row.get("unit_state") or unit == "none":
        return "In-process lane (no unit)"
    return str(unit)


def _stamp(stamp: str) -> str:
    if not stamp or stamp == "None":
        # GW-11: the ledger deliberately skips per-check-in events, so a
        # healthy lane can have no notable event; the old copy made it
        # look dead.
        return "No notable event yet"
    return stamp.replace("T", " ")[:19] + " UTC" if "T" in stamp else stamp
