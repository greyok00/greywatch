"""The Timeline page (architecture v4, its own page): the DFIR view.

Every quarantine, ban, block and program rule in order, each row
opening its evidence - the log line, the file path, the rule, the
restore command - and a one-file evidence export.

The rows merge four honest sources: the quarantine ledger (with the
copy's path and hash), the fail2ban lane's ban events, the wall's live
blocks from the daemon's snapshot, and the firewall's rule rows from
the audit trail. Everything else stays in the audit trail the CLI
serves; this page says so.
"""

from __future__ import annotations

import datetime
import pathlib

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import charts, cliapi, kit, labels, pageutil
from ui.widgets import (card, count_word, eyebrow, headline, kv_row,
                        meta, state_pill)

KINDS = ("quarantine", "ban", "block", "rule")
FILTERS = ("all", *KINDS, "routine")
_LAST = 400
_MEANINGFUL = ("deny", "block", "drop", "ask", "rule", "policy",
               "configuration", "config")


def build(window) -> Gtk.Widget:
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page.set_hexpand(True)
    page._gw_filter = "all"
    scroll.set_child(page)
    scroll._gw_body = page
    page._gw_scroll = scroll
    _refresh_into(page)
    page._gw_sig = _sig()
    return scroll


def _sig() -> str:
    return pageutil.signature("events.jsonl", "quarantine.jsonl",
                              "status.json")


def refresh(page: Gtk.Widget) -> None:
    """Repaint only when a source ledger changed; keep the scroll."""
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
    want = getattr(page, "_gw_filter", "all")
    if want == "routine":
        rows = sorted(_routine_rows(), key=_sort_key, reverse=True)
    else:
        rows = _timeline_rows()
        if want != "all":
            rows = [r for r in rows if r["kind"] == want]
    page._gw_rows = rows
    shown = rows[:_LAST]
    page._gw_shown = shown

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    head.append(headline("Timeline"))
    head.append(state_pill(*_pill(rows, shown)))
    head.set_halign(Gtk.Align.START)
    page.append(head)
    page.append(meta(
        f"Showing {len(shown)} of {len(rows)} action rows."))
    page.append(meta(
        f"{count_word(len(shown), 'action row')} newest first, merged "
        "from the quarantine ledger, fail2ban bans, firewall blocks and "
        "firewall rules. The full audit trail is 'greywatch events'."))

    page.append(_filter_row(page))
    page.append(_density_card(rows))
    page.append(_rows_card(page, shown))
    page.append(_export_row(page, shown))


_PLURALS = {"quarantine": ("quarantine", "quarantines"),
            "ban": ("ban", "bans"), "block": ("block", "blocks"),
            "rule": ("rule", "rules")}


def _pill(rows: list, shown: list) -> tuple[str, str]:
    counts = {}
    for r in shown:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
    if not shown:
        return "Nothing logged yet", "ok"
    summary = ", ".join(
        f"{v} {_PLURALS[k][1 if v != 1 else 0]}"
        for k, v in sorted(counts.items()) if k in _PLURALS)
    level = "warn" if counts.get("quarantine") else "ok"
    _ = rows
    return f"{summary}", level


def _filter_row(page) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    box.append(eyebrow("Filter"))
    combo = Gtk.ComboBoxText()
    for k in FILTERS:
        combo.append_text(k)
    kind = getattr(page, "_gw_filter", "all")
    combo.set_active(FILTERS.index(kind))
    # The page travels as signal user_data. Carrying it as an attribute on
    # the widget failed: GTK can hand the handler a different Python
    # wrapper for the same object, and the attribute was not on it.
    combo.connect("changed", _on_pick, page)
    box.append(combo)
    return box


def _on_pick(combo, page) -> None:
    _pick(page, combo.get_active_text() or "all")


def _pick(page, kind: str) -> None:
    page._gw_filter = kind
    _refresh_into(page)


def _rows_card(page, shown: list) -> Gtk.Widget:
    if not shown:
        return card(eyebrow("Rows"),
                    meta("No rows for this filter yet."))
    rows = [[_when(r.get("when")), r["kind"],
             labels.display_name(r.get("tool")),
             r.get("subject") or ""] for r in shown]
    scroller, store = _tree((("When", 150), ("Kind", 100), ("Tool", 110),
                              ("What happened", 430)), rows)
    view = scroller.get_child()
    view.connect("cursor-changed", _on_cursor, page)
    page._gw_evidence_slot = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL, spacing=8)
    return card(eyebrow("Rows, newest first"),
                meta("Select a row to view its evidence: the log line, "
                     "the file path, the rule, the restore command."),
                scroller, page._gw_evidence_slot)


def _on_cursor(view, page) -> None:
    _show_evidence(page, view)


def _show_evidence(page, tree) -> None:
    sel = tree.get_selection()
    if sel is None:
        return                       # a signal can fire before a model
    _model, it = sel.get_selected()
    if it is None:
        return
    idx = _model.get_path(it).get_indices()[0]
    shown = page._gw_shown
    if idx >= len(shown):
        return
    row = shown[idx]
    slot = page._gw_evidence_slot
    while slot.get_first_child() is not None:
        slot.remove(slot.get_first_child())
    facts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    for key, value in row.items():
        if key in ("kind", "when", "level") or not value:
            continue
        facts.append(kv_row(str(key), str(value)))
    slot.append(card(facts, cls="gw-card gw-card-quiet"))


def _export_row(page, shown: list) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    b = Gtk.Button(label="Export evidence")
    b.add_css_class("gw-quiet")
    b.connect("clicked", lambda _b: _export(page, shown))
    box.append(b)
    box.append(meta("Exports every visible row with its evidence to one "
                    "text file."))
    return box


def _export(page, shown: list) -> None:
    win = page._gw_window
    out_dir = pathlib.Path.home() / "security-reports"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        target = out_dir / f"greywatch-timeline-{stamp}.txt"
        lines = [f"greywatch evidence export - "
                 f"{count_word(len(shown), 'row')}",
                 datetime.datetime.now().isoformat(timespec="seconds"),
                 "=" * 60]
        for r in shown:
            lines.append(f"\n[{r['kind']}] {r.get('when')}")
            for key, value in r.items():
                if value and key not in ("kind", "level"):
                    lines.append(f"  {key}: {value}")
        target.write_text("\n".join(lines) + "\n")
        win.note(f"Evidence exported to {target}")
    except OSError as e:
        win.note(f"Evidence export failed: {e}")


# -- the four sources, merged ------------------------------------------

def _timeline_rows() -> list:
    rows: list = []
    rows += _quarantine_rows()
    rows += _ban_rows()
    rows += _block_rows()
    rows += _rule_rows()
    rows.sort(key=_sort_key, reverse=True)
    return rows


def _sort_key(row: dict) -> tuple:
    key = str(row.get("when") or "")
    try:
        when = datetime.datetime.fromisoformat(key.replace(" ", "T"))
    except ValueError:
        return ("", str(row.get("kind") or ""))
    try:
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        return (when.isoformat(), str(row.get("kind") or ""))
    except (TypeError, ValueError):
        return ("", str(row.get("kind") or ""))


def _quarantine_rows() -> list:
    out = []
    for r in cliapi.read_jsonl("quarantine.jsonl", last=400):
        if not isinstance(r, dict) or "orig" not in r:
            continue
        out.append({
            "kind": "quarantine", "when": r.get("ts") or "",
            "tool": str(r.get("tag") or "").split(":")[0],
            "subject": f"quarantined {r.get('orig')}",
            "verdict": r.get("tag") or "",
            "original file": r.get("orig") or "",
            "quarantined copy": r.get("file") or "",
            "sha256 (first 16)": r.get("sha256_16") or "",
            "restore command":
                "sudo /usr/lib/greywatch/apply/restore-quarantine.sh "
                + str(r.get("orig") or "")})
    return out


def _ban_rows() -> list:
    out = []
    for ev in _events():
        if str(ev.get("from_tool")) != "fail2ban":
            continue
        text = str(ev.get("text") or "")
        if "ban" not in text.lower():
            continue
        out.append({"kind": "ban", "when": ev.get("ts") or "",
                    "tool": "fail2ban", "subject": text[:200],
                    "log line": _logline(ev)})
    return out


def _block_rows() -> list:
    out = []
    snap = cliapi.read_state("status.json") or {}
    for b in (snap.get("defense") or {}).get("blocked") or []:
        out.append({"kind": "block", "when": b.get("ts") or "",
                    "tool": "the wall",
                    "subject": f"blocked {b.get('ip') or ''}",
                    "rule": b.get("reason") or "nft deny",
                    "address": str(b.get("ip") or "")})
    return out


def _rule_events() -> list:
    """Firewall, policy and ufw events, deduplicated by tool, full
    text and minute, each paired with its untruncated text."""
    out = []
    seen = set()
    for ev in _events():
        if str(ev.get("from_tool")) not in ("appfw", "policy", "ufw"):
            continue
        text = str(ev.get("text") or "")
        minute = str(ev.get("ts") or "")[:16]
        key = (str(ev.get("from_tool") or ""), text, minute)
        if key in seen:
            continue
        seen.add(key)
        out.append((ev, text))
    return out


def _rule_row(ev: dict) -> dict:
    text = str(ev.get("text") or "")
    return {"kind": "rule", "when": ev.get("ts") or "",
            "tool": ev.get("from_tool") or "",
            "subject": text[:200], "log line": _logline(ev)}


def _rule_rows(include_routine: bool = False) -> list:
    out = []
    for ev, text in _rule_events():
        if not include_routine and not any(w in text.lower()
                                           for w in _MEANINGFUL):
            continue
        out.append(_rule_row(ev))
    return out


def _routine_rows() -> list:
    out = []
    for ev, text in _rule_events():
        if any(w in text.lower() for w in _MEANINGFUL):
            continue
        out.append(_rule_row(ev))
    return out


def _events() -> list:
    return cliapi.read_jsonl("events.jsonl", last=600)


def _logline(ev: dict) -> str:
    return " ".join(str(ev.get(k) or "") for k in
                    ("ts", "from_tool", "severity", "text")).strip()


def _when(stamp: str) -> str:
    s = str(stamp or "")
    return s.replace("T", " ")[:19] or "no stamp"


def _tree(cols, rows):
    from ui.network import _tree
    return _tree(columns=cols, rows=rows)


def _density_card(rows: list) -> Gtk.Widget:
    """The action density grid: hour of the day by day of the week,
    fed by the merged rows' own stamps. A quiet day reads quietly."""
    widget, grid = charts.heatmap([r.get("when") for r in rows[:2000]],
                                  w=420, h=96)
    total = sum(sum(row) for row in grid)
    if not total:
        return kit.section_card(
            "Action density, hour by day",
            meta("No action stamps on file for the grid."))
    return kit.section_card("Action density, hour by day", widget)
