"""The Findings page (architecture v4): the workflow that handles
findings.

The triage lane carries the assistant's verdicts in order - known-bad
rows land in quarantine and say so, whitelisted rows are ignored and
say so, unknown rows wait as asks on this page with the CLI command
each stands on - and every action keeps its own reverse at hand. The
answers answer on the CLI (`greywatch answer`); this page is their
skin. Recent runs and the enabled timers complete the desk. There is no
scan control here: starting, pausing and cancelling a scan live on the
scan desk, not on this page.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from ui import actions, charts, cliapi, kit
from ui.widgets import card, eyebrow, headline, kv_row, meta, sub


def build(window) -> Gtk.Widget:
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page.set_hexpand(True)

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    head.append(headline("Findings"))
    head.set_halign(Gtk.Align.START)
    page.append(head)

    triage_slot = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    runs_slot = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    schedule_slot = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    page._gw_slots = {"triage": triage_slot, "runs": runs_slot,
                      "schedule": schedule_slot}
    page.append(triage_slot)
    page.append(runs_slot)
    page.append(schedule_slot)
    _paint(page)
    return page


def refresh(page: Gtk.Widget) -> None:
    """The shell calls this on a return visit. Repaint the triage, the
    recent runs and the schedule slots in place."""
    body = getattr(page, "_gw_body", None) or page
    if getattr(body, "_gw_slots", None) is None:
        return
    _paint(body)


def _clear(box: Gtk.Box) -> None:
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


def _paint(page: Gtk.Box) -> None:
    slots = page._gw_slots
    _clear(slots["triage"])
    slots["triage"].append(_triage_card(page))
    _clear(slots["runs"])
    slots["runs"].append(_run_history_card())
    _clear(slots["schedule"])
    slots["schedule"].append(_schedule_card())


# The schedule lists the machine's real enabled timers; only the two
# automatic scan timers are never named, because they stay disabled and
# no timed scan is armed (design 2026-11-19).
_NEVER_SHOW = ("greywatch-clam-scan.timer", "greywatch-boot-sweep.timer")


def _schedule_card() -> Gtk.Widget:
    """The timers' real schedules, read-only: the query runs on a
    worker; the card paints and fills when the answer lands."""
    rows_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    body = card(eyebrow("The schedule"), meta("reading the timers..."),
                rows_box, cls="gw-card gw-card-quiet")

    def work():
        import subprocess
        try:
            # Without --all: systemd lists the armed timers, so the set is
            # derived from the machine rather than a hardcoded allowlist.
            out = subprocess.run(
                ["systemctl", "list-timers", "--no-pager"],
                capture_output=True, text=True, timeout=15).stdout
        except Exception:   # noqa: BLE001
            out = ""
        GLib.idle_add(_schedule_fill, rows_box, out,
                      priority=GLib.PRIORITY_DEFAULT)

    threading.Thread(target=work, daemon=True,
                     name="gw-schedule-read").start()
    return body


def _schedule_fill(rows_box, out: str) -> bool:
    child = rows_box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        rows_box.remove(child)
        child = nxt
    rows = []
    for line in str(out or "").splitlines():
        parts = line.split()
        # The UNIT column sits before ACTIVATES, so the timer token can
        # be anywhere in the row; the last token is usually the
        # `.service` that ACTIVATES names.
        unit = next((t for t in parts if t.endswith(".timer")), None)
        if unit is None or unit in _NEVER_SHOW:
            continue
        index = parts.index(unit)
        # NEXT = weekday date time zone; LEFT = the time remaining. A
        # disabled timer has no LEFT value, so it is not a schedule. LAST
        # and PASSED may legitimately read n/a for an armed timer that has
        # not fired yet.
        if index < 5 or len(parts) < 6:
            continue
        next_in = parts[4]
        if next_in in ("n/a", "-"):
            continue
        when = " ".join(parts[:4])
        rows.append((unit, f"next in {next_in}. {when}"))
    if rows:
        for unit, when in rows:
            rows_box.append(kv_row(unit, when, "ok"))
    else:
        rows_box.append(meta("No timed scan is armed. Scans start from "
                             "the scan block on Security Overview."))
    return False


def _triage_card(page) -> Gtk.Widget:
    # The pending-asks read rides its worker (see _pending_asks_async):
    # the page paints at once from the on-disk stores it already owns.
    wl = cliapi.read_state("scan-whitelist.json") or {}
    wl_count = len(wl.get("entries") or [])
    blocks = [eyebrow("Triage"),
              sub("Known-bad files are auto-quarantined and reported; "
                  "whitelisted paths are ignored and reported; unknown "
                  "files wait here as pending decisions, each with the "
                  "CLI command behind it.")]
    blocks.append(kv_row("Whitelisted paths",
                         f"{wl_count} on file",
                         "ok" if wl_count else "mute"))
    recent = cliapi.read_jsonl("quarantine.jsonl", last=6)
    blocks.append(kv_row("Recent quarantine actions",
                         str(len(recent)), "warn" if recent else "ok"))
    asks_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    asks_box.append(meta("Reading the pending decisions..."))
    blocks.append(asks_box)
    _pending_asks_async(page, asks_box)
    blocks.append(meta("Nothing is waiting for your decision once this "
                       "reads clean. Unknown findings from a scan land "
                       "here."))
    return card(*blocks)


def _pending_asks_async(page, asks_box) -> None:
    """The decisions read rides a worker: a CLI subprocess on the main
    thread froze every page switch under a loaded box. The answer
    buttons themselves still route through the CLI's own record path."""
    def work():
        asks, err = _pending_asks_read()
        GLib.idle_add(_asks_fill, page, asks_box, asks, err,
                      priority=GLib.PRIORITY_DEFAULT)

    threading.Thread(target=work, daemon=True,
                     name="gw-pending-asks").start()


def _pending_asks_read() -> tuple[list, str]:
    doc = cliapi.jcall("decisions", "--pending")
    if isinstance(doc, dict):
        return doc.get("pending") or [], ""
    if doc is None:
        return [], "the decisions verb read nothing"
    return [], "the decisions verb was not JSON"


def _asks_fill(page, asks_box, asks, err) -> bool:
    child = asks_box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        asks_box.remove(child)
        child = nxt
    if err:
        asks_box.append(meta(f"Pending decisions could not be read right "
                             f"now ({err}). The CLI verb is "
                             "'greywatch decisions --pending'."))
    else:
        total = len(asks or [])
        for ask in (asks or [])[:8]:
            asks_box.append(_ask_box(page, ask))
        if total > 8:
            asks_box.append(meta(f"Showing 8 of {total} pending "
                                 "decisions. Answer these first."))
        if not asks:
            asks_box.append(meta("Nothing is waiting for your decision. "
                                 "Unknown findings from a scan land here."))
    return False


def _ask_box(page, ask: dict) -> Gtk.Widget:
    """One ask, answered in place: one button per option, wired to the
    CLI's own answer verb; the helper is the command the option stands
    on. Every action keeps its reverse at hand - the answer routes
    through the app's own gate like every other verb."""
    question = ask.get("question") or ask.get("id")
    inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    inner.append(sub(str(question)))
    opts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    for opt in (ask.get("options") or [])[:6]:
        button = Gtk.Button(label=str(opt.get("label") or opt.get("id")
                                      or "?"))
        button.connect(
            "clicked",
            lambda _b, a=ask, o=opt, btn=button:
            _answer(page, a, o, btn))
        opts.append(button)
    inner.append(opts)
    helper = "  ".join(
        str(o.get("helper") or "") for o in (ask.get("options") or [])[:3])
    inner.append(meta(helper or f"greywatch answer {ask.get('id')}"
                      "<option>"))
    ask["_gw_row"] = inner
    return inner


def _answer(page, ask: dict, opt: dict, button: Gtk.Button) -> None:
    actions.run_async(
        button,
        lambda: cliapi.call("answer", str(ask.get("id") or ""),
                            str(opt.get("id") or ""), timeout=60),
        lambda result: _answered(page, ask, result),
        pending="Answering...",
        done=button.get_label(),
    )


def _answered(page, ask: dict, result) -> None:
    rc, out, err = result if isinstance(result, tuple) else (1, "", "")
    if rc == 0:
        row = ask.get("_gw_row")
        if row is not None and row.get_parent() is not None:
            row.get_parent().remove(row)
        note = out or err or f"answer rc {rc}"
    else:
        # A failed answer keeps the ask on screen so nothing is lost.
        note = err or out or f"answer rc {rc}"
    window = getattr(page, "_gw_window", None)
    if window is not None:
        window.note(note.strip()[:120])


def _recent_runs() -> list:
    """The newest finished runs from the scan journal, newest first.

    The real journal is data/scans/<scan_id>.json - the live document
    written at the end of every run, with started_at and ended_at. The
    old reader asked run-scan-state.json for a "seconds" field neither
    writer produces, so "Recent runs" could never show a run.
    """
    try:
        folder = pathlib.Path(cliapi.state_path("scans"))
    except Exception:                    # noqa: BLE001
        return []
    out = []
    try:
        files = list(folder.glob("*.json"))
    except OSError:
        return []
    for path in files:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict):
            continue
        seconds = _run_seconds(doc)
        if seconds is None:
            continue
        out.append({"scan_id": str(doc.get("scan_id") or path.stem),
                    "key": str(doc.get("key") or ""),
                    "state": str(doc.get("state") or ""),
                    "ended_at": str(doc.get("ended_at") or ""),
                    "seconds": seconds})
    out.sort(key=lambda row: row["ended_at"], reverse=True)
    return out[:10]


def _run_seconds(doc: dict):
    started = str(doc.get("started_at") or "")
    ended = str(doc.get("ended_at") or "")
    try:
        first = dt.datetime.fromisoformat(started.replace("Z", "+00:00"))
        last = dt.datetime.fromisoformat(ended.replace("Z", "+00:00"))
        return max(0.0, (last - first).total_seconds())
    except (ValueError, TypeError):
        pass
    for row in (doc.get("scanners") or {}).values():
        try:
            value = float(row.get("duration_s") or 0.0)
        except (TypeError, ValueError, AttributeError):
            continue
        if value:
            return value
    return None


def _run_history_card() -> Gtk.Widget:
    """The last finished runs as bars, sized by the duration the journal
    actually recorded."""
    runs = _recent_runs()
    seconds = [row["seconds"] for row in runs if row["seconds"]]
    if seconds:
        newest = runs[0]
        from ui import labels
        return kit.section_card(
            "Recent runs",
            meta(f"Last run {newest['scan_id']} took "
                 f"{labels.span_words(newest['seconds'])}."),
            charts.bars(seconds, w=420, h=56))
    return kit.section_card(
        "Recent runs",
        meta("No finished runs on file yet. The bars appear after a "
             "run completes."))
