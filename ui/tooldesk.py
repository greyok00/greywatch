"""The per-tool desk: the one page shape every tool opens behind the
Advanced dropdown (architecture v4, one page per tool).

The desk is a skin over the CLI's per-tool verbs: state from
`greywatch tool <id> --json`, its own event feed from the same verb,
its own digest from the tool digests the install carries, and the
commands row naming the verbs this tool answers. Nothing is invented:
the state words, the last events and the digest are the tool's own.
"""

from __future__ import annotations

import pathlib
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from ui import actions, charts, cliapi, kit, labels, scanrequests, toolactions
from ui.jobpanel import JobPanel
from ui.widgets import (card, eyebrow, headline, kv_row, meta, state_pill,
                        sub)

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def build(window, title: str, tool_ids: tuple,
          digest_name: str = "") -> Gtk.Widget:
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page._gw_scroll = scroll
    page._gw_tool_ids = tuple(tool_ids)

    state_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    page._gw_state_box = state_box
    page._gw_action_status = meta("")
    for tid in tool_ids:
        state_box.append(kv_row(tid, "Reading the tool...", "mute"))

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    for tid in tool_ids[:1]:
        head.append(kit.icon(tid, size=24))
    head.append(headline(title))
    page._gw_pill = state_pill("Reading", "mute")
    head.append(page._gw_pill)
    head.set_halign(Gtk.Align.START)
    page.append(head)
    page._gw_note = meta("Reading the tool...")
    page.append(page._gw_note)

    specs = toolactions.actions_for(tool_ids)
    page._gw_check_spec = next(
        (a for a in specs if a["kind"] == "check"), None)
    page._gw_job_panel = None
    page._gw_last_live = {}
    bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    bar.add_css_class("gw-action-bar")
    for spec in specs:
        bar.append(_action_button(page, spec))
    page.append(bar)
    page.append(page._gw_action_status)
    if page._gw_check_spec is not None:
        panel = JobPanel(title,
                         lambda: _control(page, "pause"),
                         lambda: _control(page, "resume"),
                         lambda: _control(page, "cancel"))
        page._gw_job_panel = panel
        page.append(panel)

    monitor = getattr(window, "scan_monitor", None)
    if monitor is not None and page._gw_job_panel is not None:
        callback = lambda doc: _apply_job(page, doc)
        page._gw_live_cb = callback
        monitor.subscribe(callback)
        scroll.connect("destroy", lambda _w: monitor.unsubscribe(callback))

    page.append(card(eyebrow("State"), state_box))
    page._gw_events_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                  spacing=6)
    page._gw_events_box.append(_events_card([]))
    page.append(page._gw_events_box)
    page.append(_digest_card(digest_name or (tool_ids[0] if tool_ids
                                              else "")))
    page.append(_commands_card(tool_ids))

    scroll.set_child(page)
    scroll._gw_body = page
    scroll._gw_scroll = scroll
    scroll._gw_tool_ids = page._gw_tool_ids
    scroll._gw_check_spec = page._gw_check_spec
    scroll._gw_job_panel = page._gw_job_panel
    scroll._gw_state_box = page._gw_state_box
    scroll._gw_action_status = page._gw_action_status
    scroll._gw_note = page._gw_note
    scroll._gw_events_box = page._gw_events_box
    scroll._gw_pill = page._gw_pill
    refresh(scroll)
    return scroll


def _data_dir():
    try:
        import gwpaths
        return gwpaths.data_dir()
    except Exception:                      # noqa: BLE001
        return pathlib.Path("/var/lib/greywatch")


def _control(page, action):
    # A control belongs to the document this desk is showing. Without one
    # there is no scan id to name, and a bare control would act on
    # whatever session the service happens to hold (review C2).
    doc = getattr(page, "_gw_last_live", None) or {}
    scan_id = str(doc.get("scan_id") or "")
    if not scan_id:
        page._gw_job_panel.status.set_text("No job on file.")
        return
    ok, note = scanrequests.control_scan(_data_dir(), action, scan_id)
    if not ok:
        page._gw_job_panel.status.set_text(note)


def _action_button(page, spec):
    if spec["kind"] == "check":
        def run():
            ok, note = scanrequests.request_scan(_data_dir(),
                                                 spec["scan_key"])
            page._gw_job_panel.status.set_text(
                note if not ok else "Starting the check.")
            if ok:
                refresh(page._gw_scroll)
        return actions.action_button(spec["label"], run,
                                     cls="gw-secondary")
    body = f"{spec['label']} {spec['unit']}?"
    confirm = body if spec["kind"] in ("stop", "restart") else None
    holder = {}

    def work():
        from cli import helper_exec, helper_last_err
        rc = helper_exec("tool-control", toolactions.helper_args(spec))
        return rc, helper_last_err()

    def on_done(result):
        if isinstance(result, Exception):
            page._gw_action_status.set_text(str(result))
            return
        rc, err = result
        page._gw_action_status.set_text(
            "done" if rc == 0 else (err or f"rc {rc}"))
        refresh(page._gw_scroll)

    def run():
        actions.run_async(holder["button"], work, on_done,
                          pending="Working...")

    button = actions.action_button(spec["label"], run,
                                   cls="gw-secondary", confirm=confirm)
    holder["button"] = button
    return button


def _apply_job(page, doc):
    """Paint this desk's own job only. Another key's live document (or an
    empty one) leaves the panel idle with its controls inert: a desk must
    never mirror, pause or cancel a job it does not own (review C2/C3)."""
    spec = page._gw_check_spec
    if spec is None:
        return
    doc = doc or {}
    key = str(doc.get("key") or "")
    if not doc or key != spec["scan_key"]:
        page._gw_last_live = {}
        page._gw_job_panel.set_idle("No job on file.")
        return
    page._gw_last_live = doc
    row = (doc.get("scanners") or {}).get(spec["scan_key"]) or {}
    percent = row.get("percent")
    count = row.get("count")
    label = str(row.get("counter_label") or "")
    parts = [str(row.get("current") or "")]
    if count is not None:
        parts.append(f"{int(count):,} {label}".strip())
    text = "; ".join(part for part in parts if part)
    started = str(doc.get("started_at") or "")
    elapsed = 0.0
    try:
        import datetime as dt
        when = dt.datetime.fromisoformat(started.replace("Z", "+00:00"))
        elapsed = max(0.0, (dt.datetime.now(dt.timezone.utc) - when)
                      .total_seconds())
    except (ValueError, TypeError):
        pass
    page._gw_job_panel.update(
        str(doc.get("state") or row.get("state") or "idle"),
        percent, elapsed, text or "No job on file.")


def refresh(page: Gtk.Widget) -> None:
    """Re-read every tool on a worker, then repaint the state rows in
    place. The page is never rebuilt and the main thread never waits."""
    body = getattr(page, "_gw_body", page)
    tool_ids = tuple(getattr(page, "_gw_tool_ids", ()) or ())

    def worker():
        docs = {}
        for tid in tool_ids:
            try:
                docs[tid] = cliapi.jcall("tool", tid)
            except Exception:              # noqa: BLE001
                docs[tid] = None
        GLib.idle_add(fill, body, docs)

    threading.Thread(target=worker, daemon=True,
                     name="gw-tooldesk-refresh").start()


def fill(page, docs):
    box = getattr(page, "_gw_state_box", None)
    if box is None:
        return False
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt
    states = []
    events = []
    for tid, doc in docs.items():
        name = labels.display_name(tid)
        if not doc:
            box.append(kv_row(name, "Could not read right now", "warn"))
            continue
        state = str(doc.get("state") or "unknown")
        states.append(state)
        word, level = labels.tool_state(state)
        box.append(kv_row(name, word, level))
        events.extend((doc.get("events") or [])[:25])
    note = getattr(page, "_gw_note", None)
    if note is not None:
        note.set_text(_page_note(states, page._gw_tool_ids))
    pill = getattr(page, "_gw_pill", None)
    if pill is not None:
        word, level = _page_pill(states)
        pill.set_label(word.upper())
        for name in ("ok", "warn", "fail"):
            pill.remove_css_class(f"gw-pill-{name}")
        if level in ("ok", "warn", "fail"):
            pill.add_css_class(f"gw-pill-{level}")
    events_box = getattr(page, "_gw_events_box", None)
    if events_box is not None:
        child = events_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            events_box.remove(child)
            child = nxt
        events_box.append(_events_card(events))
    return False


def _page_pill(states: list) -> tuple[str, str]:
    if not states:
        return "The tool did not answer", "warn"
    levels = [labels.tool_state(state)[1] for state in states]
    if "fail" in levels:
        return "A tool is down", "fail"
    if "warn" in levels:
        return "Needs attention", "warn"
    return "All tools live", "ok"


def _page_note(states, tool_ids) -> str:
    if not states:
        return ("The CLI verb 'greywatch tool "
                f"{tool_ids[0] if tool_ids else '?'}' answers for this "
                "tool. Nothing loaded right now.")
    live = sum(1 for s in states if labels.tool_state(s)[1] == "ok")
    return (f"{live} of {len(states)} tools live. The feed below "
            "is the tool's own event log, newest first.")


def _events_card(events: list) -> Gtk.Widget:
    if not events:
        return card(eyebrow("Tool feed"),
                    meta("No events yet for this tool. The feed fills "
                         "as the lane writes."))
    events.sort(key=lambda e: str(e.get("ts") or ""), reverse=True)
    rows = []
    for ev in events[:30]:
        rows.append([str(ev.get("ts") or "")[:19].replace("T", " "),
                     str(ev.get("severity") or ""),
                     str(ev.get("text") or "")[:110]])
    from ui.network import _tree
    scroller, _s = _tree((("When", 150), ("Severity", 90),
                          ("What it said", 340)), rows)
    _ = _s
    stamps = [r[0] for r in rows]
    buckets = _hour_buckets(stamps, 24)
    rate = charts.sparkline(buckets, w=300, h=40)
    head = (rate if any(buckets) else
            meta("No events in the last 24 hours."))
    return card(eyebrow("Tool feed"), head, scroller)


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


def _digest_card(name: str) -> Gtk.Widget:
    path = _ROOT / "tool-digests" / f"{name}.md"
    body = ""
    try:
        body = path.read_text(encoding="utf-8")
    except OSError:
        body = ""
    text = Gtk.TextView()
    text.set_wrap_mode(Gtk.WrapMode.WORD)
    text.set_editable(False)
    text.set_cursor_visible(False)
    if body:
        text.get_buffer().set_text(body[:4000])
        head = eyebrow("Tool digest")
    else:
        text.get_buffer().set_text("No digest file for this tool. "
                                   "Digests live in the install's "
                                   "tool-digests.")
        head = eyebrow("Tool digest")
    frame = Gtk.ScrolledWindow()
    frame.set_min_content_height(180)
    frame.set_child(text)
    return card(head, frame, cls="gw-card gw-card-quiet")


def _commands_card(tool_ids: tuple) -> Gtk.Widget:
    rows = []
    for tid in tool_ids:
        rows.append(kv_row(
            tid, f"greywatch tool {tid} - greywatch log {tid} - "
                 f"greywatch events --tool {tid}"))
    if not rows:
        rows.append(meta("No tool ids on this desk."))
    return card(eyebrow("Commands"), *rows,
                cls="gw-card gw-card-quiet")


def _tree(cols, rows):
    from ui.network import _tree
    return _tree(columns=cols, rows=rows)
