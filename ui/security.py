"""The Security Center, the landing page (architecture v4).

The posture ring - one score from the four inputs - the five category
cards, and the meta strip with its four actions. NO monitoring lives on
this page: the live parts are their own pages (Network, Tools,
Timeline) and this page points to them. Every number on this page reads
the app's own stores; nothing here invents or recomputes the daemon's
work. The GUI is a skin over the CLI.
"""

from __future__ import annotations

import json
import pathlib
import time
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from ui import (actions, baseline_detail, charts, cliapi, findings, kit,
                labels, scanrequests)
from ui.jobpanel import JobPanel
from ui.widgets import (card, count_word, cta_button, eyebrow, headline,
                        kv_row, meta, state_pill, sub)

# A scan document in one of these states is not doing work. "interrupted"
# is written when a scanner dies and the service never guessed a verdict.
_SCAN_TERMINAL = ("done", "cancelled", "failed", "interrupted")
_SCALE_NOTE = "scale 0 to 100, higher is better"
_FIVE_CARDS = (
    ("virus_card", "Virus & threat protection", "clamav"),
    ("net_card", "Firewall & network", "ufw"),
    ("program_card", "Program control", "appfw"),
    ("integrity_card", "Device integrity", "aide"),
    ("updates_card", "Updates & patching", "cve-updater"),
)
_INPUT_TITLES = {"lynis_hardening": "Lynis hardening index",
                 "baseline_pass": "Baseline pass rate",
                 "cve_exposure": "CVE exposure",
                 "apparmor_exposure": "AppArmor enforcement"}
_CARD_ICONS = {"virus_card": "clamav", "net_card": "ufw",
               "program_card": "appfw", "integrity_card": "aide",
               "updates_card": "cve-updater"}


def build(window) -> Gtk.Widget:
    """The page is one scroller over one column. The column carries a
    tab switcher and a stack of three tabs: Overview holds the posture
    inputs, the one scan block and the five cards; Findings and Baseline
    detail are their own modules."""
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page.set_hexpand(True)

    switcher = Gtk.StackSwitcher()
    stack = Gtk.Stack()
    stack.set_transition_type(Gtk.StackTransitionType.NONE)
    switcher.set_stack(stack)
    switcher.set_halign(Gtk.Align.START)
    page.append(switcher)
    page.append(stack)

    overview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    findings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    baseline_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    stack.add_titled(overview, "overview", "Overview")
    stack.add_titled(findings_box, "findings", "Findings")
    stack.add_titled(baseline_box, "baseline", "Baseline detail")
    page._gw_tab_stack = stack
    page._gw_overview = overview
    page._gw_findings = findings_box
    page._gw_baseline = baseline_box

    page._gw_sig = _data_sig()
    _build_overview(window, overview, page)
    findings_page = findings.build(window)
    findings_box.append(findings_page)
    page._gw_findings_page = findings_page
    baseline_page = baseline_detail.build(window)
    baseline_box.append(baseline_page)
    page._gw_baseline_page = baseline_page
    page._gw_tabs_sig = _tabs_sig()

    monitor = getattr(window, "scan_monitor", None)
    if monitor is not None:
        callback = lambda doc: _apply_scan(page, doc)
        page._gw_live_cb = callback
        monitor.subscribe(callback)
        scroll.connect("destroy", lambda _w: monitor.unsubscribe(callback))
    scroll.set_child(page)
    scroll._gw_body = page
    page._gw_scroll = scroll
    scroll._gw_relayout = lambda width: _relayout(page, width)
    return scroll


def _data_sig() -> str:
    """What the page is built from. scan-live is deliberately absent: it
    changes every second, and the live line updates in place instead of
    rebuilding the page (the page used to flip between two layouts)."""
    return _file_sig(("posture.json", "status.json"))


def _tabs_sig() -> str:
    """What the Findings and Baseline detail tabs are painted from. A
    return visit repaints them only when one of these stores changed."""
    return _file_sig(("posture.json", "status.json", "cve-cache.json",
                      "scan-whitelist.json", "quarantine.jsonl",
                      "decisions.jsonl", "run-scan-state.json"))


def _file_sig(names) -> str:
    stamps = []
    for name in names:
        try:
            stat = pathlib.Path(cliapi.state_path(name)).stat()
            stamps.append(f"{name}:{stat.st_mtime_ns}:{stat.st_size}")
        except OSError:
            stamps.append(f"{name}:-")
    return "|".join(stamps)


def refresh(page: Gtk.Widget) -> None:
    """A return visit. Rebuild the Overview tab ONLY when the posture or
    status store changed; otherwise leave every widget where it is and
    repaint the live scan slots from the tracker's copy. The Findings and
    Baseline detail tabs repaint through their own refresh functions and
    only when the stores they read changed."""
    body = getattr(page, "_gw_body", None) or page
    sig = _data_sig()
    if sig != getattr(body, "_gw_sig", None):
        _refresh_into(body)
        body._gw_sig = sig
    _refresh_tabs(body)
    monitor = getattr(getattr(body, "_gw_window", None), "scan_monitor",
                      None)
    live = monitor.live if monitor is not None else (
        cliapi.read_state("scan-live.json") or {})
    _apply_scan(body, live)


def _refresh_tabs(body) -> None:
    sig = _tabs_sig()
    if sig == getattr(body, "_gw_tabs_sig", None):
        return
    body._gw_tabs_sig = sig
    findings_page = getattr(body, "_gw_findings_page", None)
    if findings_page is not None:
        findings.refresh(findings_page)
    baseline_page = getattr(body, "_gw_baseline_page", None)
    if baseline_page is not None:
        baseline_detail.refresh(baseline_page)


def _clear(box: Gtk.Box) -> None:
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


def _refresh_into(page: Gtk.Widget) -> None:
    """Rebuild the Overview tab. A bare body with no tab attributes is
    rebuilt in place, which keeps the scan-desk calls working."""
    window = getattr(page, "_gw_window", None)
    target = getattr(page, "_gw_overview", page)
    _build_overview(window, target, page)


def _grid_columns(width: int) -> int:
    """The card grid's column count for a window width: three on a 4K
    panel, two below it."""
    return 3 if width >= 2400 else 2


def _fill_grid(grid, page, window, columns):
    """Fill the card grid at a column count. Every card keeps its height
    in the row (row homogeneous) so the row has one bottom edge."""
    child = grid.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        grid.remove(child)
        child = nxt
    for index, (key, _title, _icon) in enumerate(_FIVE_CARDS):
        builder = globals()[key]
        # the exposure and antivirus cards need the page: their action
        # rows and live line read the stores and ask the service
        widget = (builder(window, page)
                  if key in ("updates_card", "virus_card")
                  else builder(window))
        widget.set_hexpand(True)
        widget.set_valign(Gtk.Align.FILL)
        # The updates card is always last: spanning the rest of its row
        # keeps the row from ending in an empty cell.
        span = 2 if key == "updates_card" else 1
        grid.attach(widget, index % columns, index // columns, span, 1)


def _relayout(page, width):
    """Reflow the grid when the column count changes, never for a width
    that lands in the same count."""
    columns = _grid_columns(width)
    if getattr(page, "_gw_columns", None) == columns:
        return
    page._gw_columns = columns
    grid = getattr(page, "_gw_grid", None)
    if grid is not None:
        _fill_grid(grid, page, page._gw_window, columns)


def _build_overview(window, box: Gtk.Box, page: Gtk.Box) -> None:
    # The scan block is part of the body, so a rebuild must carry its
    # state across: the daemon rewrites status.json every 60 seconds and
    # that rebuild used to drop a filed request and restart the chart.
    old_scan = getattr(page, "_gw_scan", None)
    _clear(box)
    page._gw_slots = {}

    report = cliapi.read_state("posture.json") or {}
    inputs = report.get("inputs") or {}
    score = report.get("score")
    built = str(report.get("built_at") or "")

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    head.append(headline("Security Center"))
    # GW-10: the posture pill navigates to the weakest input's row in
    # the hero card, the way "needs attention" reads as an action
    weak = _weakest_input(inputs)
    head.append(state_pill(*_posture_mark(score),
                           target=(_weak_target(page, weak)
                                   if weak else None)))
    head.set_halign(Gtk.Align.START)
    head.set_hexpand(False)
    box.append(head)
    page._gw_head = head
    box.append(meta(_head_note(score, inputs, built)))

    # the ring row: the score, and beside it the four inputs with the
    # provenance each one carried in
    ring_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=34)
    ring_row.set_hexpand(True)
    ring_row.append(charts.ring_gauge(score, size=240))

    inputs_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    inputs_box.set_valign(Gtk.Align.CENTER)
    inputs_box.set_hexpand(True)
    inputs_box.append(eyebrow("The four inputs"))
    anchors = page._gw_input_anchors = {}
    for key in ("lynis_hardening", "baseline_pass",
                "cve_exposure", "apparmor_exposure"):
        row = inputs.get(key) or {}
        value = row.get("value")
        shown = "unknown" if value is None else f"{value}/100"
        # the direction is the store's law; an older report without the
        # field still follows it (cve climbs as the machine gets worse)
        lower = row.get("direction", "lower-is-better"
                        if key == "cve_exposure"
                        else "higher-is-better") == "lower-is-better"
        level = (_input_level(value) if lower
                 else _inverted_level(value))
        if value is None:
            level = "mute"
        bar_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                          spacing=10)
        name_lab = Gtk.Label(label=_INPUT_TITLES.get(
            key, key.replace("_", " "))
            + (", lower is better" if lower else ""))
        name_lab.set_xalign(0.0)
        name_lab.set_hexpand(True)
        bar_row.append(name_lab)
        bar_row.append(kit.level_bar(value or 0, lower_is_better=lower,
                                     width=220, level=level))
        shown_lab = Gtk.Label(label=shown)
        shown_lab.set_xalign(1.0)
        if value is not None:
            shown_lab.add_css_class(f"gw-{level}")
        bar_row.append(shown_lab)
        anchors[key] = bar_row
        inputs_box.append(bar_row)
        inputs_box.append(meta(str(row.get("how") or "")))
    if report.get("unknown_inputs"):
        inputs_box.append(meta(
            "Inputs not readable here do not count. The score is rebuilt "
            "over what it can read. A root read earns the full number."))
    elevate = elevate_row(page, report, get_status_mtime())
    if elevate is not None:
        box.append(elevate)
    ring_row.append(inputs_box)
    hero = card(ring_row, cls="gw-card gw-hero")
    box.append(hero)
    page._gw_hero = hero

    # the five category cards: two columns, three at 4K. The grid is kept
    # on the page so a width change can refill it without a data rebuild.
    grid = Gtk.Grid()
    grid.set_column_homogeneous(True)
    grid.set_column_spacing(16)
    grid.set_row_spacing(16)
    grid.set_halign(Gtk.Align.FILL)
    grid.set_hexpand(True)
    page._gw_grid = grid
    # a test shell carries no geometry; the fit beat reflows after this
    columns = _grid_columns(getattr(window, "get_width", lambda: 0)())
    page._gw_columns = columns
    _fill_grid(grid, page, window, columns)
    box.append(grid)

    # The scan desk belongs below the score and the five protection
    # cards (README: "Below the score are the five protection cards
    # and the scan desk"). It is still the one antivirus start surface;
    # carrying the old state keeps a rebuild from cancelling a run.
    scan_block = _scan_block(window, page)
    box.append(scan_block)
    page._gw_scan_block = scan_block
    _carry_scan_state(page, old_scan)

    # the findings pulse: reported findings by hour, the last 24 hours,
    # fed by the audit trail the app already owns
    box.append(_findings_card())
    box.append(_pointers(window))

    # the meta strip: the four actions in one row
    box.append(_meta_strip(window, page))


def _posture_mark(score) -> tuple[str, str]:
    if score is None:
        return "withheld", "warn"
    if score >= 80:
        return "secure", "ok"
    if score >= 60:
        return "needs attention", "warn"
    return "at risk", "fail"


def _weakest_input(inputs) -> str | None:
    """The worst-scoring posture input, as the score reads it: a
    higher-is-better input scores its value, a lower-is-better input
    (CVE exposure climbs as the machine gets worse) scores its inverse.
    Unreadable inputs never claim the spot."""
    best_worst = None
    worst_key = None
    for key, row in (inputs or {}).items():
        value = row.get("value")
        if value is None:
            continue
        lower = row.get("direction", "lower-is-better"
                        if key == "cve_exposure"
                        else "higher-is-better") == "lower-is-better"
        norm = (100 - value) if lower else value
        if best_worst is None or norm < best_worst:
            best_worst, worst_key = norm, key
    return worst_key


def _weak_target(page, key: str):
    def _go():
        from ui import pageutil
        widget = (getattr(page, "_gw_input_anchors", {}) or {}).get(key)
        scroll = getattr(page, "_gw_scroll", None)
        if widget is not None and scroll is not None:
            pageutil.scroll_to_widget(scroll, widget)
    return _go


def _head_note(score, inputs, built) -> str:
    note = _SCALE_NOTE
    if score is None:
        got = sum(1 for v in inputs.values() if v.get("value") is not None)
        note = (f"the score is withheld: only {got} of 4 inputs are readable "
                "here. Run as root for the full score")
    if built:
        note = f"posture report from {built.split('T')[0]}. {note}"
    return note


def _inverted_level(value) -> str:
    if value is None:
        return "mute"
    if value >= 80:
        return "ok"
    if value >= 60:
        return "warn"
    return "fail"


def _input_level(value) -> str:
    """For lower-is-better inputs the mark mirrors the machine's real
    state: a high exposure reads red, a clean one reads green."""
    return _invert_level3(value)


def _invert_level3(value):
    if value is None:
        return "mute"
    if value <= 20:
        return "ok"
    if value <= 60:
        return "warn"
    return "fail"


def _show_layout(cr, layout) -> None:
    from gi.repository import PangoCairo
    PangoCairo.show_layout(cr, layout)


# --- the five cards ---------------------------------------------------

def _tool_row(snap, name):
    return ((snap or {}).get("tools") or {}).get(name) or {}


def _word_for(value: str):
    """(level, word) from the one vocabulary. The card head used to print
    the daemon's raw GREEN/YELLOW/RED token (review I5)."""
    word, level = labels.tool_state(value)
    return level, word


def _status_snap():
    snap = cliapi.read_state("status.json") or {}
    if not snap.get("tools"):
        return None
    return snap


def virus_card(window, page=None) -> Gtk.Widget:
    """Status only: the scan controls live on the scan block above."""
    snap = _status_snap()
    clam = _tool_row(snap, "clamav")
    fresh = _tool_row(snap, "freshclam")
    level, word = _word_for(clam.get("state") or "YELLOW")
    if snap is None:
        word, level = "Snapshot unavailable", "warn"
    f_level, f_word = _word_for(fresh.get("state") or "YELLOW")
    return card(_card_head("clamav", "Virus & threat protection",
                           (word, level), goto="Virus Scan", window=window),
                sub("The antivirus engine and its signature updater."),
                kv_row("Signatures", f_word.lower(), f_level),
                kv_row("Last finding", _last_finding_line()))


def _active(doc: dict) -> bool:
    return (str(doc.get("state") or "") in ("running", "paused")
            or bool(doc.get("external")))


def _data_dir():
    try:
        import gwpaths
        return gwpaths.data_dir()
    except Exception:                      # noqa: BLE001
        return pathlib.Path("/var/lib/greywatch")


def _scan_block(window, page) -> Gtk.Widget:
    """The one scan block: Quick, Deep, and the job panel under them.
    A job's start, chart, status and controls never leave this card."""
    panel = JobPanel(
        "Antivirus",
        lambda: _scan_control(page, "pause"),
        lambda: _scan_control(page, "resume"),
        lambda: _scan_control(page, "cancel"),
    )
    quick = actions.action_button(
        "Quick scan", lambda: _start_scan(page, "clamav-frequent"),
        cls="gw-cta")
    deep = actions.action_button(
        "Deep scan", lambda: _start_scan(page, "clamav-home"))
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    row.append(quick)
    row.append(deep)
    page._gw_scan = {"panel": panel, "quick": quick, "deep": deep,
                     "pending": None, "pending_token": None,
                     "request_id": ""}
    return card(eyebrow("Scan"),
                sub("Quick scan checks temp, Downloads, Desktop, and "
                    "Documents. Deep scan checks the whole home."),
                meta(_deep_note()), row, panel)


def _deep_note() -> str:
    """The last deep run's real size and duration, or an honest promise:
    the count appears when the run starts. Never an invented estimate."""
    try:
        journal = pathlib.Path(cliapi.state_path("scans"))
    except Exception:                    # noqa: BLE001
        return "The file count appears when the deep scan starts."
    newest = None
    for path in sorted(journal.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict) or doc.get("key") != "clamav-home":
            continue
        if str(doc.get("state") or "") != "done":
            continue
        if newest is None or str(doc.get("ended_at") or "") > str(
                newest.get("ended_at") or ""):
            newest = doc
    if newest is None:
        return "The file count appears when the deep scan starts."
    count = int(((newest.get("scanners") or {}).get("clamav") or {})
                .get("count") or 0)
    seconds = _elapsed_between(newest.get("started_at"),
                               newest.get("ended_at"))
    if not count or seconds is None:
        return "The file count appears when the deep scan starts."
    return (f"The last deep scan checked {count:,} files in "
            f"{labels.span_words(seconds)}.")


def _elapsed_between(started, ended):
    import datetime as dt
    try:
        first = dt.datetime.fromisoformat(str(started).replace("Z", "+00:00"))
        last = dt.datetime.fromisoformat(str(ended).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return max(0.0, (last - first).total_seconds())


def _carry_scan_state(page, old) -> None:
    """A body rebuild must not lose a filed request, its pending note, or
    the job chart. status.json is rewritten every 60 seconds, so a return
    visit during a scan would otherwise hand back a fresh idle block."""
    new = getattr(page, "_gw_scan", None)
    if not old or not new:
        return
    new["pending"] = old.get("pending")
    new["pending_token"] = old.get("pending_token")
    new["request_id"] = old.get("request_id") or ""
    new["last_live"] = old.get("last_live") or {}
    old_panel = old.get("panel")
    if old_panel is None:
        return
    # The chart is a history, not a snapshot: seed the new panel so a
    # rebuild does not restart it at one point.
    if old_panel._history:
        new["panel"]._history = list(old_panel._history)
    new["panel"].status.set_text(old_panel.status.get_text())
    new["panel"].pill.set_label(old_panel.pill.get_label())
    for name in ("pause", "resume", "cancel"):
        getattr(new["panel"], name).set_sensitive(
            getattr(old_panel, name).get_sensitive())
    for name in ("quick", "deep"):
        new[name].set_sensitive(old[name].get_sensitive())
    _apply_scan(page, new["last_live"])


def _start_scan(page, key: str) -> None:
    state = getattr(page, "_gw_scan", None)
    if not state or state.get("pending"):
        return
    # The GUI starts only the two antivirus scopes; "full" and "scan-all"
    # belong to the daemon's own desk and are never sent from here.
    if key not in ("clamav-frequent", "clamav-home"):
        return
    if key == "clamav-home" and not actions.ask(
            page._gw_window, "Deep scan",
            "Deep scan reads the whole home and can take hours."):
        return
    ok, note = scanrequests.request_scan(_data_dir(), key)
    if not ok:
        state["panel"].status.set_text(note)
        return
    state["request_id"] = ""
    try:
        filed = json.loads(
            scanrequests.request_path(_data_dir()).read_text())
        state["request_id"] = str(filed.get("id") or "")
    except (OSError, ValueError):
        pass
    state["pending"] = time.time()
    # A token, not the wall clock: the timer runs on GLib's monotonic
    # clock, and a wall-clock step must not leave the start disabled.
    token = time.monotonic()
    state["pending_token"] = token
    state["panel"].status.set_text("Starting the scan.")
    state["quick"].set_sensitive(False)
    state["deep"].set_sensitive(False)
    GLib.timeout_add_seconds(30, _scan_pending_timeout, page, token)


def _scan_pending_timeout(page, token=None) -> bool:
    state = getattr(page, "_gw_scan", None)
    if not state or not state.get("pending"):
        return False
    # A newer start owns its own timer; this one must not clear it.
    if token is not None and state.get("pending_token") != token:
        return False
    doc = (state.get("last_live") or {})
    if not _active(doc):
        state["pending"] = None
        state["pending_token"] = None
        # Only claim the request is still on file when it really is: the
        # service consumes a filed request even while another session
        # runs, so the file (and this request's id) is the proof.
        request_id = str(state.get("request_id") or "")
        still = False
        try:
            filed = json.loads(
                scanrequests.request_path(_data_dir()).read_text())
            still = bool(filed) and (
                not request_id or str(filed.get("id") or "") == request_id)
        except (OSError, ValueError):
            still = False
        note = ("The scan service did not answer. The request is on file "
                "and will start when the service is free." if still
                else "The scan service did not start a scan. Start it "
                     "again.")
        state["panel"].status.set_text(note)
        state["quick"].set_sensitive(True)
        state["deep"].set_sensitive(True)
    return False


def _scan_control(page, action: str) -> None:
    state = getattr(page, "_gw_scan", None) or {}
    doc = state.get("last_live") or {}
    if not doc:
        # No owned job: nothing to pause, resume or cancel here.
        state["panel"].status.set_text("No job on file.")
        return
    ok, note = scanrequests.control_scan(_data_dir(), action,
                                         doc.get("scan_id"))
    if not ok and state.get("panel") is not None:
        state["panel"].status.set_text(note)


def _apply_scan(page, doc: dict) -> None:
    """The tracker's live beat, painted into the scan block's job panel."""
    state = getattr(page, "_gw_scan", None)
    if not state:
        return
    doc = doc or {}
    state["last_live"] = doc
    if not doc:
        # No live document: idle. A just-filed request keeps its
        # "Starting the scan." note until the tracker answers or the
        # 30-second timeout reports the wait.
        if not state.get("pending"):
            state["panel"].set_idle("No scan on file.")
            state["quick"].set_sensitive(True)
            state["deep"].set_sensitive(True)
        return
    # This block owns the antivirus jobs and an external scan. Any other
    # key's live document belongs to a tool desk, so the block stays idle
    # and never mirrors that job or carries its scan id (review C2).
    key = str(doc.get("key") or "")
    external = doc.get("external") or []
    if key and key not in ("clamav", "clamav-frequent", "clamav-home") \
            and not external:
        state["last_live"] = {}
        if not state.get("pending"):
            state["panel"].set_idle("No job on file.")
            state["quick"].set_sensitive(True)
            state["deep"].set_sensitive(True)
        return
    # While a request is pending, the tracker can still be painting the
    # PREVIOUS session's finished document. It is not this request's
    # answer, so the note stays and the 30-second timeout owns the wait.
    request_id = str(state.get("request_id") or "")
    doc_id = str(doc.get("scan_id") or "")
    if (state.get("pending") and request_id and doc_id
            and doc_id != request_id
            and str(doc.get("state") or "") in _SCAN_TERMINAL):
        return
    scanner = (doc.get("scanners") or {}).get("clamav") or {}
    external = doc.get("external") or []
    if external and not scanner:
        scanner = external[0]
    status = str(doc.get("state") or scanner.get("state") or "idle")
    percent = scanner.get("percent")
    current = str(scanner.get("current") or "")
    count = scanner.get("count")
    label = str(scanner.get("counter_label") or "")
    parts = []
    if current:
        parts.append(current)
    if count is not None:
        parts.append(f"{int(count):,} {label}".strip())
    text = "; ".join(parts) or "No scan on file."
    started = str(doc.get("started_at") or "")
    elapsed = 0.0
    try:
        import datetime as dt
        when = dt.datetime.fromisoformat(started.replace("Z", "+00:00"))
        elapsed = max(0.0, (dt.datetime.now(dt.timezone.utc) - when)
                      .total_seconds())
    except (ValueError, TypeError):
        pass
    if status in _SCAN_TERMINAL:
        # Only this request's own session may answer it.
        if not (request_id and doc_id and doc_id != request_id):
            state["pending"] = None
            state["pending_token"] = None
            state["request_id"] = ""
    external_scan = bool(external and not (doc.get("scanners") or {}))
    state["panel"].update(status, percent, elapsed, text,
                          external=external_scan)
    active = _active(doc)
    state["quick"].set_sensitive(not active and not state.get("pending"))
    state["deep"].set_sensitive(not active and not state.get("pending"))


def _age_words(seconds) -> str:
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "unknown age"
    if seconds < 120:
        return f"{int(seconds)} seconds"
    if seconds < 7200:
        return f"{int(seconds // 60)} minutes"
    return f"{int(seconds // 3600)} hours"


def net_card(window) -> Gtk.Widget:
    snap = _status_snap()
    ufw = _tool_row(snap, "ufw")
    f2b = _tool_row(snap, "fail2ban")
    blocked = ((snap or {}).get("defense") or {}).get("blocked") or []
    level, word = _word_for(ufw.get("state") or "YELLOW")
    if snap is None:
        word, level = "Snapshot unavailable", "warn"
    b_level, b_word = _word_for(f2b.get("state") or "YELLOW")
    lines = [sub("Firewall rules, bans and the devices it sees."),
             kv_row("Bans", b_word.lower(), b_level),
             kv_row("Live blocks", str(len(blocked)),
                    "ok" if not blocked else "fail")]
    if window.has_page("Network"):
        lines.append(cta_button(
            "Open Network", lambda _b: window.show_page("Network")))
    headrow = _card_head("ufw", "Firewall & network", (word, level),
                         goto="App Firewall", window=window)
    return card(headrow, *lines)


def program_card(window) -> Gtk.Widget:
    snap = _status_snap()
    appfw = _tool_row(snap, "appfw")
    asks = _pending_ask_count()
    level, word = _word_for(appfw.get("state") or "YELLOW")
    if snap is None:
        word, level = "Snapshot unavailable", "warn"
    return card(_card_head("appfw", "Program control", (word, level),
                        goto="App Firewall", window=window),
                sub("The program gate: what may run and reach the "
                    "network."),
                kv_row("Pending decisions", str(asks),
                       "warn" if asks else "ok"))


def integrity_card(window) -> Gtk.Widget:
    snap = _status_snap()
    aide = _tool_row(snap, "aide")
    tetra = _tool_row(snap, "tetragon")
    aapro = _tool_row(snap, "apparmor")
    level, word = _word_for(aide.get("state") or "YELLOW")
    if snap is None:
        word, level = "Snapshot unavailable", "warn"
    t_level, t_word = _word_for(tetra.get("state") or "YELLOW")
    p_level, p_word = _word_for(aapro.get("state") or "YELLOW")
    return card(_card_head("aide", "Device integrity", (word, level),
                        goto="Integrity", window=window),
                sub("Disk changes, kernel watch and profiles."),
                kv_row("Kernel watch", t_word.lower(), t_level),
                kv_row("Profiles", p_word.lower(), p_level))


def _cve_live_snapshot():
    """The cache + patch ledger as the window can see them now, through
    the same reader the Baseline detail tab uses."""
    try:
        from ui import cveview
        rows, doc = cveview.open_rows()
        tally = cveview.counts(rows, doc)
    except Exception:                    # noqa: BLE001
        rows, doc = [], {}
        tally = {"installed": 0, "affected": 0}
    installed = int(tally.get("installed") or 0)
    affected = int(tally.get("affected") or 0)
    value = round(100 * affected / installed) if installed else None
    return rows, doc, affected, installed, value


def _patch_run(page, button, status, args, settle, pending) -> None:
    """One patch run on a worker: no CLI call ever touches the GTK
    main thread."""
    if page is None or getattr(page, "_gw_patching", False):
        return
    page._gw_patching = True
    # Which action is in flight, so a mid-run rebuild can label the
    # card for the run it is showing rather than always a patch.
    page._gw_patching_action = "all" if "--all" in args else "affected"
    button.set_sensitive(False)
    button.set_label(pending)
    status.set_text("The package helper may ask for your password. "
                    "This can take a few minutes.")

    budget = (baseline_detail.UPGRADE_CALL_TIMEOUT if "--all" in args
              else baseline_detail.AFFECTED_CALL_TIMEOUT)

    def work():
        rc, out, err = cliapi.call("patch", *args, timeout=budget)
        text = (out or err).strip().splitlines()
        GLib.idle_add(_after_patch, page, button, status, settle,
                      text[-1] if text else f"patch rc {rc}")

    threading.Thread(target=work, daemon=True,
                     name="gw-cve-patch").start()


def _after_patch(page, button, status, settle, line):
    page._gw_patching = False
    page._gw_patching_action = None
    slots = getattr(page, "_gw_slots", {}) or {}
    upd = slots.get("updates") or {}
    # A reflow or a data rebuild while the patch runs makes a fresh card:
    # the thread still holds the old widgets, so finish on the ones the
    # page now shows. Every live button is reset here, not just the one
    # this run started from, or the other stays disabled for good.
    live_button = upd.get("button")
    live_secondary = upd.get("secondary")
    if live_button is not None:
        live_button.set_label("Patch affected packages")
        live_button.set_sensitive(True)
    if live_secondary is not None:
        live_secondary.set_label("Upgrade the system")
        live_secondary.set_sensitive(True)
    if live_button is None and live_secondary is None:
        button.set_label(settle)
        button.set_sensitive(True)
    live_status = upd.get("status") or status
    live_status.set_text(line)
    rows, doc, affected, installed, value = _cve_live_snapshot()
    tally = _cve_tally(rows, doc)
    if upd.get("value") is not None:
        upd["value"].set_text("unknown" if value is None
                              else f"{value}/100")
    if upd.get("count") is not None:
        upd["count"].set_text(
            f"{affected} of {installed} installed packages" if installed
            else "No package-aware cache")
    if upd.get("rows") is not None:
        upd["rows"].set_text(_rows_line(tally))
    return False


def _cve_tally(rows, doc) -> dict:
    """The shared counts, so this card and Baseline detail agree."""
    try:
        from ui import cveview
        return cveview.counts(rows, doc)
    except Exception:                    # noqa: BLE001
        return {"installed": 0, "affected": 0, "rows": len(rows),
                "total": len(rows), "capped": False}


def _rows_line(tally: dict) -> str:
    rows = int(tally.get("rows") or 0)
    total = int(tally.get("total") or rows)
    body = count_word(rows, "open CVE row")
    if tally.get("capped") and total != rows:
        return f"{rows} of {count_word(total, 'open CVE row')} in the cache"
    return body


def updates_card(window, page=None) -> Gtk.Widget:
    rows, doc, affected, installed, value = _cve_live_snapshot()
    snap = _status_snap()
    cve_tool = _tool_row(snap, "cve-updater")
    _c_level, c_word = _word_for(cve_tool.get("state") or "YELLOW")
    if snap is None:
        c_word, _c_level = "Snapshot unavailable", "warn"
    level = _invert_level3(value)
    value_word = "unknown" if value is None else f"{value}/100"

    def kv_pair(key, shown, lvl="mute"):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        k = Gtk.Label(label=key)
        k.add_css_class("dim")
        k.set_hexpand(True)
        k.set_xalign(0.0)
        v = Gtk.Label(label=shown)
        v.set_xalign(1.0)
        if lvl in ("ok", "warn", "fail"):
            v.add_css_class(f"gw-{lvl}")
        row.append(k)
        row.append(v)
        return row, v

    value_row, value_lab = kv_pair("CVE exposure, lower is better",
                                   value_word, level)
    tally = _cve_tally(rows, doc)
    count_row, count_lab = kv_pair(
        "Packages with an open CVE",
        f"{affected} of {installed} installed packages" if installed
        else "No package-aware cache", level)
    rows_row, rows_lab = kv_pair("Open CVE rows", _rows_line(tally))
    try:
        from core import updates as _updates
        fetched = _updates.human_stamp(str(doc.get("fetched_utc") or ""))
    except Exception:                    # noqa: BLE001
        fetched = str(doc.get("fetched_utc") or "")[:16]
    lines = [
        sub("The Debian security tracker compared with the installed "
            "package versions. Patching a package to its fixed version "
            "removes its rows."),
        value_row, count_row, rows_row,
        meta(f"Tracker cache: {fetched or 'never fetched'}. "
             f"Intel lane: {c_word.lower()}."),
    ]
    if value is None:
        lines.append(meta("No package-aware CVE cache yet. The weekly "
                          "tracker refresh writes it."))
    status = meta("")
    primary = cta_button(
        "Patch affected packages",
        lambda _b: _patch_run(page, primary, status, ["--affected"],
                              "Patch affected packages", "Patching..."))
    secondary = actions.action_button(
        "Upgrade the system",
        lambda: _patch_run(page, secondary, status, ["--all"],
                           "Upgrade the system", "Upgrading..."),
        cls="gw-secondary",
        parent=window,
        confirm="Every installed package may be upgraded, not only the "
                "ones with an open CVE. This can take several minutes.")
    if page is not None and getattr(page, "_gw_patching", False):
        # a reflow rebuild mid-run must show the run, not a fresh
        # button that would start a second one; the label names the
        # action actually in flight
        action = getattr(page, "_gw_patching_action", "affected")
        for button in (primary, secondary):
            button.set_sensitive(False)
        if action == "all":
            primary.set_label("Upgrading...")
            secondary.set_label("Upgrading...")
        else:
            primary.set_label("Patching...")
        status.set_text("The package helper may ask for your password. "
                        "This can take a few minutes.")
    baseline_button = _quiet(
        "Open Baseline detail for single packages",
        lambda _b: _open_tab(page, "baseline"))
    action_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    action_box.append(primary)
    action_box.append(secondary)
    action_box.append(baseline_button)
    lines.extend([status, action_box])
    if page is not None:
        slots = getattr(page, "_gw_slots", None)
        if slots is None:
            slots = {}
            page._gw_slots = slots
        slots["updates"] = {"value": value_lab, "count": count_lab,
                            "rows": rows_lab, "button": primary,
                            "secondary": secondary, "status": status}
    return card(_card_head("cve-updater", "Updates & patching",
                           _snapshot_mark(snap), goto="Intel",
                           window=window), *lines)


def _snapshot_mark(snap) -> tuple[str, str]:
    if snap is None:
        return "Snapshot unavailable", "warn"
    return "Live", "ok"


def _last_finding_line() -> str:
    """scan-findings.jsonl is a ledger of JSON lines, not one doc; read
    the newest row and say when it landed, or say none are on file."""
    try:
        p = cliapi.state_path("scan-findings.jsonl")
    except Exception:                    # noqa: BLE001
        p = "/var/lib/greywatch/scan-findings.jsonl"
    try:
        lines = [ln for ln in open(p, encoding="utf-8").read()
                 .splitlines() if ln.strip()]
    except OSError:
        return "none on file"
    if not lines:
        return "none on file"
    try:
        row = json.loads(lines[-1])
    except ValueError:
        return "one row unreadable"
    when = str(row.get("ts") or row.get("when")
               or row.get("first_seen") or "")[:19].replace("T", " ")
    return when or "one row, no stamp"


def _pending_ask_count() -> int:
    try:
        from decisions_factory import pending_spec_pairs
    except ImportError:
        return 0
    try:
        import gwpaths
        return len(pending_spec_pairs(gwpaths.data_dir()))
    except Exception:                    # noqa: BLE001
        return 0


def _pointers(window) -> Gtk.Widget:
    row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    row.append(eyebrow("Live monitoring lives on its own screens"))
    live = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    for name in ("Network", "Tools", "Timeline"):
        if window.has_page(name):
            b = Gtk.Button(label=name)
            b.add_css_class("gw-quiet")
            b.connect("clicked",
                      lambda _b, n=name: window.show_page(n))
            live.append(b)
    row.append(live)
    row.append(meta("This page shows no monitoring: devices, lane "
                    "status and the timeline have their own screens."))
    return card(row)


def _meta_strip(window, page) -> Gtk.Widget:
    return card(
        eyebrow("Actions"),
        _actions_box(window, page),
        cls="gw-card gw-card-quiet")


def _actions_box(window, page) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    box.append(_quiet("Diagnose + fix",
                      lambda _b: _inline(page, "doctor", ["--fix"])))
    box.append(_quiet("Every check",
                      lambda _b: _inline(page, "verify")))
    box.append(_quiet("The posture report", lambda _b: _report(page)))
    return box


def _open_tab(page, name: str) -> None:
    """Switch the Security stack to one of its tabs in place."""
    stack = getattr(page, "_gw_tab_stack", None)
    if stack is not None:
        stack.set_visible_child_name(name)


def _quiet(text, cb) -> Gtk.Button:
    b = Gtk.Button(label=text)
    # An enabled secondary action must not look like a disabled one.
    b.add_css_class("gw-secondary")
    b.connect("clicked", cb)
    return b


def _inline(page, verb: str, args=()) -> None:
    # One CLI verb, on a worker: a blocking call on the main thread froze
    # the whole app for up to three minutes (the owner's 2026-11-18
    # "can't do anything with any of it" — every action pays its own
    # thread, the rail and the buttons answer instantly).
    if getattr(page, "_gw_action_busy", False):
        return
    window = getattr(page, "_gw_window", None)
    if verb == "doctor" and "--fix" in tuple(args or ()):
        # "Diagnose + fix" applies the doctor's safe fixes, so it asks
        # first and names what it will do. It never arms a scan timer.
        if not actions.ask(
                window, "Diagnose + fix",
                "The doctor will diagnose this machine and apply its safe "
                "fixes. It never starts an automatic scan."):
            return
    page._gw_action_busy = True
    if window is not None:
        window.note(f"{verb}: running.")

    def work():
        rc, out, err = cliapi.call(verb, *tuple(args or ()), timeout=180)
        first = ""
        for line in out.splitlines() + err.splitlines():
            if line.strip():
                first = line.strip()[:160]
                break
        GLib.idle_add(_inline_note, window, page, verb,
                      first, rc, priority=GLib.PRIORITY_DEFAULT)

    threading.Thread(target=work, daemon=True,
                     name=f"gw-action-{verb}").start()


def _inline_note(window, page, verb, first, rc) -> bool:
    page._gw_action_busy = False
    if window is not None:
        window.note(f"{verb}: {first or (f'rc {rc}')}")
    refresh(page)
    return False


def _report(page) -> None:
    # Same worker law as _inline: the score recount is file reads and a
    # compute pass, never a main-thread wait.
    def work():
        rc, out, _err = cliapi.call("posture", timeout=120)
        text = next((ln.strip()[:160] for ln in out.splitlines()
                     if ln.strip()), f"posture rc {rc}")
        GLib.idle_add(_inline_note, getattr(page, "_gw_window", None),
                      page, "posture", text, rc,
                      priority=GLib.PRIORITY_DEFAULT)

    threading.Thread(target=work, daemon=True,
                     name="gw-action-posture").start()


# -- the elevated read -------------------------------------------------
# The four posture inputs need root for the Lynis report, the AppArmor
# profile table and the CVE announced ledger. The re-read runs the app's
# own helper through the polkit lane (one password dialog owned by the
# desktop's auth agent, not by this app); a cancel is honored - nothing
# here re-prompts itself.
_ASK_STATE = {"session": False, "running": False}
_STALE_HOURS = 24


def root_need(report, status_mtime) -> str:
    """Why this context still needs one elevated read: missing inputs, or
    a report on file older than the suite's own snapshot."""
    unknown = list((report or {}).get("unknown_inputs") or [])
    built = str((report or {}).get("built_at") or "")
    if unknown:
        names = ", ".join(t.replace("_", " ") for t in unknown)
        return (f"{len(unknown)} of the four inputs read only with root "
                f"({names}). One approved read rebuilds the full score.")
    try:
        import datetime as dt
        when = dt.datetime.fromisoformat(built)
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        age = dt.datetime.now(dt.timezone.utc) - when
        if status_mtime is not None and \
                age > dt.timedelta(hours=_STALE_HOURS) and \
                age.total_seconds() > status_mtime:
            return ("The report on file is days older than the machine's "
                    "own snapshot. One approved read rebuilds it as "
                    "current.")
    except (ValueError, TypeError):
        pass
    return ""


def request_root_once(window, page=None, from_launch: bool = False) -> None:
    """Fire ONE elevated posture re-read and honor the answer. From a
    launch this asks once per session, ever; from the page button it
    works every time, and never two at once."""
    if _ASK_STATE["running"]:
        if window is not None:
            window.note("An elevated read is already running or waiting "
                        "on your answer.")
        return
    if from_launch:
        if _ASK_STATE["session"]:
            return
        _ASK_STATE["session"] = True
    _ASK_STATE["running"] = True
    import threading

    def work():
        from cli import helper_exec, helper_last_err
        try:
            rc = helper_exec("posture-as-root", [])
            err = helper_last_err()
        except Exception as e:                 # noqa: BLE001
            rc, err = 124, str(e)
        GLib.idle_add(_after_elevated, rc, err, window, page)

    threading.Thread(target=work, daemon=True,
                     name="gw-posture-elevate").start()


def _after_elevated(rc, err, window, page) -> bool:
    _ASK_STATE["running"] = False
    if window is not None:
        if rc == 0:
            txt = "The posture report was rebuilt with the root inputs."
        elif rc in (126, 127):
            txt = ("The elevated read was not approved; the Security "
                   "Center stays on what it can read, and the Read as "
                   "root button asks again.")
        else:
            txt = f"The elevated read did not run ({err or f'rc {rc}'})."
        window.note(txt)
    if page is not None:
        refresh(page)
    return False


def get_status_mtime() -> float | None:
    """How new the suite's own snapshot is, in seconds of age."""
    try:
        p = pathlib.Path(cliapi.state_path("status.json"))
        return max(0.0, time.time() - p.stat().st_mtime)
    except OSError:
        return None


def elevate_row(page, report, status_mtime=None) -> Gtk.Widget:
    """The page row for one approved read. The page passes itself so the
    button repaints the report in place; None hides the row."""
    why = root_need(report, status_mtime)
    if not why:
        return None
    win = page._gw_window
    return card(meta(why),
                cta_button("Read as root",
                           lambda _b: request_root_once(win, page)),
                cls="gw-card gw-card-quiet")


def _card_head(tool_id: str, title: str, pill=None, goto: str | None = None,
               window=None) -> Gtk.Box:
    """A card head: icon, eyebrow, a spacer, and the state pill on the
    right. The pill used to sit on its own line and stretch across the
    card. With a goto desk name the pill is clickable and opens that
    tool's desk (GW-10): a yellow state navigates to its fix."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
    row.append(kit.icon(tool_id, size=20))
    lab = Gtk.Label()
    # Escape the title: a raw ampersand ("Virus & threat protection",
    # "Updates & patching") made pango reject the markup and the label
    # rendered empty.
    lab.set_markup(
        f"<span weight='bold' letter_spacing='1400' "
        f"variant='small-caps'>{GLib.markup_escape_text(title.upper())}"
        f"</span>")
    lab.add_css_class("gw-eyebrow")
    lab.set_xalign(0.0)
    row.append(lab)
    spacer = Gtk.Box()
    spacer.set_hexpand(True)
    row.append(spacer)
    if pill is not None:
        target = _desk_opener(goto, window) if goto else None
        row.append(state_pill(pill[0], pill[1], target=target))
    return row


def _desk_opener(desk: str | None, window):
    """A zero-arg callable that opens one Advanced desk, or None when
    the window cannot navigate (test builds without a main window)."""
    if not desk:
        return None

    def _go():
        try:
            from ui import advanced
            label, ids, digest = advanced.desk_for(desk)
        except KeyError:
            return
        opener = getattr(window, "open_tool_page", None) if window else None
        if opener is not None:
            opener(label, ids, digest)
    return _go


def _findings_card() -> Gtk.Widget:
    """Reported findings by hour, the last 24 hours: events at MEDIUM
    or above, counted from the audit trail the app already owns. An
    all-quiet day reads honestly as quiet."""
    stamps = []
    for ev in cliapi.read_jsonl("events.jsonl", last=4000):
        sev = str(ev.get("severity") or "").upper()
        if sev in ("MEDIUM", "HIGH", "CRITICAL"):
            stamps.append(str(ev.get("ts") or ""))
    buckets = _hour_buckets(stamps, 24)
    series = [b for b in buckets]
    card_rows = [charts.sparkline(series, w=520, h=96)]
    if not any(series):
        card_rows.append(meta(
            "Nothing reported at MEDIUM or above in the last 24 hours."))
    return kit.section_card("Findings reported, last 24 hours",
                            *card_rows)


def _hour_buckets(stamps, buckets: int) -> list:
    """The last `buckets` hours as counts, oldest left. Bad stamps are
    skipped, never invented."""
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
