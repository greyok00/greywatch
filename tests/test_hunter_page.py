"""GW-125 (owner 2026-11-03, "use the same treatment for all"): the
Browser Watch page is the hunter desk — command strip (hunt now, HAR
import, the AI explainer meter, the suite's own verdict, the hunt
clock), a stat band over the hunt channels, a coverage strip, the
day-grouped feed, and the selected finding's side-by-side dossier with
its related-in-suite hand-offs.

Nothing here talks to the network: replies in tests are injected
handlers; the page renders whatever the handler returned."""
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)

from hunter import store  # noqa: E402
from ui.hunterview import (MAX_ROWS, _channel_of, _day_label,  # noqa: E402
                           HunterPanel, latest_findings)
from ui import guided  # noqa: E402


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


def _seed_mix(data_dir):
    """Three findings — two HIGH, one LOW — each with a defender note, so
    a filter has something real to narrow. Newest first in the feed this
    seeds: high-c (Today), then low-b and high-a (Yesterday). Anchors are
    pinned to the clock's own midnight (00:05 today, yesterday's 20:00
    and 18:00) rather than "N hours ago": at any wall clock an hours-ago
    offset eventually crosses the boundary it names (and did, at Nov 5
    00:38), while midnight-anchored stamps keep their day forever."""
    import datetime as dt
    now = dt.datetime.now().astimezone()
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    rows = [
        ("high-a", "HIGH", "History watcher flagged a parked domain",
         (midnight - dt.timedelta(hours=6)).isoformat()),
        ("low-b", "LOW", "Startup folder gained one helper",
         (midnight - dt.timedelta(hours=4)).isoformat()),
        ("high-c", "HIGH", "Download used a double extension",
         (midnight + dt.timedelta(minutes=5)).isoformat()),
    ]
    if dt.datetime.fromisoformat(rows[2][3]) >= now:
        rows[2] = ("high-c", "HIGH", "Download used a double extension",
                   (now - dt.timedelta(seconds=1)).isoformat())
    for fid, sev, title, ts in rows:
        store.append_finding(data_dir, {
            "id": fid, "ts": ts, "rule": f"rule-{fid}",
            "title": title, "what": f"What happened for {fid}.",
            "next": f"Next step for {fid}.", "severity": sev,
            "confidence": "medium", "status": "lead",
            "facts": [f"path={fid}.sample"], "evidence": [],
            "hunter": "1"})
        store.append_defender(data_dir, {
            "ts": ts.replace("00:00+00:00", "00:01+00:00"), "kind": "rule",
            "finding_id": fid, "severity": sev,
            "text": f"Note for {fid}.", "hint": f"Hint for {fid}."})


def _channel_seeded(data_dir):
    """One finding per live channel, plus a HAR one, so the coverage
    strip's 24-hour counts have real numbers to show. Stamps are built
    relative to now (a few hours back) so the 24 h-window test does not
    rot into a failure once the calendar moves past a hard-coded day."""
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    rows = [
        ("det-1", "malware-detected", "HIGH",
         "Antivirus named a program", now),
        ("scan-1", "scan-positive", "MEDIUM",
         "A finished scan found a real hit", now - _dt.timedelta(minutes=30)),
        ("file-1", "download-double-extension", "HIGH",
         "A download used two extensions", now - _dt.timedelta(minutes=60)),
        ("har-1", "har-double-extension", "HIGH",
         "A capture carried the same trick",
         now - _dt.timedelta(minutes=90)),
    ]
    rows = [(fid, rule, sev, title,
             ts.isoformat(timespec="seconds"))
            for fid, rule, sev, title, ts in rows]
    for fid, rule, sev, title, ts in rows:
        store.append_finding(data_dir, {
            "id": fid, "ts": ts, "rule": rule, "title": title,
            "what": f"What happened for {fid}.", "next": "Next step.",
            "severity": sev, "facts": [], "evidence": [], "hunter": "1"})


def _finding_rows(panel):
    """Feed rows only — the day-label strips between groups are plain
    children of the same list and count for nothing."""
    return [w for w in panel._list.observe_children()
            if hasattr(w, "_gw_finding_id")]


def _day_strips(panel):
    return [w.get_text() for w in panel._list.observe_children()
            if w.has_css_class("gw-day")]


def _button_with_label(root, label):
    stack = [root]
    while stack:
        widget = stack.pop(0)
        if isinstance(widget, Gtk.Button):
            child = widget.get_child()
            if isinstance(child, Gtk.Label) and child.get_text() == label:
                return widget
        stack.extend(widget.observe_children())
    raise AssertionError(f"no button labelled {label!r}")


from ui.hunterview import _clock  # noqa: E402


def _clock_of(ts):
    """The desk renders stamps in the owner's own clock; the test reads
    them through the same conversion."""
    return _clock(ts)


def _texts(widget):
    out, stack = [], [widget]
    while stack:
        w = stack.pop(0)
        if isinstance(w, Gtk.Label):
            out.append(w.get_text())
        stack.extend(w.observe_children())
    return out


def _dossier_texts(panel):
    """The dossier column: its header (title, pills) and its body."""
    return _texts(panel._dhead) + _texts(panel._detail)


def test_exactly_four_chips_with_all_active(tmp_path):
    panel = HunterPanel(tmp_path)
    assert sorted(panel._chip_btns) == ["All", "High", "Low", "Medium"]
    assert "gw-chip-on" in panel._chip_btns["All"].get_css_classes()
    assert "gw-chip-on" not in panel._chip_btns["High"].get_css_classes()


def test_high_chip_narrows_the_feed(tmp_path):
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    assert len(_finding_rows(panel)) == 3
    panel._chip_btns["High"].emit("clicked")
    pump(5)
    rows = _finding_rows(panel)
    assert len(rows) == 2, "only HIGH findings stay in the feed"
    joined = "\n".join(t for row in rows for t in _texts(row))
    assert "high-b" not in joined
    assert "Download used a double extension" in joined
    assert "Startup folder gained one helper" not in joined
    # Back to all three.
    panel._chip_btns["All"].emit("clicked")
    pump(5)
    assert len(_finding_rows(panel)) == 3


def test_chips_carry_their_counts(tmp_path):
    """GW-125: the counted chips — All names the whole pool, each
    severity names how many rows carry it."""
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    assert panel._chip_btns["All"].get_label() == "All 3"
    assert panel._chip_btns["High"].get_label() == "High 2"
    assert panel._chip_btns["Medium"].get_label() == "Medium 0"
    assert panel._chip_btns["Low"].get_label() == "Low 1"
    panel._chip_btns["High"].emit("clicked")
    pump(5)
    # The pool behind the chips stays the whole feed; counts do not fold
    # into the narrowed view.
    assert panel._chip_btns["High"].get_label() == "High 2"
    assert panel._chip_btns["All"].get_label() == "All 3"


def test_clicking_a_row_fills_the_detail_pane(tmp_path):
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    # The page starts with a pick-a-finding line, not a half-empty form.
    assert any("pick" in t.lower() for t in _texts(panel._detail))
    newest = _finding_rows(panel)[0]
    # The row is click-wired (its gesture calls the page's select), and
    # calling that handler pins the same contract the gesture fulfils.
    assert any(isinstance(c, Gtk.GestureClick)
               for c in newest.observe_controllers())
    panel._select_finding("high-c")
    pump(5)
    first = _finding_rows(panel)[0]
    pane = "\n".join(_dossier_texts(panel))
    assert "Download used a double extension" in pane
    assert "What happened for high-c." in pane
    assert "Next step for high-c." in pane
    assert "gw-row-on" in first.get_css_classes()
    # The head carries the finding's identity pills beside the title.
    joined_head = "\n".join(_texts(panel._dhead))
    assert "high" in joined_head.lower()
    assert "confidence" in joined_head.lower()


def test_ask_renders_the_injected_reply_inline(tmp_path):
    _seed_mix(tmp_path)
    replies = []

    def on_ask(question, finding=None):
        replies.append((question, finding))
        return "The rule proved it from the file name."

    panel = HunterPanel(tmp_path, on_ask=on_ask)
    panel.refresh(force=True)
    pump(5)
    panel._select_finding("high-c")
    pump(5)
    ask = _button_with_label(panel._detail, "Ask about this")
    # The seeded hunter note is already an answer for this finding; the
    # injected reply lands after it in the same list.
    assert len(list(panel._answers.observe_children())) == 1
    ask.emit("clicked")
    pump(5)
    assert len(replies) == 1
    assert "Download used a double extension" in replies[0][0]
    answers = list(panel._answers.observe_children())
    assert len(answers) == 2
    assert "The rule proved it from the file name." in _texts(answers[-1])
    # Each ask adds its reply; the list keeps the conversation history.
    ask.emit("clicked")
    pump(5)
    assert len(list(panel._answers.observe_children())) == 3


def test_answer_list_shows_only_this_findings_notes(tmp_path):
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path, on_ask=lambda q, f=None: None)
    panel.refresh(force=True)
    pump(5)
    panel._select_finding("high-c")
    pump(5)
    answers = list(panel._answers.observe_children())
    assert len(answers) == 1
    joined = "\n".join(_texts(answers[0]))
    assert "Note for high-c." in joined and "low-b" not in joined
    # The note's own hint (what to do next) is in the list too.
    assert "Hint for high-c." in joined


def test_filter_change_clears_a_hidden_selection(tmp_path):
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    panel._select_finding("high-c")
    pump(5)
    panel._chip_btns["Low"].emit("clicked")
    pump(5)
    rows = _finding_rows(panel)
    assert len(rows) == 1
    assert "gw-row-on" not in rows[0].get_css_classes(), (
        "the selected HIGH finding is filtered out; the detail pane resets")
    assert panel._selected is None


def test_feed_cap_stays_at_twenty_four(tmp_path):
    _seed_mix(tmp_path)
    for i in range(30):
        store.append_finding(tmp_path, {
            "id": f"bulk-{i}", "ts": f"2026-11-05T0{i % 10}:22:00+00:00",
            "rule": "bulk", "title": f"Bulk {i}", "what": "Bulk.",
            "next": "Nothing.", "severity": "MEDIUM",
            "facts": [], "evidence": [], "hunter": "1"})
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    assert len(_finding_rows(panel)) == MAX_ROWS


def test_feed_reads_newest_first_by_each_finding_time(tmp_path):
    """GW-119 (2026-11-03): a cycle can append an older-evidence finding
    after a newer one; the feed rides each row's own time, not the order
    the lines landed in the file."""
    rows = [
        ("late-old", "2026-11-01T09:00:00+00:00", "MEDIUM",
         "Older event, written last"),
        ("early-new", "2026-11-03T09:00:00+00:00", "HIGH",
         "Newer event, written first"),
    ]
    for fid, ts, sev, title in rows:
        store.append_finding(tmp_path, {
            "id": fid, "ts": ts, "rule": f"rule-{fid}", "title": title,
            "what": f"What happened for {fid}.", "next": "Next step.",
            "severity": sev, "facts": [], "evidence": [], "hunter": "1"})
    got = [str(f["id"]) for f in latest_findings(tmp_path)]
    assert got == ["early-new", "late-old"]
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    first = _finding_rows(panel)[0]
    assert "Newer event" in "\n".join(_texts(first)), (
        "the feed's top row must carry the newest finding's own time")


def test_a_finding_without_time_reads_last_and_never_crash(tmp_path):
    """An old writer may leave a finding without ts; it reads after every
    timed row instead of breaking the page."""
    store.append_finding(tmp_path, {
        "id": "no-ts", "rule": "rule-no-ts", "title": "No time",
        "what": "What happened.", "next": "Next step.",
        "severity": "LOW", "facts": [], "evidence": [], "hunter": "1"})
    got = [str(f["id"]) for f in latest_findings(tmp_path)]
    assert got == ["no-ts"]


# --- GW-125 desk structure ------------------------------------------------

def test_empty_store_shows_the_empty_state_not_a_blank_feed(tmp_path):
    panel = HunterPanel(tmp_path)
    pump(5)
    assert panel._empty.get_visible()
    assert "Nothing needs hunting yet" in panel._empty.get_text()
    assert _finding_rows(panel) == []


def test_command_strip_holds_clock_suite_and_har_buttons(tmp_path):
    """The desk's first row: the two action buttons, the AI meter and the
    suite's own verdict riding it, and the hunt clock on the right."""
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    buttons = [b for b in panel._cmd.observe_children()
               if isinstance(b, Gtk.Button)]
    labels = [b.get_child().get_text() for b in buttons]
    assert "Hunt now" in labels
    assert "Import HAR…" in labels
    clock = panel._clock_label.get_text()
    # No snapshot yet: "FIRST HUNT SOON"; with one, the next-hunt wording.
    assert (("FIRST HUNT" in clock and "NEXT" not in clock)
            or ("LAST " in clock and "NEXT" in clock)), clock


    suite = panel._suite_chip.get_text()
    assert suite.startswith("Suite: "), suite


def test_command_strip_says_so_after_a_hunt_request(tmp_path):
    panel = HunterPanel(tmp_path)
    _button_with_label(panel, "Hunt now").emit("clicked")
    pump(5)
    assert panel._status.get_visible()
    assert "on it" in panel._status.get_text()
    # Presence-only request: a file, not a command payload.
    assert store.request_path(tmp_path).exists()


def test_stat_band_carries_the_hunt_numbers(tmp_path):
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    texts = {}
    for key, (value, sub) in panel._tiles.items():
        texts[key] = (value.get_text(), sub.get_text())
    assert texts["leads"][0] == "3"
    assert "2 high" in texts["leads"][1]
    assert texts["cycle"][0] == "0"
    assert texts["unread"][0] == "3", "no read pointer: every note is new"
    assert texts["har"][0] == "0"
    assert "processed" in texts["har"][1]


def test_feed_foot_states_the_cadence(tmp_path):
    panel = HunterPanel(tmp_path)
    pump(5)
    foot = [t for t in _texts(panel) if "sweeps every" in t]
    assert foot, f"{panel} has no cadence footer"


def test_stat_band_reads_the_hunters_live_snapshot(tmp_path):
    """The HAR tile and the cycle tile read live.json — the hunter's own
    snapshot written each cycle — in the hunter's units."""
    _seed_mix(tmp_path)
    store.write_live(tmp_path, {
        "ts": "2026-11-03T17:30:00+00:00", "interval_s": 300.0,
        "findings_total": 3, "new_this_cycle": 2, "unread": 2,
        "har": {"processed": 4, "rejected": 1},
        "ai": {"enabled": True, "per_hour": 3, "used_hour": 1,
               "cooling": False}})
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    texts = {k: (v.get_text(), s_.get_text())
             for k, (v, s_) in panel._tiles.items()}
    assert texts["cycle"][0] == "2"
    last = _clock_of("2026-11-03T17:30:00+00:00")
    assert texts["cycle"][1] == f"last cycle {last}"
    assert texts["har"][0] == "5"
    assert "4 processed" in texts["har"][1]
    meter = panel._ai_meter.get_text()
    assert "1/3 THIS HOUR" in meter


def test_coverage_strip_counts_each_channel_per_24h(tmp_path):
    """Every live channel sweeps each cycle, so its last sweep is the
    last hunt's clock; its 24-hour count reads the findings the hunter
    wrote into that channel."""
    _channel_seeded(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    text = panel._cover_tiles["detections"].get_text()
    assert "/ 24 h" in text
    assert "1 / 24 h" in text, "one detection finding on file"
    scans = panel._cover_tiles["scans"].get_text()
    assert "1 / 24 h" in scans
    files = panel._cover_tiles["files"].get_text()
    assert "1 / 24 h" in files
    # HAR findings are feed rows labelled "HAR capture"; the coverage
    # strip keeps to the four hunt channels plus the gap tile.
    assert "har" not in panel._cover_tiles
    gap = panel._cover_tiles["browser"].get_text()
    assert "0 / 24 h" in gap, "the browser channel has nothing on file yet"


def test_channel_of_covers_every_rule_family():
    assert _channel_of("malware-detected") == ("antivirus", "detections")
    assert _channel_of("rootkit-warning") == ("rootkit scanner",
                                              "detections")
    assert _channel_of("scan-positive") == ("finished scans", "scans")
    assert _channel_of("har-mime-wrap")[0] == "HAR capture"
    assert _channel_of("download-executable") == ("downloads", "files")
    assert _channel_of("persistence-scratch-path") == ("startup automation",
                                                       "files")
    assert _channel_of("browser-history-hazard") == ("browser history",
                                                     "browser")
    # GW-160: the cfg family is its own channel, not the suite fallback
    assert _channel_of("cfg-new-extension") == ("browser config", "browser")
    assert _channel_of("cfg-search-hijack") == ("browser config", "browser")
    assert _channel_of("cfg-notification-grant") == ("browser config",
                                                     "browser")
    assert _channel_of("anything-else")[0] == "suite events"


def test_day_labels_group_the_feed(tmp_path):
    """The feed groups into the days its findings span: Today, Yesterday,
    then the date — the desk reads like a report, not a flat list."""
    import datetime as dt
    _seed_mix(tmp_path)
    old_ts = dt.datetime.now().astimezone() - dt.timedelta(days=15)
    store.append_finding(tmp_path, {
        "id": "older", "ts": old_ts.isoformat(), "rule": "bulk",
        "title": "Older day finding", "what": "What happened.",
        "next": "Next step.", "severity": "MEDIUM",
        "facts": [], "evidence": [], "hunter": "1"})
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    days = _day_strips(panel)
    assert days[0] == "Today"
    assert days[1] == "Yesterday"
    # The 15-day-old finding lands on its own dated strip; the exact
    # date moves with the wall clock, so expect it, not a calendar.
    assert days[-1] == _day_label(old_ts)


def test_day_label_words():
    import datetime as dt
    now = dt.datetime.now().astimezone()
    assert _day_label(now) == "Today"
    assert _day_label(now - dt.timedelta(days=1)) == "Yesterday"
    old = (now - dt.timedelta(days=40)).date()
    assert _day_label(old) == old.strftime("%b %d")
    assert _day_label(None) == "Earlier"


def test_related_rows_hand_off_to_the_suite(tmp_path):
    """The dossier's footer carries the finding into the pages that can
    act on it — real shell navigation, in the mockup's open → style."""
    _seed_mix(tmp_path)
    seen: list = []
    panel = HunterPanel(tmp_path, on_navigate=seen.append)
    pump(5)
    open_btn = _button_with_label(panel._related, "Open")
    open_btn.emit("clicked")
    pump(5)
    assert seen == ["protect"], "the footers' first open is Protections"
    assert len(panel._related_rows) == 4, "protect, scans, logs, home"


def test_related_open_buttons_absent_without_a_navigate_handler(tmp_path):
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    pump(5)
    buttons = [b for b in panel._related.observe_children()
               if isinstance(b, Gtk.Button)]
    assert buttons == [], "no shells in tests: nothing to open"


def test_home_row_applies_only_with_unread_notes(tmp_path):
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    assert panel._related_rows["home"].get_visible()
    from hunter import explain
    notes = store.read_defender(tmp_path)
    newest = max(str(n.get("ts") or "") for n in notes)
    explain.mark_read(tmp_path, newest)
    panel.refresh(force=True)
    pump(5)
    assert not panel._related_rows["home"].get_visible()


def test_raw_facts_and_evidence_reach_the_dossier(tmp_path):
    _seed_mix(tmp_path)
    store.append_finding(tmp_path, {
        "id": "ev-rich", "ts": "2026-11-03T10:00:00+00:00",
        "rule": "download-double-extension",
        "title": "Evidence-rich finding", "what": "Saw the drop.",
        "next": "Delete it.", "severity": "HIGH",
        "facts": ["program=invoice.pdf.exe", "folder=Downloads"],
        "evidence": [
            {"source": "browser-history", "path": "/home/x/Downloads/x.exe",
             "ts": "2026-11-03T10:00:00+00:00"},
            {"source": "har", "scan_id": "har-9",
             "ts": "2026-11-03T10:00:05+00:00"},
            {"source": "clamav", "tool": "clamscan",
             "ts": "2026-11-03T10:00:10+00:00"},
        ], "hunter": "1"})
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    panel._select_finding("ev-rich")
    pump(5)
    body = "\n".join(_texts(panel._detail))
    assert "RAW FACTS" in body
    assert "program=invoice.pdf.exe" in body
    assert "EVIDENCE" in body
    assert "/home/x/Downloads/x.exe" in body
    assert "har-9" in body
    assert "clamscan" in body


def test_dossier_evidence_overflow_names_the_rest(tmp_path):
    _seed_mix(tmp_path)
    store.append_finding(tmp_path, {
        "id": "ev-many", "ts": "2026-11-03T10:10:00+00:00",
        "rule": "download-double-extension",
        "title": "Wide evidence rail", "what": "Saw the drop.",
        "next": "Delete it.", "severity": "HIGH",
        "facts": ["program=wide.scr"],
        "evidence": [{"source": f"src-{i}", "path": f"/p/{i}",
                      "ts": "2026-11-03T10:00:00+00:00"}
                     for i in range(8)], "hunter": "1"})
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    panel._select_finding("ev-many")
    pump(5)
    body = "\n".join(_texts(panel._detail))
    assert "and 2 more piece(s)" in body


def test_copy_facts_keeps_the_page_alive_and_reports(tmp_path):
    """Copy facts: what + facts + evidence, one per line. On a display
    with a clipboard it lands there; on one without, the page says so —
    it never dies."""
    _seed_mix(tmp_path)
    panel = HunterPanel(tmp_path)
    panel.refresh(force=True)
    pump(5)
    panel._select_finding("high-c")
    pump(5)
    copy_btn = _button_with_label(panel._detail, "Copy facts")
    copy_btn.emit("clicked")
    pump(5)
    assert panel._status.get_visible()
    text = panel._status.get_text()
    assert ("copied" in text) or ("not reachable" in text), text

# --- th-A (rebuild round 2, task 8): finding cards with wired actions ------

def _buttons_of(widget):
    stack, out = [widget], []
    while stack:
        w = stack.pop(0)
        if isinstance(w, Gtk.Button):
            out.append(w)
        if hasattr(w, "observe_children"):
            stack.extend(w.observe_children())
    return out


def _card_of(panel, fid):
    return next((w for w in panel._list.observe_children()
                 if getattr(w, "_gw_finding_id", None) == fid), None)


def _card_labels(card):
    return [b.get_child().get_text() if b.get_child() else b.get_label()
            for b in _buttons_of(card)]


def _now_stamp():
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def test_every_rule_kind_has_its_action_wired(tmp_path):
    """The rule-to-action map next to _RULE_CHANNELS gives every scanner
    rule its real buttons on the card itself: malware-detected deletes
    through the quarantine lane (with quarantine as the undo and a full
    scan after), the one-shot scanner outputs get the baseline update and
    the Scans hand-off. Every card, every rule, carries Ignore forever,
    Ask and Dismiss."""
    scans = []
    seed = (
        ("mal-1", "malware-detected", "HIGH",
         ["path=/home/x/Downloads/bad.bin"], ["clamav FOUND hit"]),
        ("rk-1", "rootkit-warning", "HIGH",
         ["detail=Warning: file /etc/x.conf changed"], ["Warning: ..."]),
        ("sp-1", "scan-positive", "MEDIUM",
         ["scan_id=run-7"], ["scan run-7 finished"]),
        ("dl-1", "download-double-extension", "HIGH",
         ["path=/home/x/Downloads/doc.pdf.exe"], ["hazard"]),
    )
    for fid, rule, sev, facts, _ev in seed:
        store.append_finding(tmp_path, {
            "id": fid, "ts": _now_stamp(), "rule": rule, "title": fid,
            "what": f"What happened for {fid}.", "next": "Next step.",
            "severity": sev, "confidence": "medium", "status": "lead",
            "facts": facts, "evidence": [], "hunter": "1"})
    panel = HunterPanel(tmp_path, on_scan=scans.append)
    pump(5)
    # malware-detected: delete is the primary, quarantine is the undo
    # lane, a full scan rides after, and the scan lane is wired (button
    # present AND the injected handler asked).
    assert set(_card_labels(_card_of(panel, "mal-1"))) >= {
        "Delete now", "Quarantine (undo lane)", "Run a full scan",
        "Ignore forever", "Ask", "Dismiss this finding"}
    assert _card_labels(_card_of(panel, "rk-1")) >= [
        "Update baseline", "Re-run in Scans"]
    assert _card_labels(_card_of(panel, "sp-1")) >= [
        "Update baseline", "Re-run in Scans"]
    for fid, _rule, _sev, _facts, _ev in seed:
        card = _card_of(panel, fid)
        assert card is not None
        labels = _card_labels(card)
        for need in ("Ignore forever", "Ask", "Dismiss this finding"):
            assert need in labels, f"{fid}: {need} missing"
    # The "Run a full scan" button is a real wire, not copy-text: the
    # click reaches the injected scan seam.
    _buttons_of(_card_of(panel, "mal-1")) and [
        b.emit("clicked") for b in _buttons_of(_card_of(panel, "mal-1"))
        if b.get_child().get_text() == "Run a full scan"]
    pump(5)
    assert scans == ["full"], "the scan hand-off carries the full-scan key"


def test_ignore_forever_keys_rule_and_subject(tmp_path):
    """The suppression is keyed (rule, subject), not the finding id: a
    re-published copy of the same warning under a brand-new id never
    asks again, and the ledger row names the rule and the subject key."""
    old_ts = _now_stamp()
    store.append_finding(tmp_path, {
        "id": "legacy-format:rkh", "ts": old_ts, "rule": "rootkit-warning",
        "title": "The rootkit checker raised a warning",
        "what": "rkhunter: Warning: file changed.", "next": "Review it.",
        "severity": "HIGH", "facts": ["detail=Warning: file changed"],
        "evidence": [], "hunter": "1"})
    panel = HunterPanel(tmp_path)
    pump(5)
    card = _card_of(panel, "legacy-format:rkh")
    assert any(b.get_child().get_text() == "Ignore forever"
               for b in _buttons_of(card))
    next(b for b in _buttons_of(card)
         if b.get_child().get_text() == "Ignore forever").emit("clicked")
    pump(10)
    rows = store.quieted_findings(tmp_path)
    want = store.dedup_key("rootkit-warning", "Warning: file changed")
    assert rows[0]["rule"] == "rootkit-warning"
    assert rows[0]["key"] == want, "the ledger keeps the rule+subject key"
    assert want in store.quieted_keys(tmp_path)
    assert panel._findings == [], "the ignored finding leaves the feed"
    # A re-published identical warning with a NEW id matches the
    # (rule, subject) key and is quieted, though its id is unknown.
    store.append_finding(tmp_path, {
        "id": "fresh-id-after-refire", "ts": _now_stamp(),
        "rule": "rootkit-warning",
        "title": "The rootkit checker raised a warning",
        "what": "rkhunter: Warning: file changed.", "next": "Review it.",
        "severity": "HIGH", "facts": ["detail=Warning: file changed"],
        "evidence": [], "hunter": "1"})
    panel.refresh(force=True)
    pump(5)
    assert [f["id"] for f in panel._findings] == [], (
        "the refired warning is suppressed by rule+subject, not by id")


def test_resolved_findings_collapse_to_one_honest_line(tmp_path):
    store.append_finding(tmp_path, {
        "id": "rk-2", "ts": _now_stamp(), "rule": "rootkit-warning",
        "title": "The rootkit checker raised a warning",
        "what": "rkhunter warned.", "next": "Review it.",
        "severity": "HIGH", "facts": ["detail=Warning: x"], "evidence": [],
        "hunter": "1"})
    store.mark_resolved(tmp_path, {"id": "rk-2"},
                        "baseline updated 13:58")
    panel = HunterPanel(tmp_path)
    pump(5)
    texts = [w.get_text() for w in panel._list.observe_children()]
    assert any("resolved - baseline updated 13:58" in t for t in texts), texts
    assert _card_of(panel, "rk-2") is None, "resolved means no card"
    assert panel._findings == [], "resolved findings are not open leads"


def test_dock_groups_filter_suppressions_watcher(tmp_path):
    panel = HunterPanel(tmp_path)
    pump(5)
    groups = panel.dock_groups()
    assert [name for name, _w in groups] == ["Filter", "Suppressions",
                                             "Watcher"]
    filter_widgets = dict(groups)["Filter"]
    texts = [w.get_text() for w in filter_widgets
             if isinstance(w, Gtk.Label) and w.get_text()]
    assert any("rkhunter" in t or "severity" in t.lower() for t in texts) \
        or len(filter_widgets) >= 3, "the Filter group holds its dropdowns"
    # The suppression list rides in the dock's own group, with a way
    # back per row.
    sup = dict(groups)["Suppressions"]
    assert any(hasattr(w, "observe_children") for w in sup)


def test_thunter_page_entry_pulses_filter():
    """PAGE_ENTRY gains the hunter page: its arrival greets the Filter
    group like the other rebuilt pages greet their first group."""
    assert guided.PAGE_ENTRY.get("thunter") == "Filter"
