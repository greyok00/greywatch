"""Task 4 of the 2026-11-03 full-UI redesign: the Home hybrid the owner
approved. Unread hunter notes pin on top of Home until they are read;
after that each becomes exactly one report bubble in the conversation —
and only notes a digest actually pinned report back, never old history.

Everything here reads hunter-written files (findings.jsonl, defender
notes) with the same tmp-seeding the hunter tests use; the AI never
authors these texts, it only rewords them into a bubble."""
import json
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

from hunter import explain, store  # noqa: E402
from ui.homepage import (HomeDigest, SuiteCard, report_text,  # noqa: E402
                         suite_summary, unread_notes)


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


def _notes_at(data_dir, day):
    """Two findings with two defender notes so a digest has something to
    pin. Old is the earlier note; the newest note's ts came back so a
    test can move the read pointer exactly past the pair."""
    store.append_finding(data_dir, {
        "id": f"old-{day}", "ts": f"2026-11-{day}T09:00:00+00:00",
        "rule": "download-double-extension",
        "title": "Old finding on the plate",
        "what": "An old program dressed as a document landed.",
        "next": "Delete it.", "severity": "HIGH",
        "facts": [], "evidence": [], "hunter": "1"})
    store.append_defender(data_dir, {
        "ts": f"2026-11-{day}T09:00:01+00:00", "kind": "rule",
        "finding_id": f"old-{day}", "severity": "HIGH",
        "text": "A file named like a document is a program.",
        "hint": "Delete it."})
    store.append_finding(data_dir, {
        "id": f"new-{day}", "ts": f"2026-11-{day}T11:00:00+00:00",
        "rule": "config-suspicious-extension",
        "title": "New finding on the plate",
        "what": "A setting looks configured against usual practice.",
        "next": "Look at it in Protections.", "severity": "MEDIUM",
        "facts": [], "evidence": [], "hunter": "1"})
    store.append_defender(data_dir, {
        "ts": f"2026-11-{day}T11:00:01+00:00", "kind": "rule",
        "finding_id": f"new-{day}", "severity": "MEDIUM",
        "text": "A setting drifted from the usual safe shape.",
        "hint": "Check it."})
    return f"2026-11-{day}T11:00:01+00:00"


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


def test_unread_notes_are_pointer_relative_and_newest_first(tmp_path):
    newest = _notes_at(tmp_path, "10")
    assert [n.get("finding_id") for n in unread_notes(tmp_path)] \
        == ["new-10", "old-10"]
    explain.mark_read(tmp_path, newest)
    assert unread_notes(tmp_path) == []


def test_digest_pins_unread_with_ask_and_open_buttons(tmp_path):
    _notes_at(tmp_path, "11")
    asked, opened = [], []

    def on_explain(question, finding=None):
        asked.append((question, finding))

    def on_open():
        opened.append(True)

    dig = HomeDigest(tmp_path, on_explain=on_explain, on_open=on_open)
    count = dig.refresh()
    pump(5)
    assert count == 2
    assert dig.get_visible()
    rows = list(dig._rows.observe_children())
    assert len(rows) == 2, "the newest unread notes pin, newest first"
    # The pin ledger carries newest first and is what the hand-over reads.
    assert dig.last_ids == [
        "2026-11-11T11:00:01+00:00", "2026-11-11T09:00:01+00:00"]
    # The Ask button asks the same question the finding rows ask, with the
    # finding in tow so the advice answers about the exact line.
    ask_btn = _button_with_label(dig._rows, "Ask about this")
    ask_btn.emit("clicked")
    pump(2)
    assert asked and asked[0][0].startswith("Explain this hunter finding:")
    assert "New finding on the plate" in asked[0][0]
    assert asked[0][1].get("id") == "new-11"
    open_btn = _button_with_label(dig._rows, "Open the hunter")
    open_btn.emit("clicked")
    pump(2)
    assert opened == [True]


def test_digest_hides_when_everything_is_read(tmp_path):
    newest = _notes_at(tmp_path, "12")
    dig = HomeDigest(tmp_path)
    assert dig.refresh() == 2
    assert dig.get_visible()
    assert dig.refresh() == 2, "a refresh alone never marks anything read"
    explain.mark_read(tmp_path, newest)
    assert dig.refresh() == 0
    assert not dig.get_visible()
    assert dig.last_ids == []


def test_report_text_says_what_it_found_and_what_is_next(tmp_path):
    _notes_at(tmp_path, "13")
    findings = {f["id"]: f for f in store.read_findings(tmp_path, 10)}
    note = [n for n in store.read_defender(tmp_path, 10)
            if n.get("finding_id") == "old-13"][0]
    text = report_text(note, findings["old-13"])
    assert text.startswith("Browser Watch report")
    assert "Old finding on the plate" in text
    assert "A file named like a document is a program." in text
    assert "Delete it." in text
    # A note whose finding already rotated out still reports cleanly from
    # the note's own language.
    assert report_text(note, None).startswith("Browser Watch report")


# --- the suite-first Home lead (GW-121) ----------------------------------

def _status(tmp_path, states, pending=0, updated="2026-11-04T00:16:43+00:00",
            labels=None):
    tools = {}
    for i, s in enumerate(states):
        row = {"state": s}
        if labels and i < len(labels):
            row["label"] = labels[i]
        tools[f"t{i}"] = row
    raw = {"updated": updated, "pending_decisions": pending,
           "tools": tools}
    (tmp_path / "status.json").write_text(json.dumps(raw), encoding="utf-8")


def test_suite_summary_counts_only_real_problems(tmp_path):
    """GW-121: the verdict counts protections that want the owner's hand;
    UNKNOWN (never reported in) is neither bad nor in the checked total,
    so 'All N are green' stays a checked count."""
    _status(tmp_path, ["GREEN", "GREEN", "GREEN", "UNKNOWN"])
    verdict, subline = suite_summary(tmp_path)
    assert verdict == "All 3 protections are green"
    assert "no decisions waiting" in subline
    assert "snapshot 00:16" in subline
    _status(tmp_path, ["GREEN", "YELLOW", "RED"])
    verdict, _ = suite_summary(tmp_path)
    assert verdict == "2 protections need attention"
    _status(tmp_path, ["GREEN", "RED"])
    verdict, _ = suite_summary(tmp_path)
    assert verdict == "1 protection needs attention"
    _status(tmp_path, ["YELLOW", "ORANGE", "FAIL", "RED"])
    verdict, _ = suite_summary(tmp_path)
    assert verdict == "4 protections need attention"


def test_suite_summary_says_when_nothing_has_reported(tmp_path):
    """No snapshot (or an empty one) reads as 'starting', never as
    'all green' — an uncounted suite must not claim health."""
    verdict, _ = suite_summary(tmp_path)
    assert verdict == "The suite is starting"
    _status(tmp_path, [])
    verdict, subline = suite_summary(tmp_path)
    assert verdict == "The suite is starting"
    _status(tmp_path, ["UNKNOWN", "UNKNOWN"])
    verdict, _ = suite_summary(tmp_path)
    assert verdict == "The suite is starting"
    # Broken snapshot bytes degrade to the same honest line.
    (tmp_path / "status.json").write_text("{oops", encoding="utf-8")
    verdict, _ = suite_summary(tmp_path)
    assert verdict == "The suite is starting"


def test_suite_summary_counts_pending_decisions(tmp_path):
    _status(tmp_path, ["GREEN", "GREEN"], pending=3)
    _, subline = suite_summary(tmp_path)
    assert "3 decisions waiting" in subline
    _status(tmp_path, ["GREEN", "GREEN"], pending=1)
    _, subline = suite_summary(tmp_path)
    assert "1 decision waiting" in subline


def test_suite_summary_names_the_protections_it_counts(tmp_path):
    """GW-182 (owner 2026-11-05: "one protection... I don't know what it
    is... nothing that outlines what it needs to fix"): the count sentence
    names what it counted, using the snapshot's own labels, and the card
    opens the Protections desk where each one is answerable. A row the
    snapshot never named says so honestly instead of vanishing."""
    _status(tmp_path, ["GREEN", "YELLOW", "RED"],
            labels=["Antivirus", "Network firewall", "Startup watcher"])
    verdict, subline = suite_summary(tmp_path)
    assert verdict == "2 protections need attention"
    assert "Network firewall" in subline and "Startup watcher" in subline
    assert "no decisions waiting" in subline
    _status(tmp_path, ["RED"])
    verdict, subline = suite_summary(tmp_path)
    assert verdict == "1 protection needs attention"
    assert "one that has not named itself" in subline


def test_suite_card_opens_the_protections_desk(tmp_path):
    _status(tmp_path, ["RED"], labels=["Antivirus"])
    opened = []
    card = SuiteCard(tmp_path, on_open=lambda: opened.append(1))
    pump(5)
    assert opened == [], "a card nobody clicks leads nowhere"
    card._on_click(None, 1, 0.0, 0.0)
    assert opened == [1]


def test_suite_card_widget_leads_with_the_verdict(tmp_path):
    _status(tmp_path, ["GREEN", "GREEN", "YELLOW"])
    card = SuiteCard(tmp_path)
    pump(5)
    assert card.get_parent() is None, "the window mounts this card"
    labels = [c for c in card.observe_children()
              if isinstance(c, Gtk.Label)]
    texts = [lab.get_text() for lab in labels]
    assert texts[0] == "Security suite"
    assert "1 protection needs attention" in texts[1]
    _status(tmp_path, ["GREEN", "GREEN"])
    card.refresh()
    assert card.verdict.get_text() == "All 2 protections are green"


# --- the Home hand-over on the real window ------------------------------

@pytest.fixture(scope="module")
def win():
    from ui.window import MainWindow
    w = MainWindow()
    w.present()
    pump(30)
    yield w
    w.destroy()


@pytest.fixture
def notebook(win, tmp_path):
    """The shared module window pointed at a private, empty data dir, with
    the hand-over ledgers reset so each test starts its own story."""
    old = win.data_dir
    win.data_dir = pathlib.Path(tmp_path)
    win._pinned_ids = set()
    win._reports_shown = set()
    yield win, pathlib.Path(tmp_path)
    win.data_dir = old
    win._pinned_ids = set()
    win._reports_shown = set()


def _window_reports(win):
    return [str(p[0]) for p in getattr(win.assistant_panel, "_transcript", [])
            if str(p[0]).startswith("Browser Watch report")]


def test_hybrid_home_starts_clean_without_hunter_files(notebook):
    """Round-2 re-root (task 8): the unread pin rides the Threat
    Hunter's own rail row again - clean dir, no badge."""
    win, data_dir = notebook
    win.refresh()
    pump(6)
    badge = win._badges["thunter"]
    assert not badge.get_visible()


def test_hybrid_home_pins_then_hands_over_once(notebook):
    """Round-2 re-root (task 8): the pin survives through the Threat
    Hunter rail row's badge - two unread notes show as 2, reading them
    (mark_read, the way opening the hunter page does) agrees at zero,
    and further refreshes never re-count."""
    win, data_dir = notebook
    newest = _notes_at(data_dir, "14")
    win.refresh()
    pump(6)
    badge = win._badges["thunter"]
    assert badge.get_visible() and badge.get_text() == "2"
    explain.mark_read(data_dir, newest)
    win.refresh()
    pump(6)
    assert not badge.get_visible(), "the badge and the digest agree at zero"
    win.refresh()
    win.refresh()
    pump(6)
    assert not badge.get_visible()


def test_hybrid_home_reports_follow_window_data_dir(notebook):
    """The unread count follows the window's data dir (tests swap it,
    tools re-point it) instead of freezing the directory it was built
    with - re-rooted with the round-2 badge move to the hunter row."""
    win, data_dir = notebook
    _notes_at(data_dir, "15")
    win.refresh()
    pump(6)
    assert win._badges["thunter"].get_visible()
    # A different dir under the same pointer: the count follows the move.
    _notes_at(data_dir / "elsewhere", "16")
    win.data_dir = data_dir / "elsewhere"
    win.refresh()
    pump(6)
    assert win._badges["thunter"].get_text() == "2"
    win.data_dir = data_dir

def test_unread_notes_ride_each_notes_own_time(tmp_path):
    """The other half of GW-119 (2026-11-03): an older-evidence note can
    land in the file after a newer one; the pin order reads by the
    note's own time, not the write order."""
    store.append_finding(tmp_path, {
        "id": "new-early", "ts": "2026-11-03T11:00:00+00:00",
        "rule": "download-double-extension",
        "title": "Newer note, written first", "what": "What happened.",
        "next": "Next step.", "severity": "HIGH",
        "facts": [], "evidence": [], "hunter": "1"})
    store.append_defender(tmp_path, {
        "ts": "2026-11-03T11:00:01+00:00", "kind": "rule",
        "finding_id": "new-early", "severity": "HIGH",
        "text": "Newer note.", "hint": "Next step."})
    store.append_finding(tmp_path, {
        "id": "old-late", "ts": "2026-11-01T09:00:00+00:00",
        "rule": "startup-folder-helper",
        "title": "Older note, written last", "what": "What happened.",
        "next": "Next step.", "severity": "LOW",
        "facts": [], "evidence": [], "hunter": "1"})
    store.append_defender(tmp_path, {
        "ts": "2026-11-01T09:00:01+00:00", "kind": "rule",
        "finding_id": "old-late", "severity": "LOW",
        "text": "Older note.", "hint": "Next step."})
    assert [n.get("finding_id") for n in unread_notes(tmp_path)] \
        == ["new-early", "old-late"]
