"""Pins for the Findings page: triage, recent runs and the schedule,
with no scan controls.

Answering a decision runs on the action worker, so the click returns at
once, and the answered ask row leaves its parent when the CLI reports
back."""

from __future__ import annotations

import json
import subprocess

import gi
import pytest

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from tests.test_ui_v4 import _ShellStub
from ui import findings


class _InlineThread:
    """Run the work on the test thread, so no worker leaks past the test."""

    def __init__(self, *args, **kwargs):
        self._target = kwargs.get("target") or (args[0] if args else None)

    def start(self):
        self._target()


@pytest.fixture
def hermetic(monkeypatch):
    """No real systemctl, no real CLI, and no background threads."""
    monkeypatch.setattr(findings.threading, "Thread", _InlineThread)
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    monkeypatch.setattr(findings.cliapi, "jcall",
                        lambda *a, **k: {"pending": [], "answered": []})
    monkeypatch.setattr(findings.cliapi, "call",
                        lambda *a, **k: (0, "answered", ""))
    return findings


def _texts(w) -> str:
    out = []
    label = w.get_label() if isinstance(w, Gtk.Label) else None
    if label:
        out.append(label)
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        out.append(_texts(child))
        child = child.get_next_sibling()
    return " ".join(out)


def _buttons(w) -> list:
    out = []
    if isinstance(w, Gtk.Button):
        out.append(w)
        return out
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        out.extend(_buttons(child))
        child = child.get_next_sibling()
    return out


def _button(root, label):
    for b in _buttons(root):
        if b.get_label() == label:
            return b
    raise AssertionError(f"button {label!r} missing")


def _pump(iterations=400):
    """The answer worker lands through GLib.idle_add."""
    import time
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(iterations):
        ctx.iteration(False)
        time.sleep(0.002)


def test_findings_has_triage_runs_and_schedule_without_scan_controls(
        tmp_path, monkeypatch, hermetic):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "scan-whitelist.json").write_text(json.dumps({"entries": []}))
    (tmp_path / "quarantine.jsonl").write_text("")
    page = hermetic.build(_ShellStub())
    _pump()
    texts = _texts(page).lower()
    assert "triage" in texts
    assert "recent runs" in texts
    assert "the schedule" in texts
    labels = [b.get_label() for b in _buttons(page)]
    for forbidden in ("Quick scan", "Deep scan", "Pause", "Resume"):
        assert forbidden not in labels


def test_disabled_scan_timers_are_not_listed(tmp_path, monkeypatch):
    from ui import findings
    rows = Gtk.Box()
    # Real `systemctl list-timers --all` rows: NEXT, LEFT, LAST, PASSED,
    # UNIT, then ACTIVATES (a `.service`). Disabled units read n/a.
    out = ("Mon 2026-11-19 12:00:00 UTC  1h  Sun 2026-11-18 11:00:00 UTC  "
           "2h ago  greywatch-cve.timer  greywatch-cve.service\n"
           "Mon 2026-11-19 13:00:00 UTC  2h  Sun 2026-11-18 12:00:00 UTC  "
           "3h ago  aide-check.timer  aide-check.service\n"
           "n/a  n/a  n/a  n/a  greywatch-feeds.timer  "
           "greywatch-feeds.service\n"
           "n/a  n/a  n/a  n/a  greywatch-clam-scan.timer  "
           "greywatch-clam-scan.service\n"
           "n/a  n/a  n/a  n/a  greywatch-boot-sweep.timer  "
           "greywatch-boot-sweep.service\n")
    findings._schedule_fill(rows, out)
    text = _texts(rows)
    assert "greywatch-cve.timer" in text
    assert "aide-check.timer" in text
    assert "greywatch-feeds.timer" not in text
    assert "clam-scan" not in text
    assert "boot-sweep" not in text
    assert "n/a (in n/a)" not in text


def test_answering_a_decision_runs_off_the_main_thread_and_removes_the_ask(
        tmp_path, monkeypatch):
    from ui import findings, cliapi
    monkeypatch.setattr(cliapi, "call",
                        lambda *a, **k: (0, "answered", ""))
    page = Gtk.Box()
    page._gw_window = _ShellStub()
    box = Gtk.Box()
    ask = {"id": "ask-1", "question": "Allow this program?",
           "options": [{"id": "allow", "label": "Allow"}]}
    row = findings._ask_box(page, ask)
    box.append(row)
    button = _button(row, "Allow")
    button.emit("clicked")
    assert not button.get_sensitive()
    _pump()
    assert box.get_first_child() is None


def test_failed_answer_keeps_the_ask_row_and_notes_the_error(
        tmp_path, monkeypatch):
    from ui import findings, cliapi
    monkeypatch.setattr(cliapi, "call",
                        lambda *a, **k: (1, "", "answer refused"))
    page = Gtk.Box()
    shell = _ShellStub()
    page._gw_window = shell
    box = Gtk.Box()
    ask = {"id": "ask-2", "question": "Allow this program?",
           "options": [{"id": "allow", "label": "Allow"}]}
    row = findings._ask_box(page, ask)
    box.append(row)
    _button(row, "Allow").emit("clicked")
    _pump()
    assert box.get_first_child() is row
    assert "answer refused" in shell.last_note
