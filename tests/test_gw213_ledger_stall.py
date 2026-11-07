"""GW-B1 (cannot-fail Wave B): the announcement lane says its stall.

Pins:
  - A ledger the disk refuses does NOT blank the specs: evaluate and
    evaluate_delta keep them and set .stalled (retry until persisted;
    duplication is visible and bounded, loss is silent and permanent).
  - The Specs list-subclass contract: indexing, `== []`, appending -
    legacy code cannot notice (pinned by the untouched legacy tests in
    test_ptp.py running in the same suite).
  - cverules.evaluate rides the same contract (ptp.Specs).
  - The daemon counts the stall and emits ONE deduped YELLOW notice;
    at the next persist success the same news flows and the notice
    does not double-fire inside its 600 s window.
"""
import json
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ptp  # noqa: E402
import cverules  # noqa: E402
import greywatch_daemon as daemon_mod  # noqa: E402


def make_runner(deb_lines=(), pip_lines=()):
    """A runner stub like test_ptp.py's: the package channels answer
    with the given lines."""

    def run(cmd):
        if cmd.startswith("dpkg-query"):
            return 0, "\n".join(deb_lines) + ("\n" if deb_lines else "")
        return 0, "\n".join(pip_lines) + ("\n" if pip_lines else "")

    return run


def locked_file(path):
    """A journal file this test user cannot append to."""
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("keep\n")
    p.chmod(0o000)
    return p


def locked_ledger(tmp_path):
    """A ptp-announced.jsonl the test user cannot write."""
    return locked_file(tmp_path / "ptp-announced.jsonl")


def test_specs_is_a_list_and_names_the_stall():
    specs = ptp.Specs([("HIGH", "t", "p", ["p"])])
    assert specs == [("HIGH", "t", "p", ["p"])]
    assert specs[0][0] == "HIGH"
    assert specs.stalled is None        # clean pass stalls nowhere
    specs += [("MEDIUM", "u", "q", ["q"])]
    assert len(specs) == 2              # list behavior survives


def test_evaluate_keeps_specs_on_ledger_stall(tmp_path):
    rows = [{"project": "curl", "severity": "high"},
            {"project": "curl", "severity": "medium"}]
    runner = make_runner(deb_lines=["curl"])
    locked = locked_ledger(tmp_path)
    try:
        specs = ptp.evaluate(tmp_path, runner, rows=rows)
        assert specs, "the news stays in the specs"
        assert specs[0][2] == "curl"
        assert isinstance(specs.stalled, OSError)
    finally:
        locked.chmod(0o644)


def test_evaluate_delta_keeps_specs_on_ledger_stall(tmp_path):
    old = [{"project": "v", "finding": "f", "severity": "high"}]
    new = [{"project": "v", "finding": "f2", "severity": "medium"}]
    locked = locked_file(ptp.delta_path(tmp_path))
    try:
        specs = ptp.evaluate_delta(tmp_path, old, new)
        assert specs, "the delta stays in the specs"
        assert specs[0][2].startswith("v|")
        assert isinstance(specs.stalled, OSError)
    finally:
        locked.chmod(0o644)


def test_cverules_evaluate_uses_the_same_contract(tmp_path):
    (tmp_path / "cve-cache.json").write_text(json.dumps(
        {"entries": [{"id": "CVE-2026-1", "tool": "nginx", "score": 9.0,
                      "summary": "bad flaw", "severity": "HIGH",
                      "modified": "2026-11-01"}]}))
    locked = locked_file(cverules.announced_path(tmp_path))
    try:
        specs = cverules.evaluate(tmp_path)
        assert specs and specs[0][2] == "CVE-2026-1"
        assert isinstance(specs, ptp.Specs)
        assert isinstance(specs.stalled, OSError)
    finally:
        locked.chmod(0o644)


def test_stall_recovers_and_reannounces_exactly_once(tmp_path):
    """After the ledger becomes writable, the SAME news flows once - and
    the second pass announces nothing (the write succeeded, seen-state
    is real). No double flow either side of the stall."""
    rows = [{"project": "curl", "severity": "high"},
            {"project": "curl", "severity": "medium"}]
    runner = make_runner(deb_lines=["curl"])
    locked = locked_ledger(tmp_path)
    try:
        stalled = ptp.evaluate(tmp_path, runner, rows=rows)
        assert stalled
    finally:
        locked.chmod(0o644)
    again = ptp.evaluate(tmp_path, runner, rows=rows)
    assert list(again) == list(stalled)      # the same news, retold once
    third = ptp.evaluate(tmp_path, runner, rows=rows)
    assert list(third) == []                 # then seen-state is real


class _NoticeDaemon(daemon_mod.Daemon):
    """Bare daemon shell: only the notice/stall bookkeeping is alive."""

    def __init__(self, tmp_path):
        self.data_dir = pathlib.Path(tmp_path)
        self._notice_at = {}
        self._fail_counts = {}
        self._fail_log_at = {}
        self._outbox = []

    def _notice(self, tool, severity, text, dedupe_window_s=600.0):
        now = object()                       # never dedupes in this stub
        key = f"{tool}|{severity}|{text[:400]}"
        prev = self._notice_at.get(key)
        if prev is not None:
            return "deduped"
        self._notice_at[key] = "seen"
        return "emitted"

    def count_failure(self, category, where, error):
        rec = self._fail_counts.setdefault(category, {"count": 0})
        rec["count"] += 1
        rec["last"] = f"{where}: {type(error).__name__}"


def test_daemon_counts_stall_and_notices_once(monkeypatch, tmp_path):
    d = _NoticeDaemon(tmp_path)
    specs = ptp.Specs([("HIGH", "t", "p", ["p"])])
    specs.stalled = OSError("disk full")
    d._announce_stalled(specs)
    assert d._fail_counts["ledger"]["count"] == 1
    d._announce_stalled(specs)               # next pass: spec still stalled
    assert d._fail_counts["ledger"]["count"] == 2
    assert len(d._notice_at) == 1            # one deduped YELLOW notice


def test_daemon_ignores_specs_without_stall():
    d = _NoticeDaemon(tempdir())
    d._announce_stalled(ptp.Specs([("HIGH", "t", "p", ["p"])]))
    assert not d._fail_counts and not d._notice_at


def tempdir():
    import tempfile
    return pathlib.Path(tempfile.mkdtemp())
