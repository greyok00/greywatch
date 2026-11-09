"""GW-B2/B3/B4 (cannot-fail Wave B): the honesty lanes.

B2 - a package channel that cannot be read never reads as "nothing is
     covered": installed_names reports per-channel failure, coverage
     carries probe_failed, the watch file publishes it beside projects,
     and both renderers say UNKNOWN instead of inventing empty.
B3 - the nft verify-probe failure is latched, counted, and said in the
     defense digest; the fail-open sweep itself is unchanged (no churn,
     blocks are never removed because a probe was blind).
B4 - event lines that the reclaim cap throws away during a write
     outage are counted, published as outbox_dropped, and said in the
     fails band.
"""
import inspect
import json
import pathlib
import subprocess
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import ptp  # noqa: E402
import greywatch_daemon as daemon_mod  # noqa: E402
from ui import defense  # noqa: E402


def _runner(rc_dp=0, out_dp="curl\n", rc_pip=0, out_pip="flask\n"):

    def run(cmd):
        if cmd.startswith("dpkg-query"):
            return rc_dp, out_dp
        return rc_pip, out_pip
    return run


# ---------------------------------------------------------------- B2

def test_installed_names_reports_failed_channels():
    deb, pip, failed = ptp.installed_names(_runner())
    assert deb == {"curl"} and pip == {"flask"} and failed == []

    deb, pip, failed = ptp.installed_names(_runner(rc_dp=1, out_dp=""))
    assert deb == set() and failed == ["dpkg-query"]

    deb, pip, failed = ptp.installed_names(_runner(rc_pip=1, out_pip=""))
    assert pip == set() and failed == ["pip"]

    def raising(cmd):
        raise RuntimeError("channel gone")
    deb, pip, failed = ptp.installed_names(raising)
    assert set(failed) == {"dpkg-query", "pip"}
    assert deb == set() and pip == set()


def test_coverage_carries_probe_failed(tmp_path):
    rows = [{"project": "curl", "severity": "high"},
            {"project": "curl", "severity": "medium"}]
    ok = ptp.coverage(rows, _runner())
    assert ok and [c["project"] for c in ok] == ["curl"]
    assert ok.probe_failed is None                # clean probe: nothing

    dark = ptp.coverage(rows, _runner(rc_dp=1, out_dp=""))
    assert dark == []                             # no rows answer via deb
    assert dark.probe_failed == ["dpkg-query"]    # but the gap is NAMED


def _fresh_daemon(tmp_path):
    d = daemon_mod.Daemon.__new__(daemon_mod.Daemon)
    d.data_dir = pathlib.Path(tmp_path)
    d._fail_counts = {}
    d._fail_log_at = {}
    d._notice_at = {}
    d._lock = threading.Lock()
    d._outbox = []
    d._verify_unsure = False
    d._outbox_dropped = 0
    return d


def test_daemon_publishes_probe_failed_beside_projects(tmp_path, monkeypatch):
    d = _fresh_daemon(tmp_path)

    def fake_coverage(rows, runner):
        cov = ptp.Coverage()
        cov.append({"project": "curl", "findings": 2, "high": 1,
                    "medium": 1, "low": 0, "via": "deb",
                    "packages": ["curl"]})
        cov.probe_failed = ["dpkg-query", "pip"]
        return cov

    monkeypatch.setattr(ptp, "load_map", lambda dd: [
        {"project": "curl", "severity": "high"},        # the first read
        {"project": "curl", "severity": "medium"}])
    monkeypatch.setattr(ptp, "refresh", lambda dd: 0)
    monkeypatch.setattr(ptp, "evaluate_delta",
                        lambda *a, **k: ptp.Specs())
    monkeypatch.setattr(ptp, "evaluate", lambda *a, **k: ptp.Specs())
    monkeypatch.setattr(ptp, "coverage", fake_coverage)
    d.ptp_watch()
    watch = json.loads((tmp_path / "ptp-watch.json").read_text())
    assert watch["projects"][0]["project"] == "curl"
    assert watch["probe_failed"] == ["dpkg-query", "pip"]


def test_daemon_publishes_empty_probe_failed_when_all_ok(tmp_path,
                                                         monkeypatch):
    d = _fresh_daemon(tmp_path)

    def fake_coverage(rows, runner):
        cov = ptp.Coverage()
        cov.append({"project": "curl", "findings": 2, "high": 1,
                    "medium": 1, "low": 0, "via": "deb",
                    "packages": ["curl"]})
        cov.probe_failed = None
        return cov

    monkeypatch.setattr(ptp, "load_map", lambda dd: [
        {"project": "curl", "severity": "high"}])
    monkeypatch.setattr(ptp, "refresh", lambda dd: 0)
    monkeypatch.setattr(ptp, "evaluate_delta",
                        lambda *a, **k: ptp.Specs())
    monkeypatch.setattr(ptp, "evaluate", lambda *a, **k: ptp.Specs())
    monkeypatch.setattr(ptp, "coverage", fake_coverage)
    d.ptp_watch()
    watch = json.loads((tmp_path / "ptp-watch.json").read_text())
    assert watch["probe_failed"] == []


def test_old_watch_file_without_key_reads_as_all_ok(tmp_path):
    (tmp_path / "ptp-watch.json").write_text(json.dumps(
        {"ts": "2026-11-06T21:00:00+00:00",
         "projects": [{"project": "curl", "findings": 2, "high": 1,
                       "medium": 1, "low": 0, "via": "deb",
                       "packages": ["curl"]}]}))
    assert defense.ptp_probe_failed(tmp_path) == []
    assert defense.ptp_rows(tmp_path)[0]["project"] == "curl"


def test_unreadable_watch_file_names_no_channels(tmp_path):
    (tmp_path / "ptp-watch.json").write_text("not json")
    assert defense.ptp_probe_failed(tmp_path) == []
    (tmp_path / "ptp-watch.json").chmod(0o000)
    try:
        assert defense.ptp_probe_failed(tmp_path) == []
    finally:
        (tmp_path / "ptp-watch.json").chmod(0o644)


# ---- the defense page renders the UNKNOWN claim over a dead probe ----
def _walk_labels(host):
    out = []

    def walk(w):
        for k in list(w) if hasattr(w, "__iter__") else []:
            if getattr(k, "get_label", None):
                out.append(str(k.get_label()))
            walk(k)
    if hasattr(host, "__iter__"):
        walk(host)
    return out


@pytest.fixture
def defense_view(monkeypatch):
    import gi
    gi.require_version("Gtk", "4.0")
    v = defense.DefenseView()
    monkeypatch.setattr(defense, "cve_rows", lambda _dd: [])
    monkeypatch.setattr(defense, "psad_status", lambda: {})
    monkeypatch.setattr(defense, "arp_status", lambda: {})
    return v


def test_defense_page_says_unknown_when_channel_failed(monkeypatch,
                                                       defense_view,
                                                       tmp_path):
    v = defense_view
    monkeypatch.setattr(defense, "ptp_rows", lambda _dd: [])
    monkeypatch.setattr(defense, "ptp_probe_failed",
                        lambda _dd: ["dpkg-query", "pip"])
    v.refresh({"defense": {}})
    text = " ".join(_walk_labels(v._armor))
    assert "could not be read" in text and "UNKNOWN" in text
    assert "review map" not in text


def test_defense_page_keeps_the_old_sentence_when_all_ok(monkeypatch,
                                                         defense_view):
    v = defense_view
    monkeypatch.setattr(defense, "ptp_rows", lambda _dd: [])
    monkeypatch.setattr(defense, "ptp_probe_failed", lambda _dd: [])
    v.refresh({"defense": {}})
    text = " ".join(_walk_labels(v._armor))
    assert "nothing this machine runs is inside the review map" in text
    assert "UNKNOWN" not in text


def test_assistant_answers_unknown_when_channel_failed():
    from ui import assistant
    watch = {"projects": [], "probe_failed": ["pip"]}
    got = assistant._ptp_concept_text(
        "am i covered?", {"ptp": watch})
    assert "UNKNOWN" in got and "pip" in got
    assert "nothing this machine runs" not in got

    ok = assistant._ptp_concept_text(
        "am i covered?", {"ptp": {"projects": []}})
    assert "nothing this machine runs" in ok
    assert "UNKNOWN" not in ok


# ---------------------------------------------------------------- B3

class _Bare:
    """Just what _firewall_has_block and count_failure touch."""

    def __init__(self):
        self._verify_unsure = False
        self._fail_counts = {}
        self._fail_log_at = {}

    def count_failure(self, category, where, error):
        rec = self._fail_counts.setdefault(
            category, {"count": 0, "last": ""})
        rec["count"] += 1
        rec["last"] = f"{where}: {type(error).__name__}"


def test_verify_probe_failure_latches_and_fails_open(monkeypatch):
    b = _Bare()

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(["nft"], 10)
    monkeypatch.setattr(subprocess, "run", boom)
    assert daemon_mod.Daemon._firewall_has_block(b, "10.0.0.1") is True
    assert b._verify_unsure is True
    assert b._fail_counts["ledger"]["count"] == 1


def test_verify_probe_success_clears_the_latch(monkeypatch):
    b = _Bare()
    b._verify_unsure = True

    def ok_probe(*a, **k):
        class R:
            returncode = 0
        return R()
    monkeypatch.setattr(subprocess, "run", ok_probe)
    assert daemon_mod.Daemon._firewall_has_block(b, "10.0.0.1") is True
    assert b._verify_unsure is False

    def off_probe(*a, **k):
        class R:
            returncode = 1      # block genuinely absent: still a RUN
        return R()
    monkeypatch.setattr(subprocess, "run", off_probe)
    assert daemon_mod.Daemon._firewall_has_block(b, "10.0.0.2") is False
    assert b._verify_unsure is False   # a real verdict clears uncertainty


def test_digest_carries_verify_note_while_latched():
    # write_status is too stateful to run bare; the sentence is the
    # contract the runbooks quote, so pin its halves in the source
    # (the literals carry line breaks, so match each half).
    src = inspect.getsource(daemon_mod.Daemon.write_status)
    assert "block verification could not run; blocks are left " in src
    assert 'untouched")' in src
    assert "_verify_unsure" in src


# ---------------------------------------------------------------- B4

def test_flush_outbox_counts_drops_beyond_the_reclaim(tmp_path,
                                                      monkeypatch):
    d = _fresh_daemon(tmp_path)
    d.events_path = tmp_path / "events.jsonl"
    d.ui_gid = None
    for i in range(2500):
        d._outbox.append(json.dumps({"n": i}))

    def refuse(*a, **k):
        raise OSError("the journal is full")

    monkeypatch.setattr(daemon_mod, "append_checked", refuse)
    assert d.flush_outbox() == 0
    assert d._outbox_dropped == 500
    assert len(d._outbox) == 2000          # the newest 2000 stay


def test_flush_outbox_does_not_count_lines_that_arrived_during_the_flush(
        tmp_path, monkeypatch):
    d = _fresh_daemon(tmp_path)
    d.events_path = tmp_path / "events.jsonl"
    d.ui_gid = None
    for i in range(2500):
        d._outbox.append(f"line-{i}")

    def refuse_but_accept_new_lines(*a, **k):
        d._outbox.append("line-arrived-mid-write")
        raise OSError("the journal is full")

    monkeypatch.setattr(daemon_mod, "append_checked",
                        refuse_but_accept_new_lines)
    d.flush_outbox()
    assert d._outbox_dropped == 500        # only the reclaim's excess
    assert "line-arrived-mid-write" in d._outbox
    assert len(d._outbox) == 2001


def test_outbox_dropped_publishes_in_status():
    src = inspect.getsource(daemon_mod.Daemon.write_status)
    assert 'snap["outbox_dropped"]' in src
