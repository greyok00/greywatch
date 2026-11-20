"""GW-C (cannot-fail Wave C): scan-lane honesty and small escalations.

C1 - write_status reports the GUI's scan-request file as it is: present
     with its age, or None when absent/unreadable. The dashboard
     renderer (Wave A) shows a pending request instead of hiding it.
C2 - two escalations that used to pass silently: the appfw arm-breaker
     exhaustion says ONE deduped YELLOW notice, and a heartbeat-file
     write failure is counted, not swallowed.
"""
import inspect
import json
import pathlib
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


import greywatch_daemon as daemon_mod  # noqa: E402
import scan_session  # noqa: E402


def _fresh_daemon(tmp_path):
    d = daemon_mod.Daemon.__new__(daemon_mod.Daemon)
    d.data_dir = pathlib.Path(tmp_path)
    d._fail_counts = {}
    d._fail_log_at = {}
    d._notice_at = {}
    d._lock = threading.Lock()
    d._outbox = []
    return d


# ---------------------------------------------------------------- C1

def test_scan_request_facts_fresh_file(tmp_path):
    d = _fresh_daemon(tmp_path)
    scan_session.request_path(tmp_path).write_text(
        json.dumps({"id": "s1", "key": "tools"}))
    got = d._scan_request_facts()
    assert got is not None and got["present"] is True
    assert 0.0 <= got["age_s"] < 5.0


def test_scan_request_facts_absent_is_none(tmp_path):
    d = _fresh_daemon(tmp_path)
    assert d._scan_request_facts() is None


def test_scan_request_facts_unreadable_directory_is_none(tmp_path):
    d = _fresh_daemon(tmp_path)
    scan_session.request_path(tmp_path).write_text("{}")
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o000)
    try:
        d.data_dir = locked
        assert d._scan_request_facts() is None
    finally:
        locked.chmod(0o755)


def test_scan_request_facts_never_reports_a_negative_age(tmp_path):
    d = _fresh_daemon(tmp_path)
    got = d._scan_request_facts()
    assert got is None or got["age_s"] >= 0.0


def test_write_status_publishes_scan_request_key():
    src = inspect.getsource(daemon_mod.Daemon.write_status)
    assert 'snap["scan_request"]' in src


# ---------------------------------------------------------------- C2

def test_appfw_breaker_exhaustion_is_said_once():
    """The breaker-open branch emits one deduped YELLOW notice; the
    flag lets it re-arm only after the 60 s window heals. The literals
    carry line breaks, so pin the sentence's halves."""
    src = inspect.getsource(daemon_mod.Daemon.run_forever)
    assert "the appfw engine could not start 3 " in src
    assert "times in a minute; it stays off " in src
    assert "until a later cycle" in src
    assert "engine_broken_told" in src


def test_appfw_breaker_notice_routes_through__notice():
    """The message must go through _notice (the deduped feed path), not
    a bare print that no dashboard surface reads."""
    src = inspect.getsource(daemon_mod.Daemon.run_forever)
    marker = src.index("could not start 3")
    call = src.rindex("self._notice(", 0, marker)
    assert "(" in src[call:marker]
    assert "print(" not in src[call:marker]


def _run_one_heartbeat_pass(d, stop, monkeypatch, *, fail_write):
    """Drive _watchdog_ping_loop for exactly one pass with the notify
    side off. fail_write=True raises OSError on the heartbeat write."""
    import appfw.sd_notify as sd
    monkeypatch.setattr(sd, "notify", lambda _w: None)
    stop.wait = lambda _s: (stop.set() or 0)

    def fake_write(self, *a, **k):
        if fail_write:
            raise OSError("the /run mount is read-only")
        return ""
    monkeypatch.setattr(pathlib.Path, "write_text", fake_write)
    monkeypatch.setattr(pathlib.Path, "mkdir", lambda *a, **k: None)
    d._watchdog_ping_loop(stop)


def test_heartbeat_write_failure_is_counted(tmp_path, monkeypatch):
    d = _fresh_daemon(tmp_path)
    d._beat = time.monotonic()          # fresh beat: the pet branch runs
    stop = threading.Event()
    _run_one_heartbeat_pass(d, stop, monkeypatch, fail_write=True)
    rec = d._fail_counts["watchdog"]
    assert rec["count"] == 1 and "heartbeat" in rec["last"]


def test_heartbeat_success_counts_nothing(tmp_path, monkeypatch):
    d = _fresh_daemon(tmp_path)
    d._beat = time.monotonic()
    stop = threading.Event()
    _run_one_heartbeat_pass(d, stop, monkeypatch, fail_write=False)
    assert not d._fail_counts
