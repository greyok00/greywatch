"""Regression tests for the source-review security fix list:
status.json group-restriction, the backlog watchdog measurement
interface, the headless ask policy, swallowed failure visibility, and
--data-dir isolation. GW round 2 adds: symlink-proof root writes (GW-01),
UI identity resolution (GW-02), and the deny-once headless ask default
(GW-03)."""
import json
import os
import stat as stat_mod

import greywatch_daemon as gd
from greywatch_daemon import Daemon
from status import load_status, write_status


def mk_daemon(tmp_path, **kw):
    from registry import load_registry
    return Daemon(data_dir=tmp_path / "data", registry=load_registry(), **kw)


class _FakeSock:
    def fileno(self):
        return 0


class _FakeProc:
    def poll(self):
        return None


# ---- fix 2: status.json is not world-readable --------------------------

def test_status_written_restricted(tmp_path):
    d = mk_daemon(tmp_path)
    d.write_status()
    mode = d.status_path.stat().st_mode & 0o777
    assert mode & 0o007 == 0                       # others: nothing
    if d.ui_gid is not None:                       # owner+group read at most
        assert mode == 0o640
    else:
        assert mode == 0o600


def test_write_status_without_group_is_0600(tmp_path):
    path = str(tmp_path / "status.json")
    write_status(path, {"tools": {}}, gid=None)
    assert (os.stat(path).st_mode & 0o777) == 0o600
    assert load_status(path) == {"tools": {}}


def test_write_status_with_group_is_0640_group_set(tmp_path):
    path = str(tmp_path / "status.json")
    gid = os.getgid()
    write_status(path, {"tools": {}}, gid=gid)
    st = os.stat(path)
    assert st.st_mode & 0o777 == 0o640 and st.st_gid == gid


def test_digest_rides_the_restricted_file(tmp_path):
    """The recent digest intentionally carries event details — it may only
    appear in the group-restricted status file, never world-readable."""
    d = mk_daemon(tmp_path)
    d.consume("yara-watch",
              "eicar /tmp/eicar-rt2.txt (realtime sha256:275a021bbfb6489e)")
    d.flush_outbox()
    snap = d.write_status()
    assert snap["recent"], "digest present"
    mode = d.status_path.stat().st_mode & 0o777
    assert mode & 0o007 == 0


# ---- fix 4: the backlog watchdog asks the kernel the right way ---------

def test_backlog_query_reports_failure_unknown(tmp_path):
    from appfw.engine import Engine
    eng = Engine(data_dir=tmp_path)
    eng._ctl_sock = None
    assert eng._query_backlog() is None        # UNKNOWN, never "empty"


def test_watchdog_counts_measurement_failures(tmp_path, monkeypatch):
    from appfw.engine import Engine
    eng = Engine(data_dir=tmp_path)
    eng.running = True
    eng._proc = _FakeProc()
    eng._ctl_sock = _FakeSock()
    events = []
    eng.on_event = events.append
    eng.stop = lambda: None
    monkeypatch.setattr("appfw.engine.fcntl.ioctl",
                        lambda fd, req, arg=0: (_ for _ in ()).throw(
                            OSError("no ioctl")))
    assert eng._query_backlog() is None          # UNKNOWN, never "empty"
    step1 = eng._watchdog_step()
    assert step1 and eng._backlog_fails == 1
    assert any("measurement failed" in e for e in events)
    step2 = eng._watchdog_step()
    assert step2 and eng._backlog_fails == 2
    assert eng._last_backlog is None
    assert eng.running                            # engine NOT torn down


def test_watchdog_fail_open_on_sustained_stall(tmp_path, monkeypatch):
    """A measured, sustained verdict backlog trips FAIL-OPEN; a single
    spike does not."""
    from appfw.engine import Engine
    eng = Engine(data_dir=tmp_path)
    eng.running = True
    eng._proc = _FakeProc()
    eng._ctl_sock = _FakeSock()
    events = []
    eng.on_event = events.append
    clock = {"t": 1000.0}
    stops = []
    monkeypatch.setattr("appfw.engine.time.monotonic", lambda: clock["t"])
    backlog = {"q": 1}
    # SIOCOUTQ's third argument is a pointer to an int, so ioctl hands back
    # a 4-byte buffer (engine 2026-10-27: passing 0 returned EFAULT).
    monkeypatch.setattr(
        "appfw.engine.fcntl.ioctl",
        lambda fd, req, arg=b"\0\0\0\0": backlog["q"].to_bytes(4, "little"))
    eng.stop = lambda: stops.append("stopped")

    assert eng._watchdog_step()                  # one spike: arms, no stop
    assert stops == []
    backlog["q"] = 1 << 20
    assert eng._watchdog_step()                  # still >65536 but <2 s
    assert stops == []
    clock["t"] += 3.0
    assert not eng._watchdog_step()              # sustained → FAIL-OPEN
    assert stops == ["stopped"]
    assert any("FAIL-OPEN" in e for e in events)


# ---- fix 5: the headless ask policy is explicit and configurable -------

def test_headless_ask_verdicts_are_labeled():
    assert Daemon._appfw_ask_allow({}) == ("allow", "once")
    assert Daemon._appfw_ask_deny({}) == ("deny", "once")


def test_headless_ask_configurable_deny(tmp_path):
    d = mk_daemon(tmp_path)
    (d.data_dir / "appfw").mkdir(exist_ok=True)
    (d.data_dir / "appfw" / "config.json").write_text(
        json.dumps({"headless_ask": "deny-once"}))
    assert d._headless_ask() == "deny-once"


def test_headless_ask_default_is_deny(tmp_path):
    # GW-03: unanswered asks BLOCK by default — an "allow" here would be
    # a silent permit labeled as a pending question. allow-once is the
    # explicit, availability-first config choice.
    d = mk_daemon(tmp_path)
    assert d._headless_ask() == "deny-once"


def test_status_labels_headless_ask(tmp_path):
    d = mk_daemon(tmp_path)
    snap = d.write_status()
    assert "appfw_ask_policy" in snap
    assert "NOT user-approved" in snap["appfw_ask_policy"]


# ---- fix 6: swallowed failures are counted and visible ----------------

def test_failures_counter_visible_in_status(tmp_path):
    d = mk_daemon(tmp_path)
    d.count_failure("write", "test", OSError("disk"))
    snap = d.write_status()
    assert snap["failures"].get("write") == 1
    assert "write" in snap["degraded"]


def test_failing_write_counts_not_silently_drops(tmp_path):
    d = mk_daemon(tmp_path)
    d.consume("yara-watch",
              "eicar /tmp/eicar-rt2.txt (realtime sha256:275a021bbfb6489e)")
    d.events_path = tmp_path / "missing-dir" / "events.jsonl"  # open → OSError
    d.flush_outbox()
    snap = d.write_status()
    assert snap["failures"].get("write") == 1
    assert "write" in snap["degraded"]


def test_degraded_absent_when_healthy(tmp_path):
    d = mk_daemon(tmp_path)
    snap = d.write_status()
    assert snap["degraded"] == []


# ---- fix 7: --data-dir isolates state, including paused.json ----------

def test_data_dir_isolation_of_paused_state(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy-data"
    legacy.mkdir()
    (legacy / "paused.json").write_text(json.dumps({"paused": ["auditd"]}))
    monkeypatch.setattr(gd, "DATA_DIR", legacy)
    d = mk_daemon(tmp_path)
    (d.data_dir / "paused.json").write_text(json.dumps({"paused": ["ufw"]}))
    snap = d.write_status()
    assert snap["tools"]["ufw"]["paused"] is True
    assert "auditd" not in snap["tools"] or not snap["tools"]["auditd"].get(
        "paused")
    assert json.loads((legacy / "paused.json").read_text()) == {
        "paused": ["auditd"]}                    # legacy dir untouched

# ---- GW-01: root writes cannot be redirected by a shared-dir plant ----

def test_status_symlink_tempfile_attack_redirects_nothing(tmp_path):
    # old code: os.open(path + ".tmp", O_TRUNC) — a group member's
    # pre-planted symlink would have root truncate a foreign file.
    victim = tmp_path / "victim.conf"
    victim.write_text("VICTIM-CONTENT\n")
    path = str(tmp_path / "status.json")
    os.symlink(str(victim), path + ".tmp")
    write_status(path, {"tools": {"x": 1}}, gid=None)
    assert victim.read_text() == "VICTIM-CONTENT\n"      # foreign file intact
    assert not os.path.islink(path)                      # real file, not plant
    assert load_status(path) == {"tools": {"x": 1}}


def test_staging_dir_refuses_insecure_or_planted(tmp_path):
    stage = tmp_path / ".root-tmp"
    # (a) an over-permissive staging dir is refused, loudly, BEFORE any write
    stage.mkdir()
    stage.chmod(0o777)
    path = str(tmp_path / "status.json")
    try:
        write_status(path, {"tools": {}}, gid=None)
        raise AssertionError("overshared staging dir was accepted")
    except OSError:
        pass
    assert not os.path.exists(path)                      # nothing written
    stage.rmdir()
    # (b) a SYMLINK in the staging slot is refused (not followed, not created)
    foreign = tmp_path / "elsewhere"
    foreign.mkdir()
    os.symlink(str(foreign), str(stage))
    try:
        write_status(path, {"tools": {}}, gid=None)
        raise AssertionError("symlinked staging dir was accepted")
    except OSError:
        pass


def test_staged_tempfile_is_private_and_old_plant_not_promoted(tmp_path):
    # a leftover file at the staged name must not reach the destination:
    # the exclusive create clears OUR stale temp and rewrites it, so a
    # pre-planted payload can never be promoted by the final rename.
    path = str(tmp_path / "status.json")
    write_status(path, {"tools": {}, "n": 1}, gid=None)
    stage = tmp_path / ".root-tmp"
    st = stage.stat()
    assert stat_mod.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
    assert (st.st_mode & 0o077) == 0                     # 0700: group/world: no
    assert load_status(path) == {"tools": {}, "n": 1}
    # perms travel with the inode via the fd, not a path chmod afterwards
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_events_symlink_plant_refused_and_counted(tmp_path):
    d = mk_daemon(tmp_path)
    victim = tmp_path / "victim.log"
    victim.write_text("VICTIM\n")
    plant = d.data_dir / "events.jsonl"
    plant.unlink(missing_ok=True)
    os.symlink(str(victim), str(plant))
    d.consume("yara-watch",
              "eicar /tmp/eicar-rt2.txt (realtime sha256:275a021bbfb6489e)")
    d.flush_outbox()                                     # refused: not an
    assert victim.read_text() == "VICTIM\n"              # attacker-owned, non-
    snap = d.write_status()                              # root regular file
    assert snap["failures"].get("write") == 1
    assert "write" in snap["degraded"]


def test_trim_never_touches_a_planted_tmp_name(tmp_path):
    d = mk_daemon(tmp_path, max_events=10)
    victim = tmp_path / "victim.log"
    victim.write_text("VICTIM\n")
    for i in range(20):                                  # force a trim
        d.consume("yara-watch",
                  f"eicar /tmp/x{i}.txt (realtime sha256:275a021bbfb6489e)")
    d.flush_outbox()
    d.write_status()
    os.symlink(str(victim), str(d.events_path) + ".tmp")  # old attack name
    assert d.trim_events() > 0
    assert victim.read_text() == "VICTIM\n"
    # the attacker's plant was left exactly as planted: never followed,
    # never written through, never promoted to the real file
    assert os.path.islink(str(d.events_path) + ".tmp")
    # the rewritten real store came from the private stage: correct size,
    # no stray temp anywhere in the shared dir
    assert len(d.events_path.read_text().splitlines()) <= d.max_events
    assert [p for p in d.data_dir.iterdir()
            if p.name == "events.jsonl.tmp" or p.name.endswith(".new")] \
        == [d.data_dir / "events.jsonl.tmp"]


def test_malformed_append_to_planted_symlink_refused(tmp_path):
    d = mk_daemon(tmp_path)
    victim = tmp_path / "victim.log"
    victim.write_text("VICTIM\n")
    plant = d.data_dir / "malformed.log"
    os.symlink(str(victim), str(plant))
    d.consume("responderd", "{definitely-not-json")     # → malformed queue
    d.flush_malformed()
    assert victim.read_text() == "VICTIM\n"
    # refusal is loud: the write-category failure counter is bumped
    assert d._fail_counts.get("write", {}).get("count", 0) >= 1


# ---- GW-02: an unresolved desktop identity is never guessed ------------

def test_unresolved_ui_user_degrades_without_guessing(tmp_path, monkeypatch):
    monkeypatch.setattr(gd, "UI_USER", "definitely-no-such-user-404")
    assert gd.ui_uid() is None                            # NOT 1000
    assert gd.ui_runtime_dir() is None
    d = mk_daemon(tmp_path)
    d.write_status()                                      # no group known: 0600
    assert (d.status_path.stat().st_mode & 0o777) == 0o600


def test_user_scope_probe_honest_when_identity_unresolved(
        tmp_path, monkeypatch):
    monkeypatch.setattr(gd, "UI_USER", "definitely-no-such-user-404")
    monkeypatch.setattr(gd.os, "geteuid", lambda: 0)      # root path
    def boom(*a, **kw):
        raise AssertionError("runuser attempted with an unresolved user")
    monkeypatch.setattr(gd.subprocess, "run", boom)
    check = gd.unit_checker_factory()
    assert check({"unit": "mysvc.service", "label": "x",
                  "scope": "user", "logs": []}) == "unknown"
