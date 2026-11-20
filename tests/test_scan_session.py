import datetime as dt
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import scan_session as S


def test_request_validation_accepts_only_the_six_keys():
    good = {"id": "20261030T074500-a1b2", "key": "clamav",
            "requested_at": "2026-10-30T07:45:00+00:00"}
    assert S.validate_request(good) == ("20261030T074500-a1b2", "clamav")
    for bad in ({"id": "20261030T074500-a1b2", "key": "rm -rf /"},
                {"id": "", "key": "clamav"},
                {"id": "20261030T074500-a1b2"},
                "scan-all",
                {"id": "nope", "key": "scan-all"},
                {"id": "../../etc/passwd", "key": "aide"},
                None):
        assert S.validate_request(bad) is None


def test_clamav_lines_count_files_and_report_infections():
    p = S.parse_progress("clamav", "/home/alice/a.bin: OK")
    assert p["counted"] is True and p["current"] == "/home/alice/a.bin"
    assert p["finding"] is None
    p = S.parse_progress("clamav", "/tmp/eicar.txt: FOUND")
    assert p["finding"]["severity"] == "HIGH"
    assert "eicar.txt" in p["finding"]["text"]
    # clamscan names the signature on a hit: "path: Eicar-Signature FOUND".
    # The plain (OK|FOUND) form missed every infected file in a live run.
    p = S.parse_progress("clamav",
                         "/tmp/eicar.txt: Eicar-Signature FOUND")
    assert p["counted"] is True
    assert p["finding"]["text"] == \
        "Infected file: /tmp/eicar.txt (Eicar-Signature)"
    assert S.parse_progress("clamav", "   ") is None


def test_rkhunter_checks_count_and_warnings_are_findings():
    p = S.parse_progress("rkhunter", "Checking system commands...")
    assert p["counted"] is True
    assert p["current"].startswith("system commands")
    p = S.parse_progress(
        "rkhunter", "Warning: Hidden file found: /etc/.updated: ASCII text")
    assert p["counted"] is False
    assert p["finding"]["severity"] == "HIGH"
    assert p["finding"]["text"].startswith("Warning:")


def test_rkhunter_warning_summary_flags_the_scan_but_is_not_a_finding():
    # rkhunter ends with this line whenever any check failed, and not every
    # failure prints a "Warning:" line the parser can read. The flag lets
    # the row say "warnings logged" instead of "clean" (owner, 2026-10-31).
    p = S.parse_progress(
        "rkhunter",
        "One or more warnings have been found while checking the system.")
    assert p["counted"] is False
    assert p["finding"] is None
    assert p["warned"] is True
    # A plain check line must not set it.
    p = S.parse_progress("rkhunter", "Checking system commands...")
    assert not p.get("warned")


def test_warning_summary_reaches_the_live_document(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-a1d1", "key": "rkhunter"}))
    svc, _calls = _service(tmp_path, [([
        "Checking system commands...",
        "One or more warnings have been found while checking the system."],
        0)])
    _run(svc)
    live = json.loads((tmp_path / "scan-live.json").read_text())
    row = live["scanners"]["rkhunter"]
    assert row["state"] == "done"
    assert row["warned"] is True
    assert row["findings"] == 0


def test_scan_directories_are_readable_by_the_desktop_group(tmp_path):
    # Scans run as root and a plain mkdir made scans/ and scan-logs/ root-only
    # 0700, so the window (running as the desktop user) showed an empty
    # RECENT SCANS list and could not read a scanner's log (owner,
    # 2026-10-31). Both roots and the per-scan folder are 0770 root:<group>.
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-a1e1", "key": "clamav"}))
    svc, _calls = _service(tmp_path, [(["startup", "/tmp/a: OK"], 0)])
    svc.gid = os.getgid()
    _run(svc)
    for path in (tmp_path / "scans", tmp_path / "scan-logs",
                 tmp_path / "scan-logs" / "20261030T074500-a1e1"):
        assert path.is_dir(), path
        assert path.stat().st_mode & 0o777 == 0o770, path
        assert path.stat().st_gid == os.getgid(), path


def test_lynis_tests_count_and_warnings_are_medium():
    p = S.parse_progress("lynis", "  Performing test ID 1.1 (boot)")
    assert p["counted"] is True
    assert p["current"] == "ID 1.1 (boot)"
    p = S.parse_progress("lynis", "Warning: Found old kernel [KRNL-5830]")
    assert p["finding"] == {"severity": "MEDIUM",
                            "text": "Warning: Found old kernel [KRNL-5830]"}


def test_aide_differences_and_yara_matches_are_findings():
    # An entry the database does not know (all '+') is baseline drift, not an
    # edit to a known file — a stale database reported 128 of these at once
    # on 2026-10-30 and the owner read them as errors. The reader gets a
    # sentence, never AIDE's change string.
    p = S.parse_progress("aide", "d+++++++++++++++++++++++: /etc/passwd")
    assert p["finding"]["severity"] == "LOW"
    assert p["finding"]["routine"] is True
    assert p["finding"]["text"] == \
        "New since the file-integrity baseline: /etc/passwd"
    p = S.parse_progress("aide", "f-----------: /etc/gone.conf")
    assert p["finding"]["severity"] == "LOW"
    assert p["finding"]["routine"] is True
    assert p["finding"]["text"] == \
        "Gone since the file-integrity baseline: /etc/gone.conf"
    # A change flag on a known file is what the check exists to catch.
    p = S.parse_progress("aide", "f..H.......... : /etc/passwd")
    assert p["finding"]["severity"] == "HIGH"
    assert p["finding"].get("routine") is None
    assert p["finding"]["text"] == \
        "Changed since the file-integrity baseline: /etc/passwd"
    p = S.parse_progress("yara-tmp-scan", "Eicar-Sig /tmp/eicar.txt")
    assert p["finding"]["severity"] == "HIGH"
    assert p["finding"]["text"] == "Eicar-Sig /tmp/eicar.txt"


def test_triage_folds_known_noise_and_defaults_to_real():
    assert S.is_routine(
        "rkhunter", "Warning: Hidden file found: /etc/.updated") is True
    assert S.is_routine(
        "rkhunter", "Warning: Hidden file found: /home/alice/.secret") is False
    assert S.is_routine("lynis", "Suggestion: install auditd") is True
    assert S.is_routine("lynis", "Warning: Found old kernel") is False
    assert S.is_routine("aide", "d+++: /var/cache/apparmor/x") is True
    # Baseline drift folds wherever it is; a real change to a known file
    # does not.
    assert S.is_routine("aide", "d+++: /etc/ssh/sshd_config") is True
    assert S.is_routine("aide", "f..H.....: /etc/ssh/sshd_config") is False
    assert S.is_routine("aide", "added: /etc/new.conf") is True
    assert S.is_routine("aide", "changed: /etc/passwd") is False
    assert S.is_routine("clamav", "Infected file: /tmp/x") is False
    assert S.is_routine("weird-tool", "something nobody classified") is False


def test_exit_codes_are_per_scanner_semantics(tmp_path, monkeypatch):
    # GW-123: the per-scanner rc semantics read cleanly only when AIDE's
    # baseline exists; without one the verdict names the missing
    # baseline instead (pinned in test_gw122_gw124_closeout.py).
    db = tmp_path / "aide.db"
    db.write_bytes(b"baseline")
    monkeypatch.setattr(S, "AIDE_DB", db)
    assert S.exit_verdict("clamav", 0) == ("done", "")
    assert S.exit_verdict("clamav", 1) == ("done", "")
    assert S.exit_verdict("clamav", 2)[0] == "failed"
    assert S.exit_verdict("aide", 7) == ("done", "")
    assert S.exit_verdict("aide", 8) == ("failed", "aide exited 8")
    assert S.exit_verdict("rkhunter", 1) == ("done", "")
    assert S.exit_verdict("lynis", 1)[0] == "failed"


def test_event_lines_match_the_log_parsers():
    from events import normalize_event
    when = dt.datetime(2026, 10, 30, 7, 45, 0)
    line = S.event_line(
        "rkhunter",
        "Warning: Hidden file found: /etc/.updated: ASCII text", when)
    ev = normalize_event("rkhunter", line)
    assert ev is not None and "Hidden file" in ev.text
    assert ev.severity == "HIGH"
    line = S.event_line("lynis", "Warning: Found old kernel [KRNL-5830]", when)
    ev = normalize_event("lynis", line)
    assert ev is not None and ev.severity == "MEDIUM"
    # An already-canonical line is passed through untouched.
    raw = "[07:45:00] Warning: something"
    assert S.event_line("rkhunter", raw, when) == raw
    # ClamAV's own per-file line already parses.
    ev = normalize_event("clamav", S.event_line(
        "clamav", "/tmp/eicar.txt: FOUND", when))
    assert ev is not None and "eicar" in ev.text


def test_commands_are_fixed_per_key_and_cover_the_wider_scope():
    cmds = S.commands_for("scan-all", "/home/alice", "grey")
    assert len(cmds) == 5
    firsts = {c[0] for c in cmds}
    assert ("/usr/bin/clamdscan" in firsts or "/usr/bin/clamscan" in firsts), \
        firsts
    assert "/usr/bin/aide" in firsts
    clam = S.commands_for("clamav", "/home/alice", "grey")[0]
    assert "--stdout" in clam
    if clam[0] == "/usr/bin/clamdscan":
        assert "--fdpass" in clam, "the engine needs fdpass to read user files"
    assert "/etc" in clam and "/usr/local" in clam
    assert S.commands_for("bogus", "/home/alice", "grey") == []


# ---------------------------------------------------------------- service

import json  # noqa: E402
import time  # noqa: E402


class FakeHandle:
    def __init__(self, lines, rc=0, on_kill_rc=None):
        self._lines = list(lines)
        self.final_rc = rc
        self.killed = False
        self.on_kill_rc = on_kill_rc
        self.pauses = 0
        self.resumes = 0

    def pause(self):
        self.pauses += 1

    def resume(self):
        self.resumes += 1

    def lines(self):
        out, self._lines = self._lines, []
        return out

    def poll(self):
        if self.killed:
            return self.on_kill_rc if self.on_kill_rc is not None else -15
        return self.final_rc if not self._lines else None

    def terminate(self):
        self.killed = True


def _service(tmp_path, scripts, **kw):
    calls = []

    def spawn(argv, log_path=None, **kw):
        calls.append(argv)
        return FakeHandle(*scripts.pop(0))

    kw.setdefault("count_totals", False)
    # Never sweep the real /proc in a unit test: a live scan on the host
    # would be published as an external session and replace the test's
    # live document.
    kw.setdefault("proc_root", str(tmp_path / "no-proc"))
    svc = S.ScanService(tmp_path, spawn=spawn, home="/home/alice",
                        ui_user="grey", log=lambda *_: None,
                        which=lambda name: "/usr/bin/" + name, **kw)
    return svc, calls


def _run(svc, rounds=40):
    for _ in range(rounds):
        svc.tick()
        if not svc.running():
            break


def test_a_single_scan_writes_live_findings_and_summary(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-a1b2", "key": "clamav"}))
    svc, calls = _service(tmp_path, [(
        ["startup", "/home/alice/a.bin: OK", "/tmp/e: FOUND"], 1)])
    _run(svc)
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "done"
    assert live["scanners"]["clamav"]["count"] == 2
    assert live["real_findings"] == 1
    assert calls and ("clamscan" in " ".join(calls[0])
                      or "clamdscan" in " ".join(calls[0]))
    findings = (tmp_path / "scan-findings.jsonl").read_text().splitlines()
    row = json.loads(findings[0])
    assert row["routine"] is False
    # A timestamp with an offset: a naive local time sorted against the
    # UTC stamps everywhere else and read an hour or five out.
    assert dt.datetime.fromisoformat(row["ts"]).tzinfo is not None
    summary = json.loads((tmp_path / "scans" /
                          "20261030T074500-a1b2.json").read_text())
    assert summary["scanners"]["clamav"]["exit_code"] == 1


def test_aide_baseline_drift_is_recorded_but_folded_as_routine(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-a1c1", "key": "aide"}))
    svc, _calls = _service(tmp_path, [([
        "d+++++++++++++++++++++++: /boot/efi/EFI/new.efi",
        "f..H.......... : /etc/passwd"], 7)])
    svc._missing.discard("aide")
    _run(svc)
    rows = [json.loads(line) for line in
            (tmp_path / "scan-findings.jsonl").read_text().splitlines()]
    drift = [r for r in rows if "New since" in r["text"]]
    change = [r for r in rows if "Changed since" in r["text"]]
    assert len(drift) == 1 and drift[0]["routine"] is True
    assert drift[0]["severity"] == "LOW"
    assert len(change) == 1 and change[0]["routine"] is False
    assert change[0]["severity"] == "HIGH"
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["real_findings"] == 1
    assert live["routine_findings"] == 1


def test_scan_all_starts_every_scanner_and_marks_a_missing_one(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-b2c3", "key": "scan-all"}))
    svc, calls = _service(tmp_path, [
        ([], 0), ([], 0), ([], 0), ([], 0), ([], 0)])
    svc._missing.add("lynis")          # simulate: binary not installed
    _run(svc)
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert set(live["scanners"]) == set(S.SCAN_ALL)
    assert live["scanners"]["lynis"]["state"] == "failed"
    assert "not installed" in live["scanners"]["lynis"]["detail"]
    assert len(calls) == 4             # the missing one was never spawned


def test_a_second_request_while_running_is_rejected_not_queued(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-c3d4", "key": "clamav"}))
    svc, _calls = _service(tmp_path, [(["x"], None)])
    svc.tick()                          # session starts, child still running
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-d4e5", "key": "aide"}))
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["scan_id"] == "20261030T074500-c3d4"
    assert "already running" in live["note"]
    assert not (tmp_path / "scan-request.json").exists()
    svc.children["clamav"]["handle"].killed = True


def test_the_refusal_note_does_not_outlive_the_session(tmp_path):
    # GW-159: once the session finished, the headline was
    # "Full scan: finished · a scan is already running" - three claims in
    # one line, two of them false. The note describes a request refused
    # WHILE the scan ran; at a final state nothing is refused anymore
    # (another scan may start), so the note is cleared.
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-c3d4", "key": "clamav"}))
    svc, _calls = _service(tmp_path, [(["x"], None)])
    svc.tick()                          # session starts, child still running
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-d4e5", "key": "aide"}))
    svc.tick()                          # refused while the session runs
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert "already running" in live["note"]
    handle = svc.children["clamav"]["handle"]
    handle._lines.clear()               # the scan's output is done
    handle.final_rc = 0                 # ...and it exited cleanly
    svc.tick()                          # poll sees rc 0 -> final state
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "done"
    assert live["note"] == ""


def test_a_failed_child_is_named_not_silently_clean(tmp_path, monkeypatch):
    # GW-123: with a baseline in place an rc failure still names the rc.
    db = tmp_path / "aide.db"
    db.write_bytes(b"baseline")
    monkeypatch.setattr(S, "AIDE_DB", db)
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-e5f6", "key": "aide"}))
    svc, _calls = _service(tmp_path, [([], 9)])
    svc._missing.discard("aide")
    _run(svc)
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["scan_id"] == "20261030T074500-e5f6"
    assert live["scanners"]["aide"]["state"] == "failed"
    assert "exited 9" in live["scanners"]["aide"]["detail"]


def test_tailers_pause_for_the_session_and_resume_after(tmp_path):
    events = []
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-f6a7", "key": "rkhunter"}))
    svc, _calls = _service(tmp_path, [([], 0)],
                           consume=lambda t, l: events.append((t, l)))
    svc.set_tailer_hooks(lambda t: events.append(("pause", t)),
                         lambda t: events.append(("resume", t)))
    _run(svc)
    assert ("pause", "rkhunter") in events
    assert ("resume", "rkhunter") in events


def test_each_line_reaches_the_event_log_once(tmp_path):
    seen = []
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-0a0a", "key": "rkhunter"}))
    svc, _calls = _service(
        tmp_path,
        [(["Checking system commands...",
           "Warning: Hidden file found: /etc/.updated"], 0)],
        consume=lambda t, l: seen.append((t, l)))
    _run(svc)
    warns = [l for t, l in seen if "Hidden file" in l]
    assert len(warns) == 1
    assert warns[0].startswith("[")        # canonicalised for the log parser


def test_a_running_scan_without_its_unit_is_reported_not_faked(tmp_path):
    # A scan that had no transient unit cannot be followed after a restart.
    # It is named as lost with the reason — never silently declared clean.
    (tmp_path / "scan-live.json").write_text(json.dumps({
        "scan_id": "20261030T070000-aaaa", "key": "clamav",
        "state": "running", "ended_at": None,
        "scanners": {"clamav": {"state": "running"}}}))
    svc, _calls = _service(tmp_path, [])
    svc.recover_interrupted()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] in ("failed", "interrupted")
    assert live["scanners"]["clamav"]["state"] in ("failed", "interrupted")
    assert "restart" in (live["scanners"]["clamav"].get("detail")
                         or live.get("note") or "")


def test_a_restarted_daemon_reattaches_to_the_running_scanner(tmp_path):
    # The scanner ran as a transient unit and kept working; the new daemon
    # tails its log from the recorded offset and finishes the session.
    (tmp_path / "scan-live.json").write_text(json.dumps({
        "scan_id": "20261030T070000-bbbb", "key": "scan-all",
        "state": "running", "ended_at": None,
        "sequence": ["clamav", "aide"],
        "scanners": {
            "clamav": {"state": "done", "count": 5, "findings": 0},
            "aide": {"state": "running", "count": 2, "unit":
                     "gw-scan-20261030T070000-bbbb-aide",
                     "log_offset": 0, "duration_s": 3}}}))
    svc, calls = _service(tmp_path, [([], 0, 0)])
    svc.recover_interrupted()
    assert svc.running()                    # picked up, not killed
    _run(svc)
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "done"
    assert live["scanners"]["aide"]["state"] == "done"
    assert calls == [[]]           # re-attach, not a fresh spawn


def test_scan_all_runs_one_scanner_at_a_time_in_order(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-7f7f", "key": "scan-all"}))
    svc, calls = _service(tmp_path, [
        ([], None), ([], 0), ([], 0), ([], 0), ([], 0)])
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    running = [k for k, sc in live["scanners"].items()
               if sc["state"] == "running"]
    queued = [k for k, sc in live["scanners"].items()
              if sc["state"] == "queued"]
    assert running == ["clamav"]            # exactly one, the first key
    assert len(queued) == 4
    assert live["scanners"]["rkhunter"]["waiting_for"]
    svc.children["clamav"]["handle"].final_rc = 0
    _run(svc)
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert set(live["scanners"]) == set(S.SCAN_ALL)
    assert live["state"] == "done"
    assert len(calls) == 5


def test_the_temp_sweep_reports_folders_swept(tmp_path):
    p = S.parse_progress("yara-tmp-scan", "@@DIRS 100 /tmp/x")
    assert p["counted"] is False and p["count"] == 100
    assert p["current"] == "/tmp/x"
    p = S.parse_progress("yara-tmp-scan", "@@DIRS 1240")
    assert p["count"] == 1240 and p["finding"] is None


def test_history_keeps_the_newest_twenty(tmp_path):
    (tmp_path / "scans").mkdir()
    for i in range(22):
        p = tmp_path / "scans" / f"20260101T0000{i:02d}-aaaa.json"
        p.write_text("{}")
        time.sleep(0.002)
    svc, _calls = _service(tmp_path, [])
    svc._keep_recent()
    assert len(list((tmp_path / "scans").glob("*.json"))) == 20


def test_a_timeout_is_reported_as_failed(tmp_path):
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261030T074500-1b1b", "key": "aide"}))
    ticks = [0.0]

    def clock():
        ticks[0] += 1000.0
        return ticks[0]

    svc, _calls = _service(tmp_path, [(["still working"], None)], clock=clock)
    svc.tick()
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["scanners"]["aide"]["state"] == "failed"
    assert "timed out" in live["scanners"]["aide"]["detail"]


def test_daemon_builds_a_scan_service_over_its_own_data_dir(tmp_path):
    import greywatch_daemon as D
    daemon = D.Daemon(tmp_path)
    daemon.ui_gid = None
    assert getattr(daemon, "scans", "missing") is None
    svc = daemon.make_scan_service()
    assert svc.dir == tmp_path
    assert svc.consume == daemon.consume
    assert svc.ui_user == D.UI_USER
    assert str(svc.home).startswith("/")


def test_a_paused_file_tailer_skips_lines_written_during_a_scan(tmp_path):
    from collectors import FileTailer
    log = tmp_path / "rkhunter.log"
    log.write_text("old line\n")
    seen = []
    t = FileTailer(log, "rkhunter",
                   lambda _tool, line: seen.append(line), start_at_end=True)
    t.start()
    try:
        t.pause()
        with open(log, "a", encoding="utf-8") as fh:
            fh.write("during the scan\n")
        t._read_available()          # paused: must not deliver
        t.resume()
        with open(log, "a", encoding="utf-8") as fh:
            fh.write("after the scan\n")
        t._read_available()
    finally:
        t.stop()
    assert not any("during" in line for line in seen)
    assert any("after" in line for line in seen)


# ------------------------------------------------ one owner, one lock
# Owner 2026-11-19: "DO NOT LET IT DO MULTIPLE SCANS AT ALL. ONLY 1 AT A
# TIME. HAVE IT SEARCH FOR AND CONTROL ANY EXISTING RUNNING SCAN."


def test_the_global_lock_refuses_a_second_session(tmp_path):
    import fcntl
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120000-a1b2", "key": "clamav"}))
    svc, calls = _service(tmp_path, [([], None)])
    fd = os.open(str(S.lock_path(tmp_path)),
                 os.O_RDWR | os.O_CREAT, 0o660)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        svc.tick()
        assert not svc.running()
        assert calls == []
        # the request is not lost: it waits for the owner to free the lock
        assert (tmp_path / "scan-request.json").exists()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    svc.tick()
    assert svc.running()
    assert not (tmp_path / "scan-request.json").exists()


def test_control_files_validate_and_are_written_atomically(tmp_path):
    ok, note = S.write_control(
        tmp_path, "pause", "20261119T120000-a1b2")
    assert ok, note
    doc = json.loads(S.control_path(tmp_path).read_text())
    assert doc == {"action": "pause",
                   "scan_id": "20261119T120000-a1b2"}
    assert S.validate_control(doc) == ("pause",
                                       "20261119T120000-a1b2")
    for bad in ({"action": "rm -rf", "scan_id": None},
                {"action": "pause", "scan_id": "../../etc/passwd"},
                {"action": "pause"},
                "pause", None):
        assert S.validate_control(bad) is None
    ok, note = S.write_control(tmp_path, "stop-everything")
    assert ok is False and "not a scan control" in note


def test_pause_and_resume_drive_the_running_scanner(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120000-c3d4", "key": "clamav"}))
    svc, _calls = _service(tmp_path, [(["x"], None)])
    svc.tick()
    handle = svc.children["clamav"]["handle"]
    S.write_control(tmp_path, "pause", "20261119T120000-c3d4")
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "paused"
    assert live["scanners"]["clamav"]["paused"] is True
    assert handle.pauses == 1
    S.write_control(tmp_path, "resume", "20261119T120000-c3d4")
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "running"
    assert handle.resumes == 1
    handle._lines.clear()
    handle.final_rc = 0
    svc.tick()


def test_cancel_stops_the_session_and_says_who(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120000-e5f6", "key": "clamav"}))
    svc, _calls = _service(tmp_path, [(["x"], None)])
    svc.tick()
    handle = svc.children["clamav"]["handle"]
    S.write_control(tmp_path, "cancel", "20261119T120000-e5f6")
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "cancelled"
    assert live["scanners"]["clamav"]["state"] == "cancelled"
    assert "cancelled by you" in live["scanners"]["clamav"]["detail"]
    assert handle.killed is True
    assert not svc.running()


def test_scanner_processes_reads_proc_and_skips_our_own_unit(tmp_path):
    proc = tmp_path / "proc"
    for pid, comm, unit in ((101, "clamscan",
                             "gw-scan-20261119T120000-a1b2-clamav"),
                            (202, "rkhunter", "greywatch-boot-sweep")):
        d = proc / str(pid)
        d.mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "stat").write_text(
            f"{pid} ({comm}) S " + " ".join(["0"] * 20) + "\n")
        (d / "cgroup").write_text(f"0::/system.slice/{unit}\n")
        (d / "cmdline").write_text(
            "/usr/bin/" + comm + "\x00--check\x00")
    found = S.scanner_processes(proc)
    assert {row["tool"] for row in found} == {"clamav", "rkhunter"}
    ours = S.scanner_processes(
        proc, exclude_cgroups=["gw-scan-20261119T120000-a1b2-clamav"])
    assert [row["tool"] for row in ours] == ["rkhunter"]


def test_an_outside_scan_is_published_as_external_not_a_session(tmp_path):
    proc = tmp_path / "proc"
    d = proc / "303"
    d.mkdir(parents=True)
    (d / "comm").write_text("clamscan\n")
    (d / "stat").write_text("303 (clamscan) S " + " ".join(["0"] * 20)
                            + "\n")
    (d / "cgroup").write_text("0::/system.slice/greywatch-clam-scan.service\n")
    (d / "cmdline").write_text("/usr/bin/clamscan\x00-r\x00/home/alice\x00")
    svc, _calls = _service(tmp_path, [], proc_root=proc)
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "running"
    assert live["scanners"] == {}
    assert live["external"][0]["tool"] == "clamav"
    assert live["external"][0]["pid"] == 303


def test_the_live_row_carries_a_percent_from_the_cached_total(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"a" * 200)
    b.write_bytes(b"b" * 100)
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120000-1a2b", "key": "clamav"}))
    svc, _calls = _service(tmp_path, [(
        [f"{a}: OK", f"{b}: OK"], None)])
    svc._totals = {"files": 4, "bytes": 400}
    svc._totals_key = "clamav"
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    row = live["scanners"]["clamav"]
    assert row["total"] == 4
    # bytes move the bar (300 of 400) even though files would say 2 of 4
    assert row["percent"] == 0.75
    handle = svc.children["clamav"]["handle"]
    handle.final_rc = 0
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["scanners"]["clamav"]["percent"] == 1.0


def test_a_stale_count_cannot_land_under_a_new_scope(tmp_path):
    # The walk outlives a scope change: a legacy walk still running when a
    # scoped session takes over must not publish its wide count under the
    # new key, or the bar divides one tree's files by another tree's total.
    import threading
    started = threading.Event()
    gate = threading.Event()
    roots_walked = []

    def counter(roots):
        roots_walked.append(list(roots))
        if len(roots_walked) == 1:
            started.set()
            gate.wait(5)
            return (99, 999)
        return (3, 30)

    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120600-aaaa", "key": "clamav"}))
    svc, calls = _service(
        tmp_path, [(["x"], None), (["y"], None)],
        count_totals=True, counter=counter)
    svc.tick()                       # the legacy scan starts its wide walk
    assert started.wait(5)
    S.write_control(tmp_path, "cancel", "20261119T120600-aaaa")
    svc.tick()                       # the legacy session is cancelled
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120600-bbbb", "key": "clamav-frequent"}))
    svc.tick()                       # the frequent session walks its own tree
    deadline = time.time() + 5
    while svc._totals.get("files") != 3 and time.time() < deadline:
        time.sleep(0.01)
    assert svc._totals["files"] == 3
    gate.set()                       # the old wide walk now finishes
    deadline = time.time() + 5
    while time.time() < deadline and any(
            t.name == "gw-scan-count" and t.is_alive()
            for t in threading.enumerate()):
        time.sleep(0.01)
    assert svc._totals_key == "clamav-frequent"
    assert svc._totals["files"] == 3       # the stale 99 never applied
    cached = json.loads((tmp_path / "scan-total.json").read_text())
    assert cached["files"] == 3
    # Each walk used its own roots, and the launch spawned the narrow run.
    # Only roots that exist are walked (one absent folder no longer fails
    # the whole scan), so the assertion follows the filesystem.
    def existing(roots):
        return [root for root in roots if os.path.isdir(root)]

    assert roots_walked[0] == existing(["/home/alice", "/tmp", "/var/tmp",
                                        "/etc", "/usr/local"])
    frequent = ["/tmp", "/var/tmp", "/home/alice/Downloads",
                "/home/alice/Desktop", "/home/alice/Documents"]
    assert roots_walked[1] == existing(frequent)
    argv = calls[-1]
    expected = existing(frequent)
    assert argv[-len(expected):] == expected
    assert "/etc" not in argv


def test_the_temp_sweep_reports_its_total_and_percent(tmp_path):
    p = S.parse_progress("yara-tmp-scan", "@@TOTAL 40")
    assert p["total"] == 40
    assert p["finding"] is None
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120000-2b3c", "key": "yara-tmp-scan"}))
    svc, _calls = _service(tmp_path, [([
        "@@TOTAL 40", "@@DIRS 20 /tmp/x"], None)])
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["scanners"]["yara-tmp-scan"]["total"] == 40
    assert live["scanners"]["yara-tmp-scan"]["percent"] == 0.5
    svc.children["yara-tmp-scan"]["handle"].final_rc = 0
    svc.tick()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["scanners"]["yara-tmp-scan"]["percent"] == 1.0


def test_request_validation_accepts_the_scoped_antivirus_keys():
    for key in ("clamav-frequent", "clamav-home"):
        doc = {"id": "20261119T120000-a1b2", "key": key}
        assert S.validate_request(doc) == ("20261119T120000-a1b2", key)


def test_frequent_scope_walks_the_user_areas():
    argv = S.commands_for("clamav-frequent", "/home/alice", "grey")[0]
    assert argv[-5:] == ["/tmp", "/var/tmp", "/home/alice/Downloads",
                         "/home/alice/Desktop", "/home/alice/Documents"]
    assert "/etc" not in argv


def test_home_scope_is_the_home_only():
    argv = S.commands_for("clamav-home", "/home/alice", "grey")[0]
    assert argv[-1] == "/home/alice"
    assert "/etc" not in argv


def test_a_session_with_a_failed_child_is_failed(tmp_path):
    (tmp_path / "security-hardening").mkdir()
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120500-c3d4", "key": "scan-all"}))
    svc, _calls = _service(tmp_path, [
        ([], 0), ([], 0), ([], 0), ([], 0), ([], 0)])
    svc._missing.add("lynis")
    _run(svc)
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "failed"


def test_a_paused_session_does_not_time_out(tmp_path):
    (tmp_path / "scan-request.json").write_text(json.dumps(
        {"id": "20261119T120000-3c4d", "key": "clamav"}))
    ticks = [0.0]

    def clock():
        ticks[0] += 1000.0
        return ticks[0]

    svc, _calls = _service(tmp_path, [(["still working"], None)], clock=clock)
    svc.tick()
    S.write_control(tmp_path, "pause", "20261119T120000-3c4d")
    svc.tick()
    for _ in range(5):
        svc.tick()                       # the clock keeps advancing
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "paused"
    assert live["scanners"]["clamav"]["state"] == "running"
