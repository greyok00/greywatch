import datetime as dt
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
    p = S.parse_progress("clamav", "/home/grey/a.bin: OK")
    assert p["counted"] is True and p["current"] == "/home/grey/a.bin"
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


def test_lynis_tests_count_and_warnings_are_medium():
    p = S.parse_progress("lynis", "  Performing test ID 1.1 (boot)")
    assert p["counted"] is True
    assert p["current"] == "ID 1.1 (boot)"
    p = S.parse_progress("lynis", "Warning: Found old kernel [KRNL-5830]")
    assert p["finding"] == {"severity": "MEDIUM",
                            "text": "Warning: Found old kernel [KRNL-5830]"}


def test_aide_differences_and_yara_matches_are_findings():
    p = S.parse_progress("aide", "d+++++++++++++++++++++++: /etc/passwd")
    assert p["finding"]["severity"] == "HIGH"
    p = S.parse_progress("yara-tmp-scan", "Eicar-Sig /tmp/eicar.txt")
    assert p["finding"]["severity"] == "HIGH"
    assert p["finding"]["text"] == "Eicar-Sig /tmp/eicar.txt"


def test_triage_folds_known_noise_and_defaults_to_real():
    assert S.is_routine(
        "rkhunter", "Warning: Hidden file found: /etc/.updated") is True
    assert S.is_routine(
        "rkhunter", "Warning: Hidden file found: /home/grey/.secret") is False
    assert S.is_routine("lynis", "Suggestion: install auditd") is True
    assert S.is_routine("lynis", "Warning: Found old kernel") is False
    assert S.is_routine("aide", "d+++: /var/cache/apparmor/x") is True
    assert S.is_routine(
        "aide", "d+++: /etc/ssh/sshd_config") is False
    assert S.is_routine("clamav", "Infected file: /tmp/x") is False
    assert S.is_routine("weird-tool", "something nobody classified") is False


def test_exit_codes_are_per_scanner_semantics():
    assert S.exit_verdict("clamav", 0) == ("done", "")
    assert S.exit_verdict("clamav", 1) == ("done", "")
    assert S.exit_verdict("clamav", 2)[0] == "failed"
    assert S.exit_verdict("aide", 7) == ("done", "")
    assert S.exit_verdict("aide", 8)[0] == "failed"
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
    cmds = S.commands_for("scan-all", "/home/grey", "grey")
    assert len(cmds) == 5
    firsts = {c[0] for c in cmds}
    assert "/usr/bin/clamscan" in firsts
    assert "/usr/bin/aide" in firsts
    clam = S.commands_for("clamav", "/home/grey", "grey")[0]
    assert "--infected" not in clam, "infected-only mode hides progress"
    assert "--stdout" in clam
    assert "/etc" in clam and "/usr/local" in clam
    assert S.commands_for("bogus", "/home/grey", "grey") == []


# ---------------------------------------------------------------- service

import json  # noqa: E402
import time  # noqa: E402


class FakeHandle:
    def __init__(self, lines, rc=0, on_kill_rc=None):
        self._lines = list(lines)
        self.final_rc = rc
        self.killed = False
        self.on_kill_rc = on_kill_rc

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

    def spawn(argv):
        calls.append(argv)
        return FakeHandle(*scripts.pop(0))

    svc = S.ScanService(tmp_path, spawn=spawn, home="/home/grey",
                        ui_user="grey", log=lambda *_: None, **kw)
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
        ["startup", "/home/grey/a.bin: OK", "/tmp/e: FOUND"], 1)])
    _run(svc)
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "done"
    assert live["scanners"]["clamav"]["count"] == 2
    assert live["real_findings"] == 1
    assert calls and "clamscan" in calls[0][0]
    findings = (tmp_path / "scan-findings.jsonl").read_text().splitlines()
    row = json.loads(findings[0])
    assert row["routine"] is False
    # A timestamp with an offset: a naive local time sorted against the
    # UTC stamps everywhere else and read an hour or five out.
    assert dt.datetime.fromisoformat(row["ts"]).tzinfo is not None
    summary = json.loads((tmp_path / "scans" /
                          "20261030T074500-a1b2.json").read_text())
    assert summary["scanners"]["clamav"]["exit_code"] == 1


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


def test_a_failed_child_is_named_not_silently_clean(tmp_path):
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


def test_an_interrupted_live_file_is_marked_on_startup(tmp_path):
    (tmp_path / "scan-live.json").write_text(json.dumps({
        "scan_id": "20261030T070000-aaaa", "key": "clamav",
        "state": "running", "ended_at": None,
        "scanners": {"clamav": {"state": "running"}}}))
    svc, _calls = _service(tmp_path, [])
    svc.recover_interrupted()
    live = json.loads((tmp_path / "scan-live.json").read_text())
    assert live["state"] == "interrupted"
    assert live["scanners"]["clamav"]["state"] == "interrupted"
    assert "restart" in live["note"]


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
