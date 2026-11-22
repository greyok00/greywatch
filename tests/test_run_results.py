"""`greywatch run` must show results, not "started" notes.

Owner 2026-11-14: the run command printed rc=0 per lane and pointed at
raw log paths. These tests pin the replacement contract: each tool's
findings print as it lands, a second call attaches to a finished run
without restarting anything, root-held results (rkhunter, lynis) ride
the scan-now digest, and every failure state states itself.
"""
import argparse
import json
import pathlib
import time

import pytest

import cli


@pytest.fixture(autouse=True)
def _no_real_poll_sleep(monkeypatch):
    monkeypatch.setattr(cli, "_RUN_POLL_SECONDS", 0)


def seed_results(tmp_path: pathlib.Path, epoch: float) -> dict:
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    yara = logs / "yara-scan.log"
    clam = logs / "clam-scan.log"
    aide = logs / "last-check.txt"
    live_hit = tmp_path / "seed-hit.txt"
    live_hit.write_text("test fixture")
    yara.write_text(
        f"with_urls {live_hit} (realtime sha256:2699b)\n"
        "rule eicar matched /tmp/gone-file.txt\n")
    clam.write_text(
        "-------- SCAN SUMMARY --------\nKnown viruses: 8715384\n"
        "Infected files: 0\nTotal files: 12345\n")
    aide.write_text(
        "AIDE found differences between database and filesystem!!\n\n"
        "Summary:\n  Total number of entries:\t13172\n"
        "  Added entries:\t\t727\n  Removed entries:\t\t27\n"
        "  Changed entries:\t\t352\n")
    state = tmp_path / "run-scan-state.json"
    state.write_text(json.dumps({
        "started": "now", "epoch": epoch,
        "rkhunter_offset": 0, "yara_offset": 0, "clam_offset": 0,
        "yara_log": str(yara), "clam_log": str(clam),
        "aide_report": str(aide)}))
    return {"state": state, "yara": yara, "clam": clam, "aide": aide}


DIGEST_OUT = (
    "# TOOL rkhunter\n"
    "[09:09:01]  Warning: The file /etc/passwd has changed\n"
    "# TOOL lynis\n"
    "hardening_index=61\n"
    "warning[]=WZB-0050|Boot loader is present\n")


def _monkeypatch_state(monkeypatch, tmp_path, paths):
    monkeypatch.setattr(cli, "_run_state_path", lambda: paths["state"])
    monkeypatch.setattr(cli, "_ui_home", lambda: tmp_path)


def test_run_prints_each_result_and_verdict(tmp_path, monkeypatch, capsys):
    paths = seed_results(tmp_path, epoch=time.time() - 1)
    _monkeypatch_state(monkeypatch, tmp_path, paths)
    calls = {"n": 0}

    def running(tool):
        calls["n"] += 1
        # the start probe (calls 1-5) sees nothing yet; the first poll
        # cycle (6-10) sees the five launched scans
        return 5 < calls["n"] <= 10

    def runner(args_list, timeout=120):
        if args_list[0] == "start-all":
            return 0, "started yara\nstarted clamav\nSTATE %s\n" \
                   % paths["state"], ""
        assert args_list[0] == "digest", args_list
        return 0, DIGEST_OUT, ""

    results, rc = cli.run_every_detector(runner=runner, running=running)
    out = capsys.readouterr().out
    assert "no viruses found (12,345 files scanned)" in out
    assert "352 system files changed, 727 new, 27 gone" in out
    assert "1 file matched suspicious patterns" in out
    assert "hardening score 61 out of 100" in out
    assert "PROBLEM rkhunter" in out
    assert "Nothing dangerous" not in out
    assert "with_urls" in out  # the live hit detail
    assert rc == 0
    tools = [r["tool"] for r in results]
    assert sorted(tools) == sorted(
        ["clamav", "aide", "yara", "rkhunter", "lynis"])


def test_re_run_after_finish_digests_without_restarting(
        tmp_path, monkeypatch, capsys):
    paths = seed_results(tmp_path, epoch=time.time() - 120)
    _monkeypatch_state(monkeypatch, tmp_path, paths)

    def runner(args_list, timeout=120):
        assert args_list[0] == "digest", "must not restart scans"
        return 0, DIGEST_OUT, ""

    results, rc = cli.run_every_detector(runner=runner, running=lambda t: False)
    out = capsys.readouterr().out
    assert "showing their results" in out
    assert "Start results:" not in out
    assert "no viruses found (12,345 files scanned)" in out
    assert rc == 0
    assert len(results) == 5


def test_digest_unavailable_states_itself(tmp_path, monkeypatch, capsys):
    paths = seed_results(tmp_path, epoch=time.time() - 120)
    _monkeypatch_state(monkeypatch, tmp_path, paths)

    def runner(args_list, timeout=120):
        assert args_list[0] == "digest"
        return 0, "", "NO-STATE /usr/lib/greywatch/data/run-scan-state.json"

    results, rc = cli.run_every_detector(runner=runner, running=lambda t: False)
    capsys.readouterr()
    assert sum("could not be read from the root log" in r["headline"]
               for r in results) == 2
    assert rc == 0


def test_clam_infected_head_reads_plurals_right():
    mark, head, det, n = cli._clamav_result(
        "/tmp/payload.txt: Win.Trojan.Xy FOUND\n"
        "/tmp/payload2.txt: Win.Trojan.Zz FOUND\n"
        "Infected files: 2\nTotal files: 9999\n", True)
    assert mark == "RED" and head == "2 INFECTED FILES, paths below"


def test_still_running_tools_time_out_honestly(tmp_path, monkeypatch, capsys):
    paths = seed_results(tmp_path, epoch=time.time() - 1)
    _monkeypatch_state(monkeypatch, tmp_path, paths)
    monkeypatch.setattr(cli, "_RUN_POLL_SECONDS", 0)
    monkeypatch.setattr(cli, "_RUN_START_GRACE", 0)
    monkeypatch.setattr(cli, "_RUN_TIMEOUTS",
                        {t: 0.01 for t in cli._RUN_TOOLS})

    def runner(args_list, timeout=120):
        return 0, "STATE %s\n" % paths["state"], ""

    results, rc = cli.run_every_detector(runner=runner, running=lambda t: True)
    out = capsys.readouterr().out
    assert sum("still running after" in r["headline"]
               for r in results) == 5
    assert "keeps going in the background" in out
    assert rc == 0


def test_failed_start_is_exit_err(tmp_path, monkeypatch, capsys):
    paths = seed_results(tmp_path, epoch=time.time() - 1)
    _monkeypatch_state(monkeypatch, tmp_path, paths)
    monkeypatch.setattr(cli, "_RUN_START_GRACE", 0)

    def runner(args_list, timeout=120):
        return 1, "", "start failed at the helper"

    results, rc = cli.run_every_detector(runner=runner, running=lambda t: False)
    out = capsys.readouterr().out
    root_rows = [r["headline"] for r in results
                 if r["tool"] in cli._RUN_ROOT_TOOLS]
    assert sum("did not run" in h for h in root_rows) == 2
    assert "the helper said: start failed at the helper" in out
    assert rc == 1


def test_json_mode_files_the_request(tmp_path, monkeypatch, capsys):
    # The run verb is the request seam now (owner 2026-11-18): json mode
    # files the request into THIS tmp dir and reports it - never the
    # real data dir, never the helper.
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    rc = cli.cmd_run(argparse.Namespace(json=True, scan="full"))
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert doc["requested"] is True
    assert (tmp_path / "scan-request.json").exists()


def test_digest_section_splitting():
    sections = cli._split_digest(
        "# TOOL rkhunter\nwarning one\n\n# TOOL lynis\nhardening_index=61\n")
    assert sections == {"rkhunter": ["warning one"],
                        "lynis": ["hardening_index=61"]}


def test_parser_fallback_counts_bare_warnings():
    mark, head, det, n = cli._rkhunter_result(
        "Warning: bare line without the timestamp prefix", started=True)
    assert mark == "RED" and n == 1 and "Warning:" in det[0]




def test_yara_stale_entries_are_history_not_threats(tmp_path):
    gone = tmp_path / "absent.txt"          # never created
    mark, head, det, n = cli._yara_result(
        f"eicar {gone}\n", started=True)
    assert mark == "GREEN" and n == 0
    assert "old entry: rule eicar matched" in " ".join(det)
    assert "matched suspicious patterns" not in head


def test_yara_live_hit_counts_and_gone_notes(tmp_path):
    live = tmp_path / "live.txt"
    live.write_text("present")
    mark, head, det, n = cli._yara_result(
        f"bad_rule {live}\nx_rule /nope/missing.txt\n", started=True)
    assert mark == "RED" and n == 1
    assert "file\(s\) no longer exist" in det[-1] or "no longer exist" in det[-1] or "older" in det[-1]


def test_clam_journal_names_a_killed_scan(tmp_path):
    log = tmp_path / "clam-scan.log"
    log.write_text("WARNING: nothing\n")
    import time as tmod
    (tmp_path / "clam-run.log").write_text(
        f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} clamscan start\n"
        f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} clamscan exit rc=137\n")
    text = cli.add_clam_journal(log.read_text(), str(log), tmod.time() - 60)
    assert "killed" in text


def test_clean_aide_and_clam_heads():
    assert cli._aide_result(
        "AIDE found no differences between database and filesystem!",
        True)[0] == "GREEN"
    mark, head, det, n = cli._clamav_result(
        "Infected files: 0\nTotal files: 4200\n", True)
    assert mark == "GREEN" and "4,200" in head and "no viruses" in head


def test_triage_scan_guard(owner="2026-11-18"):
    from greywatch_daemon import triage_scan_due
    # Retired (owner 2026-11-17, the neverending scan): no finding ever
    # launches a scan again - the antivirus is the daily timer and the
    # owner's own run.
    for ev in ({"from_tool": "yara-watch", "severity": "HIGH"},
               {"from_tool": "psad", "severity": "CRITICAL"},
               {"from_tool": "clamav", "severity": "HIGH"},
               {"from_tool": "yara-watch", "severity": "MEDIUM"}):
        assert not triage_scan_due(ev, False, 0.0, 10_000_000.0)


def test_finished_run_history_retires_after_thirty_minutes(tmp_path,
                                                           monkeypatch,
                                                           capsys):
    """A finished run's digest is history, not a rerun for six hours:
    past the window the next call starts a fresh scan (owner 2026-11-
    14, the run that printed the same problems twice)."""
    paths = seed_results(tmp_path, epoch=time.time() - 130 * 60)
    _monkeypatch_state(monkeypatch, tmp_path, paths)
    launched = []

    def runner(args_list, timeout=120):
        launched.append(args_list[0])
        return 0, f"started x\nSTATE {paths['state']}\n", ""

    results, rc = cli.run_every_detector(runner=runner,
                                         running=lambda t: False)
    out = capsys.readouterr().out
    assert "started fresh" not in out
    assert launched == ["start-all"], "a stale history must not be reprinted"


def test_findings_whitelist_filters_and_never_counts(tmp_path,
                                                     monkeypatch):
    """The owner's ignore list: whitelisted paths drop out of the clam
    digest with an honest note, and never count as findings. The state
    dir is redirected: the lookup must read the SAME file the test
    writes, never whatever the host's real whitelist happens to hold.
    The entries are written with their subtree flag EXPLICIT: add()
    sniffs the host filesystem (p.is_dir() at add time) to decide it,
    and these paths exist on some machines and not others - a CI box
    read the same entries as exact-file matches and filtered nothing."""
    from core import scan_whitelist as W
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    W.save({"version": 1, "entries": [
        {"target": "/tmp/pytest-of-grey", "subtree": True},
        {"target": "/etc/unicornscan", "subtree": True},
    ]})
    mark, head, det, n = cli._clamav_result(
        "/etc/unicornscan/payloads.conf: Py.Trojan.NecroBot FOUND\n"
        "/tmp/pytest-of-grey/p8/x: Eicar-Test-Signature FOUND\n"
        "/tmp/REAL-threat.txt: Win.Trojan.BAD FOUND\n"
        "Infected files: 3\nTotal files: 99\n", True)
    assert n == 1 and "/tmp/REAL-threat" in det[0]
    assert "whitelisted paths ignored this run" in head
    assert mark == "RED"
