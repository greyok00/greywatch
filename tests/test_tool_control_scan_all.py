"""tool-control.sh scan-all — the shell half of the full scan.

Owner 2026-11-19: "DO NOT LET IT DO MULTIPLE SCANS AT ALL. ONLY 1 AT A
TIME. HAVE IT SEARCH FOR AND CONTROL ANY EXISTING RUNNING SCAN."

The helper no longer launches any scanner. It files ONE request; the
resident service owns the one slot, runs the five scanners in order, and
the window latches onto the live document. These tests pin that contract:
a request is written, no scanner or systemctl process is started, and the
single-arg branch still refuses extra arguments."""
import json
import os
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apply" / "tool-control.sh"


def _run(tmp_path, extra=()):
    env = dict(os.environ, GW_DATA_DIR=str(tmp_path))
    return subprocess.run(["bash", str(SCRIPT), "scan-all", *extra],
                          capture_output=True, text=True, env=env,
                          timeout=30)


def test_scan_all_files_one_full_request(tmp_path):
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr
    doc = json.loads((tmp_path / "scan-request.json").read_text())
    assert doc["key"] == "full"
    assert re.fullmatch(r"\d{8}T\d{6}-[0-9a-f]{4}", doc["id"]), doc


def test_scan_all_launches_no_scanner_and_no_unit(tmp_path):
    calls = tmp_path / "calls.log"
    calls.write_text("")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("systemctl", "clamscan", "rkhunter", "lynis", "aide",
                 "yara"):
        stub = bindir / name
        stub.write_text(f'#!/bin/sh\necho "{name} $*" >> "{calls}"\n'
                        "exit 0\n")
        stub.chmod(0o755)
    env = dict(os.environ, GW_DATA_DIR=str(tmp_path),
               PATH=str(bindir) + ":" + os.environ["PATH"])
    r = subprocess.run(["bash", str(SCRIPT), "scan-all"],
                       capture_output=True, text=True, env=env,
                       timeout=30)
    assert r.returncode == 0, r.stderr
    assert calls.read_text() == ""            # nothing was launched
    assert (tmp_path / "scan-request.json").exists()


def test_a_second_request_replaces_the_one_slot_never_a_second_run(tmp_path):
    assert _run(tmp_path).returncode == 0
    first = json.loads((tmp_path / "scan-request.json").read_text())
    assert _run(tmp_path).returncode == 0
    second = json.loads((tmp_path / "scan-request.json").read_text())
    # One request slot on disk; the daemon's global lock is what makes a
    # second scanner impossible, and no second request file exists.
    assert first["id"] != second["id"]
    assert sorted(p.name for p in tmp_path.glob("scan-request*")) == \
        ["scan-request.json"]


def test_scan_all_is_one_arg_branch(tmp_path):
    r = subprocess.run(["bash", str(SCRIPT), "scan-all", "extra"],
                       capture_output=True, text=True, timeout=15)
    assert r.returncode != 0


def test_start_all_skips_the_daily_timer_and_the_retired_engine(tmp_path):
    calls = tmp_path / "calls.log"
    calls.write_text("")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "systemctl"
    stub.write_text(f'#!/bin/sh\necho "systemctl $*" >> "{calls}"\n'
                    "exit 0\n")
    stub.chmod(0o755)
    env = dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"])
    r = subprocess.run(["bash", str(SCRIPT), "start-all"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    log = calls.read_text()
    assert "responderd.service" in log
    # the daily clam timer and the retired, masked engine are never armed
    assert "greywatch-clam-scan.timer" not in log
    assert "clamav-daemon.service" not in log
    assert "scan-all" not in log          # batch start is NOT scan-all
