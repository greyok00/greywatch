"""tool-control.sh scan-all — the shell half of the one-click full scan.

Runs the real script with systemctl AND every heavy scanner binary stubbed
by a tmp_path PATH dir (the launch is by env-overridable BIN variable,
so the absolute-path default still matches production). Asserts each
on-demand scanner is launched exactly once, and that a second scan-all
while a scanner is already running SKIPS that scanner instead of piling
on (the 2026-11-06 orphan-storm finding: three test-run clamscan
processes left grinding the whole home directory at 97% CPU)."""
import fcntl
import os
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apply" / "tool-control.sh"
SCANNERS = {
    "clamscan": ("CLAMSCAN_BIN", "clam-scan.lock"),
    "rkhunter": ("RKHUNTER_BIN", "rkhunter.lock"),
    "lynis": ("LYNIS_BIN", "lynis.lock"),
}


def _stub_bin(tmp_path, calls, names):
    """A PATH dir of a fake systemctl recording its arguments, plus
    recording stubs for the scanner binaries that the script launches
    through CLAMSCAN_BIN/RKHUNTER_BIN/LYNIS_BIN."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "systemctl"
    stub.write_text(
        "#!/bin/sh\n"
        f'echo "systemctl $*" >> "{calls}"\n'
        "exit 0\n")
    stub.chmod(0o755)
    for name in names:
        stub = bindir / name
        stub.write_text(
            "#!/bin/sh\n"
            f'echo "{name}" >> "{calls}"\n'
            "exit 0\n")
        stub.chmod(0o755)
    return bindir


def _run(tmp_path, calls, bindir):
    # GW_USER_HOME pins GH so clam-scan.log lands in tmp, not the real home;
    # the scanner BIN/OVERRIDE vars route the launches at the stubs
    env = dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"],
               GW_USER_HOME=str(tmp_path))
    for name, (env_name, _lock) in SCANNERS.items():
        env[env_name] = str(bindir / name)
    env["RKHUNTER_LOG"] = str(tmp_path / "rkhunter.log")
    env["LYNIS_LOG"] = str(tmp_path / "lynis.log")
    return subprocess.run(["bash", str(SCRIPT), "scan-all"],
                          capture_output=True, text=True, env=env,
                          timeout=30)


def _wait_scanner_launches(calls, names, timeout=2.0):
    """The scanners are launched detached (backgrounded subshells that
    outlive the script), so their stub entries land milliseconds AFTER
    the run returns; poll for them with a bounded wait."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        log = calls.read_text()
        if all(log.count(name) >= 1 for name in names):
            return log
        time.sleep(0.05)
    return calls.read_text()


def test_scan_all_launches_every_scanner_once(tmp_path):
    calls = tmp_path / "calls.log"
    calls.write_text("")
    bindir = _stub_bin(tmp_path, calls, SCANNERS)
    r = _run(tmp_path, calls, bindir)
    assert r.returncode == 0, r.stderr
    log = _wait_scanner_launches(calls, SCANNERS)
    # the three backgrounded scanners, each launched exactly once
    for name in SCANNERS:
        assert log.count(name) == 1, log
    # the two systemd-started scanners, each exactly once
    assert log.count("yara-tmp-scan.service") == 1, log
    assert log.count("aide-check.service") == 1, log
    # the batch stops there — it must not fall through to per-unit control
    assert "not allowed" not in (r.stderr or ""), r.stderr


def test_scan_all_skips_scanners_already_running(tmp_path):
    # the duplicate guard: a scanner whose lock is held is NOT launched a
    # second time, and the run still exits 0 (a busy scanner is not an error)
    calls = tmp_path / "calls.log"
    calls.write_text("")
    bindir = _stub_bin(tmp_path, calls, SCANNERS)
    sh_dir = tmp_path / "security-hardening"
    sh_dir.mkdir()
    held = []                 # keep refs: a rebound file object gets GC'd,
    for name in SCANNERS:     # closing the fd and SILENTLY releasing the lock
        lock_path = sh_dir / SCANNERS[name][1]
        handle = open(lock_path, "w")  # noqa: SIM115 — held for the test
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        held.append(handle)
    r = _run(tmp_path, calls, bindir)
    assert r.returncode == 0, r.stderr
    time.sleep(0.5)                     # any wrongly-launched scanner lands
    log = calls.read_text()
    for name in SCANNERS:
        assert log.count(name) == 0, log          # skipped, never spawned
    assert "already running" in (r.stderr or ""), r.stderr


def test_scan_all_is_one_arg_branch(tmp_path):
    # scan-all takes no further argument: anything else is a usage error
    r = subprocess.run(["bash", str(SCRIPT), "scan-all", "extra"],
                       capture_output=True, text=True, timeout=15)
    assert r.returncode != 0


def test_start_all_and_stop_all_unchanged(tmp_path):
    # the pre-existing one-shot batch control must still work
    calls = tmp_path / "calls.log"
    calls.write_text("")
    bindir = _stub_bin(tmp_path, calls, [])
    env = dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"])
    r = subprocess.run(["bash", str(SCRIPT), "start-all"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    log = calls.read_text()
    assert "responderd.service" in log
    assert "clamav-daemon.service" in log
    assert "scan-all" not in log          # batch start is NOT scan-all
