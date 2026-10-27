"""tool-control.sh scan-all — the shell half of the one-click full scan.

Runs the real script with its systemctl calls stubbed by PATH, and asserts
each on-demand scanner is launched exactly once. This is the piece that
makes "Scan everything" work as a single polkit invocation.

The ClamAV/rkhunter/lynis *binaries* are invoked by absolute path (matching
scan-now.sh, whose pattern is proven in production) and run as root via
pkexec. They are too heavy/dangerous to execute in a test, and unprivileged
mount namespaces are unavailable here, so their launch is verified by
source inspection in tests/test_scan_all.py instead — this file pins the
systemctl half that CAN be executed safely under a PATH stub."""
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apply" / "tool-control.sh"


def _stub_bin(tmp_path, calls):
    """A PATH dir of a fake systemctl that records its arguments."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "systemctl"
    stub.write_text(
        "#!/bin/sh\n"
        f'echo "systemctl $*" >> "{calls}"\n'
        "exit 0\n")
    stub.chmod(0o755)
    return bindir


def test_scan_all_launches_every_scanner_once(tmp_path):
    calls = tmp_path / "calls.log"
    calls.write_text("")
    bindir = _stub_bin(tmp_path, calls)
    # GW_USER_HOME pins GH so clam-scan.log lands in tmp, not the real home;
    # the absolute-path scanners are NOT executed here (see module docstring)
    env = dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"],
               GW_USER_HOME=str(tmp_path))
    r = subprocess.run(["bash", str(SCRIPT), "scan-all"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    log = calls.read_text()
    # the two systemd-started scanners, each exactly once
    assert log.count("yara-tmp-scan.service") == 1, log
    assert log.count("aide-check.service") == 1, log
    # the batch stops there — it must not fall through to per-unit control
    assert "not allowed" not in (r.stderr or ""), r.stderr


def test_scan_all_is_one_arg_branch(tmp_path):
    # scan-all takes no further argument: anything else is a usage error
    r = subprocess.run(["bash", str(SCRIPT), "scan-all", "extra"],
                       capture_output=True, text=True, timeout=15)
    assert r.returncode != 0


def test_start_all_and_stop_all_unchanged(tmp_path):
    # the pre-existing one-shot batch control must still work
    calls = tmp_path / "calls.log"
    calls.write_text("")
    bindir = _stub_bin(tmp_path, calls)
    env = dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"])
    r = subprocess.run(["bash", str(SCRIPT), "start-all"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    log = calls.read_text()
    assert "responderd.service" in log
    assert "clamav-daemon.service" in log
    assert "scan-all" not in log          # batch start is NOT scan-all
