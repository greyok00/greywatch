"""The patch helper runs apt only for installed packages, with a bounded
argument shape, and reports the before/after versions."""
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apply" / "patch-packages.sh"


def _bins(tmp_path):
    calls = tmp_path / "apt.log"
    calls.write_text("")
    apt = tmp_path / "apt-get"
    apt.write_text("#!/bin/sh\n"
                   f'echo "$*" >> "{calls}"\n'
                   "exit 0\n")
    apt.chmod(0o755)
    dpkg = tmp_path / "dpkg-query"
    dpkg.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        '  *Version*) echo "1.0"; exit 0 ;;\n'
        '  *missing*) exit 1 ;;\n'
        "esac\n"
        "exit 0\n")
    dpkg.chmod(0o755)
    return apt, dpkg, calls


def _run(tmp_path, *args):
    apt, dpkg, calls = _bins(tmp_path)
    env = dict(os.environ, APT_GET_BIN=str(apt),
               DPKG_QUERY_BIN=str(dpkg))
    proc = subprocess.run(["bash", str(SCRIPT), *args],
                          capture_output=True, text=True, env=env,
                          timeout=30)
    return proc, calls


def test_the_helper_upgrades_only_the_named_installed_package(tmp_path):
    proc, calls = _run(tmp_path, "openssl")
    assert proc.returncode == 0, proc.stderr
    assert "patched openssl 1.0 -> 1.0" in proc.stdout
    log = calls.read_text()
    assert "install --only-upgrade -- openssl" in log


def test_a_bad_name_never_reaches_apt(tmp_path):
    proc, calls = _run(tmp_path, "../etc/passwd")
    assert proc.returncode != 0
    assert calls.read_text() == ""


def test_a_package_that_is_not_installed_is_refused(tmp_path):
    proc, calls = _run(tmp_path, "missing")
    assert proc.returncode != 0
    assert "not installed" in proc.stderr
    assert calls.read_text() == ""


def test_all_runs_one_upgrade_command(tmp_path):
    proc, calls = _run(tmp_path, "--all")
    assert proc.returncode == 0, proc.stderr
    log = calls.read_text()
    assert "upgrade" in log
    assert "--only-upgrade" not in log
