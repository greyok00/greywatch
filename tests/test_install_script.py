"""install.sh self-test — a full install into a staging dir must produce
every deployable piece (substituted unit, complete polkit allowlist,
icons, launcher) and pass its own --check; an empty deployment must fail
the check loudly. No root, no system files touched."""
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_install(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(ROOT / "install.sh"), *args],
                          cwd=ROOT, capture_output=True, text=True,
                          timeout=180)


def test_staged_full_install_passes_its_own_check(tmp_path):
    stage = tmp_path / "stage"
    out = run_install("--root", str(stage))
    assert out.returncode == 0, out.stdout + out.stderr
    unit = (stage / "etc/systemd/system/greywatch.service")
    policy = (stage / "usr/share/polkit-1/actions/greywatch.apply.policy")
    unit_src = unit.read_text(encoding="utf-8")
    assert "__GW_HOME__" not in unit_src
    assert f"ExecStart=/usr/bin/python3 {ROOT}/greywatch_daemon.py" in unit_src
    assert "CPUQuota=50%" in unit_src and "MemoryMax=768M" in unit_src
    assert "NoNewPrivileges=true" in unit_src
    assert "nft delete table inet greywatch_appfw" in unit_src
    assert policy.is_file()
    policy_src = policy.read_text(encoding="utf-8")
    assert "__GW_HOME__" not in policy_src
    for helper in ("unban-ip", "scan-now", "harden"):
        assert f"{ROOT}/apply/{helper}.sh" in policy_src, helper
    for s in ("16", "24", "32", "48", "64", "128", "256"):
        assert (stage / f"home/.local/share/icons/hicolor/{s}x{s}/apps/"
                        "greywatch.png").is_file(), s
    entry = stage / "home/.local/share/applications/greywatch.desktop"
    assert "ui/app.py" in entry.read_text(encoding="utf-8")
    chk = run_install("--check", "--root", str(stage))
    assert chk.returncode == 0, chk.stdout + chk.stderr
    assert "everything matches" in chk.stdout


def test_check_fails_loudly_on_empty_deployment(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    r = run_install("--check", str(empty))
    assert r.returncode == 1
    assert "✗" in r.stdout