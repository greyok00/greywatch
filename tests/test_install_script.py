"""install.sh self-test — a full install into a staging dir must produce
every deployable piece (root-owned program tree at usr/lib/greywatch with
the state dir separate, substituted unit, complete polkit allowlist,
icons, launcher) and pass its own --check; an empty deployment must fail
the check loudly. No root, no system files touched.

Acceptance for the source-review security fix: the root service's
ExecStart and the polkit helpers point at the INSTALLED program tree —
never at a user-writable checkout."""
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_install(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(ROOT / "install.sh"), *args],
                          cwd=ROOT, capture_output=True, text=True,
                          timeout=300)


def test_staged_full_install_passes_its_own_check(tmp_path):
    stage = tmp_path / "stage"
    out = run_install("--root", str(stage))
    assert out.returncode == 0, out.stdout + out.stderr
    lib = stage / "usr/lib/greywatch"
    data = stage / "var/lib/greywatch"
    assert (lib / "greywatch_daemon.py").is_file()
    assert (lib / "apply/unban-ip.sh").is_file()
    assert (lib / "ui").is_dir()
    assert data.is_dir()                      # runtime state lives apart

    # no leftover caches or data in the program tree
    assert not (lib / "data").exists()
    assert list(lib.glob("**/__pycache__")) == []

    unit = stage / "etc/systemd/system/greywatch.service"
    policy = stage / "usr/share/polkit-1/actions/greywatch.apply.policy"
    unit_src = unit.read_text(encoding="utf-8")
    assert "__GW_HOME__" not in unit_src
    assert "__GW_LIB__" not in unit_src and "__GW_DATA__" not in unit_src
    assert "__GW_UI_USER__" not in unit_src     # GW-02: identity resolved
    assert "Environment=GREYWATCH_UI_USER=" in unit_src
    # the daemon must run from the installed, root-owned tree — NOT the checkout
    assert f"{ROOT}/greywatch_daemon.py" not in unit_src
    assert ("ExecStart=/usr/bin/python3 "
            f"{lib}/greywatch_daemon.py --data-dir {data}") in unit_src
    assert "CPUQuota=50%" in unit_src and "MemoryMax=768M" in unit_src
    assert "NoNewPrivileges=true" in unit_src
    assert "nft delete table inet greywatch_appfw" in unit_src
    assert policy.is_file()
    policy_src = policy.read_text(encoding="utf-8")
    assert "__GW_HOME__" not in policy_src and "__GW_LIB__" not in policy_src
    for helper in ("unban-ip", "scan-now", "harden", "tool-control"):
        assert f"{lib}/apply/{helper}.sh" in policy_src, helper
    # modules-load.d file: the appfw engine needs nfnetlink_queue + nft_queue
    modules = stage / "etc/modules-load.d/greywatch-appfw.conf"
    assert modules.is_file()
    msrc = modules.read_text(encoding="utf-8")
    assert "nfnetlink_queue" in msrc and "nft_queue" in msrc
    for s in ("16", "24", "32", "48", "64", "128", "256"):
        assert (stage / f"home/.local/share/icons/hicolor/{s}x{s}/apps/"
                        "greywatch.png").is_file(), s
    entry = stage / "home/.local/share/applications/greywatch.desktop"
    assert "ui/app.py" in entry.read_text(encoding="utf-8")
    chk = run_install("--check", "--root", str(stage))
    assert chk.returncode == 0, chk.stdout + chk.stderr
    assert "everything matches" in chk.stdout


def test_staged_program_tree_and_helpers_other_write_free(tmp_path):
    """Acceptance: an ordinary user must be unable to modify the code the
    root daemon runs, its imported modules, or the polkit helpers — every
    file/dir in the program tree must be other-write-free."""
    stage = tmp_path / "stage"
    out = run_install("--root", str(stage))
    assert out.returncode == 0, out.stdout + out.stderr
    loose = subprocess.run(["find", str(stage / "usr/lib/greywatch"),
                            "-perm", "-o+w"], capture_output=True, text=True)
    assert loose.stdout.strip() == "", loose.stdout
    # helpers must be executable in the installed tree
    helper = stage / "usr/lib/greywatch/apply/unban-ip.sh"
    assert helper.stat().st_mode & 0o111


def test_check_fails_loudly_on_empty_deployment(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    r = run_install("--check", str(empty))
    assert r.returncode == 1
    assert "✗" in r.stdout


def test_check_rejects_user_writable_exec_target(tmp_path):
    """The staged check must fail when the program tree gains an
    other-writable file — a user-writable ExecStart is exactly what the
    deployment refuses."""
    stage = tmp_path / "stage"
    out = run_install("--root", str(stage))
    assert out.returncode == 0, out.stdout + out.stderr
    daemon = stage / "usr/lib/greywatch/greywatch_daemon.py"
    daemon.chmod(0o666)                      # simulate a loosened tree
    chk = run_install("--check", "--root", str(stage))
    assert chk.returncode == 1
    assert "other-writable" in chk.stdout