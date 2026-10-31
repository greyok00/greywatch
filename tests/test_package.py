import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "build-deb.sh"


def _version():
    import tomllib
    return tomllib.loads(
        (ROOT / "pyproject.toml").read_text())["project"]["version"]


VER = _version()


def test_deb_packages_the_program():
    """packaging/build-deb.sh yields a valid .deb with a runnable payload."""
    if not (shutil.which("dpkg-deb") and SCRIPT.exists()):
        import pytest
        pytest.skip("dpkg-deb or packaging script not available")
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp)
        subprocess.run([SCRIPT, str(out)], cwd=ROOT, check=True,
                       capture_output=True, text=True)
        deb = out / f"greywatch_{VER}_amd64.deb"
        assert deb.exists() and deb.stat().st_size > 1_000_000

        info = subprocess.run(["dpkg-deb", "--info", str(deb)],
                              capture_output=True, text=True, check=True)
        assert f"Version: {VER}" in info.stdout
        assert "Maintainer: greyok00 <greyok00@users.noreply.github.com>" \
            in info.stdout

        contents = subprocess.run(["dpkg-deb", "--contents", str(deb)],
                                  capture_output=True, text=True,
                                  check=True).stdout
        # A module that ships .so dropped its .py, so the package only runs
        # on the Python minor it was compiled for; Depends must say so or
        # apt installs a tree that cannot import (Debian 12's 3.11, or 3.13).
        abis = {line.split(".cpython-")[1].split("-")[0]
                for line in contents.splitlines() if ".cpython-" in line}
        deps = next(line for line in map(str.strip, info.stdout.splitlines())
                    if line.startswith("Depends:"))
        if abis:
            assert len(abis) == 1, abis
            abi = abis.pop()
            minor = int(abi[1:])
            assert f"python3 (>= {abi[0]}.{minor})" in deps, deps
            assert f"python3 (<< {abi[0]}.{minor + 1})" in deps, deps
            # no readable fallback survives beside the compiled module
            assert "opt/greywatch/ui/window.py" not in contents
        else:
            assert "python3 (>= 3.12)" in deps, deps
        for required in ("opt/greywatch/greywatch_daemon.py",
                         "opt/greywatch/cli.py",
                         "etc/systemd/system/greywatch.service",
                         "usr/share/polkit-1/actions/greywatch.apply.policy",
                         "usr/share/applications/greywatch.desktop",
                         "usr/share/icons/hicolor/256x256/apps/greywatch.png"):
            assert required in contents, required
        # runtime state and the test tree never ship in the package
        bad = [line for line in contents.splitlines()
               if "/tests/" in line or "data/" in line]
        assert not bad, bad[:3]

        # the filled unit must point at /opt/greywatch, never hold the
        # template placeholder, and the payload must actually run
        extract = pathlib.Path(tmp) / "x"
        subprocess.run(["dpkg-deb", "-x", str(deb), str(extract)],
                       check=True,
                       capture_output=True, text=True)
        unit = (extract / "etc/systemd/system/greywatch.service").read_text()
        for placeholder in ("__GW_HOME__", "__GW_LIB__", "__GW_DATA__",
                            "__GW_UI_USER__"):
            assert placeholder not in unit
        # The package must not bake a personal account name in: the field
        # ships empty and postinst persists the desktop identity it finds.
        ui_line = next(ln for ln in unit.splitlines()
                       if ln.startswith("Environment=GREYWATCH_UI_USER="))
        assert ui_line == "Environment=GREYWATCH_UI_USER="
        assert "grey" not in ui_line
        assert ("ExecStart=/usr/bin/python3 "
                "/opt/greywatch/greywatch_daemon.py "
                "--data-dir /var/lib/greywatch") in unit
        assert unit.count("/opt/greywatch/greywatch_daemon.py") == 1
        cli = extract / "opt/greywatch/cli.py"
        version = subprocess.run(["python3", str(cli), "--version"],
                                 capture_output=True, text=True, check=True)
        assert version.stdout.startswith(f"greywatch {VER} (pyproject.toml)")

def test_the_installer_refuses_modules_from_another_python(tmp_path):
    """A tree whose .so were built elsewhere must not be deployed silently."""
    tree = tmp_path / "tree"
    (tree / "ui").mkdir(parents=True)
    mod = tree / "ui" / "window.cpython-399-x86_64-linux-gnu.so"
    mod.write_bytes(b"")
    src = (ROOT / "install.sh").read_text()
    start = src.index("_check_abi() {")
    fn = src[start:src.index("\n}\n", start) + 3]
    probe = tmp_path / "probe.sh"
    probe.write_text(fn + '\n_check_abi "$1"\n')
    env = {**os.environ, "GREYWATCH_PYTHON": shutil.which("python3") or "python3"}
    got = subprocess.run(["bash", str(probe), str(tree)],
                         capture_output=True, text=True, env=env)
    assert got.returncode == 2
    assert "compiled for Python 3.99" in got.stderr
    assert "wheel" in got.stderr
    # A source checkout (no .so) passes the same check.
    mod.unlink()
    ok = subprocess.run(["bash", str(probe), str(tree)],
                        capture_output=True, text=True, env=env)
    assert ok.returncode == 0 and not ok.stderr
