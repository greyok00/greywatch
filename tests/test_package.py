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
        assert ("Environment=GREYWATCH_UI_USER=grey"   # build-time default;
                in unit)                               # postinst persists the
                                                       # desktop identity
        assert ("ExecStart=/usr/bin/python3 "
                "/opt/greywatch/greywatch_daemon.py "
                "--data-dir /var/lib/greywatch") in unit
        assert unit.count("/opt/greywatch/greywatch_daemon.py") == 1
        cli = extract / "opt/greywatch/cli.py"
        version = subprocess.run(["python3", str(cli), "--version"],
                                 capture_output=True, text=True, check=True)
        assert version.stdout.startswith(f"greywatch {VER} (pyproject.toml)")