import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "build-wheel.sh"


def test_wheel_packages_the_program_tree():
    """packaging/build-wheel.sh yields an installable py3-none-any wheel."""
    if not (shutil.which("bash") and SCRIPT.exists()):
        import pytest
        pytest.skip("packaging script not available")
    try:
        subprocess.run(["python3", "-m", "build", "--version"],
                       check=True, capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        import pytest
        pytest.skip("python -m build not available")
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp)
        subprocess.run([SCRIPT, str(out)], cwd=ROOT, check=True,
                       capture_output=True, text=True)
        wheels = list(out.glob("greywatch-*.whl"))
        assert len(wheels) == 1 and wheels[0].name == \
            "greywatch-0.1.0-py3-none-any.whl"

        names = subprocess.run(["python3", "-m", "zipfile", "-l",
                                str(wheels[0])], capture_output=True,
                               text=True, check=True).stdout
        # the real tree rides verbatim in _tree; nothing that would not
        # install cleanly ships
        for required in ("greywatch/_tree/cli.py",
                         "greywatch/_tree/registry.json",
                         "greywatch/_tree/pyproject.toml",
                         "greywatch/_launch.py",
                         "greywatch/__init__.py"):
            assert required in names, required
        bad = [n for n in names.splitlines()
               if "tests/" in n or "/data/" in n or ".so" in n
               or ".github/" in n or "doc/shots" in n]
        assert not bad, bad[:3]

        # install into a throwaway venv and prove the launcher runs the
        # real CLI from an unrelated cwd
        venv = pathlib.Path(tmp) / "wtest"
        subprocess.run(["python3", "-m", "venv", str(venv)], check=True,
                       capture_output=True)
        subprocess.run([str(venv / "bin" / "pip"), "install", "-q",
                        str(wheels[0])], check=True, capture_output=True)
        version = subprocess.run(
            [str(venv / "bin" / "gw"), "--version"],
            capture_output=True, text=True, check=True, cwd="/")
        assert version.stdout.startswith("greywatch 0.1.0")