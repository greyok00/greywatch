import pathlib
import subprocess
import sys

import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_version_flag_matches_pyproject():
    """cli --version reads pyproject.toml — the ONE version source."""
    out = subprocess.run([sys.executable, "cli.py", "--version"], cwd=ROOT,
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    want = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert out.stdout.strip() == f"greywatch {want} (pyproject.toml)"