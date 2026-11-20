"""GW-180: the hunter unit's ExecStart runs hunter/main.py BY PATH.

Python starts a path-run script with the script's own directory on
sys.path, so hunter/main.py could not import its own `hunter` package -
the deb-installed hunter looped "No module named 'hunter'" every 15 s and
nothing in the tree could see it, because every test imports hunter.main
as a MODULE (whose sys.path already holds the parent). The bootstrap at
the top of main.py points the search back one level; this pin runs the
file exactly the way the unit does and keeps it that way.
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_hunter_main_runs_by_path_like_the_unit_does():
    # --help exits before argparse enforces --data-dir, so this exercises
    # the full import chain without touching any store or hunting state.
    proc = subprocess.run([sys.executable, "hunter/main.py", "--help"],
                          cwd=ROOT, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "gw-hunter" in proc.stdout, "argparse help did not print"
