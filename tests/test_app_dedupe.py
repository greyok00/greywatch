"""Launch dedupe: the matcher that identifies a running greywatch GUI or
tray helper from a /proc cmdline, and the single-instance lock contract
(after the automatic kill, a second instance still cannot steal the
lock while the first is alive)."""
import fcntl
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.app import _is_dup, _single_instance         # noqa: E402


def test_relative_and_absolute_guis_are_duplicates():
    assert _is_dup(["python3", "ui/app.py", ""])
    assert _is_dup(["python3", "/home/x/greywatch/ui/app.py"])


def test_tray_helpers_count_as_part_of_the_instance():
    assert _is_dup(["/usr/bin/python3",
                    "/opt/gw/ui/tray_helper.py"])


def test_unrelated_processes_do_not_match():
    assert _is_dup(["python3", "-m", "pytest", "tests/"]) is False
    assert _is_dup(["/usr/share/word/apply/cve-refresh.sh"]) is False
    assert _is_dup([""]) is False


def test_the_lock_still_refuses_a_second_instance(tmp_path, monkeypatch):
    import ui.app as A
    monkeypatch.setattr(A, "ROOT", tmp_path)
    lock_dir = tmp_path / "data"
    lock_dir.mkdir()
    hold = open(lock_dir / "gui.lock", "w")
    fcntl.flock(hold, fcntl.LOCK_EX | fcntl.LOCK_NB)
    A._LOCK = None
    try:
        assert A._single_instance() is False
    finally:
        fcntl.flock(hold, fcntl.LOCK_UN)
        A._LOCK = None

def test_module_form_is_matched_too():
    # `python3 -m ui.app` (launcher/relaunch module form) is the same GUI —
    # if the matcher misses it, launches stack up and the lock refuses a
    # restart with "already running".
    assert _is_dup(["python3", "-m", "ui.app"])
    assert _is_dup(["/usr/bin/python3", "-m", "ui.app"])
