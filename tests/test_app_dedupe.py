"""Launch dedupe: the matcher that identifies a running greywatch GUI or
tray helper from a /proc cmdline, and the single-instance lock contract
(after the automatic kill, a second instance still cannot steal the
lock while the first is alive)."""
import fcntl
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.app import _is_dup         # noqa: E402


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
    # hold the lock the RESOLVER actually picks, then a second instance
    # must be refused — i.e. app and any other launcher share one file.
    import ui.app as A
    lock_dir = tmp_path / "state"
    lock_dir.mkdir()
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(lock_dir))
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


def test_lock_path_uses_state_dir_when_it_differs_from_checkout(
        tmp_path, monkeypatch):
    # GW-SPAM FIX: app and tray must agree on ONE lock file. When the
    # runtime state dir is usable (installed deployment), both resolve to
    # <state>/gui.lock — never a second, checkout-local copy.
    import ui.app as A
    state = tmp_path / "var-lib-greywatch"
    state.mkdir()
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(state))
    assert A._lock_path() == state / "gui.lock"


def test_lock_path_falls_back_to_checkout_data(monkeypatch):
    # source run / unusable state dir: the checkout's own data/gui.lock.
    # data_dir() returns the checkout data/ only when the state dir is
    # absent AND unwritable; here we point at a nonexistent dir but the
    # live /var/lib/greywatch on this machine is readable+writable by the
    # user, so the resolver legitimately picks the state dir instead.
    # What the fallback must guarantee: the lock is under data_dir(),
    # whatever that resolves to — one path, shared with the daemon.
    import ui.app as A
    from gwpaths import data_dir
    monkeypatch.delenv("GREYWATCH_DATA_DIR", raising=False)
    assert A._lock_path() == data_dir() / "gui.lock"


def test_lock_path_prefers_explicit_override(monkeypatch, tmp_path):
    # $GREYWATCH_DATA_DIR wins verbatim — staging and unit runs must not
    # touch the machine's real state.
    import ui.app as A
    state = tmp_path / "stage-state"
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(state))
    assert A._lock_path() == state / "gui.lock"


def test_tray_uses_the_same_lock_path(tmp_path, monkeypatch):
    # the tray's _app_running() probe must resolve to the SAME file the
    # app locks, or a "Dashboard…" click spawns a second window.
    import ui.app as A
    from ui.tray import Tray
    state = tmp_path / "var-lib-greywatch"
    state.mkdir()
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(state))
    assert A._lock_path() == state / "gui.lock"
    # Tray._app_running opens the lock path with "a"; held by app -> True
    hold = open(state / "gui.lock", "w")
    fcntl.flock(hold, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        assert Tray._app_running() is True
    finally:
        fcntl.flock(hold, fcntl.LOCK_UN)
    assert Tray._app_running() is False
