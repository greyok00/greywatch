import atexit
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

_ESCAPATORS = frozenset({"pkexec", "sudo", "su", "runuser", "doas"})
_xvfb = None


def _private_display() -> None:
    """Give GUI tests an X display nobody is looking at.

    Several suites build real GTK windows (the wizard, the dashboard). Run
    against the session display they appear on the owner's screen — a plain
    `pytest` opened five greywatch windows mid-session (2026-10-27). We
    start our own Xvfb and point DISPLAY at it, in-process, so pytest's
    output capture keeps working (an os.execvp re-run swallowed everything).

    Escapes:
      GREYWATCH_TEST_DISPLAY=1 — use the real display on purpose
      GREYWATCH_XVFB=1         — a display was already picked for us
    """
    global _xvfb
    if os.environ.get("GREYWATCH_TEST_DISPLAY") == "1":
        return
    if os.environ.get("GREYWATCH_XVFB") == "1" or _xvfb is not None:
        return
    xvfb = shutil.which("Xvfb")
    if xvfb is None:
        return
    for num in range(95, 130):
        sock = pathlib.Path(f"/tmp/.X11-unix/X{num}")
        if sock.exists():
            continue
        proc = subprocess.Popen(
            [xvfb, f":{num}", "-screen", "0", "1600x1000x24",
             "-nolisten", "tcp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if sock.exists():
                break
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if sock.exists():
            _xvfb = proc
            os.environ["DISPLAY"] = f":{num}"
            os.environ["GREYWATCH_XVFB"] = "1"

            def _stop():
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

            atexit.register(_stop)
            return
        proc.terminate()


_private_display()


# MESA's DRI3 loader parks GPU buffer fds in the lowest free slots and
# dup2-closes around them while buffers reallocate; measured under gdb on
# 2026-11-03, with stdin free it takes fd 0 outright and any tempfile dance
# in the same process dies with an fd-0 lottery. Keep fd 0 occupied so
# lowest-free-fd callers never land on stdin's number.
# The open fd is parked in this module-level name so nothing frees it.
_stdin_guard = os.open(os.devnull, os.O_RDONLY)
os.dup2(_stdin_guard, 0)


@pytest.fixture(autouse=True)
def _never_escalate(monkeypatch):
    """No test may pop a password prompt on the owner's screen.

    A wizard test reached the real helper path and polkit drew an
    "Authenticate" dialog on the live desktop (2026-10-27). A guarded call
    behaves like a refused helper — rc 1, empty output — so the code under
    test takes its normal failure path instead of blocking on a password.
    """
    def guard(fn):
        def inner(args, *a, **k):
            argv = list(args) if isinstance(args, (list, tuple)) else [args]
            head = str(argv[0]).rsplit("/", 1)[-1] if argv else ""
            if head in _ESCAPATORS:
                return subprocess.CompletedProcess(
                    argv, 1, "", "blocked in tests: privilege escalation")
            return fn(args, *a, **k)
        return inner

    monkeypatch.setattr(subprocess, "run", guard(subprocess.run))


@pytest.fixture(autouse=True, scope="session")
def _hermetic_stale_guard():
    """GUI tests must not depend on the live daemon's heartbeat age.

    The dashboard's stale-snapshot guard shows a waiting panel whenever
    status.json's stamp is older than ui.homepage's 90 s law — and a test
    run meets that whenever the machine's daemon is idle or wedged, which
    would turn the whole suite environment-dependent. It is session-scoped
    ON PURPOSE: the module-scoped MainWindow fixtures boot before any
    function-scoped fixture could patch. The guard's own pins
    (tests/test_dock_host.py) restore the real predicate captured at
    import time, so the threshold and the None/missing branch stay
    product-pinned there."""
    try:
        import ui.window as W
        real = W.snapshot_stale
        W.snapshot_stale = lambda *a, **k: False
        yield
        W.snapshot_stale = real
    except Exception:                     # noqa: BLE001 — not a GUI run
        yield


@pytest.fixture
def assume_kernel_modules(monkeypatch):
    """Pretend nfnetlink_queue/nft_queue are loaded.

    The arm/disarm and transport tests stub the worker process, so whether
    this host can actually modprobe the queue modules is irrelevant. A CI
    runner has neither the modules nor modprobe rights, and without this the
    engine refuses to arm and the tests fail on the environment rather than
    on the code (release run 2026-10-27).
    """
    from appfw.engine import Engine
    monkeypatch.setattr(Engine, "_ensure_queue_module",
                        staticmethod(lambda: None))


# --- the retired v3 interface ----------------------------------------------
# These modules still import the page modules the v4 rebuild removed
# (ui.window, ui.scanview, ui.dock, ...). They stay on disk; collection
# starts at the current surface (test_ui_v4, test_ui_baseline,
# test_scan_*, test_gui_cli_parity, test_install_script).
LEGACY_V3 = [
    "test_decision_identity.py",
    "test_desk_narrowing.py", "test_dock_host.py", "test_guided.py",
    "test_gw158.py", "test_gw168_169.py", "test_gw170.py", "test_gw181.py",
    "test_gw183.py", "test_gw186.py", "test_gw194.py", "test_gw205.py",
    "test_gw207_defense_rebuild.py", "test_gw210_unconfuse.py",
    "test_gw214_probe_honesty.py",
    "test_gw217_wizard_explains.py", "test_harden_h1.py",
    "test_help_he1.py", "test_homepage.py", "test_hunter_page.py",
    "test_hunter_ui.py", "test_mini_tile.py", "test_pause_contract.py",
    "test_popup_queue.py", "test_ptp.py", "test_quarantine_ui_actions.py",
    "test_scanview.py", "test_settings_st2.py", "test_settings_ws.py",
    "test_site_class.py", "test_site_rows.py", "test_sitesview.py",
    "test_startup_popup_drain.py", "test_tab_shell.py",
    "test_tool_control.py", "test_ui_discover.py", "test_ui_harden.py",
    "test_wizard.py",
    "test_overview_v3.py", "test_log_v1.py", "test_gw161_fixes.py",
    "test_gw209_auditlog.py", "test_gw215_badge_one_list.py",
    "test_gw208_console_services.py", "test_gw197.py",
    "test_assistant_tiers.py",
    "test_protections_p1.py", "test_scans_s2.py", "test_app_dedupe.py",
    "test_gw174.py", "test_gw160.py", "test_fit_law.py",
    "test_e6_visual_baselines.py", "test_ui_polish.py",
    "test_rail_scrollbar.py", "test_gw216_decisions_band.py",
    "test_desk_min_width.py", "test_audit_round3.py",
    "test_gw122_gw124_closeout.py", "test_scan_all.py",
    "test_bulk_executor.py",
    "test_appfw_ask_bridge.py", "test_decisions_window_visual.py",
    "test_e7_a11y_walk.py", "test_gw171.py",
]

collect_ignore = list(LEGACY_V3)
