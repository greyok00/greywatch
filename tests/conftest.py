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
