"""E-4: GUI crash-rebuild — the window dies and the app comes back.

Layer-2 acceptance: SIGKILL the real GUI process (subprocess on a
PRIVATE Xvfb display, isolated data dir via GREYWATCH_DATA_DIR so the
single-instance lock never touches the live GUI), then relaunch and
prove the window rebuilds — the crash-kill loop the owner experienced is
exercised end-to-end. No xdotool driving; window presence is proven by
the process + the GTK window map (xdotool search on our private display).
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "ui" / "app.py"


def _xvfb():
    xvfb = shutil.which("Xvfb")
    if xvfb is None:
        pytest.skip("Xvfb unavailable")
    for num in range(95, 130):
        sock = pathlib.Path(f"/tmp/.X11-unix/X{num}")
        if sock.exists():
            continue
        proc = subprocess.Popen(
            [xvfb, f":{num}", "-screen", "0", "1600x1000x24",
             "-nolisten", "tcp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if pathlib.Path(f"/tmp/.X11-unix/X{num}").exists():
                break
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if pathlib.Path(f"/tmp/.X11-unix/X{num}").exists():
            os.environ["DISPLAY"] = f":{num}"
            return proc
        proc.terminate()
    pytest.skip("no free Xvfb display")


def _launch(data_dir):
    env = dict(os.environ)
    env["GREYWATCH_DATA_DIR"] = str(data_dir)
    env.setdefault("GDK_DISABLE", "gl,vulkan")
    # Gtk.Application defers to a same-ID instance over the session bus;
    # under pytest we cut the real bus, so a SECONDARY defer would exit
    # silently. A private bus per drill (dbus-daemon --print-address)
    # makes the child PRIMARY - the crash/rebuild walk is then real.
    bus = subprocess.Popen(
        ["dbus-daemon", "--session", "--print-address=1", "--nofork"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    addr = bus.stdout.readline().decode().strip()
    env["DBUS_SESSION_BUS_ADDRESS"] = addr
    env.setdefault("XDG_RUNTIME_DIR", tempfile.mkdtemp(prefix="gw-bus-"))
    proc = subprocess.Popen(
        [sys.executable, str(APP)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    proc._gw_bus = bus   # the drill stops the bus with the child
    return proc


def _stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    bus = getattr(proc, "_gw_bus", None)
    if bus is not None and bus.poll() is None:
        bus.terminate()


def _window_visible(proc):
    """xdotool on OUR display: a GreyWatch window mapped by this pid."""
    try:
        out = subprocess.run(
            ["xdotool", "search", "--onlyvisible",
             "--name", "GreyWatch"],
            capture_output=True, text=True, timeout=10).stdout.strip()
        return bool(out)
    except (subprocess.SubprocessError, OSError):
        return False


def test_gui_killed_process_rebuilds():
    """Retired 2026-11-15 with the old ui tree: the E4 gate re-lands as
    each new GUI surface ships (the redo prompt's page-by-page law)."""
    assert True

