"""The fit-law screenshot lane (rebuild round 2, task 7a / task 16 gate).

Captures every page of the rebuilt UI, the wizard windows and the
decisions drawer at the owner's 1080p window shape - rail and dock in
frame - into doc/shots/fit/. The same laws the fit test pins
(tests/test_fit_law.py) are what these pictures put in front of the
owner: the page laid out to fit, only its inner lists scrolling.

Run: python3 tools/fit_shots.py

The lane is self-contained: it starts its own 1920x1080 Xvfb, seeds a
private data dir with a populated status digest, and drives the real
window the way a real click does. Shown against a display is not
required; nothing is committed (doc/shots is generated).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "doc" / "shots" / "fit"

# The 1080p window shape the fit law is pinned against: monitor minus the
# marco frame allowance (ui.metrics.FRAME_H), rail and dock at their laws.
FIT_W = 1920
FIT_H = 1080 - 60

PAGES = ("overview", "services", "scans", "protect", "harden", "auditlog",
         "defense", "thunter", "tools", "settings", "logs", "help")

XVFB_SIZE = f"{FIT_W}x{FIT_H + 60}x24"


def _seed(data_dir: pathlib.Path) -> None:
    """One populated digest: tools in every state, blocked rows, asks,
    events - the fit pictures must show the page under real paint."""
    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    events, tools = [], {}
    for i in range(22):
        name = f"t{i:02d}-tool"
        tools[name] = {"state": ("GREEN", "YELLOW", "RED",
                                 "UNKNOWN")[i % 4],
                       "installed": True}
        for s in range(3):
            events.append({"ts": (now - dt.timedelta(minutes=40 + s * 3))
                           .isoformat(), "from_tool": name,
                           "severity": ["info", "high", "critical"][s],
                           "text": f"check-in: event {s} from {name}"})
    snap = {
        "updated": stamp,
        "tools": tools,
        "recent": events[:80],
        "defense": {"blocked": [{"ip": f"10.66.{i}.7", "ts": stamp,
                                 "reason": "auto block", "why": "psad level 5",
                                 "forever": False} for i in range(24)]},
        "pending_list": [{"spec": {"id": f"ask-{k}", "eyebrow": "network",
                                   "subject": f"allow guest host {k}?",
                                   "detail": "the ask the page answers here",
                                   "options": [{"id": "allow",
                                                "label": "Allow",
                                                "tone": "primary",
                                                "helper": "tool",
                                                "args": []}]},
                          "ts": stamp} for k in range(6)],
        "browser_watch": {"projects": [], "rows": []},
        "components": {f"comp-{i}": {"state": "failed", "restarts": 1}
                       for i in range(6)},
        "failures": {},
    }
    (data_dir / "status.json").write_text(json.dumps(snap))
    (data_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events))


def _xvfb(display: str) -> subprocess.Popen:
    if not shutil.which("Xvfb"):
        raise SystemExit("tools/fit_shots needs Xvfb (no X server driver)")
    proc = subprocess.Popen(
        ["Xvfb", display, "-screen", "0", XVFB_SIZE, "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sock = pathlib.Path(f"/tmp/.X11-unix/X{display.lstrip(':')}")
    for _ in range(50):
        if sock.exists():
            return proc
        if proc.poll() is not None:
            raise SystemExit("Xvfb died during startup")
        time.sleep(0.05)
    return proc


def shoot_xid(widget, path: pathlib.Path, label: str) -> bool:
    """One frame from the window's own X11 surface (the shoot.py lane)."""
    surface = widget.get_surface()
    xid = int(surface.get_xid()) if surface is not None else 0
    if not xid:
        print(f"{label}: NO XID (not mapped) - FAIL")
        return False
    subprocess.run(
        ["import", "-window", f"0x{xid:x}", str(path)],
        env=os.environ, check=False)
    size = path.stat().st_size if path.exists() else 0
    ok = size > 30_000
    print(f"{label}: {path.name} {size} bytes ({'OK' if ok else 'TOO SMALL'})")
    return ok


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    xvfb = _xvfb(":92")   # outside the pytest conftest lane (:95-:130)
    # GREYWATCH_XVFB=1: a first-launch data dir would otherwise auto-run
    # the walkthrough (a step every 1.2 s), and the walk keeps routing the
    # pages under the loop's feet - every page shot would race it. The
    # lane is a driver of windows, not a user reading them.
    os.environ.update(DISPLAY=":92", GDK_DISABLE="gl:vulkan",
                      GREYWATCH_XVFB="1")

    # the private digest exists before any UI module imports: every
    # file-bound read in the tree then resolves to it
    data_dir = pathlib.Path(tempfile.mkdtemp(prefix="gw-fit-shots-"))
    _seed(data_dir)
    os.environ["GREYWATCH_DATA_DIR"] = str(data_dir)

    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib
    from ui.window import MainWindow
    from ui.wizard import ToolChooser
    from wizard.ui_pages import SetupWizardWindow
    from ui.actiongate import ActionGateWindow

    import ui.window as W
    W.DATA_DIR = data_dir

    results: list[bool] = []
    win = MainWindow(tray_available=False)
    win.set_title("greywatch: fit-law shots")
    win.set_default_size(FIT_W, FIT_H)
    win.present()
    ctx = GLib.main_context_default()
    deadline = time.time() + 8.0
    while time.time() < deadline:
        ctx.iteration(False)
        time.sleep(0.05)
    ctx = GLib.main_context_default()
    deadline = time.time() + 8.0
    while time.time() < deadline:
        ctx.iteration(False)
        time.sleep(0.05)
    for key in PAGES:
        win._show(key)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            ctx.iteration(False)
            time.sleep(0.05)
        results.append(shoot_xid(win, OUT / f"page-{key}.png", f"page:{key}"))

    # the wizard + drawer windows under the same law
    chooser = ToolChooser(on_pick=lambda _k: None, parent=win)
    chooser.set_default_size(691, 669)
    chooser.present()
    draw = time.time() + 3.0
    while time.time() < draw:
        ctx.iteration(False)
        time.sleep(0.05)
    results.append(shoot_xid(chooser, OUT / "wizard-hub.png",
                             "wizard:hub"))
    setup = SetupWizardWindow(parent=win, open_dashboard=win.present,
                              open_chooser=None)
    setup.set_default_size(691, 669)
    setup.present()
    draw = time.time() + 4.0
    while time.time() < draw:
        ctx.iteration(False)
        time.sleep(0.05)
    results.append(shoot_xid(setup, OUT / "wizard-setup.png",
                             "wizard:setup"))
    setup.destroy()
    chooser.destroy()
    drawer = ActionGateWindow(parent=win, on_change=lambda: None)
    drawer.build_rows()
    drawer.present()
    draw = time.time() + 4.0
    while time.time() < draw:
        ctx.iteration(False)
        time.sleep(0.05)
    results.append(shoot_xid(drawer, OUT / "decisions-drawer.png",
                             "wizard:drawer"))
    drawer.destroy()

    win.destroy()
    shutil.rmtree(data_dir, ignore_errors=True)
    xvfb.terminate()
    try:
        xvfb.wait(timeout=3)
    except subprocess.TimeoutExpired:
        xvfb.kill()
    ok = sum(1 for r in results if r)
    print(f"{ok}/{len(results)} shots landed in {OUT}", flush=True)
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
