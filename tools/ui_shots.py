#!/usr/bin/env python3
"""ui-shots: the verify pass. Renders every page of the real window on a
private Xvfb against seeded data and writes one PNG per page to
doc/ui-shots/<label>/, for reading back with the eyes (owner redo prompt,
step 2/3: every page verified with a screenshot before ship).

    python3 tools/ui_shots.py            # all pages
    python3 tools/ui_shots.py scans tools
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

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
os.environ.setdefault("GDK_DISABLE", "gl,vulkan")


def _seed(data_dir: pathlib.Path) -> None:
    """Real-shaped data so pages paint populated states, the same
    idea the fit-law fixture uses (an empty state fits anything)."""
    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    tools = {}
    for name, state in (("clamav", "GREEN"), ("yara-watch", "GREEN"),
                        ("yara-tmp-scan", "GREEN"), ("freshclam", "GREEN"),
                        ("ufw", "GREEN"), ("appfw", "GREEN"),
                        ("psad", "GREEN"), ("fail2ban", "GREEN"),
                        ("arpwatch", "GREEN"), ("net-watch", "GREEN"),
                        ("auditd", "GREEN"), ("apparmor", "GREEN"),
                        ("tetragon", "GREEN"), ("responderd", "GREEN"),
                        ("rkhunter", "GREEN"), ("lynis", "GREEN"),
                        ("cve-updater", "GREEN")):
        tools[name] = {"state": state, "installed": True,
                       "last_event": "check-in: ok", "unit": name + ".service"}
    events = [{"ts": (now - dt.timedelta(minutes=m + 1)).isoformat(),
               "from_tool": list(tools)[i % len(tools)],
               "severity": ["info", "medium", "high"][i % 3],
               "text": "check-in: seeded event for the verify pass"}
              for i, m in enumerate(range(len(tools) * 3))]
    asks = [{"spec": {"id": "seed-ask-1", "eyebrow": "programs",
                      "subject": "let example-app reach its update server?",
                      "detail": "one per-page decision, answered in place",
                      "options": [{"id": "allow", "label": "Allow",
                                   "tone": "primary", "helper": "tool",
                                   "args": ["noop"]}]}}
            ]
    snapshot = {"updated": stamp, "tools": tools,
                "recent": events[:60], "defense": {"blocked": []},
                "pending_list": asks,
                "browser_watch": {"projects": [], "rows": []},
                "components": {}, "failures": {}}
    (data_dir / "status.json").write_text(json.dumps(snapshot))
    (data_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events))


def _xvfb() -> dict:
    try:
        import gi
        gi.require_version("Gtk", "4.0")
    except (ImportError, ValueError) as exc:
        print(f"GTK4 unavailable: {exc}", file=sys.stderr)
        sys.exit(2)
    xvfb = shutil.which("Xvfb")
    if not xvfb:
        print("Xvfb not found; refusing any real display", file=sys.stderr)
        sys.exit(2)
    for num in range(90, 140):
        proc = subprocess.Popen([xvfb, f":{num}", "-screen", "0",
                                 "1440x900x24", "-nolisten", "tcp"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            import time
            time.sleep(0.6)
            env = dict(os.environ, DISPLAY=f":{num}")
            probe = gi.require_version
            del probe
            os.environ["DISPLAY"] = env["DISPLAY"]
            return env | {"_XVFB_PID": str(proc.pid)}
        except Exception:
            proc.terminate()
    print("no free Xvfb display", file=sys.stderr)
    sys.exit(2)


def main(argv: list[str]) -> int:
    env = _xvfb()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="gw-uishots-"))
    _seed(tmp)
    os.environ["GREYWATCH_DATA_DIR"] = str(tmp)
    import importlib
    win_mod = importlib.import_module("ui.window")
    win_mod.DATA_DIR = tmp
    win = win_mod.MainWindow(tray_available=False)
    win.set_default_size(1440, 900)
    win.present()
    pages = list(win._builders) if not argv else [k for k in argv
                                                  if k in win._builders]
    out_dir = REPO / "doc" / "ui-shots" / "2026-11-14"
    out_dir.mkdir(parents=True, exist_ok=True)
    import gi
    from gi.repository import Gtk, Gdk, Graphene  # noqa: E402
    try:
        loop = GLib = None
        from gi.repository import GLib  # noqa: E402
        loop = GLib.MainLoop()
    except ImportError:
        loop = None
    from gi.repository import GLib  # noqa: E402
    captured: list[str] = []
    failed: list[str] = []

    def shoot():
        try:
            key = pages_pop[0]
        except IndexError:
            loop.quit()
            return
        pages_pop.pop(0)
        win._show(key)
        win.refresh()

        def grab():
            try:
                # xwd reads the Xvfb framebuffer directly: no GI binding
                # gymnastics, the pixels ARE what the screen shows
                out = out_dir / f"{key}.png"
                disp = os.environ["DISPLAY"]
                xwd = subprocess.run(["xwd", "-root", "-display", disp],
                                     capture_output=True, timeout=30)
                if xwd.returncode != 0 or not xwd.stdout:
                    raise RuntimeError("xwd failed: " +
                                       xwd.stderr.decode()[-120:])
                conv = subprocess.run(
                    ["convert", "xwd:-", str(out)], input=xwd.stdout,
                    capture_output=True, timeout=60)
                if conv.returncode != 0 or not out.exists():
                    raise RuntimeError("convert failed: " +
                                       conv.stderr.decode()[-120:])
                captured.append(str(out))
            except Exception as exc:                    # noqa: BLE001
                failed.append(f"{key}: {exc}")
            if pages_pop:
                GLib.timeout_add(400, shoot)
            else:
                GLib.timeout_add(100, loop.quit)
            return False
        GLib.timeout_add(900, grab)
        return False

    pages_pop = list(pages)
    GLib.idle_add(shoot)
    GLib.timeout_add(90_000, loop.quit)             # never hang the sweep
    loop.run()
    print(f"captured {len(captured)} pages to {out_dir}:")
    for line in captured:
        print(" ", line)
    if failed:
        print("failed:")
        for line in failed:
            print(" ", line, file=sys.stderr)
    pid = env.get("_XVFB_PID")
    if pid:
        subprocess.run(["kill", pid])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
