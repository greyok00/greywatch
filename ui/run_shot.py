#!/usr/bin/env python3
"""One visual proof of the rebuilt shell: its own Xvfb, the real app
entry, one root-window capture, then it all stops.

Never launches on :0: the display is a private Xvfb (:97). One launch
is one task - this script is that task. Usage:

    python3 ui/run_shot.py [page label] [outfile] [question]

The page label opens a registered page by rail name; the shot lands at
outfile (default /tmp/gw-ui-shots/shell.png). A third argument seeds one
question into the page's ask surface before the capture (the assistant
page reads it through its panel), proving the rendered answer, not just
the empty box.
"""

import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PAGE = sys.argv[1] if len(sys.argv) > 1 else "Security Center"
OUT = (sys.argv[2] if len(sys.argv) > 2
       else "/tmp/gw-ui-shots/shell.png")
QUESTION = sys.argv[3] if len(sys.argv) > 3 else ""
CLICK = sys.argv[4] if len(sys.argv) > 4 else ""
DISPLAY_NUM = 97


def main() -> int:
    pathlib.Path(OUT).parent.mkdir(parents=True, exist_ok=True)
    geometry = os.environ.get("GW_SHOT_GEOM", "1600x1000")
    try:
        width, height = (int(part) for part in geometry.lower().split("x", 1))
        os.environ["GW_UI_WIDTH"] = str(width)
        os.environ["GW_UI_HEIGHT"] = str(height)
    except ValueError:
        pass
    os.environ["DISPLAY"] = f":{DISPLAY_NUM}"
    xvfb = subprocess.Popen(
        ["Xvfb", f":{DISPLAY_NUM}", "-screen", "0",
         f'{os.environ.get("GW_SHOT_GEOM", "1600x1000")}x24',
         "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)

    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk, GLib, Gio

    import ui.app as app_mod

    app = app_mod.App()
    # The live desktop app owns the org.greywatch.GUI bus name; without
    # NON_UNIQUE this run would hand its activation to that instance and
    # return at once. The shot must paint its own window.
    app.set_flags(Gio.ApplicationFlags.NON_UNIQUE)

    def on_activate(_app):
        app_mod.App.do_activate(_app)
        win = _app._win
        # A 4K capture must exercise the 4K layout, not the 1280x800
        # default inside a 4K Xvfb screen.
        if os.environ.get("GW_SHOT_MAX") == "1":
            win.maximize()
        # Pages build on first show now: show_page handles a label that
        # was never built, so the shot can request any page by label.
        if PAGE:
            win.show_page(PAGE)
        if os.environ.get("GW_SHOT_ADVANCED") == "1":
            button = getattr(win, "_rail_rows", {}).get("Advanced")
            if button is not None:
                button.emit("clicked")

        def snap():
            if CLICK:
                target = [None]

                def walk(w):
                    if target[0] is None \
                            and isinstance(w, Gtk.Button) \
                            and w.get_label() == CLICK:
                        target[0] = w
                    c = w.get_first_child()
                    while c is not None and target[0] is None:
                        walk(c)
                        c = c.get_next_sibling()

                walk(win._stack.get_visible_child())
                if target[0] is not None:
                    target[0].grab_focus()
                    target[0].activate()
                    ctx = GLib.main_context_default()
                    for _ in range(60):
                        ctx.iteration(False)
                        time.sleep(0.02)
                    print("click: pressed", CLICK)
                else:
                    print("click: button not found:", CLICK)
            if QUESTION:
                body = getattr(win._pages.get(PAGE), "_gw_body", None) \
                    or win._pages.get(PAGE)
                panel = getattr(body, "_gw_panel", None)
                if panel is None:
                    print("ask: no ask surface on this page")
                else:
                    panel.entry.set_text(QUESTION)
                    panel._send()
                    # Pump the main loop until the plan lands: the pack
                    # build and the knowledge search run on their worker.
                    ctx = GLib.main_context_default()
                    for _ in range(400):
                        ctx.iteration(False)
                        time.sleep(0.02)
                    print("ask: seeded:", QUESTION)
            r = subprocess.run(
                ["import", "-window", "root", OUT],
                env={**os.environ, "DISPLAY": f":{DISPLAY_NUM}"},
                capture_output=True, text=True)
            print("shot:", OUT, r.returncode,
                  (r.stderr or "").strip()[:200])
            print("pages:", list(win._pages.keys()))
            _app.quit()
            return False

        GLib.timeout_add_seconds(
            int(os.environ.get("GW_SHOT_WAIT", "4")), snap)

    app.connect("activate", on_activate)
    try:
        app.run(None)
    finally:
        xvfb.terminate()
        try:
            xvfb.wait(timeout=4)
        except subprocess.TimeoutExpired:
            xvfb.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
