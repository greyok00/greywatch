#!/usr/bin/env python3
"""Tray helper — a GTK3 process that owns the panel icon.

Why a separate process: the main app is GTK4 and AyatanaAppIndicator3 (the
ONLY tray binding that has ever rendered correctly on this mate-panel) pulls
GTK3 into whatever process loads it. Two GTK stacks in one process crash, so
the tray lives here. The parent app talks to this helper over stdin/stdout,
one JSON object per line:

    parent → here:  {"cmd": "update", "pending": N,
                     "alerts": [[tool, mark, text], ...]}
                    {"cmd": "quit"}   (or a closed stdin = exit)
    here → parent:  {"event": "ready"} on startup success
                    {"event": "open"}  on menu Dashboard / alert items
                    {"event": "quit"}  on menu Quit

Everything here is GTK3 (Gtk.main loop, AyatanaAppIndicator3); nothing GTK4
is ever imported. If the session bus or indicator host is missing this prints
why and exits 1 — the parent treats that as "tray unavailable".
"""
import errno
import fcntl
import json
import pathlib
import os
import sys

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3 as AppIndicator, Gtk, GLib

ITEM_ID = "greywatch"
ICON = "greywatch"

_pending = 0


def send(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def build_menu(alerts, on_open, on_quit) -> Gtk.Menu:
    """Dashboard / pending+alerts summary / the actual latest alerts / Quit —
    same order the GTK3 tray used. Rebuilt fresh on every update: a rebuilt
    menu is how ayatana indicators refresh."""
    menu = Gtk.Menu()
    dash = Gtk.MenuItem(label="Dashboard…")
    dash.connect("activate", lambda _m: on_open())
    menu.append(dash)
    summary = Gtk.MenuItem(
        label=f"{_pending} pending decision(s), {len(alerts)} alert(s)")
    summary.set_sensitive(False)
    menu.append(summary)
    menu.append(Gtk.SeparatorMenuItem())
    for tool, mark, text in alerts:
        item = Gtk.MenuItem(label=f"{mark} {tool}: {text[:44]}")
        item.connect("activate", lambda _m: on_open())
        menu.append(item)
    menu.append(Gtk.SeparatorMenuItem())
    quit_item = Gtk.MenuItem(label="Quit")
    quit_item.connect("activate", lambda _m: on_quit())
    menu.append(quit_item)
    menu.show_all()
    return menu


def main() -> int:
    indicator = AppIndicator.Indicator.new(
        ITEM_ID, ICON, AppIndicator.IndicatorCategory.APPLICATION_STATUS)
    indicator.set_status(AppIndicator.IndicatorStatus.ACTIVE)
    # direct asset path beats the theme lottery: with the name resolve the
    # panel could render a libappindicator FALLBACK (blue shield) instead of
    # our dark GW logo (2026-10-24 GUI pass finding).
    _logo = str(pathlib.Path(__file__).resolve().parents[1] / "assets"
            / "logo" / "greywatch-icon-128.png")
    if os.path.exists(_logo):
        indicator.set_icon_full(_logo, "greywatch")

    menu = build_menu([], lambda: send({"event": "open"}),
                      lambda: send({"event": "quit"}))
    indicator.set_menu(menu)

    def handle(line: str) -> None:
        global _pending
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            print(f"tray-helper: bad line {line[:120]!r}", file=sys.stderr)
            return
        if msg.get("cmd") == "update":
            _pending = int(msg.get("pending") or 0)
            indicator.set_menu(build_menu(
                msg.get("alerts") or [],
                lambda: send({"event": "open"}),
                lambda: send({"event": "quit"})))
        elif msg.get("cmd") == "quit":
            Gtk.main_quit()

    fd = sys.stdin.fileno()
    buf = bytearray()

    def watcher():
        # non-blocking read: a blocking readline() here would freeze the
        # GTK main loop (and with it every D-Bus call on the tray item).
        try:                                 # idempotent — safe per tick
            fcntl.fcntl(fd, fcntl.F_SETFL,
                        fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        except OSError:
            pass
        try:
            chunk = os.read(fd, 4096)        # what is ready NOW, b"" on EOF
            if chunk == b"":
                Gtk.main_quit()              # EOF: parent closed stdin
                return False
        except OSError as e:
            if e.errno != errno.EAGAIN:      # not "nothing ready" → stdin
                Gtk.main_quit()              # is gone; exit cleanly
                return False
            chunk = None
        if chunk:
            buf.extend(chunk)
        while b"\n" in buf:
            end = buf.index(b"\n")
            line = bytes(buf[:end])
            del buf[:end + 1]
            handle(line.decode("utf-8", "replace"))
        return True

    # a 250 ms poll keeps stdin off the GTK main loop and lets a dead parent
    # (closed stdin) end the helper cleanly.
    GLib.timeout_add(250, watcher)
    send({"event": "ready"})
    Gtk.main()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"tray-helper failed: {e}", file=sys.stderr)
        sys.exit(1)