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
        # `mark` is a severity word (High/Medium), not an emoji: a GTK menu
        # label cannot carry the theme's status ink, and emoji render
        # differently on every machine (design pass 2026-10-27).
        item = Gtk.MenuItem(label=f"{mark} · {tool}: {text[:44]}")
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
