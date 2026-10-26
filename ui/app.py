import fcntl
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_LOCK = None


def _single_instance() -> bool:
    global _LOCK
    try:
        lock_path = ROOT / "data" / "gui.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        _LOCK = open(lock_path, "w")
        fcntl.flock(_LOCK, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _LOCK.write(str(os.getpid()))
        _LOCK.flush()
        return True
    except (OSError, BlockingIOError):
        return False


def main() -> int:
    if not _single_instance():
        print("greywatch is already running (close it from the tray first).")
        return 0
    try:
        os.environ.setdefault("GDK_DISABLE", "gl:vulkan")
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Notify", "0.7")
        from gi.repository import Gtk, GLib
    except Exception as e:
        print(f"GUI failed — CLI remains: greywatch status|events|tail|log|"
              f"decisions|answer. (GTK error: {e})")
        return 0
    try:
        from ui.decisions import DecisionBroker
        from ui.window import MainWindow

        broker = DecisionBroker()

        tray = None
        try:
            from ui.tray import Tray
            tray = Tray(badge_cb=broker.badge)
            broker.set_tray(tray)
        except Exception as e:
            print("tray unavailable (window close will exit):", e)
            tray = None


        app = Gtk.Application(application_id="org.greywatch.Dashboard")

        def on_activate(application):
            win = MainWindow(on_status_change=broker.pump,
                             tray_available=tray is not None,
                             quit_cb=application.quit)
            application.add_window(win)
            if tray is not None:
                tray.on_show = lambda: win.present()
                tray.on_quit = application.quit
            win.present()
            win._show("tools")        # the Security home (never "status")
            GLib.timeout_add_seconds(60, broker.pump_once)
            try:
                from ui.minitile import MiniTileWindow, tile_wanted
                if tile_wanted():
                    tile = MiniTileWindow()
                    application.add_window(tile)
                    tile.present()
            except Exception as e:
                print("status tile unavailable:", e)

        app.connect("activate", on_activate)
        app.connect("shutdown", lambda _a: tray.stop() if tray else None)
        app.run([])
        return 0
    except Exception as e:
        print(f"GUI failed — CLI remains: greywatch status|events|tail|log|"
              f"decisions|answer. Daemon untouched. (error: {e})")
        return 0


if __name__ == "__main__":
    sys.exit(main())
