import fcntl
import os
import pathlib
import signal
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_LOCK = None


def _is_dup(parts) -> bool:
    for p in parts:
        if p.endswith("ui/app.py") or p.endswith("ui/tray_helper.py") \
                or p == "ui.app":
            return True
    return False


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _kill_duplicates() -> None:
    """Kill every other greywatch GUI instance (app + tray helper) so a
    new launch always ends with exactly one running — launching again is
    a restart, never a stack-up."""
    me = os.getpid()
    dups = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == me:
            continue
        try:
            parts = (entry / "cmdline").read_bytes().decode(
                "utf-8", "replace").split("\0")
        except OSError:
            continue
        if _is_dup(parts):
            dups.append(pid)
    if not dups:
        return
    for pid in dups:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    for _ in range(30):
        if not any(_alive(p) for p in dups):
            break
        time.sleep(0.1)
    for pid in dups:
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    print(f"restarted: closed {len(dups)} previous greywatch instance(s).")


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
    _kill_duplicates()
    if not _single_instance():
        print("greywatch is already running (close it from the tray first).")
        return 0
    try:
        # comma syntax is load-bearing: "gl:vulkan" is an invalid token GTK
        # silently ignores, leaving the GL renderer (and its EGL native
        # windows) attached — a window hide then aborts the process.
        os.environ.setdefault("GDK_DISABLE", "gl,vulkan")
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
            win._ensure_default_on()
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
