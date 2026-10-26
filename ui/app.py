#!/usr/bin/env python3
"""greywatch GUI entry — crash-safe, single-instance, GTK4 + Gtk.Application.

Launched standalone:
    python3 ~/greywatch/ui/app.py

The audit (2026-10-23) found the old launch calling `_show("status")`, a view
key that no longer existed; that hid all five screens and produced the grey
window. The stack keeps only real keys, and this file asks for "tools" (the
Security home).

GTK4 notes (Pass 2, 2026-10-25): Gtk.main()/Gtk.main_quit() are GONE in GTK4,
so the loop is a Gtk.Application with an "activate" callback; the tray (Gio
StatusNotifierItem — no GTK widgets) gets an app-level show/quit hook and is
unowned again at shutdown. The single-instance flock is GTK-agnostic and
still runs before anything GTK.
"""
import fcntl
import os
import pathlib
import sys

# launched as ui/app.py: the PROJECT root must be importable (ui.xxx modules)
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_LOCK = None


def _single_instance() -> bool:
    """Hold data/gui.lock for the process lifetime. A second launch exits
    instead of opening a duplicate dashboard."""
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
        # The RAM budget (master prompt: GUI idle < 150 MB) is blown by the
        # GTK4 startup probe of GL/Vulkan alone: on this X11+NVIDIA box it
        # maps ~75 MB of Mesa/LLVM/nvidia heap for a dashboard that renders
        # no 3D anything. GDK reads this only at init — set BEFORE Gtk.
        # The cairo renderer is the renderer GTK3 used; visually identical.
        # (Measured 2026-10-25: 244 MB with probes, 153-161 MB without.)
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

        # The tray is optional: a missing indicator must not kill the app.
        tray = None
        try:
            from ui.tray import Tray
            tray = Tray(badge_cb=broker.badge)
            broker.set_tray(tray)
        except Exception as e:
            print("tray unavailable (window close will exit):", e)
            tray = None

        # The app-fw engine belongs to the ROOT daemon alone (one table, one
        # queue — never two owners). The GUI starts nothing: it displays the
        # engine's status and answers nothing directly (headless chain).

        app = Gtk.Application(application_id="org.greywatch.Dashboard")

        def on_activate(application):
            win = MainWindow(on_status_change=broker.pump,
                             tray_available=tray is not None,
                             quit_cb=application.quit)
            application.add_window(win)
            if tray is not None:
                # the panel icon opens THIS window, never a second process
                # (the gui.lock fallback in tray.py only fires without one).
                tray.on_show = lambda: win.present()
                tray.on_quit = application.quit
            win.present()
            win._show("tools")        # the Security home (never "status")
            GLib.timeout_add_seconds(60, broker.pump_once)

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