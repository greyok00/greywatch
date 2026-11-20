"""One tracker above the pages.

The window owns this object, not a page. It reads the daemon's live scan
document every second no matter which screen is showing, keeps the last
copy, and hands it to every page that subscribed. Switching screens and
coming back therefore costs nothing and loses nothing: the page paints
from the copy it already has and the same beat keeps moving it.

It is deliberately invisible. The scan's state lives in the scan card and
the progress bar, never in the navigation rail.
"""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib

from ui import cliapi


class ScanMonitor:
    def __init__(self, window=None):
        self.window = window
        self.live: dict = {}
        self._callbacks = []
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._beat()
        GLib.timeout_add_seconds(1, self._beat)

    def subscribe(self, callback) -> None:
        if callback not in self._callbacks:
            self._callbacks.append(callback)
        try:
            callback(self.live)
        except Exception:                       # noqa: BLE001
            pass

    def unsubscribe(self, callback) -> None:
        try:
            self._callbacks.remove(callback)
        except ValueError:
            pass

    def _beat(self) -> bool:
        try:
            doc = cliapi.read_state("scan-live.json") or {}
        except Exception:                       # noqa: BLE001
            doc = {}
        if doc != self.live:
            self.live = doc
            for callback in list(self._callbacks):
                try:
                    callback(doc)
                except Exception as e:          # noqa: BLE001
                    print(f"greywatch ui: scan tracker callback failed: "
                          f"{type(e).__name__}: {e}")
        return True
