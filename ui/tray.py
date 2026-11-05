import json
import os
import pathlib
import subprocess
import sys
import threading

import gi
gi.require_version("Gio", "2.0")
from gi.repository import GLib  # noqa: E402

_HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "tray_helper.py")


def _offline(why) -> None:
    print(f"tray unavailable ({why}): window close will exit", flush=True)


class Tray:

    def __init__(self, badge_cb=None, icon="greywatch", on_show=None,
                 on_quit=None, item_id="greywatch"):
        self.badge_cb = badge_cb          # kept for the old call shape
        self.icon = icon
        self.item_id = item_id
        self.on_show = on_show            # fired on the main GLib context
        self.on_quit = on_quit
        self._proc = None
        self._pending, self._alerts = 0, []
        self.start()

    def start(self):
        try:
            self._proc = subprocess.Popen(
                [sys.executable, _HELPER],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True, start_new_session=True)
        except Exception as e:
            self._proc = None
            self._offline(e)
            return
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self.refresh_badge()

    def _read_loop(self):
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            event = msg.get("event")
            if event == "open":
                GLib.idle_add(self._fire, self.on_show or self._spawn_app)
            elif event == "quit":
                GLib.idle_add(self._fire, self.on_quit)
        self._proc = None
        GLib.idle_add(_offline, "helper exited")

    def _send(self, obj) -> None:
        try:
            if self._proc is not None and self._proc.stdin:
                self._proc.stdin.write(json.dumps(obj) + "\n")
                self._proc.stdin.flush()
        except (OSError, BrokenPipeError, ValueError):
            pass                          # dead helper stays non-fatal

    @staticmethod
    def _fire(cb):
        try:
            if callable(cb):
                cb()
        except Exception:
            pass

    @staticmethod
    def _app_running() -> bool:
        # the SAME lock the app takes (ui.app._lock_path): one resolution,
        # never a second path.
        import fcntl
        try:
            from ui.app import _lock_path
            lock = _lock_path()
        except Exception:
            lock = pathlib.Path(_HELPER).resolve().parents[1] / "data" / "gui.lock"
        try:
            with open(lock, "a") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fh, fcntl.LOCK_UN)
            return False
        except OSError:
            return True

    def _spawn_app(self):
        if self._app_running():
            if self.on_show:
                self.on_show()
            return
        app = os.path.join(os.path.dirname(os.path.abspath(_HELPER)),
                           "app.py")
        subprocess.Popen([sys.executable, app], start_new_session=True)

    def stop(self):
        try:
            if self._proc is not None:
                self._send({"cmd": "quit"})
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._proc.terminate()
        except Exception:
            pass
        self._proc = None

    def refresh_badge(self) -> int:
        pending = 0
        alerts = []
        try:
            from datetime import datetime, timezone, timedelta
            from greywatch_daemon import read_events, DATA_DIR
            answered = set()
            try:
                from decisions_factory import pending_ids
                answered = pending_ids(DATA_DIR / "decisions.jsonl")
            except (ImportError, OSError):
                pass
            from ui.models import feed_worthy
            evs = read_events(DATA_DIR / "events.jsonl", 500)
            hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            for e in reversed(evs):
                spec = e.get("interaction")
                if spec and spec.get("id") not in answered:
                    pending += 1
                if not feed_worthy(e):
                    continue
                try:
                    ts = datetime.fromisoformat(
                        e.get("ts", "").replace("Z", "+00:00"))
                    if ts >= hour_ago and e.get("severity") in ("HIGH",
                                                                "CRITICAL"):
                        alerts.append((e.get("from_tool", "?"), "High",
                                       e.get("text", "")))
                    elif ts >= hour_ago and e.get("severity") == "MEDIUM":
                        alerts.append((e.get("from_tool", "?"), "Medium",
                                       e.get("text", "")))
                except (ValueError, TypeError):
                    continue
                if len(alerts) >= 5:
                    break
            alerts.reverse()
        except Exception:
            pass
        self._pending, self._alerts = pending, alerts
        self._send({"cmd": "update", "pending": pending,
                    "alerts": [list(a) for a in alerts]})
        return pending + len(alerts)
