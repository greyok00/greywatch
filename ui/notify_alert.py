from __future__ import annotations

import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from appfw import rules as R          # noqa: E402
from appfw.rules import RuleStore     # noqa: E402

from gwpaths import data_dir as _gw_data

DATA = _gw_data()
ALERTS_SETTING_PATH = _gw_data() / "greywatch-ui-settings.json"


class BlockedQueue:

    def __init__(self, data_dir):
        self.data_dir = pathlib.Path(data_dir)
        self.burst: list[dict] = []      # {"app", "host", "ts"}
        self.last_shown = 0.0

    def add_deny(self, app: str, host: str) -> str:
        self.burst = [b for b in self.burst if time.time() - b["ts"] < 600]
        self.burst.append({"app": app or "<unknown>", "host": host,
                           "ts": time.time()})
        self.last_shown = time.time()
        latest = self.burst[-1]
        if len(self.burst) == 1:
            return (f"⛔ Blocked {latest['app']} → {latest['host']}\n"
                    "Unblock all or review from the dashboard.")
        return (f"⛔ {len(self.burst)} connected attempts blocked "
                f"(latest: {latest['app']} → {latest['host']})\n"
                "Unblock all or review from the dashboard.")

    def unblock_all(self) -> list:
        s = RuleStore(self.data_dir / "appfw" / "rules")
        done = []
        for b in self.burst:
            if b["app"] == "<unknown>" or b["app"] in done:
                continue
            done.append(b["app"])
            s.add(R.validate(f"appfw-app-{pathlib.Path(b['app']).name}",
                             "allow", "always", "process.path", b["app"]))
        self.burst.clear()
        return done

    def pending(self) -> int:
        return len(self.burst)


import re

_DRE = re.compile(r"appfw (\S+) → (\S+) (allow|deny)\b")

CRITICAL_TOOLS = ("fail2ban", "yara-watch", "yara-tmp-scan", "rkhunter")
CRITICAL_SEVS = ("HIGH", "CRITICAL")


def parse_deny(text: str):
    m = _DRE.search(str(text or ""))
    if not m:
        return None
    return {"app": m.group(1), "host": m.group(2), "action": m.group(3)}


def critical_filter(events) -> list:
    out = []
    for e in events or ():
        if not isinstance(e, dict):
            continue
        tool = e.get("from_tool", "")
        if tool in CRITICAL_TOOLS and e.get("severity") in CRITICAL_SEVS:
            out.append((tool, str(e.get("text", ""))[:200]))
    return out[-1:] if out else []      # only the newest is shown


class CriticalEvents:

    SEEN_WINDOW = 600.0

    def __init__(self):
        self.count = 0
        self.latest: tuple = ("", "")
        self._stamped = 0.0

    def add(self, tool: str, text: str) -> str:
        self.count += 1
        self.latest = (tool, text)
        self._stamped = time.time()
        return (f"⚠ {tool}: {text}"
                f" ({self.count} critical events since the last burst "
                "ended.)")

    def stale(self) -> bool:
        return time.time() - self._stamped > self.SEEN_WINDOW


class NotifyAlert:

    APP = "greywatch"
    SUMMARY = "App firewall"

    def __init__(self, blocked: BlockedQueue, notifier=None):
        self.blocked = blocked
        self._notify_cls = notifier      # injected in tests; gi lazily below
        self._n = None

    def _cls(self):
        if self._notify_cls is not None:
            return self._notify_cls
        import gi
        gi.require_version("Notify", "0.7")
        from gi.repository import Notify
        if not Notify.is_initted():
            Notify.init(self.APP)
        return Notify

    def _tile(self, app: str = "", host: str = ""):
        """The picture beside the notification text.

        A desktop notification can carry an image, so the same rule as the
        in-app card applies: the destination's map tile when the local
        country table knows the address, otherwise the program's own icon
        or a drawn initial (owner 2026-10-29: "or a geoip map of the
        location by default... make it more visual"). The country lookup
        is the offline GeoIP table, never whois, so a notification stays
        instant.
        """
        try:
            from ui import identity, visuals
        except Exception:
            return None
        code = name = ""
        try:
            if host:
                code, name = identity.geoip_country(host)
        except Exception:
            pass
        try:
            if code:
                return visuals.host_tile(
                    {"country": code, "country_name": name}, 64)
            title = pathlib.Path(app or "").name
            if title:
                return visuals.program_tile("", title, 64, binary=title)
        except Exception:
            pass
        return None

    @staticmethod
    def _attach_image(note, picture) -> None:
        if picture is None:
            return
        # 0.7.2 renamed the property; the older setter stays for distros
        # that still ship 0.7.0/0.7.1.
        for name in ("set_image_from_pixbuf", "set_icon_from_pixbuf"):
            setter = getattr(note, name, None)
            if setter is not None:
                try:
                    setter(picture)
                    return
                except Exception:
                    continue

    def show(self, text: str, app: str = "", host: str = "") -> None:
        try:
            cfg = (json.loads(ALERTS_SETTING_PATH.read_text())
                   if ALERTS_SETTING_PATH.exists() else {})
            if not cfg.get("alerts"):
                return
        except (OSError, ValueError):
            pass
        cls = self._cls()
        picture = self._tile(app, host)
        try:
            if self._n is None:
                self._n = cls.Notification.new(self.SUMMARY, text)
                self._n.set_timeout(8000)
                self._attach_image(self._n, picture)
                for add in ("add_action",):
                    if hasattr(self._n, add):
                        self._n.add_action(
                            "unblock-all", "Unblock all", self._on_unblock)
                        self._n.add_action(
                            "review", "Review", self._on_review)
                self._n.show()
            else:
                self._attach_image(self._n, picture)
                self._n.update(self.SUMMARY, text)
                self._n.show()
        except Exception:
            self._n = None               # a bus hiccup must never loop

    def _on_unblock(self, *_a):
        done = self.blocked.unblock_all()
        if done:
            self.show(f"✓ Allowed forever: {', '.join(done[:3])}"
                      f"{'…' if len(done) > 3 else ''}")
        return done

    def _on_review(self, *_a):
        import subprocess
        subprocess.Popen([sys.executable, str(ROOT / "ui" / "app.py")])

    def handle_deny(self, app: str, host: str) -> str:
        text = self.blocked.add_deny(app, host)
        # Name the country on the first line; the picture below it is the
        # map of that same place, so the two say the same thing.
        try:
            from ui import identity
            code, name = identity.geoip_country(host)
        except Exception:
            name = ""
        if name:
            text = text.replace("\n", f"  ·  {name}\n", 1)
        self.show(text, app=app, host=host)
        return text


class CriticalSquare(NotifyAlert):

    SUMMARY = "Security: critical event"
    APP = "greywatch-critical"
