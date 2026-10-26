"""ui.notify_alert — the ONE blocked-traffic square, owner-specced 2026-10-24.

One single reusable notification per action-burst (no scrolling, no popup
storm): every new app-fw DENY updates the same square in place with the
count + the latest blocked item; its buttons are 'Unblock all' (allow-
always every blocked program of the burst) and 'Review' (open the
dashboard). Pure state lives in BlockedQueue (testable, no GTK); the gi
calls are thin and lazily imported so tests never need a session bus.
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from appfw import rules as R          # noqa: E402
from appfw.rules import RuleStore     # noqa: E402

DATA = ROOT / "data"
ALERTS_SETTING_PATH = ROOT / "data" / "greywatch-ui-settings.json"


class BlockedQueue:
    """The burst state for the square: newest denies, one replaceable text."""

    def __init__(self, data_dir):
        self.data_dir = pathlib.Path(data_dir)
        self.burst: list[dict] = []      # {"app", "host", "ts"}
        self.last_shown = 0.0

    def add_deny(self, app: str, host: str) -> str:
        """New deny → burst item. Returns the square's TEXT (owner asked:
        nothing scrolling — one square, refreshed, never a stack)."""
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
        """Allow-forever each distinct blocked program of the burst —
        written straight into the grey-owned store; no prompts, no pops."""
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

# master prompt §4: critical-event classes that deserve the desktop square
CRITICAL_TOOLS = ("fail2ban", "yara-watch", "yara-tmp-scan", "rkhunter")
CRITICAL_SEVS = ("HIGH", "CRITICAL")


def parse_deny(text: str):
    """Engine mirror line → {app, host, action} or None (lifecycle lines
    ('appfw engine: …') never match)."""
    m = _DRE.search(str(text or ""))
    if not m:
        return None
    return {"app": m.group(1), "host": m.group(2), "action": m.group(3)}


def critical_filter(events) -> list:
    """ONE shared square for critical events (master prompt §4): the newest
    wins, coalesced — never a stack. Pure: input event dicts, output
    (tool, text) pairs, oldest-first."""
    out = []
    for e in events or ():
        if not isinstance(e, dict):
            continue
        tool = e.get("from_tool", "")
        if tool in CRITICAL_TOOLS and e.get("severity") in CRITICAL_SEVS:
            out.append((tool, str(e.get("text", ""))[:200]))
    return out[-1:] if out else []      # only the newest is shown


class CriticalEvents:
    """Coalescing state for the critical square: count + latest, bounded."""

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
    """The square. GTK/libnotify thin; fake-friendly for tests."""

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

    def show(self, text: str) -> None:
        """ONE replaceable square — .update() reuses it, always.
        Owner alert switch (order 2026-10-25 "STOP THE POPUPS"): the
        ui-settings file may carry "alerts": true to re-enable; the
        DEFAULT is silent (popups off, dashboard state stays truthful)."""
        try:
            cfg = (json.loads(ALERTS_SETTING_PATH.read_text())
                   if ALERTS_SETTING_PATH.exists() else {})
            if not cfg.get("alerts"):
                return
        except (OSError, ValueError):
            pass
        cls = self._cls()
        try:
            if self._n is None:
                self._n = cls.Notification.new(self.SUMMARY, text)
                self._n.set_timeout(8000)
                for add in ("add_action",):
                    if hasattr(self._n, add):
                        self._n.add_action(
                            "unblock-all", "Unblock all", self._on_unblock)
                        self._n.add_action(
                            "review", "Review", self._on_review)
                self._n.show()
            else:
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
        self.show(text)
        return text


class CriticalSquare(NotifyAlert):
    """The critical-events square (fail2ban/YARA/rkhunter): same
    replace-one-square machinery, a different summary word."""

    SUMMARY = "Security: critical event"
    APP = "greywatch-critical"