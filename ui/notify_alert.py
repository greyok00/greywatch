from __future__ import annotations

import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from appfw import rules as R          # noqa: E402
from appfw.rules import RuleStore     # noqa: E402

from events import lane_for        # GW-197: threat lane vs tool lane
from gwpaths import data_dir as _gw_data

DATA = _gw_data()
ALERTS_SETTING_PATH = _gw_data() / "greywatch-ui-settings.json"

# Quieting preferences (owner-approved shape, 2026-11-05): one master
# switch, one global 30-minute snooze that re-arms itself, and a
# permanent switch per lane. A file that cannot be read fails OPEN:
# silence must always be a chosen state, never a broken one.
ALERTS_PREF_DEFAULTS = {
    "alerts": True,
    "deny_popups": True,
    "critical_popups": True,
    "alerts_snooze_until": 0.0,
}


def read_alert_prefs(path=None) -> dict:
    p = pathlib.Path(path) if path else ALERTS_SETTING_PATH
    try:
        loaded = dict(json.loads(p.read_text()))
    except (OSError, ValueError):
        loaded = {}
    prefs = dict(ALERTS_PREF_DEFAULTS)
    for key in ALERTS_PREF_DEFAULTS:
        if isinstance(loaded.get(key), bool):
            prefs[key] = loaded[key]
        elif key == "alerts_snooze_until":
            try:
                prefs[key] = float(loaded.get(key) or 0.0)
            except (TypeError, ValueError):
                pass
    return prefs


def write_alert_prefs(path=None, **keys) -> dict:
    """Merge the given keys into the settings file, riding through every
    other key (themes and the rest live in the same file)."""
    p = pathlib.Path(path) if path else ALERTS_SETTING_PATH
    try:
        data = json.loads(p.read_text())
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    for key, value in keys.items():
        if key in ALERTS_PREF_DEFAULTS:
            data[key] = value
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data) + "\n")
    return data


def allow_popup(lane: str, now=None, path=None) -> tuple[bool, str]:
    """Gate order: master switch → snooze stamp → per-lane switch."""
    prefs = read_alert_prefs(path)
    if not prefs["alerts"]:
        return False, "notifications are off"
    t = time.time() if now is None else float(now)
    if t < prefs["alerts_snooze_until"]:
        return False, "snoozed"
    what = f"{lane} popups are off"
    if lane == "deny" and not prefs["deny_popups"]:
        return False, what
    if lane == "critical" and not prefs["critical_popups"]:
        return False, what
    return True, ""


def snooze_alerts(minutes: float = 30.0, now=None, path=None) -> float:
    """Stamp alerts_snooze_until for minutes; returns the stamp."""
    t = time.time() if now is None else float(now)
    stamp = t + minutes * 60.0
    write_alert_prefs(path, alerts_snooze_until=stamp)
    return stamp


def clear_snooze(path=None) -> None:
    """End a snooze early (and never extend one that already lapsed)."""
    write_alert_prefs(path, alerts_snooze_until=0.0)


def is_private(addr: str) -> bool:
    """True for addresses that never left the machine's own networks."""
    import ipaddress
    try:
        a = ipaddress.ip_address(str(addr or ""))
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_multicast or a.is_unspecified)


def place_words(host: str) -> str:
    """The popup's place line: the country's name, "local network", or
    nothing when the table honestly does not know."""
    try:
        from ui import identity
        code, name = identity.geoip_country(host)
        if name:
            return str(name)
        if is_private(identity._addr_only(host)):
            return "local network"
    except Exception:
        pass
    return ""


class BlockedQueue:

    WINDOW_S = 600.0            # a (app, destination) burst lives 10 minutes
    REPEAT_REFRESH_S = 120.0    # a repeat re-presents at most this often
    PAIR_CAP = 64

    def __init__(self, data_dir):
        self.data_dir = pathlib.Path(data_dir)
        self.pairs: dict[tuple[str, str], dict] = {}
        self.last_shown = 0.0

    def add_deny(self, app: str, host: str, now=None) -> tuple:
        """Group repeats per (app, host).

        Returns (text, kind, record): "fresh" pops with the full story,
        "repeat-ok" re-presents the same pair with a counter no more often
        than REPEAT_REFRESH_S, "repeat-quiet" updates the count silently.
        """
        t = time.time() if now is None else float(now)
        for key, rec in list(self.pairs.items()):
            if t - rec["last"] > self.WINDOW_S:
                del self.pairs[key]
        name = app or "<unknown>"
        rec = self.pairs.get((name, host))
        if rec is None:
            rec = {"count": 0, "first": t, "last": t, "shown_at": 0.0}
            self.pairs[(name, host)] = rec
            while len(self.pairs) > self.PAIR_CAP:
                oldest = min(self.pairs, key=lambda k: self.pairs[k]["last"])
                del self.pairs[oldest]
        rec["count"] += 1
        rec["last"] = t
        rec["app"] = name
        rec["host"] = host
        if rec["count"] == 1:
            rec["shown_at"] = t          # handle_deny pops this immediately
            text = (f"⛔ Blocked {self.pretty(name)} → {host}\n"
                    "Unblock all or review from the dashboard.")
            return text, "fresh", rec
        if t - rec["shown_at"] >= self.REPEAT_REFRESH_S:
            rec["shown_at"] = t
            text = (f"⛔ {rec['count']} blocked: "
                    f"{self.pretty(name)} → {host}\n"
                    "Unblock all or review from the dashboard.")
            return text, "repeat-ok", rec
        return "", "repeat-quiet", rec

    @staticmethod
    def pretty(app: str) -> str:
        """An unattributed row is a fact, not a placeholder: say so."""
        return "an unidentified program" if app == "<unknown>" else app

    def unblock_all(self) -> list:
        s = RuleStore(self.data_dir / "appfw" / "rules")
        done = []
        for (_name, _host), rec in list(self.pairs.items()):
            app = rec["app"]
            if app == "<unknown>" or app in done:
                continue
            done.append(app)
            s.add(R.validate(f"appfw-app-{pathlib.Path(app).name}",
                             "allow", "always", "process.path", app))
        self.pairs.clear()
        return done

    def pending(self) -> int:
        return len(self.pairs)


import re

_DRE = re.compile(r"appfw (\S+) → (\S+) (allow|deny)\b")
# the daemon's event writer also emits a verdict-first shape — every recent
# deny row used it alone (2026-11-05 live finding: "appfw …" rows had gone
# quiet entirely), so a parser matching only _DRE read a busy firewall as
# silence and no notification ever fired
_DRE_VERDICT = re.compile(r"\b(allow|deny) (\S+) → (\S+)(?:\s|\))")

CRITICAL_TOOLS = ("fail2ban", "yara-watch", "yara-tmp-scan", "rkhunter")
CRITICAL_SEVS = ("HIGH", "CRITICAL")


def _event_age(ts, now=None) -> float | None:
    """Seconds since a daemon event stamp, or None when it carries no
    readable timestamp. Old alarms must not greet the user on the next
    launch: the newest HIGH in the file is not news forty minutes later
    (owner live finding, 2026-11-05: the 17:03 rkhunter alarm popped on
    first launch at 17:26)."""
    try:
        import datetime as _dt
        when = _dt.datetime.fromisoformat(str(ts).strip())
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        now = (_dt.datetime.now(_dt.timezone.utc) if now is None else now)
        return (now - when).total_seconds()
    except (ValueError, TypeError):
        return None


def critical_filter(events, now=None, window=None) -> list:
    """The criticals worth a popup, split by lane (GW-197, owner
    2026-11-06: BOTH lanes speak, each with its own controls). A tool
    lane entry carries tool controls (Start tool); a threat lane entry
    names what was found and leaves the controls to its decision.
    Events that already carry their own decision dialog never pop twice
    here. Returns the newest entry as a dict: lane, tool, text."""
    if window is None:               # read at call time: the class is
        window = CriticalEvents.SEEN_WINDOW   # defined further down
    out = []
    for e in events or ():
        if not isinstance(e, dict):
            continue
        tool = str(e.get("from_tool", ""))
        if e.get("severity") not in CRITICAL_SEVS:
            continue
        if isinstance(e.get("interaction"), dict):
            continue                 # it has its own decision dialog
        lane = lane_for(e)
        # Fail open on a missing stamp; fail CLOSED on one we can read.
        age = _event_age(e.get("ts"), now)
        if age is not None and age > window:
            continue
        out.append({"lane": lane, "tool": tool,
                    "text": str(e.get("text", ""))[:200]})
    newest = {}                     # the newest PER LANE: a tool-down and
    for d in out:                   # a threat can be news at the same time,
        newest[d["lane"]] = d       # and only one lane must not eat the
    return list(newest.values())    # other's voice (GW-197)


# Unit-less scanners (rkhunter, lynis: their verdict lives in their logs,
# GW-192) have no unit to start; the local way to start them is to run the
# scan now, which scan-now.sh does as root, logging to the usual files.
SCAN_NOW = {"rkhunter": "rkhunter", "lynis": "lynis"}


def _run(cmd, timeout=45) -> int:
    try:
        import subprocess
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).returncode
    except (OSError, subprocess.SubprocessError):
        return -1


def start_tool(name: str, run=None) -> tuple[bool, str]:
    """Start a real local protection from the notification itself.

    A critical event about rkhunter or fail2ban is a statement about a tool
    this dashboard manages, not an outside threat, so its popup must offer
    the tool's own lever: user units start on the user bus, root units go
    through the tool-control helper, and unit-less scanners start by
    running their scan. Returns (ok, words for the user)."""
    try:
        from registry import load_registry, get_tool
        tool = get_tool(load_registry(), str(name or "")) or {}
    except Exception:
        tool = {}
    run = _run if run is None else run
    unit = tool.get("unit")
    label = tool.get("label") or "that program"
    if unit is None and str(name) in SCAN_NOW:
        rc = run(["pkexec", str(ROOT / "apply" / "scan-now.sh"),
                  SCAN_NOW[str(name)]], timeout=45)
        return rc == 0, (f"Running the {label} scan now; its dashboard row "
                         "turns green when the log speaks.")
    if not unit:
        return False, f"Nothing to start: {label} is not a managed tool."
    if unit == "greywatch.service":
        return False, "GreyWatch's own unit restarts with the app window."
    if tool.get("scope") == "user":
        rc = run(["systemctl", "--user", "start", unit])
        return rc == 0, (f"Started {label}. Its row on the dashboard will "
                         "turn green when it checks in.")
    rc = run(["pkexec", str(ROOT / "apply" / "tool-control.sh"),
              "start", unit])
    return rc == 0, (f"Started {label}. Its row on the dashboard will turn "
                     "green when it checks in.")


def parse_deny(text: str):
    s = str(text or "")
    m = _DRE.search(s)
    if m:
        return {"app": m.group(1), "host": m.group(2), "action": m.group(3)}
    m = _DRE_VERDICT.search(s)
    if not m:
        return None
    return {"app": m.group(2), "host": m.group(3), "action": m.group(1)}


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
    LANE = "deny"                 # which quieting switch governs this square

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
        """The picture beside the notification text. Every popup carries
        one; the ladder runs from the most specific picture downwards:

        1. the destination's map tile (offline GeoIP table, never whois),
        2. the program's own icon or a drawn initial,
        3. a drawn local-network tile for private addresses,
        4. a plain shield when nothing is known.
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
            if title and title != "<unknown>":
                # a brighter card than the in-app default: notification
                # bubbles are not the app's dark cards, and a dark tile
                # on a grey bubble reads as a shapeless blob
                return visuals.program_tile("", title, 64, binary=title,
                                            accent="#54687c")
            if is_private(identity._addr_only(host)):
                return visuals.local_tile(64)
            return visuals.shield_tile(64)
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

    def show(self, text: str, app: str = "", host: str = "",
             gate: bool = True, summary: str = "") -> None:
        if gate:
            ok, _why = allow_popup(self.LANE, path=ALERTS_SETTING_PATH)
            if not ok:
                return
        cls = self._cls()
        picture = self._tile(app, host)
        title = summary or self.SUMMARY
        try:
            if self._n is None:
                self._n = cls.Notification.new(title, text)
                self._n.set_timeout(8000)
                self._attach_image(self._n, picture)
                if hasattr(self._n, "add_action"):
                    self._wire_actions(self._n)
                self._n.show()
            else:
                self._attach_image(self._n, picture)
                self._n.update(title, text)
                self._n.show()
        except Exception:
            self._n = None               # a bus hiccup must never loop

    def _wire_actions(self, note) -> None:
        """libnotify actions are fixed on the square's first creation, so
        each lane declares its own set here. The deny lane acts on the
        outside connection; the critical lane (which is about this
        machine's own tools) is handled by CriticalSquare's override."""
        note.add_action("block-site", "Block address", self._on_block_site)
        note.add_action("block-app", "Block program", self._on_block_app)
        note.add_action("snooze", "Snooze 30 min", self._on_snooze)
        note.add_action("unblock-all", "Unblock all", self._on_unblock)
        note.add_action("review", "Review", self._on_review)

    def _on_block_site(self, *_a):
        """Deny this destination forever: a rule on the address itself."""
        host = getattr(self, "_last_host", "")
        ip = ""
        try:
            from ui import identity
            ip = identity._addr_only(host)
        except Exception:
            pass
        if not ip:
            return []
        s = RuleStore(self.blocked.data_dir / "appfw" / "rules")
        s.add(R.validate(f"appfw-ip-{ip}", "deny", "always", "dst.ip", ip))
        self.show(f"⛔ Every connection to {ip} now denied.\n"
                  "Undo it from Settings, Trusted sites.", gate=False)
        return [ip]

    def _on_block_app(self, *_a):
        """Deny this program's connections forever — only when it is one
        we could name."""
        app = getattr(self, "_last_app", "")
        if not app or app == "<unknown>":
            self.show("Nothing to block: the program was never named.\n"
                      "Block the address instead.", gate=False)
            return []
        s = RuleStore(self.blocked.data_dir / "appfw" / "rules")
        s.add(R.validate(f"appfw-deny-{pathlib.Path(app).name}",
                         "deny", "always", "process.path", app))
        self.show(f"⛔ {pathlib.Path(app).name} can no longer connect.\n"
                  "Undo it from Settings, Trusted programs.", gate=False)
        return [app]

    def _on_snooze(self, *_a):
        snooze_alerts(30)
        self.show("🔕 Popups quiet for 30 minutes.\n"
                  "They come back by themselves; the switch lives in "
                  "Settings, Notifications.", gate=False)
        return True

    def _on_unblock(self, *_a):
        done = self.blocked.unblock_all()
        if done:
            self.show(f"✓ Allowed forever: {', '.join(done[:3])}"
                      f"{'…' if len(done) > 3 else ''}", gate=False)
        return done

    def _on_review(self, *_a):
        import subprocess
        subprocess.Popen([sys.executable, str(ROOT / "ui" / "app.py")])

    def handle_deny(self, app: str, host: str, now=None) -> str:
        text, kind, rec = self.blocked.add_deny(app, host, now=now)
        self._last_app = app                  # what Block program acts on
        self._last_host = host                # what Block address acts on
        if kind == "repeat-quiet":
            return ""                    # same pair, already on screen
        place = place_words(host)
        if place and text:
            text = text.replace("\n", f"  ·  {place}\n", 1)
        self.show(text, app=app, host=host)
        return text


class CriticalSquare(NotifyAlert):

    SUMMARY = "Security: critical event"
    APP = "greywatch-critical"
    LANE = "critical"

    def show(self, text: str, gate: bool = True, lane: str = "tool"):
        """Two faces, two voices (owner 2026-11-06): a tool critical says
        Maintenance and offers the tool's own levers; a threat critical
        says Security and never offers tool controls. The summary is
        chosen before the first libnotify create, since actions and
        title are fixed there."""
        self._lane = lane
        super().show(text, gate=gate, summary=self._summary(lane))

    def _summary(self, lane: str = "tool") -> str:
        return ("Security: critical event" if lane == "threat" else
                "Maintenance: a tool needs attention")

    def _wire_actions(self, note) -> None:
        """Tool criticals are about the machine's OWN tools (a rootkit
        scanner down, bans failing) — not an outside connection — so the
        popup starts the tool instead of offering block actions that
        would do nothing (owner live finding, 2026-11-05). Threat
        criticals (GW-197) get the pair of actions that fit them: none
        of them start a tool."""
        if getattr(self, "_lane", "tool") == "threat":
            note.add_action("snooze", "Snooze 30 min", self._on_snooze)
            note.add_action("review", "Review", self._on_review)
            return
        note.add_action("start-tool", "Start tool", self._on_start_tool)
        note.add_action("snooze", "Snooze 30 min", self._on_snooze)
        note.add_action("review", "Review", self._on_review)

    def _on_start_tool(self, *_a):
        events = getattr(self, "blocked", None)
        name = events.latest[0] if events and events.latest[0] else ""
        ok, words = start_tool(name)
        self.show(("✓ " if ok else "✗ ") + words, gate=False)
        return ok

