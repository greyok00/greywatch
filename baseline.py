"""baseline — per-app destination profiles from the events ledger
(plan Task 5, design §6.1 [4]).

The app's own history is the L1 witness: an app→destination pair seen
ALLOWED before is a silent allow; anything else is an anomaly input to
the chain. Streaming builder: bounded dicts, garbage lines counted,
rotation files included, nothing loaded whole (108 MB class file).
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re
import time

import subprocess

from status import load_status

MAX_APPS = 10_000
MAX_DESTS = 2_000

# Ledger text shapes: TWO real producers exist (review C4).
#   engine.py:640   'appfw <app> → <dst>:<port> <action> [note]'  (action last)
#   live writer     'deny <app> → <dst>:<port> (<note>)'          (action first)
_APPFW_ROW = re.compile(
    r"^\s*(?:(?P<pre3>appfw)\s+)?(?:(?P<action>allow|deny|block)\s+)?"
    r"(?P<app>[^ \s][^\s]*(?:\s[^\s]*?)*?)\s+→\s+"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)"
    r":(?P<port>\d{1,5})(?:\s+\(|\s|$)")
_APPFW_ROW_ACTION_LAST = re.compile(
    r"^\s*appfw\s+(?P<app>[^ \n][^\n]*?)\s+→\s+"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)"
    r":(?P<port>\d{1,5})\s+(?P<action>allow|deny|block)\b")


class Baseline:
    __slots__ = ("apps", "bad_lines", "caps_evicted", "built_at", "skipped_unattributed")

    def __init__(self):
        self.apps: dict[str, dict[tuple[str, int], dict]] = {}
        self.skipped_unattributed: int = 0
        self.bad_lines = 0
        self.caps_evicted = 0
        self.built_at = time.time()

    def count_for(self, app: str, dst: str, port: int) -> int:
        row = self.apps.get(app, {}).get((dst, port))
        return row["n"] if row else 0


def _another_tool_row(raw: str) -> bool:
    """True when a non-parsing line is still recognizably another tool's
    row (out of scope for the appfw ledger): a JSON object with a
    from_tool that is not appfw. Content-judged, spacing-independent —
    compact and spaced producer shapes behave the same."""
    if not raw.startswith("{"):
        return False
    try:
        doc = json.loads(raw)
    except ValueError:
        return False
    return isinstance(doc, dict) and doc.get("from_tool") not in (
        None, "appfw")


def _evict_coldest(apps: dict) -> None:
    """Cap enforcement: drop the app with the oldest most-recent activity."""
    coldest = min(apps.items(),
                  key=lambda kv: max((e["last"] for e in kv[1].values()),
                                     default=0.0))
    apps.pop(coldest[0], None)


def build(data_dir, now: float) -> Baseline:
    base = Baseline()
    data_dir = pathlib.Path(data_dir)
    paths = sorted(data_dir.glob("events.jsonl.old-*"))
    current = data_dir / "events.jsonl"
    if current.exists():
        paths.append(current)
    for path in paths:
        try:
            fh = path.open("r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                raw = line.strip()
                row = _parse_ledger_line(line)
                if row is None:
                    # bad_lines counts parse-quality failures of OUR
                    # ledger (carried minor 10/M6). Judge by CONTENT,
                    # not spacing: a line that parses as JSON and names
                    # another tool is out of scope, not garbage; only
                    # undecodable lines and malformed appfw texts count.
                    if raw and not _another_tool_row(raw):
                        base.bad_lines += 1
                    continue
                app, dst, port, action, ts = row
                if "attribution miss" in (app or "") or " " in (app or "") \
                        or not (app or "").strip():
                    base.skipped_unattributed = getattr(
                        base, "skipped_unattributed", 0) + 1
                    continue
                per_app = base.apps.setdefault(app, {})
                if len(per_app) >= MAX_DESTS and (dst, port) not in per_app:
                    base.caps_evicted += 1
                    continue
                entry = per_app.setdefault(
                    (dst, port), {"n": 0, "allow": 0, "last": 0.0})
                entry["n"] += 1
                if action == "allow":
                    entry["allow"] += 1
                entry["last"] = max(entry["last"], ts)
                if len(base.apps) > MAX_APPS:
                    _evict_coldest(base.apps)
                    base.caps_evicted += 1
    return base


def _parse_ledger_line(line: str) -> tuple[str, str, int, str, float] | None:
    """One ledger line → (app, dst, port, action, epoch) or None.
    Lines are JSON; the appfw verdict text is a FIELD VALUE, so parse
    JSON first, regex the text second. Anything not an appfw row with a
    string text counts against bad_lines (garbage or other-tool rows)."""
    line = line.strip()
    if not line:
        return None
    try:
        doc = json.loads(line)
    except ValueError:
        return None
    if not isinstance(doc, dict) or doc.get("from_tool") != "appfw":
        return None
    text = doc.get("text")
    if not isinstance(text, str):
        return None
    m = _APPFW_ROW_ACTION_LAST.match(text) or _APPFW_ROW.match(text)
    if not m:
        return None
    try:
        port = int(m.group("port"))
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    ts = 0.0
    ts_raw = doc.get("ts")
    if isinstance(ts_raw, str):
        try:
            # Explicit zone or 'Z' → UTC epoch. A naive host-local parse
            # would drift the ledger's recency math by the machine's
            # offset (carried minor 10/M6); the daemon writes UTC.
            raw = ts_raw.replace("Z", "+00:00")
            when = _dt.datetime.fromisoformat(raw)
            if when.tzinfo is None:
                when = when.replace(tzinfo=_dt.timezone.utc)
            ts = when.timestamp()
        except (ValueError, TypeError):
            # legacy second-precision shape without a zone: UTC by the
            # writer's contract, never host-local
            try:
                import calendar
                import time as _t
                stp = _t.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S")
                ts = calendar.timegm(stp)
            except (ValueError, TypeError):
                ts = 0.0
    return (m.group("app").strip(),
            m.group("dst").strip().lower().rstrip("."),
            port, m.group("action"), ts)


def profile_verdict(base: Baseline, app: str, dst: str,
                    port: int) -> dict | None:
    """L1 witness: the pair must have been ALLOWED before to earn a
    baseline allow now. Deny-history alone is never permission."""
    row = base.apps.get(app, {}).get((dst, port))
    if row and row["allow"] > 0:
        return {"action": "allow", "basis": "baseline",
                "count": row["n"], "allows": row["allow"]}
    return None


def anomaly_inputs(base: Baseline, app: str, dst: str, port: int) -> dict:
    per_app = base.apps.get(app, {})
    row = per_app.get((dst, port))
    now = time.time()
    last_any = max((e["last"] for e in per_app.values()), default=0.0)
    return {
        "first_contact": row is None,
        "quiet_app": bool(last_any) and (now - last_any > 60 * 86400),
        "new_port_class": row is None,
    }


def baseline_verifier(data_dir=None):
    """Per-tool: unit exists, active, enabled; per-config: the file
    the tool needs is present with the value the suite requires.
    Returns a list of (tool, check, state, detail). Moved here from
    cli.py (2026-11-16): the root daemon publishes the posture store
    with these same checks, and the daemon cannot import cli (cli
    imports the daemon module)."""
    out = []
    UNIT_TABLE = [
        ("responderd", "responderd.service", False),
        ("tetragon", "tetragon.service", False),
        # The owner retired the resident engine (2026-11-17: an uncapped
        # clamd made real work impossible) and the automatic scan timers
        # stay off (owner order 2026-11-19). The antivirus is the
        # one-shot lane started from the window or the CLI, so this
        # timer's healthy state is disabled and inactive.
        ("clamav", "greywatch-clam-scan.timer", False, False),
        ("yara-watch", "yara-watch.service", True),
        ("yara-tmp-scan", "yara-tmp-scan.timer", True),
        ("freshclam", "clamav-freshclam.service", False),
        ("ufw", "ufw.service", False),
        ("auditd", "auditd.service", False),
        ("arpwatch", "arpwatch@{iface}.service", False),
        ("psad", "psad.service", False),
        ("apparmor", "apparmor.service", False),
        ("fail2ban", "fail2ban.service", False),
        ("aide", "aide-check.timer", False),
        ("clam-scan", "greywatch-clam-scan.timer", False, False),
    ]
    from registry import default_iface
    for name, unit, user, *want in UNIT_TABLE:
        want_enabled = want[0] if want else True
        real_unit = unit.replace("{iface}", default_iface())
        args = ["systemctl"] + (["--user"] if user else [])
        act = subprocess.run(args + ["is-active", real_unit],
                             capture_output=True, text=True,
                             timeout=10).stdout.strip()
        en = subprocess.run(args + ["is-enabled", real_unit],
                            capture_output=True, text=True,
                            timeout=10).stdout.strip()
        if want_enabled:
            ok = act == "active" and en == "enabled"
            check = f"{real_unit} active+enabled"
        else:
            ok = en == "disabled" and act != "active"
            check = f"{real_unit} disabled (automatic scans off)"
        if ok:
            state = "ENABLED" if want_enabled else "OFF-BY-DESIGN"
        else:
            state = f"active={act} enabled={en}"
        out.append((name, check, state, ""))
    # Superseded (owner 2026-11-17): D1-a's resident clamd engine is
    # retired - the unit is masked and the antivirus answer is the
    # one-shot lane (the timer above, the definitions check below, the
    # scan-now helper on demand). No socket is asked for any more.
    try:
        daily = pathlib.Path("/var/lib/clamav/daily.cld")
        age = time.time() - daily.stat().st_mtime
        out.append(("clam-signatures",
                    "daily.cld age",
                    "FRESH" if age < 86400 * 8
                    else f"STALE ({int(age // 86400)}d)", ""))
    except OSError:
        out.append(("clam-signatures", "daily.cld age", "MISSING", ""))

    BIN_TABLE = [("lynis", "/usr/sbin/lynis"), ("rkhunter", "/usr/bin/rkhunter")]
    import shutil
    for name, bin_path in BIN_TABLE:
        out.append((name, f"binary {bin_path}",
                    "PRESENT" if shutil.which(bin_path) else "MISSING", ""))
    FILES_TABLE = [
        ("arpwatch-config", pathlib.Path("/etc/default/arpwatch"),
         'ARGS="-a -p"'),
        ("psad-config", pathlib.Path("/etc/psad/psad.conf"),
         "ENABLE_AUTO_IDS             Y;"),
        ("yara-rules", pathlib.Path.home() / "security-hardening"
            / "yara-rules" / "index.yar", None),
    ]
    for name, path, want in FILES_TABLE:
        try:
            text = path.read_text(errors="replace")
            if want is None:
                out.append((name, "config file", "PRESENT", ""))
            elif want in text:
                out.append((name, "config value", "ARMED", ""))
            else:
                out.append((name, want,
                            "NOT SET", f"add to {path} then restart the tool"))
        except OSError:
            out.append((name, "config file", "MISSING",
                        f"create {path}"))
    try:
        import gwpaths
        data_dir = pathlib.Path(data_dir) if data_dir else gwpaths.data_dir()
    except Exception:                    # noqa: BLE001
        data_dir = pathlib.Path(data_dir or "/var/lib/greywatch")
    load_status(str(data_dir / "status.json"))
    yara_path = pathlib.Path.home() / "security-hardening" /         "yara-rules" / "index.yar"
    for name, source in (("cve-updater", str(data_dir / "cve-cache.json")),
                         ("yara-hunting", str(yara_path))):
        sp = pathlib.Path(source)
        try:
            age = time.time() - sp.stat().st_mtime
            if "yara" in name.lower():
                # rules are static: PRESENT is the check; freshness rides
                # the yara-watch service that consumes them continuously
                out.append((name, source, "PRESENT", ""))
            else:
                out.append((name, source,
                            "FRESH" if age < 86400 * 8
                            else f"STALE ({int(age // 3600)}h)", ""))
        except OSError:
            out.append((name, source, "MISSING", ""))
    return out
