"""Daemon-side desktop notification fallback.

When the GUI dashboard is closed, the daemon (root, no display) cannot
fire libnotify bubbles through PyGObject. This module bridges that gap
by calling ``notify-send`` as the UI user via ``runuser``.

Gate order mirrors ui/notify_alert.py allow_popup:
    master switch -> snooze stamp -> per-lane switch -> burst cap -> dedupe.

Only fires for HIGH or CRITICAL severity. At most one bubble per lane
per 120 seconds, deduplicated by (tool, text[:200]).
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from appfw.rules import RuleStore  # noqa: E402

from events import lane_for  # noqa: E402
from gwpaths import data_dir as _gw_data  # noqa: E402

DATA = _gw_data()
ALERTS_SETTING_PATH = DATA / "greywatch-ui-settings.json"

# Quieting preferences — identical shape to ui/notify_alert.py
ALERTS_PREF_DEFAULTS = {
    "alerts": True,
    "deny_popups": True,
    "critical_popups": True,
    "alerts_snooze_until": 0.0,
}

# Burst cap: one bubble per lane per 120 seconds
BURST_WINDOW_S = 120.0

# Dedupe key: (tool, text[:200])
_DEDUPE_MAX_LEN = 200


def _read_alert_prefs(path=None) -> dict:
    """Read prefs from a file path, or from data_dir + settings file."""
    if path is None:
        p = ALERTS_SETTING_PATH
    elif isinstance(path, pathlib.Path):
        # Could be a directory or a file path
        if path.is_file():
            p = path
        else:
            p = path / "greywatch-ui-settings.json"
    else:
        p = pathlib.Path(path) / "greywatch-ui-settings.json"
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


def _burst_ok(lane: str, now: float) -> bool:
    """Return True if at least one bubble has NOT been fired in this lane
    within the last BURST_WINDOW_S seconds."""
    key = f"burst_{lane}"
    last = _burst_at.get(key)
    if last is not None and now - last < BURST_WINDOW_S:
        return False
    _burst_at[key] = now
    return True


def _dedup_ok(tool: str, text: str, now: float) -> bool:
    """Return True if this (tool, text[:200]) has NOT been fired within
    the last BURST_WINDOW_S seconds."""
    key = f"{tool}|{text[:_DEDUPE_MAX_LEN]}"
    last = _dedup_at.get(key)
    if last is not None and now - last < BURST_WINDOW_S:
        return False
    _dedup_at[key] = now
    return True


def notify(
    tool: str,
    severity: str,
    text: str,
    data_dir: pathlib.Path | str | None = None,
    ui_user: str = "grey",
    ui_alive=None,
) -> None:
    """Fire a desktop notification bubble via notify-send.

    Parameters
    ----------
    tool : str
        The originating tool name (e.g. "appfw", "self-heal").
    severity : str
        One of the event severity levels. Only HIGH and CRITICAL fire.
    text : str
        The notification body. Truncated to 200 chars for dedupe.
    data_dir : pathlib.Path | str | None
        The daemon's data directory (for the prefs file).
        Defaults to gwpaths data_dir.
    ui_user : str
        The desktop user to run notify-send as. Defaults to "grey".
    ui_alive : callable | None
        A zero-arg callable returning bool. If it returns True,
        the GUI owns notifications and this function returns
        immediately without firing.

    Returns
    -------
    None — always silent.
    """
    # Only HIGH and CRITICAL
    if severity not in ("HIGH", "CRITICAL"):
        return

    # GUI alive? — daemon defers to GUI
    if ui_alive is not None:
        try:
            if ui_alive():
                return
        except Exception:
            pass

    prefs = _read_alert_prefs(data_dir)

    # Master switch
    if not prefs["alerts"]:
        return

    # Snooze stamp
    now = time.time()
    if now < prefs["alerts_snooze_until"]:
        return

    # Per-lane switch: lane_for expects a dict event
    ev = {"from_tool": tool, "severity": severity}
    lane = lane_for(ev)
    if lane == "deny" and not prefs["deny_popups"]:
        return
    if lane == "critical" and not prefs["critical_popups"]:
        return

    # Burst cap
    if not _burst_ok(lane, now):
        return

    # Dedupe
    if not _dedup_ok(tool, text, now):
        return

    # Fire notify-send as the UI user
    _fire_notify(tool, severity, text, data_dir, ui_user)


# Module-level state
_burst_at: dict[str, float] = {}
_dedup_at: dict[str, float] = {}


def _fire_notify(
    tool: str,
    severity: str,
    text: str,
    data_dir: pathlib.Path | str | None,
    ui_user: str,
) -> None:
    """Execute notify-send via runuser -u USER -- env DISPLAY=:0
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/UID/bus notify-send
    -a GreyWatch -u critical|normal -t 20000 TITLE TEXT.

    Uses subprocess.Popen with output to DEVNULL. Never waits.
    Never raises.
    """
    # Resolve UI user's UID for the bus path
    try:
        import pwd
        pw = pwd.getpwnam(ui_user)
        uid = pw.pw_uid
    except (KeyError, ValueError):
        uid = None

    bus_path = f"/run/user/{uid}/bus" if uid is not None else ""

    title = f"GreyWatch [{severity}] {tool}"
    body = text[:500]
    urgency = "critical" if severity in ("HIGH", "CRITICAL") else "normal"
    timeout_ms = 20000  # 20 seconds

    cmd = (
        ["runuser", "-u", ui_user, "--", "env",
         "DISPLAY=:0",
         f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus_path}",
         "notify-send",
         "-a", "GreyWatch",
         "-u", urgency,
         "-t", str(timeout_ms),
         title, body]
    )

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except Exception:
        pass  # non-fatal: desktop bus unavailable
