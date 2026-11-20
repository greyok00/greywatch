from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

HEARTBEAT = pathlib.Path("/run/greywatch/heartbeat")
MAX_AGE_S = 30.0
HUNTER_UNIT = "greywatch-hunter.service"


def _hunter_live(data_dir: str) -> pathlib.Path:
    return pathlib.Path(data_dir) / "hunter" / "live.json"


def _arg_data_dir(argv: list[str]) -> str:
    # The deb/install units pass --data-dir; the default is the same
    # place the deb fills (GW-155), so the watchdog can read the
    # hunter's own stamp from the real store.
    if "--data-dir" in argv:
        return argv[argv.index("--data-dir") + 1]
    return "/var/lib/greywatch"


def _hunter_stale(data_dir: str) -> bool:
    """True when an active hunter is not stamping its live file.

    The daemon heartbeat gets the same fail-closed treatment: a live
    file missing while the unit claims to run means the stamping loop
    is broken, so restarting is the fix. The threshold matches the
    dashboard's own clock (2.5 hunt intervals), not the 300 s interval
    alone - a slow boot's first hunt must not look dead."""
    live = _hunter_live(data_dir)
    try:
        doc = json.loads(live.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    interval = doc.get("interval_s") or 300.0
    try:
        interval = max(60.0, float(interval))
    except (TypeError, ValueError):
        interval = 300.0
    try:
        age = time.time() - live.stat().st_mtime
    except OSError:
        return True
    return age > max(60.0, interval * 2.5)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    data_dir = _arg_data_dir(argv)
    unit_alive = subprocess.run(["systemctl", "is-active", "--quiet",
                                 "greywatch.service"]).returncode == 0
    if not unit_alive:
        print("watchdog: unit not active - restarting")
        subprocess.run(["systemctl", "restart", "greywatch.service"])
        return 0
    try:
        age = time.time() - HEARTBEAT.stat().st_mtime
    except OSError:
        # The daemon's ping loop writes this file alongside every
        # sd_notify pet (greywatch_daemon._watchdog_ping_loop): missing
        # while the unit is active means that loop is broken, so
        # restarting is the fix, not the problem. (Recovery audit A2 -
        # this lane was previously dead code: no writer exists, and its
        # first run restarted the unit forever.)
        print("watchdog: no heartbeat file - restarting (fail-closed)")
        subprocess.run(["systemctl", "restart", "greywatch.service"])
        return 0
    if age > MAX_AGE_S:
        print(f"watchdog: heartbeat stale {age:.0f} s (>{MAX_AGE_S:.0f}) "
              "- restarting")
        subprocess.run(["systemctl", "restart", "greywatch.service"])
        return 0
    # GW-155: the hunter is its own unit and the deb route can leave it
    # enabled but failed (or silently not started at all on old
    # installs) - the daemon watchdog never looked at it. Restart it the
    # same way: not active, or active but not stamping.
    live = _hunter_live(data_dir)
    active = subprocess.run(["systemctl", "is-active", "--quiet", HUNTER_UNIT])
    if active.returncode == 4:
        # "not found": no hunter unit installed here (the hunter lane
        # does not exist on this route) - nothing to watch, stay quiet.
        return 0
    if active.returncode != 0:
        age_txt = "-"
        try:
            age = time.time() - live.stat().st_mtime
            age_txt = f"{age:.0f} s old"
        except OSError:
            pass
        print(f"watchdog: {HUNTER_UNIT.split('.')[0]} not active "
              f"({age_txt}) - restarting")
        subprocess.run(["systemctl", "restart", HUNTER_UNIT])
        return 0
    if _hunter_stale(data_dir):
        print(f"watchdog: hunter live stamp stale - restarting {HUNTER_UNIT}")
        subprocess.run(["systemctl", "restart", HUNTER_UNIT])
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
