from __future__ import annotations

import pathlib
import subprocess
import sys
import time

HEARTBEAT = pathlib.Path("/run/greywatch/heartbeat")
MAX_AGE_S = 30.0


def main() -> int:
    unit_alive = subprocess.run(["systemctl", "is-active", "--quiet",
                                 "greywatch.service"]).returncode == 0
    if not unit_alive:
        print("watchdog: unit not active — restarting")
        subprocess.run(["systemctl", "restart", "greywatch.service"])
        return 0
    try:
        age = time.time() - HEARTBEAT.stat().st_mtime
    except OSError:
        print("watchdog: no heartbeat file — restarting (fail-closed)")
        subprocess.run(["systemctl", "restart", "greywatch.service"])
        return 0
    if age > MAX_AGE_S:
        print(f"watchdog: heartbeat stale {age:.0f} s (>{MAX_AGE_S:.0f}) "
              "— restarting")
        subprocess.run(["systemctl", "restart", "greywatch.service"])
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
