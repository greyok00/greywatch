#!/usr/bin/env python3
"""ui-shots: one private-Xvfb screenshot per page of the current shell.

The old sweep imported ``ui.window``, which the v4 shell deleted, so it
could never run. This is a thin batch driver over ``ui/run_shot.py``: each
page gets its own short-lived app process, its own Xvfb display, and one
root-window capture. No screenshot ever touches the live desktop.

    python3 tools/ui_shots.py
    python3 tools/ui_shots.py --views "Security Center,Tools"
    python3 tools/ui_shots.py --out doc/ui-shots/2026-11-20-before
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import pathlib
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
RUN_SHOT = REPO / "ui" / "run_shot.py"
PAGES = (
    "Security Center", "Network", "Tools", "Timeline", "Assistant", "Help",
)


def _slug(label: str) -> str:
    return "-".join(label.lower().split())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=None,
                        help="output directory (default: doc/ui-shots/<date>)")
    parser.add_argument("--views", default=",".join(PAGES),
                        help="comma-separated page labels")
    parser.add_argument("--geometry", default="1440x900",
                        help="private Xvfb geometry (default: 1440x900)")
    args = parser.parse_args(argv)
    if not RUN_SHOT.is_file():
        print(f"missing capture driver: {RUN_SHOT}", file=sys.stderr)
        return 2
    out = pathlib.Path(args.out) if args.out else (
        REPO / "doc" / "ui-shots" / dt.date.today().isoformat()
    )
    out.mkdir(parents=True, exist_ok=True)
    requested = [p.strip() for p in args.views.split(",") if p.strip()]
    failed: list[str] = []
    for label in requested:
        target = out / f"{_slug(label)}.png"
        env = dict(os.environ, GW_SHOT_GEOM=args.geometry)
        print(f"== {label} -> {target}")
        proc = subprocess.run(
            [sys.executable, str(RUN_SHOT), label, str(target)],
            cwd=str(REPO), env=env, text=True, capture_output=True,
            timeout=120,
        )
        detail = (proc.stdout or "") + (proc.stderr or "")
        print(detail.strip()[-800:])
        if proc.returncode != 0 or not target.is_file():
            failed.append(label)
        time.sleep(1.0)
    if failed:
        print("failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    print(f"captured {len(requested)} page(s) in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
