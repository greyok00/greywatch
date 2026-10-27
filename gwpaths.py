"""gwpaths — one resolver for where greywatch runtime state lives.

The installed daemon's CODE lives in /usr/lib/greywatch (root-owned,
never writable by unprivileged users); its STATE must not. This module
resolves the runtime data directory the same way for the daemon, the
desktop UI, and every helper:

  1. $GREYWATCH_DATA_DIR — explicit override (unit file, tests, staging),
  2. /var/lib/greywatch — the installed deployment's state dir, used
     only when it exists AND this process can read and write it,
  3. this checkout's own data/ directory — source runs.
"""
from __future__ import annotations

import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
STATE_DIR = pathlib.Path("/var/lib/greywatch")


def data_dir() -> pathlib.Path:
    env = os.environ.get("GREYWATCH_DATA_DIR")
    if env:
        return pathlib.Path(env)
    try:
        if STATE_DIR.is_dir() and os.access(STATE_DIR, os.R_OK | os.W_OK):
            return STATE_DIR
    except OSError:
        pass
    return ROOT / "data"

def ui_user() -> str:
    """The desktop-user identity the daemon talks to. GW-02: resolved and
    VALIDATED once at install time and persisted in the systemd unit;
    $GREYWATCH_UI_USER overrides that for tests and staging. "grey" is
    only the last-resort default name — callers must treat an
    unresolvable lookup as unknown (no uid/gid), never invent an id."""
    return os.environ.get("GREYWATCH_UI_USER") or "grey"
