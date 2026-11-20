# assistant/audit.py
"""Append-only audit for chat-initiated actions.

The daemon owns decisions.jsonl and stays untouched (spec), so the
assistant keeps its own ledger tagged via=assistant. Primary location is
the shared data dir; a read-only one falls back to the user's XDG state.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib

import gwpaths

NAME = "assistant-actions.jsonl"


def record(action: str, tool: str, ok: bool) -> pathlib.Path | None:
    line = json.dumps({"ts": dt.datetime.now(dt.timezone.utc)
                       .isoformat(timespec="seconds"),
                       "action": action, "tool": tool,
                       "ok": bool(ok), "via": "assistant"})
    candidates = [(gwpaths.data_dir() / NAME, False)]
    xdg = os.environ.get("XDG_STATE_HOME") or os.path.expanduser(
        "~/.local/state")
    fallback = pathlib.Path(xdg) / "greywatch"
    candidates.append((fallback / NAME, True))
    for path, need_dir in candidates:
        try:
            if need_dir:
                path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                path.touch(mode=0o600, exist_ok=True)
            fresh = not path.exists()
            with open(path, "a", encoding="utf-8") as fh:
                if fresh:
                    # creation-time hardening: the umask must not widen the
                    # ledger (0600 like the rest of the daemon's writes)
                    try:
                        os.fchmod(fh.fileno(), 0o600)
                    except OSError:
                        pass
                fh.write(line + "\n")
            return path
        except OSError:
            continue
    return None
