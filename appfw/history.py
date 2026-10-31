from __future__ import annotations

import json
import os
import pathlib
import time

MAX_BYTES = 1_048_576


def _path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "appfw" / "engine-history.jsonl"


def record(data_dir, event: str, reason: str = "",
           detail: str = "") -> None:
    """One line per transition, group-readable, capped at 1 MB.

    The owner could not answer "why did the firewall turn off" because the
    only record lived in a root-only event file. This file is the answer,
    and the App Firewall card reads its last three lines.
    """
    path = _path(data_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if path.stat().st_size > MAX_BYTES:
                os.replace(path, path.with_name(path.name + ".1"))
        except OSError:
            pass
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": str(event)[:40],
            "reason": str(reason)[:300],
            "detail": str(detail)[:300],
        }
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, (json.dumps(entry, separators=(",", ":"))
                          + "\n").encode())
        finally:
            os.close(fd)
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass
    except OSError:
        pass


def recent(data_dir, limit: int = 3) -> list[dict]:
    try:
        lines = _path(data_dir).read_text(errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for line in reversed(lines):
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if isinstance(doc, dict) and doc.get("event"):
            out.append(doc)
        if len(out) >= limit:
            break
    return out
