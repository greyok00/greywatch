"""appfw.atomicio — crash-safe writes for every control file (P0-a).

P0 hardening (2026-10-24 master prompt): enable.json and rule files must
survive a mid-write kill — tmp file, fsync, atomic rename. The prior content
is the safe state; a failed write never leaves a torn file behind.
"""
from __future__ import annotations

import json
import os
import pathlib


def write_json_atomic(path, doc, fsync_dir: bool = True) -> None:
    """Write JSON atomically: tempfile in the same directory, fsync, rename.
    The directory is fsynced too (rename durability on crash)."""
    path = pathlib.Path(path)
    payload = json.dumps(doc, indent=1) + "\n"
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp), str(path))     # atomic flip — INSIDE the guard,
    except BaseException:                   # so any failure cleans the tmp up
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    if fsync_dir:
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)