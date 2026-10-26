from __future__ import annotations

import json
import os
import pathlib


def write_json_atomic(path, doc, fsync_dir: bool = True) -> None:
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
