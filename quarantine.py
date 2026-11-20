"""One reading of the quarantine ledger, for every surface that shows it.

The ledger is append-only: a quarantine row, then later a marker saying
the copy was restored, deleted, or expired. The UI used to render every
line, so 573 old test-artifact rows (570 from pytest scratch trees, all
from 2026-10-27) sat on the Firewall/Defense tab as if they were live
threats, and the close-out markers read as duplicates.

`live_rows` is the honest answer to "what is in quarantine right now":
the newest file-backed row per original path, dropped once a closing
marker for that path follows it. Nothing is deleted here - markers are
appended, never rewritten, which keeps the ledger a record.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib

CLOSING = frozenset({"deleted", "restored", "expired"})

# Paths that only a test run produces. A row naming one of these was
# written into the live ledger by a test process, never a real quarantine.
TEST_SCRATCH = ("/tmp/pytest-of-", "/tmp/gw-eicar", "/var/tmp/gw-eicar",
                "/dev/shm/gw-eicar")


def read_rows(path) -> list[dict]:
    p = pathlib.Path(path)
    try:
        raw = p.read_text(errors="replace")
    except OSError:
        return []
    out = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def live_rows(rows) -> list[dict]:
    """Newest file-backed row per original path, with closed paths gone."""
    live: dict[str, dict] = {}
    for row in rows:
        orig = str(row.get("orig") or "")
        if not orig:
            continue
        if row.get("action") in CLOSING:
            live.pop(orig, None)
            continue
        if row.get("file"):
            live[orig] = row
    return list(live.values())


def _age_days(stamp, now: _dt.datetime) -> float | None:
    try:
        ts = _dt.datetime.fromisoformat(str(stamp))
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=now.tzinfo)
    return (now - ts).total_seconds() / 86400.0


def prune_markers(rows, now=None, stale_days: float = 7.0,
                  exist=None) -> list[dict]:
    """The expiry markers a prune would append. Read-only.

    A row expires when its copy is gone from disk, when its original
    path is a test scratch tree, or when it is older than `stale_days`.
    `exist` is injectable so tests never stat the live filesystem.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    exists = exist or (lambda p: pathlib.Path(p).exists())
    out = []
    for row in live_rows(rows):
        orig = str(row.get("orig") or "")
        filed = str(row.get("file") or "")
        reason = None
        if any(orig.startswith(pre) for pre in TEST_SCRATCH):
            reason = "test artifact"
        elif not exists(filed):
            reason = "copy gone"
        else:
            age = _age_days(row.get("ts"), now)
            if age is not None and age > stale_days:
                reason = f"older than {stale_days:g} days"
        if reason:
            out.append({"ts": now.isoformat(timespec="seconds"),
                        "action": "expired", "orig": orig, "reason": reason})
    return out


def append_markers(path, markers) -> int:
    if not markers:
        return 0
    p = pathlib.Path(path)
    with p.open("a") as fh:
        for m in markers:
            fh.write(json.dumps(m, separators=(",", ":")) + "\n")
    return len(markers)
