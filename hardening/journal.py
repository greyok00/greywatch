"""Rollback journal: append-only JSONL of hardening changes.

Each line is one object: {"id", "ts", "before", "plan"}. Binary
before-values (e.g. unit files read as bytes) are base64-encoded by the
caller under before[id]["blob"]; this module stores and returns them as-is.
"""

import json
from datetime import datetime, timezone


# post-plan consolidation: journal WRITES belong to apply/harden.sh in
# production (it records before-values + plan mid-apply, before any
# mutation); this in-process writer remains for tests and for the day a
# stdout-returning run_helper in wiz/common lets Apply route through the
# python side again — keep the two writers' record shape identical.
def write_entry(journal_path, entry_id, before, plan):
    """Append one entry to the journal. Returns True on success."""
    record = {
        "id": entry_id,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "before": before,
        "plan": list(plan),
    }
    try:
        with open(journal_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return True
    except OSError:
        return False


def _read_all(journal_path):
    """Yield parsed entries, skipping blank or corrupt lines."""
    try:
        with open(journal_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(entry, dict):
            yield entry


def read_latest(journal_path):
    """Return the most recent (last) entry, or None."""
    latest = None
    for entry in _read_all(journal_path):
        latest = entry
    return latest


def read_entry(journal_path, entry_id):
    """Return the entry with the given id, or None if absent."""
    for entry in _read_all(journal_path):
        if entry.get("id") == entry_id:
            return entry
    return None
