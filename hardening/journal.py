
import json
from datetime import datetime, timezone


def write_entry(journal_path, entry_id, before, plan):
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
    latest = None
    for entry in _read_all(journal_path):
        latest = entry
    return latest


def read_entry(journal_path, entry_id):
    for entry in _read_all(journal_path):
        if entry.get("id") == entry_id:
            return entry
    return None
