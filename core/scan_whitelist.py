"""The scan-finding whitelist: paths the scanners may flag but the owner
has ruled out, one file with add/remove/list and matches applied at every
finding surface (the run digest, the auto-quarantine). Lives in the state
dir group-writable so the CLI edits it without root."""
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import re

DEFAULT_NAME = "scan-whitelist.json"


def load(path: pathlib.Path | None = None) -> dict:
    path = pathlib.Path(path or _state_path())
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("entries"), list):
            return doc
    except (OSError, ValueError):
        pass
    return {"version": 1, "entries": []}


def _state_path() -> pathlib.Path:
    try:
        import gwpaths
        return gwpaths.data_dir() / DEFAULT_NAME
    except Exception:                       # noqa: BLE001
        return pathlib.Path.home() / DEFAULT_NAME


def save(doc: dict, path: pathlib.Path | None = None) -> None:
    path = pathlib.Path(path or _state_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = pathlib.Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    os.replace(tmp, path)
    try:
        chmod_group_writable(path)
    except OSError:
        pass


def chmod_group_writable(path: pathlib.Path) -> None:
    os.chmod(path, 0o664)


def add(target: str, reason: str = "", path=None) -> tuple[bool, str]:
    """Add a whitelist entry: a file path, or a directory whose whole
    subtree is ruled out. Tolerant of trailing slashes and ~."""
    entry = normalize(target)
    if not entry:
        return False, "give a path: whitelist add /full/path [REASON]"
    doc = load(path)
    for e in doc["entries"]:
        if e["target"] == entry["target"]:
            return False, f"already whitelisted: {e['target']}"
    entry["reason"] = reason or entry.get("reason", "")
    entry["added"] = _dt.datetime.now(_dt.timezone.utc).isoformat(
        timespec="seconds")
    doc["entries"].append(entry)
    save(doc, path)
    kind = "subtree" if entry.get("subtree") else "file"
    return True, f"whitelisted ({kind}): {entry['target']}"


def remove(target: str, path=None) -> tuple[bool, str]:
    doc = load(path)
    norm = normalize(target)
    keep = [e for e in doc["entries"]
            if e["target"] != norm.get("target")]
    if len(keep) == len(doc["entries"]):
        return False, f"not on the whitelist: {target}"
    doc["entries"] = keep
    save(doc, path)
    return True, f"removed from the whitelist: {target}"


def normalize(target: str) -> dict:
    target = str(target or "").strip().rstrip("/")
    target = os.path.expanduser(target)
    if target.startswith("/"):
        target = target.rstrip("/")

        p = pathlib.Path(target)
        subtree = p.is_dir()
        return {"target": target, "subtree": subtree}
    if target.startswith("~"):
        return {"target": target, "subtree": True}
    return {"target": target, "subtree": False}


def match(path: str, doc: dict | None = None) -> bool:
    """True when a finding path is ruled out: an exact entry, or inside
    a whitelisted subtree, or a whitelisted prefix pattern (fnmatch via
    a leading *, a prefix ending in /*)."""
    if doc is None:
        doc = load()
    pth = str(path)
    for e in doc["entries"]:
        t = e["target"]
        if pth == t:
            return True
        if e.get("subtree") and pth.startswith(t.rstrip("/") + "/"):
            return True
        if t.endswith("/*") and pth.startswith(t[:-2]):
            return True
    return False


def hits(rows: list, doc: dict | None = None) -> tuple[list, int]:
    """Split flagged rows into (kept, ignored_count) by the whitelist."""
    if doc is None:
        doc = load()
    def path_of(row):
        text = str(row if isinstance(row, str) else row.get("text", ""))
        head = text.split(": ", 1)[0].strip()
        return head
    kept = [r for r in rows if not match(path_of(r), doc)]
    return kept, len(rows) - len(kept)
