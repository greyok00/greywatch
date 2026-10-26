from __future__ import annotations

import json
import os

GREEN, YELLOW, RED, OFF = "GREEN", "YELLOW", "RED", "OFF"
UNKNOWN = "UNKNOWN"      # the probe could not answer — never guess
NO_UNIT = "no-unit"      # = NOT INSTALLED (the unit never existed)

_RANK = {GREEN: 0, UNKNOWN: 1, YELLOW: 1, RED: 2}


def worst_from(states, rank=_RANK):
    return max(states, key=lambda s: rank.get(s, 2))

ACTIVE, INACTIVE, FAILED, NO_UNIT, UNKNOWN_UNIT = \
    "active", "inactive", "failed", "no-unit", "unknown"


def classify(unit_state: str, log_state: str,
             expects_unit: bool, needs_log: bool) -> str:
    if expects_unit and unit_state == UNKNOWN_UNIT:
        return UNKNOWN         # the probe failed — do not invent a verdict
    if expects_unit and unit_state == NO_UNIT:
        return YELLOW          # no unit ANYWHERE → the tool isn't installed
    if expects_unit and unit_state == FAILED:
        return RED
    if needs_log and log_state == "unreadable":
        return YELLOW          # root-readable only: the root daemon reads it
    if needs_log and log_state == "missing":
        if expects_unit and unit_state == INACTIVE:
            return RED         # dead unit AND nothing written
        return YELLOW
    if expects_unit and unit_state == INACTIVE:
        return RED             # installed, not running
    return GREEN


def log_state_of(path: str) -> str:
    if str(path).startswith("journal:"):
        return "ok"
    try:
        if not os.path.exists(path):
            return "missing"
        with open(path, "rb"):
            return "ok"
    except (OSError, PermissionError):
        return "unreadable"


def snapshot(registry: list, unit_checker) -> dict:
    tools = {}
    for t in registry:
        expects = t.get("unit") is not None
        t["_installed_hint"] = t.get("installed", True)
        unit_state = unit_checker(t) if expects else NO_UNIT
        log_states = [log_state_of(p) for p in t.get("logs", [])]
        if expects and log_states:
            state = worst_from(classify(unit_state, ls, True, True)
                               for ls in log_states)
        elif expects:                       # unit-managed, journal-based tool
            state = classify(unit_state, "ok", True, False)
        elif log_states:
            state = worst_from(classify(unit_state, ls, False, True)
                               for ls in log_states)
        else:
            state = GREEN
        tools[t["name"]] = {
            "label": t["label"], "state": state, "last_event": None,
            "unit_state": unit_state,
            "installed": t.get("_installed", None),
        }
    return {"updated": _utc_now(), "tools": tools}


def _utc_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc) \
        .isoformat(timespec="seconds")


def write_status(path: str, status: dict) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump(status, f, separators=(",", ":"))
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    os.chmod(path, 0o644)


def load_status(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"updated": None, "tools": {}}
