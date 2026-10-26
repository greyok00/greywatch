"""Tool state machine — GREEN/YELLOW/RED semantics (G2.5).

- GREEN: unit running (or not unit-managed) AND log readable.
- YELLOW: log missing/unreadable but unit still fine (or timer idle).
- RED: unit reported failed/inactive when the registry says it must run.
Unit truth comes from an injectable checker (systemctl in prod, stub in tests) —
never parsed from the daemon's own guesses.
"""
from __future__ import annotations

import json
import os

GREEN, YELLOW, RED, OFF = "GREEN", "YELLOW", "RED", "OFF"
UNKNOWN = "UNKNOWN"      # the probe could not answer — never guess
NO_UNIT = "no-unit"      # = NOT INSTALLED (the unit never existed)

_RANK = {GREEN: 0, UNKNOWN: 1, YELLOW: 1, RED: 2}


def worst_from(states, rank=_RANK):
    """Worst of an iterable of state strings (inverse rank)."""
    return max(states, key=lambda s: rank.get(s, 2))

# states the injectable checker may report for a unit
ACTIVE, INACTIVE, FAILED, NO_UNIT, UNKNOWN_UNIT = \
    "active", "inactive", "failed", "no-unit", "unknown"


def classify(unit_state: str, log_state: str,
             expects_unit: bool, needs_log: bool) -> str:
    """Owner semantics 2026-10-23:
    installed + running = GREEN; installed + not running = RED;
    not installed = YELLOW (the app's words, spelled out in the UI)."""
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
    """exists+readable → 'ok'; exists but unreadable → 'unreadable';
    missing → 'missing'; special journal refs → 'ok' (checked by collector)."""
    if str(path).startswith("journal:"):
        return "ok"
    try:
        if not os.path.exists(path):
            return "missing"
        with open(path, "rb"):
            return "ok"
        # a 1-byte probe read is enough; existence + open covers perms
    except (OSError, PermissionError):
        return "unreadable"


def snapshot(registry: list, unit_checker) -> dict:
    """Build the status.json `tools` section.

    unit_checker(tool_dict) -> unit_state string ("" when none expected).
    Tools with a unit get the unit truth; log-only tools classify on logs;
    state_only tools classify on unit alone.
    """
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
    """ATOMIC write via tmp rename — status.json must never be torn.
    0644 explicit: the CLI/GUI read this snapshot as the grey user, and the
    daemon unit runs UMask=0077 (tranche 1a) — an umask-open() here would
    land the file root-only and every reader would see 'not written yet'
    while the daemon was healthy (found by the 2026-10-24 battery)."""
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