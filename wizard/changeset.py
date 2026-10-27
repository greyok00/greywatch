from __future__ import annotations

import json
import os
import pathlib
import re

_SCHEMA_PATH = pathlib.Path(__file__).with_name("schema.json")


def _load_schema() -> dict:
    with open(_SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


_SCHEMA = _load_schema()

_FIELD_SCHEMA = _SCHEMA["fields"]
_CHANGE_SCHEMA = _FIELD_SCHEMA["changes"]["items"]["fields"]

CONTROL_ID_RE = re.compile(_CHANGE_SCHEMA["control_id"]["pattern"])
JOURNAL_ID_RE = re.compile(_FIELD_SCHEMA["journal_id"]["pattern"])
ACTIONS = frozenset(_CHANGE_SCHEMA["action"]["enum"])

ALLOWED_KEYS = frozenset(_SCHEMA["allowed_keys"])
CHANGE_ALLOWED_KEYS = frozenset(
    _SCHEMA["fields"]["changes"]["items"]["allowed_keys"])
_CHANGE_REQUIRED = frozenset(
    _SCHEMA["fields"]["changes"]["items"]["required"])
FRAG_PATH_RE = re.compile(_CHANGE_SCHEMA["backup_path"]["pattern"])

_PATH_CHARS = ("/", "\\")
_CONTROL_SHAPES = ("\n", "\r", "\t", " ")


def _control_id_errors(name: str, value) -> list[str]:
    if not isinstance(value, str) or isinstance(value, bool):
        return [f"{name}: expected a string, got {type(value).__name__}"]
    out: list[str] = []
    if any(ch in value for ch in _CONTROL_SHAPES):
        out.append(
            f"{name}: whitespace or control characters inside {name} are "
            f"rejected (smuggle shape: newline/tab/space payload)")
    if any(ch in value for ch in _PATH_CHARS) or value.startswith("."):
        out.append(
            f"{name}: path-like values are rejected {value!r} — ids are "
            f"labels, never file paths (smuggle shape: absolute/relative "
            f"path)")
    if not CONTROL_ID_RE.fullmatch(value):
        out.append(
            f"{name}: characters outside the allowed set "
            f"[A-Za-z0-9._-] are rejected {value!r} (smuggle shape: "
            f"metacharacter payload)")
    return out


def validate(changeset, controls: list) -> list[str]:
    errors: list[str] = []
    if not isinstance(changeset, dict):
        return ["changeset: expected a JSON object"]
    for key in changeset:
        if key not in ALLOWED_KEYS:
            errors.append(
                f"changeset: unknown key {key!r} — allowed keys: "
                f"{sorted(ALLOWED_KEYS)}")
    for key in sorted(ALLOWED_KEYS):
        if key not in changeset:
            errors.append(f"changeset: missing required key {key!r}")
    if errors:
        return errors

    version = changeset["version"]
    if not isinstance(version, int) or isinstance(version, bool):
        errors.append(
            f"changeset: version must be the integer 1, got {version!r}")
    elif version != _SCHEMA["version"]:
        errors.append(
            f"changeset: unsupported version {version!r} — only version 1 "
            f"is accepted")
    jid = changeset["journal_id"]
    jid_errors = _control_id_errors("journal_id", jid)
    errors.extend(jid_errors)
    if not jid_errors and isinstance(jid, str) \
            and not JOURNAL_ID_RE.fullmatch(jid):
        errors.append(
            f"journal_id: expected the form YYYYMMDD-HHMMSS (^[0-9]{8}-"
            f"[0-9]{6}$), got {jid!r}")

    changes = changeset["changes"]
    if not isinstance(changes, list):
        errors.append(
            f"changes: expected a list, got {type(changes).__name__}")
        return errors

    known_ids: set[str] = set()
    for ctrl in controls:
        cid = ctrl.get("id") if isinstance(ctrl, dict) \
            else getattr(ctrl, "id", None)
        if isinstance(cid, str):
            known_ids.add(cid)

    for index, change in enumerate(changes):
        if not isinstance(change, dict):
            errors.append(
                f"changes[{index}]: expected an object, got "
                f"{type(change).__name__}")
            continue
        for key in change:
            if key not in CHANGE_ALLOWED_KEYS:
                errors.append(
                    f"changes[{index}]: unknown key {key!r} — allowed "
                    f"keys: {sorted(CHANGE_ALLOWED_KEYS)}")
        for key in sorted(_CHANGE_REQUIRED):
            if key not in change:
                errors.append(f"changes[{index}]: missing required key {key!r}")
        if "control_id" in change:
            errors.extend(
                _err_prefix(f"changes[{index}]", "control_id",
                            _control_id_errors("control_id",
                                               change["control_id"])))
            cid = change["control_id"]
            if isinstance(cid, str) and cid not in known_ids:
                errors.append(
                    f"changes[{index}].control_id: {cid!r} is not in the "
                    f"loaded controls — unknown controls are rejected, "
                    f"never executed as anything")
        if "action" in change:
            action = change["action"]
            if not isinstance(action, str) or action not in ACTIONS:
                errors.append(
                    f"changes[{index}].action: {action!r} is not an "
                    f"executable action — must be one of "
                    f"{sorted(ACTIONS)}")
        if "backup_path" in change:
            errors.extend(
                _err_prefix(f"changes[{index}]", "backup_path",
                            _backup_path_errors(change["backup_path"])))
    seen_ids: set[str] = set()
    for index, change in enumerate(changes):
        cid = change.get("control_id") if isinstance(change, dict) else None
        if isinstance(cid, str):
            if cid in seen_ids:
                errors.append(
                    f"changes[{index}].control_id: duplicate {cid!r} in one "
                    f"changeset — one pass carries at most one change per "
                    f"control (smuggle shape: apply-then-rollback same-id "
                    f"pair)")
            seen_ids.add(cid)
    return errors


def _backup_path_errors(value) -> list[str]:
    if not isinstance(value, str) or isinstance(value, bool):
        return [f"backup_path: expected a string, got "
                f"{type(value).__name__}"]
    out: list[str] = []
    segments = value.replace("\\", "/").split("/")
    if ".." in segments:
        out.append(
            f"backup_path: '..' segments are rejected {value!r} "
            f"(smuggle shape: path traversal)")
    if any(ch in value for ch in _CONTROL_SHAPES):
        out.append(
            f"backup_path: whitespace inside backup_path is rejected "
            f"{value!r} (smuggle shape: newline/tab/space payload)")
    if not FRAG_PATH_RE.fullmatch(value):
        out.append(
            f"backup_path: {value!r} is outside the per-pass fragment "
            f"layout — expected data/harden/journal/<journal_id>/"
            f"<name>.json (or an absolute path ending in .../harden/"
            f"journal/<journal_id>/<name>.json); unrelated absolute "
            f"paths are refused (smuggle shape: out-of-scope path)")
    if value.startswith("/") and FRAG_PATH_RE.fullmatch(value):
        real = os.path.realpath(value)
        if not real.startswith("/") or not FRAG_PATH_RE.fullmatch(real):
            out.append(
                f"backup_path: {value!r} resolves (symlink) outside the "
                f"per-pass fragment layout {real!r} (smuggle shape: "
                f"symlinked path)")
    return out


def _err_prefix(index: str, field: str, errs: list[str]) -> list[str]:
    return [e.replace(f"{field}:", f"{index}.{field}:", 1) for e in errs]


def build(journal_id: str, applied_cards: list) -> dict:
    changes = []
    for card in applied_cards:
        if isinstance(card, dict):
            cid = card.get("control_id") or card.get("id")
            bp = card.get("backup_path")
        else:
            cid = getattr(card, "control_id", None) or getattr(card, "id", None)
            bp = getattr(card, "backup_path", None)
        action = card.get("action", "apply") if isinstance(card, dict) \
            else getattr(card, "action", "apply")
        if not isinstance(cid, str) or not cid:
            raise ValueError(f"card without a control_id: {card!r}")
        changes.append({
            "control_id": cid, "action": action,
            "backup_path": bp if isinstance(bp, str) and bp else
            "data/harden/journal/%s/%s.json" % (journal_id, cid)})
    return {"version": _SCHEMA["version"], "journal_id": journal_id,
            "changes": changes}


def write_document(changeset, controls, path) -> list[str]:
    errors = validate(changeset, controls)
    if errors:
        return errors
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(changeset, sort_keys=True) + "\n")
    return []
