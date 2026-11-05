"""Hunter state files — plain JSON under ``<data_dir>/hunter/``.

The window and the CLI read these files; only the hunter process writes
them. Same contract as the rest of the app: whole writes by rename
(``status.atomic_replace``), append-only JSONL for findings and defender
notes, and a trim that keeps only the newest lines.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import status

FINDINGS_KEEP = 2000
DEFENDER_KEEP = 500


def hunter_dir(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "hunter"


def _prepare(data_dir) -> pathlib.Path:
    d = hunter_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


def state_path(data_dir) -> pathlib.Path:
    return _prepare(data_dir) / "state.json"


def live_path(data_dir) -> pathlib.Path:
    return hunter_dir(data_dir) / "live.json"


def findings_path(data_dir) -> pathlib.Path:
    return hunter_dir(data_dir) / "findings.jsonl"


def defender_path(data_dir) -> pathlib.Path:
    return hunter_dir(data_dir) / "defender.jsonl"


def request_path(data_dir) -> pathlib.Path:
    return hunter_dir(data_dir) / "request.json"


def config_path(data_dir) -> pathlib.Path:
    return hunter_dir(data_dir) / "config.json"


def read_config(data_dir) -> dict:
    try:
        doc = json.loads(config_path(data_dir).read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def write_config(data_dir, cfg: dict) -> None:
    """The user-owned config.json (AI keys, read pointer, web-wave
    switches) written by atomic replace like every other state file -
    a plain write_text dies half-written under power loss or a race,
    and its keys with it."""
    try:
        config_path(data_dir).parent.mkdir(parents=True, exist_ok=True)
        status.atomic_replace(str(config_path(data_dir)),
                              json.dumps(cfg, separators=(",", ":")))
    except (OSError, ValueError):
        pass


def kept_extensions(data_dir) -> list[dict]:
    """Extensions the user chose to keep, as the ledger on file: a list
    of {"ext": <browser extension id>, "name": <label>}. The hunter's
    own directory name for an installed extension is its id, so the key
    survives version updates."""
    rows = read_config(data_dir).get("kept_extensions")
    if not isinstance(rows, list):
        return []
    out = []
    for row in rows:
        if isinstance(row, dict) and str(row.get("ext") or "").strip():
            out.append({"ext": str(row["ext"]),
                        "name": str(row.get("name") or "")})
    return out


def kept_extension_ids(data_dir) -> set[str]:
    return {row["ext"] for row in kept_extensions(data_dir)}


def keep_extension(data_dir, ext_id: str, name: str = "") -> list[dict]:
    """Record that an extension stays: idempotent, and every other
    config key rides through untouched."""
    ext_id = str(ext_id)
    rows = kept_extensions(data_dir)
    for row in rows:
        if row["ext"] == ext_id:
            if name and name != row["name"]:
                row["name"] = name
                write_config(data_dir, {**read_config(data_dir),
                                        "kept_extensions": rows})
            return rows
    rows.append({"ext": ext_id, "name": str(name or ext_id)})
    write_config(data_dir, {**read_config(data_dir), "kept_extensions": rows})
    return kept_extensions(data_dir)


def unkeep_extension(data_dir, ext_id: str) -> list[dict]:
    rows = [row for row in kept_extensions(data_dir)
            if row["ext"] != str(ext_id)]
    write_config(data_dir, {**read_config(data_dir), "kept_extensions": rows})
    return rows


def quieted_findings(data_dir) -> list[dict]:
    """Findings the user dismissed, as the ledger on file: a list of
    {"id": <finding id>, "rule": <rule>, "label": <title fragment>}.
    The finding id IS the dedup key (rule + subject), so an unchanged
    subject re-raises onto the same id and never re-appends; a changed
    subject is a new id and still alerts."""
    rows = read_config(data_dir).get("quieted_findings")
    if not isinstance(rows, list):
        return []
    out = []
    for row in rows:
        if isinstance(row, dict) and str(row.get("id") or "").strip():
            out.append({"id": str(row["id"]),
                        "rule": str(row.get("rule") or ""),
                        "label": str(row.get("label") or "")})
    return out


def quieted_ids(data_dir) -> set[str]:
    return {row["id"] for row in quieted_findings(data_dir)}


def quiet_finding(data_dir, f: dict) -> list[dict]:
    fid = str((f or {}).get("id") or "")
    if not fid:
        return quieted_findings(data_dir)
    rows = quieted_findings(data_dir)
    for row in rows:
        if row["id"] == fid:
            if row["label"] != str(f.get("title") or "")[:80]:
                row["label"] = str(f.get("title") or "")[:80]
                write_config(data_dir, {**read_config(data_dir),
                                        "quieted_findings": rows})
            return rows
    rows.append({"id": fid, "rule": str(f.get("rule") or ""),
                 "label": str(f.get("title") or "")[:80]})
    write_config(data_dir, {**read_config(data_dir), "quieted_findings": rows})
    return quieted_findings(data_dir)


def unquiet_finding(data_dir, fid: str) -> list[dict]:
    rows = [row for row in quieted_findings(data_dir)
            if row["id"] != str(fid)]
    write_config(data_dir, {**read_config(data_dir), "quieted_findings": rows})
    return rows


def inbox_dir(data_dir) -> pathlib.Path:
    d = _prepare(data_dir) / "inbox"
    d.mkdir(parents=True, exist_ok=True)
    return d


def processed_dir(data_dir) -> pathlib.Path:
    d = _prepare(data_dir) / "processed"
    d.mkdir(parents=True, exist_ok=True)
    return d


def read_state(data_dir) -> dict:
    try:
        doc = json.loads(state_path(data_dir).read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def write_state(data_dir, state: dict) -> None:
    try:
        status.atomic_replace(str(state_path(data_dir)),
                              json.dumps(state, separators=(",", ":")))
    except (OSError, ValueError):
        pass


def write_live(data_dir, doc: dict) -> None:
    try:
        status.atomic_replace(str(live_path(data_dir)),
                              json.dumps(doc, separators=(",", ":")))
    except (OSError, ValueError):
        pass


def read_live(data_dir) -> dict:
    try:
        doc = json.loads(live_path(data_dir).read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def append_jsonl(path: pathlib.Path, row: dict) -> bool:
    line = json.dumps(row, separators=(",", ":")) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        return False
    return True


def append_finding(data_dir, row: dict) -> bool:
    return append_jsonl(findings_path(data_dir), row)


def append_defender(data_dir, row: dict) -> bool:
    return append_jsonl(defender_path(data_dir), row)


def read_jsonl(path: pathlib.Path, limit: int = 100) -> list[dict]:
    try:
        lines = pathlib.Path(path).read_text(
            errors="replace").splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def read_findings(data_dir, limit: int = 100) -> list[dict]:
    return read_jsonl(findings_path(data_dir), limit)


def read_defender(data_dir, limit: int = 100) -> list[dict]:
    return read_jsonl(defender_path(data_dir), limit)


def _trim(path: pathlib.Path, keep: int) -> None:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return
    if len(lines) <= keep:
        return
    try:
        status.atomic_replace(str(path),
                              "".join(l + "\n" for l in lines[-keep:]))
    except (OSError, ValueError):
        pass


def trim(data_dir) -> None:
    """Explicit retention: findings keep 2000 rows, defender notes 500 —
    the hunter rewrites its own files, never the daemon's event store."""
    _trim(findings_path(data_dir), FINDINGS_KEEP)
    _trim(defender_path(data_dir), DEFENDER_KEEP)


def take_request(data_dir) -> bool:
    """Consume a 'hunt now' request. Presence is the whole message; the
    file's contents are never executed or trusted."""
    path = request_path(data_dir)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def dedup_key(rule: str, subject: str) -> str:
    blob = f"{rule}|{subject}".encode("utf-8", "replace")
    return hashlib.sha256(blob).hexdigest()[:16]