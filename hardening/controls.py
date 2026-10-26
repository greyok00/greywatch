from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

_REQUIRED = ("id", "group", "what", "severity")
_LIST_KEYS = ("nist", "cis")

KNOWN_CONTROL_ACTIONS = frozenset({"install-prompt"})


@dataclass
class Control:
    id: str
    group: str
    what: str
    baseline: str = ""
    probe: str = ""
    fix: list = field(default_factory=list)
    nist: list[str] = field(default_factory=list)
    cis: list[str] = field(default_factory=list)
    severity: str = "LOW"
    probe_invert: bool = False
    advisory: bool = False
    family: str | None = None
    nist_family: str | None = None
    cis_ref: str | None = None
    break_risk: str | None = None
    default: object = False
    persist: bool = False
    condition: str = "always"
    action: str | None = None


def _norm_default(value):
    if value is True or value is False:
        return bool(value)
    if isinstance(value, str) and value.strip().upper().replace("_", "-") \
            == "FLAG-ONLY":
        return "FLAG-ONLY"
    if isinstance(value, str) and value.strip().lower() == "true":
        return True
    return False


def _norm_action(value):
    if not isinstance(value, str):
        return None
    normed = value.strip().lower()
    return normed if normed in KNOWN_CONTROL_ACTIONS else None


def _norm_condition(value):
    if value is None:
        return "always"
    text = str(value).strip()
    if not text or text.lower() == "always":
        return "always"
    if text.lower().replace("_", "-") == "fresh-install":
        return "fresh-install"
    if text.lower().startswith("not-installed:"):
        return "not-installed:" + text.split(":", 1)[1].strip()
    return "always"


def load_controls(base_dir: pathlib.Path) -> list[Control]:
    path = pathlib.Path(base_dir) / "hardening-controls.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    entries = raw.get("controls", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        return []
    out: list[Control] = []
    for e in entries:
        if not isinstance(e, dict) or not all(k in e for k in _REQUIRED):
            continue
        out.append(Control(
            id=e["id"], group=e["group"], what=e["what"],
            baseline=e.get("baseline", ""), probe=e.get("probe", ""),
            fix=e.get("fix", []),
            nist=list(e.get("nist") or []), cis=list(e.get("cis") or []),
            severity=e["severity"],
            probe_invert=bool(e.get("probe_invert", False)),
            advisory=bool(e.get("advisory", False)),
            family=e.get("family"),
            nist_family=e.get("nist_family"),
            cis_ref=e.get("cis_ref"),
            break_risk=e.get("break_risk"),
            default=_norm_default(e.get("default", False)),
            persist=bool(e.get("persist", False)),
            condition=_norm_condition(e.get("condition")),
            action=(_norm_action(e.get("action"))),
        ))
    return out
