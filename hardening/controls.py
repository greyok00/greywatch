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


_UNIT_INSTALL_TARGET = "/etc/systemd/system/greywatch.service"
_UNIT_TEXT_PATH = (pathlib.Path(__file__).resolve().parents[1] / "doc"
                   / "greywatch.service")


def _unit_text() -> str:
    """The shipped hardened unit file, rendered for this installation —
    __GW_LIB__ goes to the program tree and __GW_DATA__ to the runtime
    state dir, exactly as install.sh fills them. Unreadable or
    unresolvable file: return the unresolved marker, so the plan skips
    the step honestly instead of guessing."""
    try:
        text = _UNIT_TEXT_PATH.read_text(encoding="utf-8")
    except OSError:
        return "TRANCHE"
    data = None
    try:
        from gwpaths import data_dir as _gw_data, ui_user as _ui_user
        data = str(_gw_data())
        user = _ui_user()
    except ImportError:
        pass
    if data is None or user is None:
        return "TRANCHE"
    return text.replace("__GW_LIB__", str(_UNIT_TEXT_PATH.parents[1])) \
               .replace("__GW_DATA__", data) \
               .replace("__GW_UI_USER__", user)


def _resolve_templates(entry: dict) -> dict:
    """Substitute the two shipped placeholders so probes and the apply
    plan never see them: {{unit}} is this app's own systemd unit, and
    the unit-install text slot marked TRANCHE carries the shipped unit
    file's content. Anything that still shows a template afterwards is
    treated as unresolvable by the apply pipeline (honest skip)."""
    entry["probe"] = str(entry.get("probe", "") or "").replace(
        "{{unit}}", "greywatch")
    steps = []
    for step in entry.get("fix", []) or []:
        if isinstance(step, list) and step and step[0] == "unit-install":
            step = list(step)
            if len(step) >= 2 and step[1] == "{{unit}}":
                step[1] = _UNIT_INSTALL_TARGET
            if len(step) >= 3 and step[2] == "TRANCHE":
                step[2] = _unit_text()
        steps.append(step)
    entry["fix"] = steps
    return entry


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
        e = _resolve_templates(e)
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
