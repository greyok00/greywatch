# hardening/controls.py — generic loader for hardening-controls.json.
# stdlib only. Missing/invalid file yields an empty list, never an import
# error: the controls file ships with deployments, not with this package.
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

_REQUIRED = ("id", "group", "what", "severity")
_LIST_KEYS = ("nist", "cis")

# W4's latent minor, closed: the loader validates control.action against
# this known set. `action` names the special verb a card offers the owner
# (today only install-prompt — a package install is owner-clicked, never
# silent); anything else is decorative-knob class and falls back to None
# instead of loading as an unrecongized verb callers would KeyError on.
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
    # ---- master-prompt (Setup Wizard) schema fields. All optional and
    # tolerant: older/leaner controls files simply leave them out and the
    # loader fills the neutral defaults below. `default` is normalized to
    # bool or the literal "FLAG-ONLY" (_norm_default); `condition` to
    # "always", "fresh-install", or "not-installed:<pkg>"
    # (_norm_condition) — unrecognized spellings fail closed.
    # NOTE for W-baseline: branch on default only via
    # `default is True`, `default is False`, `default == "FLAG-ONLY"`.
    family: str | None = None
    nist_family: str | None = None
    cis_ref: str | None = None
    break_risk: str | None = None
    default: object = False
    persist: bool = False
    condition: str = "always"
    # Optional wizard verb tag: when present it names the special action a
    # card for this control should offer the owner — e.g. "install-prompt"
    # for the ClamAV control (the package must be installed by the owner's
    # hand, never silently). Tolerant: absent -> None; a non-string value
    # is ignored (None), never turned into a verb we cannot execute.
    action: str | None = None


def _norm_default(value):
    """Normalize the wizard's `default` to True, False, or "FLAG-ONLY".

    Case-insensitive on the sentinel ("flag-only"/"FLAG_ONLY" all count),
    so a typo can never load as a third unrecognized state that callers
    branch on unpredictably. Unknown non-bool strings fail closed to
    False (never silently on).
    """
    if value is True or value is False:
        return bool(value)
    if isinstance(value, str) and value.strip().upper().replace("_", "-") \
            == "FLAG-ONLY":
        return "FLAG-ONLY"
    if isinstance(value, str) and value.strip().lower() == "true":
        return True
    return False


def _norm_action(value):
    """Normalize `action` to a KNOWN_CONTROL_ACTIONS member or None.

    NOTE (W4 deferred minor closed here): a hand-edited or unrecognized
    action used to load verbatim and could KeyError later on an
    unvalidated verb; now only a recognized action loads — anything
    else (missing, non-string, empty, unknown spelling) falls back to
    None with this note as the breadcrumb."""
    if not isinstance(value, str):
        return None
    normed = value.strip().lower()
    return normed if normed in KNOWN_CONTROL_ACTIONS else None


def _norm_condition(value):
    """Normalize `condition`: None/empty -> "always"; unrecognized
    spellings fail closed to "always" rather than becoming a variant the
    caller cannot match."""
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
    """Load hardening-controls.json from `base_dir`.

    Returns [] when the file is absent, unreadable, or fails schema checks.
    Fix-grammar verbs (sh, unit-install, sysctl-set, service-off,
    pkg-upgrade) are validated structurally only; execution is elsewhere.
    """
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
