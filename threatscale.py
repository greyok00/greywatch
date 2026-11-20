"""threatscale — threat levels 1-4 as validated data (LAW-1).

The scale is DATA; enforcement is deterministic code. A malformed or
hostile scale file must never be able to arm a change: load_scale()
either returns a validated scale or the built-in default paired with a
reason that says exactly why. The design (§6.1) fixes the boundaries:
L1 silent-allow, L2 grouped-row, L3 card (never expires), L4 critical
card (never expires); popups are the L3/L4 cards, configurable.
"""
from __future__ import annotations

import json
import pathlib

# Design §6.1 defaults: only genuine L3/L4 reach a card; L4 also marks
# the lane where the popup card is styled critical.
DEFAULT_SCALE = {
    "levels": {"L1": 0, "L2": 20, "L3": 55, "L4": 80},
    "popup_lane": "cards",   # cards | critical-only | all
}

ALLOWED_LANES = ("cards", "critical-only", "all")
REQUIRED_LEVELS = ("L1", "L2", "L3", "L4")

# The lane each level surfaces through — the single map every later
# phase (CLI, GUI) reads instead of re-deciding what "L3" looks like.
SURFACES = {
    "L1": "silent-allow",
    "L2": "grouped-row",
    "L3": "card",
    "L4": "critical-card",
}


def load_scale(data_dir) -> tuple[dict, str | None]:
    """Validated scale from <data_dir>/threatscale.json, or the built-in
    default with a reason. Never raises for content problems: LAW-1 —
    a broken data file must refuse to arm, not crash the enforcer."""
    scale = dict(DEFAULT_SCALE)
    levels = dict(DEFAULT_SCALE["levels"])
    if data_dir is None:
        return scale, "scale file absent: built-in default in force"
    path = pathlib.Path(data_dir) / "threatscale.json"
    try:
        raw = path.read_text()
    except OSError:
        return scale, f"scale file absent ({path.name}): built-in default in force"
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        return scale, f"scale parse failed ({exc}): built-in default in force"
    if not isinstance(doc, dict):
        return scale, "scale parse failed (not an object): built-in default in force"
    levels_doc = doc.get("levels")
    if not isinstance(levels_doc, dict):
        return scale, "scale parse failed (levels not an object): built-in default in force"
    for name in REQUIRED_LEVELS:
        if name not in levels_doc:
            return scale, f"scale parse failed (missing {name}): built-in default in force"
        value = levels_doc[name]
        if not isinstance(value, int) or isinstance(value, bool):
            return scale, f"scale parse failed ({name} not int): built-in default in force"
        levels[name] = value
    ordered = [levels[name] for name in REQUIRED_LEVELS]
    if ordered != sorted(ordered):
        return scale, "scale parse failed (thresholds must be monotonic): built-in default in force"
    lane = doc.get("popup_lane", DEFAULT_SCALE["popup_lane"])
    if lane not in ALLOWED_LANES:
        return scale, (f"scale parse failed (popup_lane {lane!r} not one of "
                       f"{', '.join(ALLOWED_LANES)}): built-in default in force")
    scale["levels"], scale["popup_lane"] = levels, lane
    return scale, None


def level_for(score: int, scale: dict) -> str:
    """Deterministic banding: thresholds are minimums, L4 absorbs the top."""
    levels = scale.get("levels", DEFAULT_SCALE["levels"])
    for name in ("L4", "L3", "L2"):
        if score >= levels[name]:
            return name
    return "L1"
