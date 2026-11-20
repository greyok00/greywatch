"""threatscale: levels as validated data (plan Task 1, LAW-1).

The scale file is DATA the daemon enforces with deterministic code.
load_scale() must never trust a malformed file: it returns the built-in
default and records why, so a broken scale can never arm a change.
"""
from __future__ import annotations

import json

import pytest

import threatscale


def _write(tmp_path, doc: object) -> None:
    (tmp_path / "threatscale.json").write_text(json.dumps(doc))


def test_valid_scale_loads_with_levels_and_lane(tmp_path):
    _write(tmp_path, {"levels": {"L1": 0, "L2": 20, "L3": 55, "L4": 80},
                      "popup_lane": "critical-only"})
    scale, reason = threatscale.load_scale(tmp_path)
    assert reason is None
    assert scale["levels"] == {"L1": 0, "L2": 20, "L3": 55, "L4": 80}
    assert scale["popup_lane"] == "critical-only"


def test_missing_file_yields_builtin_default_and_says_so(tmp_path):
    scale, reason = threatscale.load_scale(tmp_path)
    assert scale == threatscale.DEFAULT_SCALE
    assert reason and "absent" in reason.lower()


def test_missing_threshold_key_rejected(tmp_path):
    _write(tmp_path, {"levels": {"L1": 0, "L2": 20, "L3": 55},   # L4 gone
                      "popup_lane": "critical-only"})
    scale, reason = threatscale.load_scale(tmp_path)
    assert scale == threatscale.DEFAULT_SCALE
    assert reason and "L4" in reason


def test_non_monotonic_thresholds_rejected(tmp_path):
    _write(tmp_path, {"levels": {"L1": 10, "L2": 20, "L3": 55, "L4": 40},
                      "popup_lane": "critical-only"})
    scale, reason = threatscale.load_scale(tmp_path)
    assert scale == threatscale.DEFAULT_SCALE
    assert reason and "monotonic" in reason


def test_unknown_popup_lane_rejected(tmp_path):
    _write(tmp_path, {"levels": {"L1": 0, "L2": 20, "L3": 55, "L4": 80},
                      "popup_lane": "show-everything-loud"})
    scale, reason = threatscale.load_scale(tmp_path)
    assert scale == threatscale.DEFAULT_SCALE
    assert reason and "popup_lane" in reason


def test_invalid_json_rejected(tmp_path):
    (tmp_path / "threatscale.json").write_text("{levels: not json")
    scale, reason = threatscale.load_scale(tmp_path)
    assert scale == threatscale.DEFAULT_SCALE
    assert reason and "parse" in reason


def test_levels_must_be_ints(tmp_path):
    _write(tmp_path, {"levels": {"L1": 0, "L2": "twenty", "L3": 55, "L4": 80},
                      "popup_lane": "critical-only"})
    scale, reason = threatscale.load_scale(tmp_path)
    assert scale == threatscale.DEFAULT_SCALE
    assert reason and "int" in reason


def test_level_boundaries_l1_to_l4():
    scale, _ = threatscale.load_scale(None)   # no config: defaults 0/20/55/80
    lv = threatscale.level_for
    assert lv(0, scale) == "L1"
    assert lv(19, scale) == "L1"
    assert lv(20, scale) == "L2"
    assert lv(54, scale) == "L2"
    assert lv(55, scale) == "L3"
    assert lv(79, scale) == "L3"
    assert lv(80, scale) == "L4"
    assert lv(100, scale) == "L4"


def test_surfaces_map_lane_names():
    s = threatscale.SURFACES
    assert s["L1"] == "silent-allow"
    assert s["L2"] == "grouped-row"
    assert s["L3"] == "card"
    assert s["L4"] == "critical-card"


def test_level_for_never_crashes_on_out_of_range_scores():
    scale, _ = threatscale.load_scale(None)
    assert threatscale.level_for(-5, scale) == "L1"
