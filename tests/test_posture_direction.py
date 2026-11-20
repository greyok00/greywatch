"""The posture score's one direction law (caught live 2026-11-15).

The CVE input measures EXPOSURE: more open rows, higher value, worse
machine. The score reads higher-is-better. So the exposure must
contribute inverted - 100 minus exposure - or a fully exposed machine
scores the combined ring toward perfect (seen live: 220 open rows of
220 cached read cve_exposure=100 and a root run would have ridden that
to a near-perfect score).

Three inputs must survive the withhold law for a score at all, so the
tests pin lynis readable and let apparmor stay unreadable.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from core import posture


@pytest.fixture(autouse=True)
def _readable_lynis(monkeypatch):
    monkeypatch.setattr(
        posture, "_lynis_index",
        lambda: (100, "test: pinned lynis index"))


def _dir(base: pathlib.Path, rows: list) -> pathlib.Path:
    d = base / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "cve-cache.json").write_text(
        json.dumps({"suite": "trixie", "installed_count": 900,
                    "entries": [
                        {"id": i, "severity": s, "package": p,
                         "installed": ins, "fixed": fix}
                        for i, s, p, ins, fix in rows]}))
    return d


_BASE = [("a", "l", "ENABLED", "f")]
_FULL = [("c1", "HIGH", "pkg1", "1.0", "2.0"),
         ("c2", "HIGH", "pkg2", "1.0", "2.0")]   # two open HIGH rows
_MANY = [(f"c{i}", "HIGH", f"pkg{i}", "1.0", "2.0")
         for i in range(200)]


def _patched_dir(base: pathlib.Path) -> pathlib.Path:
    d = _dir(base, _MANY)
    (d / "cve-patched.jsonl").write_text("".join(
        json.dumps({"package": f"pkg{i}", "to": "2.0"}) + "\n"
        for i in range(200)))
    return d


def test_open_cve_rows_drop_the_score_not_lift_it(tmp_path):
    full = posture.compute(baseline_rows=_BASE,
                           data_dir=_dir(tmp_path / "a", _MANY))
    clean = posture.compute(baseline_rows=_BASE,
                            data_dir=_patched_dir(tmp_path / "b"))
    assert full["score"] is not None and clean["score"] is not None
    assert clean["inputs"]["cve_exposure"]["value"] == 0
    assert full["inputs"]["cve_exposure"]["value"] > 0
    assert clean["score"] >= full["score"], \
        "an open-CVE machine must not outscore a patched one"


def test_cve_input_keeps_exposure_as_its_value_and_says_direction(
        tmp_path):
    rep = posture.compute(baseline_rows=_BASE, data_dir=_dir(tmp_path, _FULL))
    cve = rep["inputs"]["cve_exposure"]
    # two open packages of 900 installed -> 0 on the integer scale
    assert cve["value"] == 0
    assert cve["direction"] == "lower-is-better"
    base = rep["inputs"]["baseline_pass"]
    assert base["direction"] == "higher-is-better"


def test_score_math_renormalizes_over_the_readable_three(tmp_path):
    rep = posture.compute(baseline_rows=_BASE, data_dir=_dir(tmp_path, _FULL))
    # readable: lynis 100 (w .35), baseline 100 (w .30), cve exposure 0
    expect = round((0.35 * 100 + 0.30 * 100
                    + 0.20 * 100) / 0.85)
    assert rep["score"] == expect
    assert rep["renormalized_over"] == ["baseline_pass", "cve_exposure",
                                        "lynis_hardening"]
    # withheld law untouched: apparmor unreadable here, so three of four
    # stay readable and the score stands; starve one and it withholds
    empty = tmp_path / "c" / "state"
    empty.mkdir(parents=True, exist_ok=True)
    lone = posture.compute(baseline_rows=None, data_dir=empty)
    assert lone["score"] is None
    assert "apparmor_exposure" in lone["unknown_inputs"]


def test_should_replace_keeps_the_wider_report_on_file():
    # Live 2026-11-16: the desktop user's regular refresh clobbered the
    # root-built report (Lynis and AppArmor had fed it), and the Security
    # Center then read the narrow numbers back. The file keeps inputs
    # only a root read could see; an equal or wider run still replaces.
    from core.posture import should_replace
    root_wide = {"unknown_inputs": []}
    grey_narrow = {"unknown_inputs": ["lynis_hardening",
                                      "apparmor_exposure"]}
    grey_wider_than_this = {"unknown_inputs": ["lynis_hardening"]}
    assert not should_replace(root_wide, grey_narrow)
    assert should_replace(None, grey_narrow)          # first write wins
    assert should_replace(grey_wider_than_this, root_wide)
    assert should_replace(grey_wider_than_this, grey_wider_than_this)
