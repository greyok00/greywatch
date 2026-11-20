"""Package-aware CVE matching: installed version vs the suite fix."""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import cve_data

if cve_data.version_compare("1", "2") is None:
    pytest.skip("no Debian version comparator on this host",
                allow_module_level=True)


def _tracker():
    return {"openssl": {
        "CVE-2026-0001": {
            "description": "still open",
            "releases": {"trixie": {
                "status": "resolved",
                "repositories": {"trixie": "3.0-1"},
                "fixed_version": "0", "urgency": "high"}},
        },
        "CVE-2026-0002": {
            "description": "already fixed",
            "releases": {"trixie": {
                "status": "resolved",
                "repositories": {"trixie": "1.0-1"},
                "fixed_version": "0", "urgency": "low"}},
        },
        "CVE-2026-0003": {
            "description": "no fixed version yet",
            "releases": {"trixie": {"status": "open",
                                    "urgency": "medium"}},
        },
    }}


def test_open_rows_only_below_the_fixed_version():
    rows = cve_data.open_rows(
        _tracker(), {"libssl3": {"version": "1.0-1", "source": "openssl"}},
        "trixie")
    ids = {row["id"] for row in rows}
    assert "CVE-2026-0001" in ids
    assert "CVE-2026-0002" not in ids      # installed equals the fix
    assert "CVE-2026-0003" in ids          # no fix, still open
    row = [r for r in rows if r["id"] == "CVE-2026-0001"][0]
    assert row["package"] == "libssl3"
    assert row["fixed"] == "3.0-1"
    assert row["severity"] == "HIGH"
    assert row["tool"] == "openssl"


def test_another_suite_has_no_rows():
    rows = cve_data.open_rows(
        _tracker(), {"libssl3": {"version": "1.0-1", "source": "openssl"}},
        "bookworm")
    assert rows == []


def test_installed_packages_unwraps_the_source_field():
    got = cve_data.installed_packages("pkg\t1.0\tsrc (2.0)\nplain\t2.0\t\n")
    assert got["pkg"] == {"version": "1.0", "source": "src"}
    assert got["plain"] == {"version": "2.0", "source": "plain"}


def _cve_refresh():
    import importlib.util
    root = pathlib.Path(__file__).resolve().parents[1]
    path = root / "cve-refresh.py"
    spec = importlib.util.spec_from_file_location("cve_refresh_plan", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_cache_records_the_true_total_and_the_cap():
    mod = _cve_refresh()
    rows = [{"package": f"p{i}"} for i in range(7)]
    doc = mod.cap_entries(rows, limit=5)
    assert doc["total_entries"] == 7
    assert doc["capped"] is True
    assert len(doc["entries"]) == 5


def test_exposure_text_names_packages_without_a_parenthetical(tmp_path):
    from core import posture
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 100,
        "entries": [{"package": "openssl", "id": "CVE-1",
                     "severity": "HIGH", "installed": "1",
                     "fixed": "2"}]}))
    _value, how = posture._cve_exposure(tmp_path)
    assert "package(s)" not in how
    assert "1" in how and "100" in how


def test_a_partial_patch_still_writes_the_ledger(tmp_path, monkeypatch):
    import argparse

    import cli
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "cve-cache.json").write_text(json.dumps({"entries": [
        {"package": "openssl", "id": "CVE-2026-1"},
        {"package": "libc6", "id": "CVE-2026-2"},
    ]}))
    versions = {"openssl": "1", "libc6": "1"}

    def installed(_text=None):
        return {p: {"version": v} for p, v in versions.items()}

    def helper(_name, _args, timeout=0, **_kw):
        versions["openssl"] = "2"   # one package moved before the run failed
        return 1

    monkeypatch.setattr(cve_data, "installed_packages", installed)
    monkeypatch.setattr(cli, "helper_exec", helper)
    rc = cli.cmd_patch(argparse.Namespace(
        packages=[], all=False, affected=True, json=False))
    assert rc == cli.EXIT_ERR
    rows = [json.loads(line) for line in
            (tmp_path / "cve-patched.jsonl").read_text().splitlines()]
    assert [(r["package"], r["from"], r["to"], r["rc"]) for r in rows] == [
        ("openssl", "1", "2", 1)]
