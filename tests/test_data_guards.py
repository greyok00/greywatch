"""A test run cannot touch the live state or the live quarantine ledger.

Root cause (2026-11-13 audit): tests ran the quarantine helpers with the
scripts' hardcoded /var/lib default, and 580 rows of pytest scratch
paths were written into the production ledger on 2026-10-27.
"""
import json
import os
import pathlib
import subprocess

import pytest

import gwpaths
import quarantine as Q


def test_explicit_override_still_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    assert gwpaths.data_dir() == tmp_path


def _rows(*items):
    return [json.loads(i) for i in items]


def test_live_rows_hide_closed_paths():
    rows = _rows(
        '{"orig":"/a/x","file":"/q/x.1","ts":"2026-01-01"}',
        '{"orig":"/a/y","file":"/q/y.1","ts":"2026-01-01"}',
        '{"orig":"/a/x","action":"deleted","ts":"2026-01-02"}',
        '{"orig":"/a/z","file":"/q/z.1","ts":"2026-01-03"}')
    live = Q.live_rows(rows)
    assert [r["orig"] for r in live] == ["/a/y", "/a/z"]


def test_prune_expires_test_artifacts_and_missing_copies():
    rows = _rows(
        '{"orig":"/tmp/pytest-of-grey/pytest-1/x","file":"/q/x.quar",'
        ' "ts":"2026-01-01"}',
        '{"orig":"/home/grey/Docs.zip","file":"/q/d.quar",'
        ' "ts":"2026-01-01"}',
        '{"orig":"/home/grey/keep.txt","file":"/q/k.quar",'
        ' "ts":"2026-01-01"}')
    markers = Q.prune_markers(
        rows, exist=lambda p: p == "/q/k.quar", stale_days=9999)
    reasons = {m["orig"]: m["reason"] for m in markers}
    assert reasons["/tmp/pytest-of-grey/pytest-1/x"] == "test artifact"
    assert reasons["/home/grey/Docs.zip"] == "copy gone"
    assert "/home/grey/keep.txt" not in reasons


def test_cli_prune_dry_run_writes_nothing(monkeypatch, tmp_path, capsys):
    import cli
    ledger = tmp_path / "quarantine.jsonl"
    line = json.dumps({"orig": "/tmp/pytest-of-grey/pytest-1/x",
                       "file": str(tmp_path / "gone.quar"),
                       "ts": "2026-01-01"})
    ledger.write_text(line + "\n")
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    rc = cli.main(["quarantine", "prune", "--dry-run"])
    assert rc == 0
    assert ledger.read_text() == line + "\n"       # unchanged
    assert "would expire 1" in capsys.readouterr().out


def test_helper_refuses_the_live_ledger_from_a_test_run(monkeypatch):
    monkeypatch.delenv("GW_QUAR_MANIFEST", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "test")
    r = subprocess.run(["bash", "apply/delete-quarantine.sh", "/tmp/x"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 78, r.stderr
    assert "refusing" in r.stderr


def test_helper_manifest_default_follows_the_data_dir(tmp_path):
    qdir = tmp_path / "quarantine"
    qdir.mkdir()
    copy = qdir / "x.quar"
    copy.write_text("payload")
    ledger = tmp_path / "quarantine.jsonl"
    ledger.write_text(json.dumps({"orig": "/tmp/dead/x", "file": str(copy),
                                  "ts": "2026-01-01"}) + "\n")
    env = dict(os.environ, GREYWATCH_DATA_DIR=str(tmp_path))
    env.pop("GW_QUAR_MANIFEST", None)
    env.pop("PYTEST_CURRENT_TEST", None)
    r = subprocess.run(
        ["bash", "apply/delete-quarantine.sh", "/tmp/dead/x"],
        capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    assert not copy.exists()
    assert json.loads(ledger.read_text().splitlines()[-1])["action"] == \
        "deleted"
