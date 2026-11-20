"""Research-wave doctor pin: a tripped supervisor breaker surfaces in
the service lane row (DEGRADED, named), read from the daemon's own
components block - the one source of truth. Honesty contract: a tripped
breaker is a lane that stopped restarting on its own; the owner sees it,
the vocabulary stays in the doctor's verdict set.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import doctor  # noqa: E402


def _write_status(tmp_path, components):
    (tmp_path / "status.json").write_text(
        json.dumps({"updated": "2026-11-12T06:00:00+00:00",
                    "components": components}))
    import os
    os.chmod(tmp_path / "status.json", 0o600)


def test_tripped_breaker_degrades_the_service_row(tmp_path, monkeypatch):
    _write_status(tmp_path, {"tail:appfw-watcher": {
        "state": "tripped", "restarts": 3}})
    # the unit reads active (the daemon itself is fine); the snapshot is
    # fresh; the row must still name the tripped lane and go DEGRADED
    import subprocess as sp
    fake = sp.CompletedProcess([], 0, "active\n", "")
    monkeypatch.setattr(doctor, "_probe",
                        lambda argv: fake if "is-active" in argv else
                        sp.CompletedProcess([], 0, "", ""))
    row = doctor.row_service(tmp_path)
    assert row["verdict"] == "DEGRADED"
    assert "tripped" in row["text"] and "tail:appfw-watcher" in row["text"]


def test_components_without_trips_stay_ready(tmp_path, monkeypatch):
    _write_status(tmp_path, {"tail:appfw-watcher": {
        "state": "active", "restarts": 0}})
    import subprocess as sp
    fake = sp.CompletedProcess([], 0, "active\n", "")
    monkeypatch.setattr(doctor, "_probe",
                        lambda argv: fake if "is-active" in argv else
                        sp.CompletedProcess([], 0, "", ""))
    # fresh snapshot: doctor.row_service stats the mtime; age must be ~0
    import os
    os.utime(tmp_path / "status.json")
    row = doctor.row_service(tmp_path)
    assert row["verdict"] == "READY", row


def test_unreadable_status_never_boots_the_row_to_degraded(tmp_path,
                                                           monkeypatch):
    # no status.json at all: the tripped scan must not fabricate a trip
    import subprocess as sp
    fake = sp.CompletedProcess([], 0, "active\n", "")
    monkeypatch.setattr(doctor, "_probe",
                        lambda argv: fake if "is-active" in argv else
                        sp.CompletedProcess([], 0, "", ""))
    (tmp_path / "status.json").write_text("{}")
    import os
    os.utime(tmp_path / "status.json")
    row = doctor.row_service(tmp_path)
    assert row["verdict"] == "READY", row
