"""GW-D1 (cannot-fail Wave D): the doctor's machine-readable verdict.

--machine (doctor(machine=True)) prints a final "DOCTOR <n_red>
<n_yellow>" line and returns 0 with no RED, 3 with any RED. The CLI
passthrough (cmd_doctor) keeps today's behavior: exit 0 and no DOCTOR
line, so scripts and runbooks keep working.
"""
import pathlib
import sys
from argparse import Namespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import doctor as doctor_mod  # noqa: E402


def _registry_stub():
    return [{"name": "clamav", "unit": "clam-scan.timer", "logs": ()}]


def _patch_hunter(monkeypatch, verdict="READY"):
    monkeypatch.setattr(doctor_mod, "hunter_service_row",
                        lambda fix=False:
                        {"name": "hunter.service", "verdict": verdict,
                         "stamp": "ok", "actions": []})


def _broken_before(monkeypatch):
    monkeypatch.setattr(
        doctor_mod.setup_mod, "probe_tool",
        lambda spec: {"verdict": "BROKEN", "remediation": ["x"]})


def _ready_before(monkeypatch):
    monkeypatch.setattr(
        doctor_mod.setup_mod, "probe_tool",
        lambda spec: {"verdict": "READY", "remediation": []})


def _ready_lanes(monkeypatch):
    monkeypatch.setattr(doctor_mod, "health_snapshot", lambda dd: [
        {"lane": "service", "verdict": "READY", "text": "ok", "ts": "t"},
        {"lane": "scan", "verdict": "READY", "text": "ok", "ts": "t"},
        {"lane": "firewall", "verdict": "NEUTRAL", "text": "ok",
         "ts": "t"},
        {"lane": "backlog", "verdict": "READY", "text": "ok", "ts": "t"}])


@pytest.fixture(autouse=True)
def stub_system(monkeypatch):
    """No probe touches the real units in these tests."""
    monkeypatch.setattr(doctor_mod, "_registry", _registry_stub)


def test_doctor_machine_is_exit_coded_on_a_broken_tool(
        monkeypatch, capsys):
    _ready_lanes(monkeypatch)
    _patch_hunter(monkeypatch)
    _broken_before(monkeypatch)
    rc = doctor_mod.doctor(fix=False, machine=True)
    out = capsys.readouterr().out
    assert rc == 3
    assert "DOCTOR 1 0" in out


def test_doctor_machine_is_zero_when_everything_reads_ready(
        monkeypatch, capsys):
    _ready_lanes(monkeypatch)
    _patch_hunter(monkeypatch)
    _ready_before(monkeypatch)
    rc = doctor_mod.doctor(fix=False, machine=True)
    out = capsys.readouterr().out
    assert rc == 0
    assert "DOCTOR 0 0" in out


def test_doctor_machine_counts_a_broken_service_lane(
        monkeypatch, capsys):
    _ready_before(monkeypatch)
    _patch_hunter(monkeypatch)
    monkeypatch.setattr(doctor_mod, "health_snapshot", lambda dd: [
        {"lane": "service", "verdict": "BROKEN", "text": "unit inactive",
         "ts": "t"},
        {"lane": "scan", "verdict": "DEGRADED", "text": "waiting",
         "ts": "t"},
        {"lane": "firewall", "verdict": "NEUTRAL", "text": "unchecked",
         "ts": "t"},
        {"lane": "backlog", "verdict": "READY", "text": "none",
         "ts": "t"}])
    rc = doctor_mod.doctor(fix=False, machine=True)
    out = capsys.readouterr().out
    assert rc == 3
    assert "DOCTOR 1 1" in out


def test_doctor_machine_says_neutral_without_counting_it_failure(
        monkeypatch, capsys):
    _ready_lanes(monkeypatch)
    _patch_hunter(monkeypatch)
    _ready_before(monkeypatch)
    rc = doctor_mod.doctor(fix=False, machine=True)
    out = capsys.readouterr().out
    assert rc == 0
    assert "NEUTRAL" in out          # said honestly in the row table
    assert "DOCTOR 0 0" in out       # an honest absence is not a failure


def test_passthrough_keeps_exit_zero_and_no_doctor_line(
        monkeypatch, capsys):
    """cmd_doctor's contract: scripts get exit 0 and today's format."""
    _ready_lanes(monkeypatch)
    _patch_hunter(monkeypatch)
    _broken_before(monkeypatch)
    monkeypatch.setattr(doctor_mod, "persist_snapshot",
                        lambda *a, **k: None)
    import cli
    rc = cli.cmd_doctor(Namespace(fix=False, only=None))
    out = capsys.readouterr().out
    assert rc == 0
    assert "DOCTOR" not in out       # the machine line is opt-in only


def test_human_mode_renders_the_lane_rows(monkeypatch, capsys):
    _ready_lanes(monkeypatch)
    _patch_hunter(monkeypatch)
    _ready_before(monkeypatch)
    rc = doctor_mod.doctor(fix=False)
    out = capsys.readouterr().out
    assert rc == 0
    assert "service" in out and "backlog" in out
    assert "🟢" in out
    assert "DOCTOR" not in out
