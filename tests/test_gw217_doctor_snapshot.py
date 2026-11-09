"""GW-D2/D3 (cannot-fail Wave D): the honest rows and the always-on
health snapshot.

The four service rows never read as safe over silence: an unreadable
thing is NEUTRAL, "cannot check as this user" is said, and a row whose
builder raises degrades that row alone. The snapshot - the same rows -
is published by the daemon every cycle and persisted to
doctor-last.json beside status.json (the CLI's run does the same,
best-effort, exit code untouched).
"""
import inspect
import json
import os
import pathlib
import sys
from argparse import Namespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


import doctor as doctor_mod  # noqa: E402
import greywatch_daemon as daemon_mod  # noqa: E402


class _Done:
    def __init__(self, rc, out=""):
        self.returncode = rc
        self.stdout = out


# ---------------------------------------------------------------- D2

def test_row_service_broken_when_unit_inactive(tmp_path, monkeypatch):
    (tmp_path / "status.json").write_text("{}")
    monkeypatch.setattr(doctor_mod, "_probe",
                        lambda argv: _Done(0, "inactive"))
    row = doctor_mod.row_service(tmp_path)
    assert row["verdict"] == "BROKEN" and "inactive" in row["text"]


def test_row_service_stale_snapshot_is_degraded(tmp_path, monkeypatch):
    path = tmp_path / "status.json"
    path.write_text("{}")
    old = __import__("time").time() - 3600
    os.utime(path, (old, old))
    monkeypatch.setattr(doctor_mod, "_probe",
                        lambda argv: _Done(0, "active"))
    row = doctor_mod.row_service(tmp_path)
    assert row["verdict"] == "DEGRADED" and "older than 90" in row["text"]


def test_row_service_ready_when_fresh(tmp_path, monkeypatch):
    (tmp_path / "status.json").write_text("{}")
    monkeypatch.setattr(doctor_mod, "_probe",
                        lambda argv: _Done(0, "active"))
    row = doctor_mod.row_service(tmp_path)
    assert row["verdict"] == "READY"


def test_row_service_unreadable_snapshot_is_neutral(tmp_path,
                                                    monkeypatch):
    monkeypatch.setattr(doctor_mod, "_probe",
                        lambda argv: _Done(0, "active"))
    row = doctor_mod.row_service(tmp_path)
    assert row["verdict"] == "NEUTRAL" and "cannot be read" in row["text"]


def test_row_scan_fresh_request_is_said_not_hidden(tmp_path,
                                                   monkeypatch):
    (tmp_path / "scan-request.json").write_text("{}")
    row = doctor_mod.row_scan(tmp_path)
    assert row["verdict"] == "READY" and "scan request is on disk" \
        in row["text"]


def test_row_scan_aged_request_is_degraded(tmp_path, monkeypatch):
    path = tmp_path / "scan-request.json"
    path.write_text("{}")
    old = __import__("time").time() - 3600
    os.utime(path, (old, old))
    row = doctor_mod.row_scan(tmp_path)
    assert row["verdict"] == "DEGRADED" and "has waited" in row["text"]


def test_row_scan_rejected_marker_is_said(tmp_path, monkeypatch):
    (tmp_path / "scan-request.json").write_text("{}")
    (tmp_path / "scan-request.json.rejected").write_text("garbage")
    row = doctor_mod.row_scan(tmp_path)
    assert "rejected" in row["text"]


def test_row_scan_unreadable_dir_is_neutral(tmp_path):
    row = doctor_mod.row_scan(tmp_path)
    assert row["verdict"] == "NEUTRAL"
    assert "cannot read as this user" in row["text"]


def test_row_firewall_uncheckable_is_neutral_not_green(tmp_path,
                                                       monkeypatch):
    monkeypatch.setattr(doctor_mod, "_probe", lambda argv: _Done(1, ""))
    row = doctor_mod.row_firewall(tmp_path)
    assert row["verdict"] == "NEUTRAL" and "cannot check" in row["text"]


def test_row_firewall_table_present_is_ready(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor_mod, "_probe",
                        lambda argv: _Done(0, "table inet greywatch_blocks"
                                           "\n"))
    assert doctor_mod.row_firewall(tmp_path)["verdict"] == "READY"


def test_row_firewall_no_table_says_nothing_was_blocked(tmp_path,
                                                        monkeypatch):
    monkeypatch.setattr(doctor_mod, "_probe", lambda argv: _Done(0, ""))
    row = doctor_mod.row_firewall(tmp_path)
    assert row["verdict"] == "NEUTRAL" and "nothing was ever blocked" \
        in row["text"]


def test_row_backlog_aged_is_degraded(tmp_path):
    (tmp_path / "status.json").write_text(json.dumps(
        {"pending_decisions": 25}))
    row = doctor_mod.row_backlog(tmp_path)
    assert row["verdict"] == "DEGRADED" and "25" in row["text"]


def test_row_backlog_zero_is_ready(tmp_path):
    (tmp_path / "status.json").write_text(json.dumps(
        {"pending_decisions": 0}))
    row = doctor_mod.row_backlog(tmp_path)
    assert row["verdict"] == "READY" and "no pending decisions" \
        in row["text"]


def test_row_backlog_unreadable_is_neutral(tmp_path):
    row = doctor_mod.row_backlog(tmp_path)
    assert row["verdict"] == "NEUTRAL" and "cannot read as this user" \
        in row["text"]


def test_row_backlog_missing_key_is_neutral_not_ready(tmp_path):
    (tmp_path / "status.json").write_text("{}")
    row = doctor_mod.row_backlog(tmp_path)
    assert row["verdict"] == "NEUTRAL" and "no pending-decision count" \
        in row["text"]


# ---------------------------------------------------------------- D3

def test_health_snapshot_covers_all_five_lanes(tmp_path):
    rows = doctor_mod.health_snapshot(tmp_path)
    assert [r["lane"] for r in rows] == ["service", "scan", "firewall",
                                         "backlog", "ledger"]
    for r in rows:
        assert set(r) == {"lane", "verdict", "text", "ts"}
        assert r["verdict"] in ("READY", "DEGRADED", "BROKEN", "NEUTRAL")


def test_health_snapshot_degrades_only_the_broken_row(tmp_path,
                                                      monkeypatch):
    def boom(_dd):
        raise RuntimeError("this builder is sick")
    boom.__name__ = "row_scan"          # the fallback row names its builder
    # health_snapshot captured the builders at import time; name the
    # sick one by rebuilding the tuple.
    monkeypatch.setattr(doctor_mod, "_HEALTH_BUILDERS", (
        doctor_mod.row_service, boom, doctor_mod.row_firewall,
        doctor_mod.row_backlog, doctor_mod.row_ledger))
    rows = doctor_mod.health_snapshot(tmp_path)
    scan = next(r for r in rows if r["lane"] == "scan")
    assert scan["verdict"] == "NEUTRAL"
    assert "could not run" in scan["text"] and "RuntimeError" \
        in scan["text"]
    assert len(rows) == 5                     # the other rows still ran


# ---------------------------------------------------------------- D4
# the ledger row (0.3.0 wave F2): growth says its name.

def test_row_ledger_over_cap_says_so(tmp_path, monkeypatch):
    import greywatch_daemon
    (tmp_path / "events.jsonl").write_text('{"ts": "1"}\n')
    monkeypatch.setattr(greywatch_daemon, "MAX_EVENTS", 20_000)
    monkeypatch.setattr(greywatch_daemon, "count_lines",
                        lambda p: 20_400)
    row = doctor_mod.row_ledger(tmp_path)
    assert row["verdict"] == "DEGRADED"
    assert "20400" in row["text"]
    assert "cap" in row["text"]


def test_row_ledger_under_cap_is_ready_with_numbers(tmp_path):
    (tmp_path / "events.jsonl").write_text('{"ts": "1"}\n{"ts": "2"}\n'
                                           '{"ts": "3"}')
    row = doctor_mod.row_ledger(tmp_path)
    assert row["verdict"] == "READY"
    assert "3 lines" in row["text"]


def test_row_ledger_without_events_is_neutral(tmp_path):
    row = doctor_mod.row_ledger(tmp_path)
    assert row["verdict"] == "NEUTRAL"
    assert "cannot" in row["text"]


def test_count_lines_counts_records_not_bytes(tmp_path):
    from greywatch_daemon import count_lines
    p = tmp_path / "x.jsonl"
    assert count_lines(p) == 0                    # nothing on disk: 0 lines
    p.write_text("a\nb\nc\nd\ne")                 # no trailing newline
    assert count_lines(p) == 5
    p.write_text("a\nb\n")
    assert count_lines(p) == 2
    big = tmp_path / "big.jsonl"
    big.write_text("y\n" * 10)
    assert count_lines(big) == 10        # trailing newline is no record
    big.write_text("\n".join(f"e{i}" for i in range(11)))
    assert count_lines(big) == 11        # no trailing newline still counts


def test_persist_snapshot_writes_and_rereads(tmp_path):
    rows = [{"lane": "service", "verdict": "READY", "text": "ok",
             "ts": "t"}]
    path = doctor_mod.persist_snapshot(tmp_path, rows)
    assert path is not None
    doc = json.loads(path.read_text())
    assert doc["rows"][0]["lane"] == "service"
    mode = path.stat().st_mode & 0o777
    assert mode in (0o600, 0o640)             # never world-readable


def test_persist_snapshot_skips_silently_when_it_cannot_write(
        tmp_path, monkeypatch):
    import status as status_mod

    def refuse(path, status, gid=None):
        raise OSError("read-only")
    monkeypatch.setattr(status_mod, "write_status", refuse)
    assert doctor_mod.persist_snapshot(tmp_path,
                                       [{"lane": "x", "verdict": "READY",
                                         "text": "", "ts": "t"}]) is None


def test_cli_doctor_persists_best_effort(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor_mod, "_registry", lambda: [])
    monkeypatch.setattr(doctor_mod, "hunter_service_row",
                        lambda fix=False: {"name": "hunter.service",
                                           "verdict": "READY",
                                           "stamp": "ok", "actions": []})
    monkeypatch.setattr(doctor_mod.setup_mod, "probe_tool",
                        lambda spec: {"verdict": "READY",
                                      "remediation": []})
    monkeypatch.setattr(doctor_mod, "DATA_DIR", str(tmp_path))
    import cli
    rc = cli.cmd_doctor(Namespace(fix=False, only=None))
    assert rc == 0
    doc = json.loads((tmp_path / "doctor-last.json").read_text())
    assert [r["lane"] for r in doc["rows"]] == ["service", "scan",
                                                "firewall", "backlog",
                                                "ledger"]


def test_daemon_publishes_the_snapshot_every_cycle():
    """The Diagnostics pane's data rides in status.json, not in a file
    only a manual doctor run would refresh."""
    src = inspect.getsource(daemon_mod.Daemon.write_status)
    assert 'snap["doctor"]' in src and "persist_snapshot" in src
