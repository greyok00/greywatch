"""GW-155 .. GW-157: the deb hunter dead lane, the hunter's notes
prose, and the CLI's help strings, each pinned so they stay fixed.

The deb lane is the owner-visible heart of GW-155: on the packaged
route the hunter service could stay never-started while every tool
row and the status snapshot read healthy - the fill, the postinst, the
watchdog, and the doctor must all know the hunter exists.
"""
import contextlib
import datetime as dt
import io
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ------------------------------------------------------------- GW-155 cli

def _run_cli(monkeypatch, tmp_path, live):
    import cli
    import hunter.store as store
    store._prepare(tmp_path)
    store.write_live(tmp_path, live)
    monkeypatch.setattr(cli, "DATA_DIR", tmp_path)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.cmd_hunter(type("A", (), {
            "hunt": False, "notes": False, "no_ai": False})())
    return rc, buf.getvalue()


def test_cli_hunter_stamps_stale_in_words(tmp_path, monkeypatch):
    """`gw hunter` must say 'not responding' when the live stamp is old -
    the dashboard's not-responding rule, in the CLI's own words."""
    old = dt.datetime.now().astimezone() - dt.timedelta(hours=3)
    rc, out = _run_cli(monkeypatch, tmp_path, {
        "ts": old.isoformat(), "interval_s": 300,
        "findings_total": 4, "unread": 2})
    assert rc == 0
    assert "hunter not responding" in out
    assert "doctor" in out, "the CLI points at the repair surface"


def test_cli_hunter_fresh_prints_no_warning(tmp_path, monkeypatch):
    now = dt.datetime.now().astimezone()
    rc, out = _run_cli(monkeypatch, tmp_path, {
        "ts": now.isoformat(), "interval_s": 300,
        "findings_total": 1, "unread": 0})
    assert rc == 0
    assert "not responding" not in out


# ------------------------------------------------------- GW-155 doctor

def _doctor(monkeypatch, tmp_path, rules):
    import doctor
    monkeypatch.setattr(doctor, "DATA_DIR", tmp_path)

    def fake_run(argv, **k):
        joined = " ".join(argv)
        for needle, rc, out in rules:
            if needle in joined:
                return subprocess.CompletedProcess(argv, rc, stdout=out,
                                                   stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    monkeypatch.setattr(doctor.subprocess, "run", fake_run)
    return doctor


def _hunters_rules(active=True, enabled=True):
    return [
        ("is-enabled", 0, "enabled" if enabled else "disabled"),
        ("is-active", 0 if active else 3, "active" if active else "inactive"),
        ("restart", 0, ""), ("enable", 0, ""),
    ]


def test_doctor_hunter_row_offline_when_unit_missing(tmp_path, monkeypatch):
    d = _doctor(monkeypatch, tmp_path, [
        ("is-enabled", 0, "not-found"), ("is-active", 3, "inactive")])
    row = d.hunter_service_row(False)
    assert row["verdict"] == "OFFLINE"
    assert row["actions"] == [] and row["stamp"] == "no unit"


def test_doctor_hunter_row_broken_when_active_but_stale(tmp_path,
                                                        monkeypatch):
    live = tmp_path / "hunter" / "live.json"
    live.parent.mkdir()
    old = dt.datetime.now().astimezone() - dt.timedelta(minutes=90)
    live.write_text(json.dumps({"ts": old.isoformat(), "interval_s": 300}))
    d = _doctor(monkeypatch, tmp_path, _hunters_rules(active=True))
    row = d.hunter_service_row(True)
    assert row["verdict"] == "BROKEN"
    assert any("restarted" in a for a in row["actions"])
    assert "stale" in row["stamp"]


def test_doctor_hunter_row_ready_when_running_and_fresh(tmp_path,
                                                        monkeypatch):
    live = tmp_path / "hunter" / "live.json"
    live.parent.mkdir()
    live.write_text(json.dumps({
        "ts": dt.datetime.now().astimezone().isoformat(),
        "interval_s": 300}))
    d = _doctor(monkeypatch, tmp_path, _hunters_rules(active=True))
    row = d.hunter_service_row(False)
    assert row["verdict"] == "READY" and row["actions"] == []
    assert "min ago" in row["stamp"]


def test_doctor_hunter_fix_enables_a_never_started_unit(tmp_path,
                                                        monkeypatch):
    live = tmp_path / "hunter" / "live.json"
    live.parent.mkdir()
    live.write_text(json.dumps({
        "ts": dt.datetime.now().astimezone().isoformat(),
        "interval_s": 300}))
    d = _doctor(monkeypatch, tmp_path, _hunters_rules(active=False,
                                                      enabled=False))
    row = d.hunter_service_row(True)
    assert row["verdict"] == "OFFLINE"
    assert any(a.startswith("enabled") for a in row["actions"])
    assert any(a.startswith("restarted") for a in row["actions"])


# ------------------------------------------------------- GW-156 prose

def test_persistence_what_is_prose_and_facts_keep_the_lines(monkeypatch):
    import hunter.web as web
    monkeypatch.setattr(web, "_crontab_lines",
                        lambda: ["* * * * * curl http://example.invalid/x"])
    monkeypatch.setattr(web, "_startup_files", lambda *a, **k: [])
    f = web.persistence_findings("/home/alice")[0]
    assert f["what"].startswith("The user crontab has 1 entry that runs")
    assert "pull" not in f["what"].split("runs")[0]
    assert "curl http://example.invalid/x" in f["facts"][1]
    assert "path=user crontab #" in f["facts"][0]


def test_persistence_prose_grammar_tracks_the_count(monkeypatch):
    import hunter.web as web
    monkeypatch.setattr(web, "_crontab_lines", lambda: ["a", "b"])
    monkeypatch.setattr(web, "_startup_files", lambda *a, **k: [])
    f = web.persistence_findings("/home/alice")[0]
    assert "2 entries that run" in f["what"]
    assert " pull " in f["what"]


# ------------------------------------------------------- GW-157 help

def _subparsers(parser):
    import argparse
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            return a
    raise AssertionError("no subcommands")


def test_every_cli_subcommand_carries_help():
    import cli
    parser = cli.build_parser()
    sub = _subparsers(parser)
    helps = {a.dest: a.help for a in sub._choices_actions}
    expected = {"status", "events", "tail", "log", "answer", "action"}
    assert expected <= set(helps), {k: helps.get(k) for k in expected}
    assert all(helps[k] for k in expected), \
        "a subcommand help is empty: " + str(
            {k: helps[k] for k in expected})


def test_answer_and_tail_positional_help_is_real():
    import cli
    root = cli.build_parser()
    answer = _subparsers(root).choices["answer"]
    tail = _subparsers(root).choices["tail"]
    texts = " ".join(
        str(a.help or "") if hasattr(a, "help") else ""
        for a in answer._actions + tail._actions)
    for fragment in ("decisions --pending", "the option id",
                     "start this many lines down"):
        assert fragment in texts, fragment
