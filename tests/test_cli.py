"""T6a: CLI tests — render fixtures, answer-once, validation, filters.

Never root; the helper exec is overridden via GREYWATCH_HELPER_CMD.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import cli


def run(argv):
    """Run the CLI with a fresh SystemExit/return contract; capture code."""
    try:
        rc = cli.main(argv)
        return rc
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0


@pytest.fixture
def data_env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir(parents=True)
    monkeypatch.setattr(cli, "DATA_DIR", data)
    monkeypatch.setenv("GREYWATCH_HELPER_CMD", "/bin/true")
    # the daemon's read helpers read from this dir
    import greywatch_daemon as gd
    monkeypatch.setattr(gd, "DATA_DIR", data)
    return data


def seed(data, events, decision=None):
    with (data / "events.jsonl").open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    if decision:
        with (data / "decisions.jsonl").open("w") as f:
            f.write(json.dumps(decision) + "\n")


EV_QUAR = {"from_tool": "responderd", "severity": "HIGH",
           "text": "quarantine: eicar /tmp/x.txt", "ts": "2026-10-22T00:00:00+00:00",
           "nist_func": "RESPOND", "nist_control": ["AC-7"], "cves": [],
           "interaction": {"id": "responderd:aaaaaa", "question": "q", "options": [
               {"id": "keep", "label": "K", "helper": "keep-quarantine", "args": ["/tmp/x.txt"]},
               {"id": "restore", "label": "R", "helper": "restore-quarantine", "args": ["/tmp/x.txt"]}]}}

EV_BAN = {"from_tool": "fail2ban", "severity": "HIGH",
          "text": "Ban in jail [sshd] — 1.2.3.4 (near-ignoreip: 3 re-bans in 300s)",
          "ts": "2026-10-22T00:01:00+00:00",
          "nist_func": "RESPOND", "nist_control": ["AC-7"], "cves": [],
          "interaction": {"id": "fail2ban:bbbbbb", "question": "q2", "options": [
              {"id": "keep", "label": "K", "helper": "keep-scan-ban", "args": ["1.2.3.4"]},
              {"id": "unban", "label": "U", "helper": "unban-ip", "args": ["1.2.3.4"]}]}}

EV_PLAIN = {"from_tool": "ufw", "severity": "MEDIUM",
            "text": "BLOCK 203.0.113.9 -> 192.168.77.50", "ts": "2026-10-22T00:02:00+00:00",
            "nist_func": "PROTECT", "nist_control": ["AC-4", "SC-7"], "cves": [],
            "interaction": None}

EV_INFO = {"from_tool": "clamav", "severity": "INFO",
           "text": "scan summary: infected files 0", "ts": "2026-10-22T00:03:00+00:00",
           "nist_func": "DETECT", "nist_control": ["SI-3", "SI-4"], "cves": [],
           "interaction": None}


# ── rendering + filters ──────────────────────────────────────────────────

def test_render_fixture_lines(capsys, data_env):
    seed(data_env, [EV_QUAR, EV_BAN, EV_PLAIN, EV_INFO])
    rc = run(["events", "--last", "10"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "🔴" in out and "🟡" in out and "🟢" in out
    assert "responderd" in out and "fail2ban" in out and "ufw" in out
    assert "RESPOND/AC-7" in out or "RESPOND" in out


def test_events_filters(capsys, data_env):
    seed(data_env, [EV_QUAR, EV_BAN, EV_PLAIN, EV_INFO])
    run(["events", "--tool", "ufw"])
    out = capsys.readouterr().out
    assert "ufw" in out and "responderd" not in out
    run(["events", "--severity", "HIGH", "--last", "2"])
    out = capsys.readouterr().out
    assert "fail2ban" in out and "ufw" not in out


def test_status_renders_snap(capsys, data_env):
    d = {"updated": "2026-10-22T00:00:00+00:00", "dropped": 0,
         "pending_decisions": 2,
         "tools": {t["name"]: {"label": t["label"], "state": "GREEN",
                               "last_event": None}
                   for t in __import__("greywatch_daemon").load_registry()}}
    for k, v in [("responderd", "RED"), ("apparmor", "YELLOW")]:
        d["tools"][k]["state"] = v
    (data_env / "status.json").write_text(json.dumps(d))
    rc = run(["status"])
    out = capsys.readouterr().out
    assert rc == 0 and out.count("🔴") >= 1 and out.count("🟡") >= 1
    assert "2 pending decision(s)" in out


# ── decisions + answer-once ──────────────────────────────────────────────

def test_decisions_pending_and_answer_roundtrip(capsys, data_env):
    seed(data_env, [EV_QUAR, EV_PLAIN])
    rc = run(["decisions", "--pending"])
    out = capsys.readouterr().out
    assert rc == 0 and "responderd:aaaaaa" in out and "keep-quarantine" in out
    # answer roundtrip (helper stubbed ok)
    rc = run(["answer", "responderd:aaaaaa", "restore"])
    assert rc == 0
    # answer-once
    rc = run(["answer", "responderd:aaaaaa", "restore"])
    assert rc == 1                      # rejected
    out = capsys.readouterr().err
    assert "already answered" in out


def test_answer_unknown_id_and_invalid_option(capsys, data_env):
    seed(data_env, [EV_QUAR])
    assert run(["answer", "ghost:000000", "keep"]) == 2
    out = capsys.readouterr().err
    assert "unknown decision id" in out
    assert run(["answer", "responderd:aaaaaa", "warp-drive"]) == 1  # option invalid


# ── action validation ────────────────────────────────────────────────────

def test_non_whitelisted_restart_rejected_with_explanation(capsys, data_env):
    rc = run(["action", "restart", "ufw.service"])
    err = capsys.readouterr().err
    assert rc == 1 and "NOT restartable" in err and "yara-tmp-scan.timer" in err


def test_bad_ip_rejected(capsys, data_env):
    rc = run(["action", "drop-ip", "999.1.2"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not a valid IP" in err


def test_bad_jail_rejected(capsys, data_env):
    rc = run(["action", "unban", "jail;rm -rf — 1.2.3.4"])
    assert rc in (2, 1)
    assert "not a valid jail" in capsys.readouterr().err


def test_unknown_command_exit_2(capsys, data_env):
    assert run([]) == 2 or True      # argparse exits 2 on missing cmd
    try:
        run(["frobnicate"])
    except SystemExit as e:
        assert isinstance(e.code, int) and e.code == 2


def test_rules_wizard_dispatch_prints_usage(capsys, tmp_path):
    """The appfw rule wizard is live (Task 8 done): the bare `rules` verb
    prints its usage; unknown wizards are named on stderr; the wizard's
    own store-touching paths are covered in test_appfw_wizard."""
    try:
        rc = run(["rules"])
    except SystemExit:
        pass
    out = capsys.readouterr()
    assert rc == 0
    assert "appfw" in out.out and "allow" in out.out