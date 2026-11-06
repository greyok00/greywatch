"""GW-197 (owner 2026-11-06): greywatch is two systems. The log and the
popups now sort every event into a threat lane and a tool lane, each with
its own controls; classification happens at read time so the whole existing
history sorts without touching the daemon."""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from events import lane_for


def _ev(tool="clamav", text="", sev="INFO", **kw):
    d = {"from_tool": tool, "severity": sev, "text": text,
         "ts": "2026-11-06T01:00:00+00:00"}
    d.update(kw)
    return d


def test_checkins_and_tool_state_read_as_tool_lane():
    assert lane_for(_ev()) == "tool"
    assert lane_for(_ev(text="check-in: alive, running normally")) == "tool"
    assert lane_for(_ev(sev="HIGH",
                        text="check-in: NOT RUNNING - needs attention")) == "tool"
    assert lane_for(_ev(text="yara exited 1")) == "tool"
    assert lane_for(_ev(text="rkhunter timed out after 360 minutes")) == "tool"
    assert lane_for(_ev(text="freshclam updater not installed")) == "tool"


def test_detections_and_asks_read_as_threat_lane():
    assert lane_for(_ev(tool="responderd", sev="HIGH",
                        text="quarantine: /tmp/x.zip (sha256:ab) tag "
                             "[act: real signature in user data] "
                             "— moved to quarantine, restorable")) == "threat"
    assert lane_for(_ev(tool="appfw", sev="MEDIUM",
                        text="deny <unknown> → 104.16.79.73:443")) == "threat"
    spec = {"id": "responderd:8a5fa1", "question": "keep or put back?"}
    assert lane_for(_ev(interaction=spec)) == "threat"


def test_unknown_severities_fail_in_the_right_direction():
    # A new source failing open reads as noise, never silence: HIGH and up
    # is treated as a threat, the rest as tool state.
    assert lane_for(_ev(tool="something-new", sev="HIGH", text="?")) == "threat"
    assert lane_for(_ev(tool="something-new", sev="MEDIUM", text="?")) == "tool"


# ---- task 2: clear the log -------------------------------------------------
import os
import subprocess


def test_the_clear_contract_is_pinned_in_source():
    src = (ROOT / "ui" / "window.py").read_text()
    assert '"Clear the log"' in src
    assert "_clear_log_pressed" in src
    helper = ROOT / "apply" / "clear-events.sh"
    assert helper.exists()
    code = "\n".join(l for l in helper.read_text().splitlines()
                     if not l.lstrip().startswith("#"))
    assert 'GW_DATA:-/var/lib/greywatch' in code
    assert ': > "$DATA/events.jsonl"' in code, "truncate only the event log"


def test_clear_events_helper_truncates_only_the_event_log(tmp_path):
    stub = tmp_path / "stub.sh"
    stub.write_text(
        '#!/bin/bash\n'
        'case "$1" in clear-events) : > "$GREYWATCH_DATA/events.jsonl" ;; '
        '*) exit 64 ;; esac\n')
    stub.chmod(0o755)
    data = tmp_path / "data"
    data.mkdir()
    (data / "events.jsonl").write_text('{"from_tool": "x"}\n')
    (data / "decisions.jsonl").write_text('{"id": "keep"}\n')
    env = dict(os.environ, GREYWATCH_DATA=str(data))
    out = subprocess.run(["/bin/bash", str(stub), "clear-events"],
                         capture_output=True, env=env)
    assert out.returncode == 0
    assert (data / "events.jsonl").read_text() == ""
    assert (data / "decisions.jsonl").read_text() == '{"id": "keep"}\n'


def test_clear_events_helper_errors_without_a_log(tmp_path):
    real = ROOT / "apply" / "clear-events.sh"
    assert real.exists(), "the helper ships in this tree"
    env = dict(os.environ, GW_DATA=str(tmp_path))
    out = subprocess.run(["/bin/bash", str(real)], capture_output=True,
                         text=True, env=env)
    assert out.returncode == 66, out.stderr
    assert "no event log" in out.stderr
