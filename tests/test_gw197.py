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


# ---- task 3: log rows carry raw events; tool rows fix from the row ---------
import os as _os
import sys as _sys
_sys.path.insert(0, str(ROOT))


def test_control_label_matches_the_desk_verb():
    from ui.toolsdesk import control_label
    assert control_label({"name": "yara-watch", "paused": True,
                          "unit": "x.service"}) == "Resume"
    assert control_label({"name": "rkhunter", "unit": None}) == "Run scan"
    assert control_label({"name": "freshclam",
                          "unit": "clamav-freshclam.service"}) == "Update now"
    assert control_label({"name": "clamav",
                          "unit": "clamav-daemon.service"}) == "Start tool"


def test_log_row_values_carry_the_raw_event_and_lane():
    import ui.window as winmod
    ev = {"from_tool": "fail2ban", "severity": "HIGH",
          "text": "check-in: NOT RUNNING - needs attention",
          "ts": "2026-11-06T01:00:00+00:00"}
    display, raw, lane = winmod.log_row_values(ev, "9:00 fail2ban",
                                               "NOT RUNNING", "ink")
    assert raw is ev and lane == "tool"
    assert display[3] == "9:00 fail2ban" and display[-1] == "NOT RUNNING"


def test_threat_card_options_offer_delete_only_for_real_targets():
    import ui.window as winmod
    spec = {"id": "responderd:8a5fa1", "options": [
        {"id": "keep", "label": "Keep quarantined",
         "helper": "keep-quarantine", "args": ["/tmp/Docs.zip"]}]}
    ev = {"from_tool": "responderd", "severity": "HIGH",
          "text": "quarantine: /tmp/Docs.zip ...", "interaction": spec,
          "ts": "2026-11-06T01:00:00+00:00"}
    opts = winmod.threat_card_options(ev)
    ids = [o["id"] for o in opts]
    assert ids == ["keep", "delete"]
    assert opts[:1] == spec["options"], "the stored options come first"


def test_the_lanes_never_mix_their_controls():
    src = (ROOT / "ui" / "window.py").read_text()
    tool_fn = src.split("def _log_tool_actions")[1].split("def ")[0]
    threat_fn = src.split("def _log_threat_actions")[1].split("def ")[0]
    for word in ("delete", "quarantine", "file-action"):
        assert word not in tool_fn, f"tool rows never touch {word}"
    for word in ("_control_requested", "start_tool", "control_label"):
        assert word not in threat_fn, f"threat rows never touch {word}"
