# tests/test_assistant_advice.py
"""The advice engine: every tool playbook, every event class the parsers
emit, and the hard invariant that advice never executes anything."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest

from assistant import advice
from registry import load_registry


def _tools():
    return [t["name"] for t in load_registry()]


# ---- coverage -------------------------------------------------------------

def test_every_registry_tool_has_an_event_playbook():
    missing = [name for name in _tools() if name not in advice._RULES]
    assert missing == [], f"tools without a playbook: {missing}"


def test_every_registry_tool_has_real_commands_or_an_app_action():
    """Steps must be actionable for THIS install: a unit from the
    registry, a log path from the registry, or an in-app scan action."""
    for name in _tools():
        spec = advice._spec(name)
        cmds = [c for c in (advice._unit_cmd(name),
                            advice._log_cmd(name)) if c]
        assert cmds or advice._app_scan(name) or spec.get("state_only"), \
            f"{name} has no command, log, or app action"


# ---- event classes --------------------------------------------------------

EVENT_TABLE = [
    ("appfw", "appfw /usr/bin/curl → 1.2.3.4:443 answered: deny",
     "blocked a program"),
    ("appfw", "appfw engine armed (headless fallback: deny-once)",
     "without its popup"),
    ("apparmor", "AppArmor DENIED profile=lynis comm=lynis",
     "outside its jail"),
    ("auditd", "type=AVC avc:  denied  { read } for apparmor=\"DENIED\"",
     "AppArmor denial relayed"),
    ("auditd", "type=ANOM_ABEND pid=4242 comm=browser",
     "crashed on its own"),
    ("rkhunter", "Rootkit scanner is down and could not be repaired",
     "not running"),
    ("rkhunter", "Warning: /usr/bin/foo has changed",
     "flagged something for review"),
    ("rkhunter", "Warning: The following suspicious (large) shared memory "
                 "segment(s) were found",
     "shared-memory segments"),
    ("lynis", "The security auditor is down and could not be repaired",
     "not running"),
    ("lynis", "Warning: hardening index dropped",
     "weakness to improve"),
    ("aide", "AIDE: differences found in /etc",
     "changed since the last integrity check"),
    ("clamav", "Infected files: 2",
     "found malware"),
    ("clamav", "Scan clean; infected files: 0",
     "came back clean"),
    ("fail2ban", "fail2ban banned 203.0.113.9 (sshd)",
     "locked out after repeated failed logins"),
    ("fail2ban", "fail2ban Unban 203.0.113.9",
     "released"),
    ("ufw", "UFW BLOCK_UNKNOWN IN=eth0 SRC=203.0.113.5",
     "unexpected source"),
    ("ufw", "UFW BLOCK IN=eth0 SRC=203.0.113.5 DPT=23",
     "firewall doing its job"),
    ("responderd", "quarantine /tmp/x.bin → /var/quarantine/x.bin",
     "moved into quarantine"),
    ("responderd", "kill pid 4242 (threat rule)",
     "stopped a running process"),
    ("arpwatch", "new station 192.168.1.50",
     "joined your network"),
    ("tetragon", "exec /usr/bin/curl",
     "program started"),
    ("net-watch", "burst of denied connections",
     "unusual connection behaviour"),
    ("yara-watch", "YARA matched Eicar-Sig in /tmp/e",
     "known-bad pattern"),
    ("freshclam", "ClamAV update error: failed to download",
     "could not be refreshed"),
    ("cve-updater", "cve cache updated from NVD",
     "known-flaw list was refreshed"),
]


@pytest.mark.parametrize("tool,text,phrase", EVENT_TABLE)
def test_event_classification(tool, text, phrase):
    row = {"tool": tool, "severity": "HIGH", "text": text,
           "ts": "2026-10-29T13:50:00+00:00"}
    out = advice.advise_event(row)
    assert phrase in out, out
    assert text in out                      # the raw line stays pasteable


def test_deny_on_an_engine_armed_line_is_not_a_denial():
    row = {"tool": "appfw", "severity": "MEDIUM",
           "text": "appfw engine armed (headless fallback: deny-once)",
           "ts": "2026-10-29T13:50:00+00:00"}
    out = advice.advise_event(row)
    assert "blocked a program" not in out


def test_advice_carries_a_run_it_yourself_note_only_with_commands():
    with_cmd = advice.advise_event(
        {"tool": "fail2ban", "severity": "HIGH",
         "text": "fail2ban banned 203.0.113.9 (sshd)",
         "ts": "2026-10-29T13:50:00+00:00"})
    assert "run yourself" in with_cmd and "sudo tail -n 50" in with_cmd
    no_cmd = advice.advise_event(
        {"tool": "appfw", "severity": "INFO",
         "text": "appfw /usr/bin/curl → 1.2.3.4:443 allow",
         "ts": "2026-10-29T13:50:00+00:00"})
    assert "run yourself" not in no_cmd


# ---- tool state advice ----------------------------------------------------

def _pack(tools, recent=()):
    from assistant.packer import build_pack
    return build_pack({"tools": tools}, list(recent), "help")


def test_red_tool_gets_scan_and_registry_commands():
    pack = _pack({"ufw": {"state": "RED", "installed": True}})
    out = advice.advise_tool(pack, "ufw")
    assert "not running" in out
    assert "systemctl status ufw.service" in out
    assert "run yourself" in out


def test_paused_tool_says_resume_not_reinstall():
    pack = _pack({"ufw": {"state": "GREEN", "installed": True,
                          "paused": True}})
    out = advice.advise_tool(pack, "ufw")
    assert "paused" in out
    assert "Resume Firewall" in out


def test_state_column_disagreement_with_the_log_is_called_out():
    """The owner's recurring puzzle: 17/17 green on screen while the
    rootkit scanner logged that it is down."""
    recent = [{"from_tool": "rkhunter", "severity": "HIGH",
               "text": "Rootkit scanner is down and could not be repaired",
               "ts": "2026-10-29T13:50:00+00:00"}]
    pack = _pack({"rkhunter": {"state": "GREEN", "installed": True}}, recent)
    out = advice.advise_tool(pack, "rkhunter")
    assert "disagreement" in out
    assert "Rootkit scan" in out            # the app action, from SCAN_MODES
    assert "Trust the log" in out


def test_unknown_tool_returns_none():
    assert advice.advise_tool(_pack({}), "nope") is None


# ---- priorities and correlation -------------------------------------------

def test_priorities_rank_a_stopped_layer_above_a_high_event():
    pack = _pack(
        {"ufw": {"state": "RED", "installed": True},
         "fail2ban": {"state": "GREEN", "installed": True}},
        [{"from_tool": "fail2ban", "severity": "HIGH",
          "text": "fail2ban banned 203.0.113.9 (sshd)",
          "ts": "2026-10-29T13:50:00+00:00"}])
    out = advice.advise_priorities(pack)
    assert out.index("Firewall") < out.index("Intrusion blocker")
    assert "systemctl status ufw.service" in out


def test_nothing_waiting_is_said_plainly():
    pack = _pack({"ufw": {"state": "GREEN", "installed": True}})
    out = advice.advise_priorities(pack)
    assert out.startswith("Nothing needs a decision")
    assert advice.needs_attention(pack) == []


def test_state_vs_events_explains_healthy_but_noisy():
    pack = _pack(
        {"ufw": {"state": "GREEN", "installed": True}},
        [{"from_tool": "ufw", "severity": "HIGH",
          "text": "UFW BLOCK SRC=203.0.113.5", "ts": "2026-10-29T13:50:00+00:00"}])
    out = advice.advise_state_vs_events(pack)
    assert "state says whether a layer is running" in out
    assert "1 of 1 layers are green" in out
    assert "1 high-severity event(s)" in out


# ---- hard invariant -------------------------------------------------------

def test_advice_module_cannot_execute_anything():
    src = pathlib.Path(advice.__file__).read_text()
    for banned in ("import subprocess", "import os", "os.system",
                   "subprocess.", "eval(", "exec(", "popen", "Popen"):
        assert banned not in src, f"advice.py must not contain {banned!r}"
