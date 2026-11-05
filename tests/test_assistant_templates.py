# tests/test_assistant_templates.py
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from assistant.templates import (answer_event, answer_overview,
                                 answer_tool_status, compose)

from tests.test_assistant_packer import STATUS, EVENTS


def test_overview_lists_states():
    text = answer_overview(build_pack())
    assert "Fail2ban" in text and "RED" in text


def build_pack():
    from assistant.packer import build_pack
    return build_pack(STATUS, EVENTS, "overview")


def test_event_explains_newest():
    text = answer_event(build_pack())
    assert "apparmor" in text.lower()


def test_tool_status_named_tool():
    assert answer_tool_status(build_pack(), "fail2ban") is not None
    assert "fail2ban" in answer_tool_status(build_pack(), "fail2ban").lower()
    assert answer_tool_status(build_pack(), "nope-tool") is None


def test_compose_dispatch_unknown_slot_is_none():
    assert compose("summary", build_pack()) is None
    assert compose("overview", build_pack()) is not None


def test_tool_status_wording_uses_pack_paused():
    from assistant.packer import build_pack
    status = {"tools": {"fail2ban": {"state": "RED", "installed": True,
                                     "paused": True}}}
    pack = build_pack(status, [], "tool status", registry=None)
    text = answer_tool_status(pack, "fail2ban")
    assert "paused" in text.lower()
    assert "current layer state: red" in text.lower()

def test_event_no_canned_reassurance_for_high():
    ev = [{"from_tool": "yara-watch", "severity": "HIGH",
           "text": "YARA matched Eicar-Sig in /tmp/e",
           "ts": "2026-10-29T10:00:00+00:00"}]
    text = answer_event({"recent": ev})
    assert "usually normal" not in text
    assert text.endswith(".")


def test_event_reassurance_kept_for_medium_and_clean_punctuation():
    ev = [{"from_tool": "apparmor", "severity": "MEDIUM",
           "text": "AppArmor DENIED profile=lynis comm=lynis",
           "ts": "2026-10-29T10:00:00+00:00"}]
    text = answer_event({"recent": ev})
    assert "usually normal" in text
    assert ".;" not in text


def test_event_with_tool_hint_lists_only_that_tool():
    """A tool-named question must answer that tool's events in the user's
    local time, with the raw log text intact so it can be copied out."""
    pack = {"recent": [
        {"tool": "appfw", "severity": "MEDIUM",
         "text": "appfw ollama → 34.36.133.15:443 allow",
         "ts": "2026-10-29T20:53:51+00:00"},
        {"tool": "rkhunter", "severity": "HIGH",
         "text": "Warning: The following suspicious (large) shared memory "
                 "segment(s) were found",
         "ts": "2026-10-29T20:50:42+00:00"},
    ]}
    text = answer_event(pack, "rkhunter")
    assert "shared memory" in text
    assert text.startswith("Newest")
    assert "· High:" in text
    # plain-language meaning first, raw line kept for copying
    assert "rootkit scanner found something suspicious" in text.lower()
    assert "\n  raw: Warning: The following suspicious" in text
    assert "appfw ollama" not in text
    # single HIGH line → no "normal policy" reassurance
    assert "usually normal" not in text


def test_event_hint_miss_falls_back_to_text_mention():
    """The hint matches the log body too (a tool's warning relayed via
    another channel), not just the from_tool column."""
    pack = {"recent": [
        {"tool": "auditd", "severity": "HIGH",
         "text": "rkhunter reported: file properties changed",
         "ts": "2026-10-29T20:51:00+00:00"},
    ]}
    text = answer_event(pack, "rkhunter")
    assert text is not None
    assert "file properties changed" in text


def test_event_hint_with_no_rows_returns_none():
    pack = {"recent": [
        {"tool": "appfw", "severity": "MEDIUM", "text": "appfw x allow",
         "ts": "2026-10-29T20:53:51+00:00"},
    ]}
    assert answer_event(pack, "rkhunter") is None


def test_answer_detail_explains_one_row_with_raw_line():
    row = {"tool": "appfw", "severity": "MEDIUM",
           "text": "appfw chromium → 192.179.30.141:443 allow",
           "ts": "2026-10-29T14:44:18+00:00"}
    from assistant.templates import answer_detail
    text = answer_detail(row)
    assert "allowed" in text.lower()
    assert "raw: appfw chromium" in text
    assert "App firewall" in text
    assert "usually normal" in text


def test_answer_detail_high_has_no_reassurance():
    row = {"tool": "rkhunter", "severity": "HIGH",
           "text": "Warning: suspicious (large) shared memory segments",
           "ts": "2026-10-29T13:50:42+00:00"}
    from assistant.templates import answer_detail
    text = answer_detail(row)
    assert "rootkit scanner found something suspicious" in text.lower()
    assert "usually normal" not in text


def test_plain_sentence_down_tools_are_not_described_as_clean():
    """The listing said 'Rootkit scan clean' over a raw line reading
    'is down and could not be repaired' — an outright contradiction."""
    from ui import plain
    down = "RKHunter (rootkit scan) is down and could not be repaired automatically"
    assert "clean" not in plain.sentence({"from_tool": "rkhunter", "text": down}).lower()
    assert "not running" in plain.sentence({"from_tool": "rkhunter", "text": down}).lower()
    lynis = "Lynis (audit) is down and could not be repaired automatically"
    assert "not running" in plain.sentence({"from_tool": "lynis", "text": lynis}).lower()


def test_plain_sentence_auditd_avc_denial_is_named():
    """An AppArmor denial relayed through auditd is not 'routine system
    activity' — that is the line the owner asked about ('that denied')."""
    from ui import plain
    t = 'AVC apparmor="DENIED" operation="open" profile="/usr/sbin/clamd"'
    s = plain.sentence({"from_tool": "auditd", "text": t}).lower()
    assert "routine" not in s and "stopped" in s


def test_answer_detail_layer_sentence_is_grammatical():
    """The detail layer names the tool, then says what it does as a
    sentence. The old 'is the layer that {desc}' spliced nonsense."""
    row = {"tool": "auditd", "severity": "MEDIUM",
           "text": "AVC apparmor=DENIED operation=open", "ts": None}
    from assistant.templates import answer_detail
    text = answer_detail(row)
    assert "is the layer that" not in text
    assert "System event log: records system events" in text
