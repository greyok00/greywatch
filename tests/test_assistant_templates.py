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
