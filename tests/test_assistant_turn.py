# tests/test_assistant_turn.py
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ui.assistant import plan_turn
from assistant.intents import Intent, parse_intent

from tests.test_assistant_packer import build_pack_for_tests

FRIENDLY = {"ufw": ("Firewall", "Blocks unwanted connections.")}


def _pack():
    return build_pack_for_tests()


def test_overview_is_template_not_model():
    out = plan_turn("is everything ok?", _pack(), None, {"ufw"}, FRIENDLY)
    assert out["kind"] == "template" and out["slot"] == "overview"


def test_intent_question_with_model():
    class FakeLlm:
        def is_ready(self):
            return True

        def ask_sync(self, prompt, max_tokens=48):
            return '{"task": "intent", "action": "pause", "tool": "ufw"}'
    out = plan_turn("pause the firewall", _pack(), FakeLlm(), {"ufw"},
                    FRIENDLY)
    assert out["kind"] == "model"
    intent, _ = parse_intent(out["intent_reply"])
    assert intent == Intent("pause", "ufw")


def test_no_llm_falls_back_to_templates():
    out = plan_turn("explain the newest event", _pack(), None, set(), FRIENDLY)
    assert out["kind"] == "template" and out["slot"] == "explain_event"


def test_unknown_question_becomes_summary_prompt():
    class FakeLlm:
        def is_ready(self):
            return True

        def ask_sync(self, prompt, max_tokens=48):
            return '{"task": "summary"}'
    out = plan_turn("what is the meaning of life?", _pack(), FakeLlm(),
                    {"ufw"}, FRIENDLY)
    assert out["kind"] == "summary" and "pack" in out["prompt"]

def test_intent_without_action_json_becomes_summary():
    """Intent slot whose reply carries no action JSON becomes a summary
    turn: nothing executes, nothing stalls (dead fallback removed)."""
    class FakeLlm:
        def is_ready(self):
            return True

        def ask_sync(self, prompt, max_tokens=48):
            return '{"task": "intent", "tool": "pause ufw"}'
    out = plan_turn("pause ufw", _pack(), FakeLlm(), {"ufw"}, FRIENDLY)
    assert out["kind"] == "summary"
    assert "intent_reply" not in out

def test_red_pause_warning_present():
    from ui.assistant import warning_line
    assert "RED" in warning_line("pause", "RED")


def test_no_warning_for_other_paths():
    from ui.assistant import warning_line
    assert warning_line("pause", "GREEN") == ""
    assert warning_line("resume", "RED") == ""
    assert warning_line("overview", "RED") == ""