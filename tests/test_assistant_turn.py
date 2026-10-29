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


def test_pause_the_firewall_is_deterministic_not_model():
    """A live 360M router returned junk on this exact question (empty
    reply, then 'fail2ban'), so the action verbs + tool words decide
    before the model is ever asked. The model's only router job is the
    leftover ambiguity."""
    calls = []

    class FakeLlm:
        def is_ready(self):
            return True

        def ask_sync(self, prompt, max_tokens=48):
            calls.append(prompt)
            return '{"task": "intent", "action": "pause", "tool": "ufw"}'
    out = plan_turn("pause the firewall", _pack(), FakeLlm(), {"ufw"},
                    FRIENDLY)
    assert out["kind"] == "intent"
    assert out["intent"] == Intent("pause", "ufw")
    assert calls == []          # the model was never consulted


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
    # the question is the prompt's LAST line — a tiny model continues the
    # final line, so the instruction text must sit above it (seen live)
    assert out["prompt"].rstrip().endswith("question: what is the meaning of life?")

def test_intent_without_action_json_becomes_summary():
    """A verb-less question that lands the intent slot without action JSON
    becomes a summary turn: nothing executes, nothing stalls."""
    class FakeLlm:
        def is_ready(self):
            return True

        def ask_sync(self, prompt, max_tokens=48):
            return '{"task": "intent", "tool": "pause ufw"}'
    out = plan_turn("what does the risk meter mean?", _pack(),
                    FakeLlm(), {"ufw"}, FRIENDLY)
    assert out["kind"] == "summary"
    assert "intent_reply" not in out


def test_trigger_free_intent_json_still_reaches_the_model_path():
    """No action verb in the question: the model remains the router, and
    a well-formed intent JSON still flows to the confirm gate."""
    class FakeLlm:
        def is_ready(self):
            return True

        def ask_sync(self, prompt, max_tokens=48):
            return 'Sure! {"task": "intent", "action": "pause", "tool": "ufw"}'
    out = plan_turn("what does the risk meter mean?", _pack(),
                    FakeLlm(), {"ufw"}, FRIENDLY)
    assert out["kind"] == "model"
    intent, _ = parse_intent(out["intent_reply"])
    assert intent == Intent("pause", "ufw")


def test_rootkit_question_names_the_rkhunter_events():
    """'what did the rootkit scanner find?' answered the WRONG event (an
    appfw allow line) because the event template showed only the newest
    row overall and ignored the tool the question names."""
    pack = {"recent": [
        {"tool": "appfw", "severity": "MEDIUM",
         "text": "appfw ollama → 34.36.133.15:443 allow",
         "ts": "2026-10-29T20:53:51+00:00"},
        {"tool": "rkhunter", "severity": "HIGH",
         "text": "Warning: The following suspicious (large) shared memory "
                 "segment(s) were found",
         "ts": "2026-10-29T20:50:42+00:00"},
    ]}
    out = plan_turn("what did the rootkit scanner find?", pack, None,
                    {"rkhunter", "appfw"},
                    {"rkhunter": ("Rootkit scanner", "x"),
                     "appfw": ("App firewall", "y")})
    assert out["kind"] == "template" and out["slot"] == "explain_event"
    assert "rkhunter" in out["text"].lower()
    assert "shared memory" in out["text"]
    assert "appfw ollama" not in out["text"]


def test_analyze_logs_is_not_rejected_and_not_model():
    """'"analyze logs' fell to the canned overview (or model slop); the
    widened event net must catch it, model armed or not."""
    class FakeLlm:
        def __init__(self):
            self.calls = 0

        def is_ready(self):
            return True

        def ask_sync(self, prompt, max_tokens=48):
            self.calls += 1
            return "fail2ban"          # what the real 360M model returned
    pack = {"recent": [
        {"tool": "rkhunter", "severity": "HIGH",
         "text": "suspicious shared memory segments",
         "ts": "2026-10-29T20:50:42+00:00"},
    ]}
    llm = FakeLlm()
    out = plan_turn("analyze logs", pack, llm, {"rkhunter"}, FRIENDLY)
    assert out["kind"] == "template"
    assert out["slot"] == "explain_event"
    assert "suspicious shared memory" in out["text"]
    assert llm.calls == 0

def test_red_pause_warning_present():
    from ui.assistant import warning_line
    assert "RED" in warning_line("pause", "RED")


def test_no_warning_for_other_paths():
    from ui.assistant import warning_line
    assert warning_line("pause", "GREEN") == ""
    assert warning_line("resume", "RED") == ""
    assert warning_line("overview", "RED") == ""
