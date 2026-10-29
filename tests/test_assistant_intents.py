# tests/test_assistant_intents.py
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from assistant.intents import Intent, INTENTS, describe, parse_intent, validate

FRIENDLY = {"ufw": ("Firewall", "Blocks unwanted connections.")}


def test_parse_valid_intent():
    intent, rest = parse_intent(
        'do it {"task":"intent","action":"pause","tool":"ufw"} now')
    assert intent == Intent("pause", "ufw") and rest == "do it   now"


def test_parse_bad_action_is_mapped():
    intent, _ = parse_intent(
        '{"task":"intent","action":"stop","tool":"ufw"}')  # task intent
    assert intent is not None
    assert intent.action in INTENTS


def test_validate_rejects_unknown_tool():
    reason = validate(Intent("pause", "banana"), {"ufw"})
    assert reason and "banana" in reason
    assert validate(Intent("pause", "ufw"), {"ufw"}) is None
    # overview needs no tool
    assert validate(Intent("overview", ""), {"ufw"}) is None


def test_describe_mentions_plain_name_and_action():
    sentence = describe(Intent("pause", "ufw"), FRIENDLY)
    assert "Firewall" in sentence and "pause" in sentence.lower()
