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


def test_failed_parse_strips_the_json_span():
    for bad in ('plz {"task":intent broken} now',                  # invalid JSON
                'plz {"task":"summary","tool":"ufw"} now',          # wrong task
                'plz {"task":"intent","action":"banana"} now'):     # unmapped
        intent, rest = parse_intent(bad)
        assert intent is None and "{" not in rest and "}" not in rest
    intent, rest = parse_intent("no json at all")
    assert intent is None and rest == "no json at all"


SCANS = {"scan-all": {}, "rkhunter": {}, "clamav": {}}


def test_parse_scan_intent():
    intent, _ = parse_intent(
        '{"task":"intent","action":"scan","tool":"rkhunter"}')
    assert intent == Intent("scan", "rkhunter")
    intent, _ = parse_intent(
        '{"task":"intent","action":"run","tool":"scan-all"}')
    assert intent == Intent("scan", "scan-all")


def test_validate_scan_against_app_scans_only():
    assert validate(Intent("scan", "rkhunter"), {"ufw"}, SCANS) is None
    # a protection name is not a scan key
    assert validate(Intent("scan", "ufw"), {"ufw"}, SCANS) is not None
    assert validate(Intent("scan", "rm -rf /"), {"ufw"}, SCANS) is not None
    # no scan list supplied: nothing may run
    assert validate(Intent("scan", "rkhunter"), {"ufw"}) is not None


def test_describe_scan_uses_the_button_title():
    titles = {"scan-all": "Scan everything", "rkhunter": "Rootkit scan"}
    assert describe(Intent("scan", "rkhunter"), FRIENDLY, titles) \
        == "Start the rootkit scan now?"
    assert "every" in describe(Intent("scan", "scan-all"), FRIENDLY, titles)


# --- settings actions: the window's own controls, one intent each -------

def test_validate_firewall_and_learning_need_on_or_off():
    assert validate(Intent("firewall", value="on"), {"ufw"}) is None
    assert validate(Intent("firewall", value="off"), {"ufw"}) is None
    assert validate(Intent("firewall", value="maybe"), {"ufw"}) is not None
    assert validate(Intent("learning", value="on"), {"ufw"}) is None
    assert validate(Intent("learning", value=""), {"ufw"}) is not None


def test_validate_trust_takes_a_plain_site_only():
    assert validate(Intent("trust_site", value="example.com"), set()) is None
    assert validate(Intent("block_site", value="ads.example.org"), set()) is None
    for bad in ("https://example.com", "example.com/path", "example.com:443",
                "user@example.com", "not a site", ""):
        assert validate(Intent("trust_site", value=bad), set()) is not None


def test_validate_program_needs_a_name():
    assert validate(Intent("trust_program", value="/usr/bin/foo"), set()) is None
    assert validate(Intent("trust_program", value=" "), set()) is not None


def test_validate_pages_and_bulk_actions():
    for page in ("security", "tools", "logs", "settings", "help"):
        assert validate(Intent("open_page", value=page), set()) is None
    assert validate(Intent("open_page", value="wizard"), set()) is not None
    assert validate(Intent("enable_all"), set()) is None
    assert validate(Intent("update_lists"), set()) is None


def test_describe_settings_actions_is_plain_english():
    assert describe(Intent("firewall", value="on"), FRIENDLY) \
        == "Turn the app firewall on?"
    assert "off" in describe(Intent("firewall", value="off"), FRIENDLY)
    assert describe(Intent("trust_site", value="example.com"), FRIENDLY) \
        == "Trust example.com from now on, without asking?"
    assert describe(Intent("open_page", value="logs"), FRIENDLY) \
        == "Open the Logs page?"
    assert describe(Intent("enable_all"), FRIENDLY) \
        == "Turn every stopped protection back on?"


def test_model_json_verbs_map_to_settings_actions():
    intent, _ = parse_intent(
        '{"task":"intent","action":"firewall_off"}')
    assert intent == Intent("firewall", value="off")
    intent, _ = parse_intent(
        '{"task":"intent","action":"block","target":"ads.example.com"}')
    assert intent == Intent("block_site", value="ads.example.com")
    intent, _ = parse_intent('{"task":"intent","action":"open","target":"settings"}')
    assert intent == Intent("open_page", value="settings")
