# tests/test_assistant_router.py
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import assistant.router as router


def test_route_valid_json():
    r = router.route("is everything ok?",
                     ask=lambda p: '{"task": "overview", "tool": ""}')
    assert r[0] == "overview"


def test_route_extracts_json_from_noisy_reply():
    r = router.route("pause ufw", ask=lambda p: 'sure! {"task":"intent","tool":"ufw"} thanks')
    assert r[0] == "intent" and r[1].find("ufw") >= 0


def test_two_bad_replies_degrade_to_summary():
    asks = iter(["no json here", "still not json"])
    r = router.route("why?", ask=lambda p: next(asks))
    assert r[0] == "summary" and r[1] == ""


def test_unknown_slot_or_bad_tool_degrades():
    r = router.route("x", ask=lambda p: '{"task": "banana"}')
    assert r[0] == "summary"
    r = router.route("x", ask=lambda p: '{"task":"tool_status","tool":"banana"}',
                     tool_names="apparmor ufw")
    assert r[0] == "summary"


def test_retry_resends_full_prompt_with_question():
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        if len(prompts) == 1:
            return "no json yet"
        assert "pause ufw" in prompt and "apparmor ufw" in prompt
        return '{"task":"intent","tool":"ufw"}'

    r = router.route("pause ufw", ask, tool_names="apparmor ufw")
    assert r == ("intent", "ufw") and len(prompts) == 2


def test_words_only_skips_model():
    router.words_only = True
    try:
        assert router.route("x", ask=lambda p: (_ for _ in ()).throw(
            AssertionError("model must not be called"))) == ("summary", "")
    finally:
        router.words_only = False

def test_route_intent_with_action_returns_json_text():
    r = router.route(
        "pause ufw",
        ask=lambda p:
            'sure! {"task":"intent","action":"pause","tool":"ufw"} thanks')
    assert r[0] == "intent"
    assert r[1] == '{"task":"intent","action":"pause","tool":"ufw"}'


def test_route_intent_without_action_keeps_tool_reply():
    r = router.route(
        "pause ufw",
        ask=lambda p: 'sure! {"task":"intent","tool":"ufw"} thanks')
    assert r[0] == "intent" and r[1] == "ufw"


SCANS = "scan-all yara-tmp-scan clamav rkhunter lynis aide"


def test_model_scan_slot_is_normalised_to_a_scan_intent():
    """The live 1.7B answers a scan request with task "scan" and a scan
    name, not with task "intent"; both must reach the same confirm gate."""
    from assistant.intents import parse_intent
    r = router.route("check for spyware",
                     ask=lambda p: '{"task": "scan", "tool": "clamav"}',
                     scan_names=SCANS)
    assert r[0] == "intent"
    assert parse_intent(r[1])[0].action == "scan"
    assert parse_intent(r[1])[0].tool == "clamav"
    # a loose or invented tool falls back to the app's primary button
    for loose in ('{"task":"scan","tool":"scan"}',
                  '{"task":"scan","tool":"/bin/rm"}',
                  '{"task":"intent","action":"scan","tool":"everything"}'):
        r = router.route("scan", ask=lambda p, t=loose: t, scan_names=SCANS)
        assert r[0] == "intent", loose
        assert parse_intent(r[1])[0].tool == "scan-all", loose


def test_model_scan_without_a_scan_list_is_refused():
    r = router.route("scan", ask=lambda p: '{"task":"scan","tool":"clamav"}')
    assert r[0] == "summary"
