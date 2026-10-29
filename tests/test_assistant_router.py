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


def test_words_only_skips_model():
    router.words_only = True
    try:
        assert router.route("x", ask=lambda p: (_ for _ in ()).throw(
            AssertionError("model must not be called"))) == ("summary", "")
    finally:
        router.words_only = False