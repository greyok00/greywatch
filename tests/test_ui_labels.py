from ui import labels


def test_raw_daemon_tokens_become_words():
    assert labels.tool_state("GREEN") == ("Live", "ok")
    assert labels.tool_state("YELLOW") == ("Attention", "warn")
    assert labels.tool_state("RED") == ("Down", "fail")
    assert labels.tool_state("what") == ("Unknown", "mute")


def test_posture_and_scan_words_are_stable():
    assert labels.posture(85) == ("Secure", "ok")
    assert labels.posture(65) == ("Needs attention", "warn")
    assert labels.posture(20) == ("At risk", "fail")
    assert labels.posture(None) == ("Withheld", "warn")
    assert labels.scan_state("running") == ("Running", "warn")
    assert labels.scan_state("cancelled") == ("Cancelled", "fail")


def test_display_names_drop_parentheticals():
    assert labels.clean_tool_label("Responderd (auto-responder)") == "Responderd"
    assert labels.clean_tool_label("ClamAV (antivirus)") == "ClamAV"
    assert labels.display_name("yara-watch") == "YARA Watch"
