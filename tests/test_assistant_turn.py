# tests/test_assistant_turn.py
import datetime as _dt
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ui.assistant import _connection_target, plan_turn
from assistant.intents import Intent, parse_intent, validate

from tests.test_assistant_packer import build_pack_for_tests

FRIENDLY = {"ufw": ("Firewall", "Blocks unwanted connections.")}


def _today_at(hours):
    """An ISO timestamp for *hours* past local midnight today.

    The time-window rungs compare against the owner's clock, so a fixed
    date in a test starts failing the day after it is written (it did,
    2026-10-30). Negative hours reach back into the previous evening.
    """
    midnight = _dt.datetime.now().astimezone().replace(
        hour=0, minute=0, second=0, microsecond=0)
    return (midnight + _dt.timedelta(hours=hours)).isoformat()


def _pack():
    return build_pack_for_tests()


def test_overview_is_template_not_model():
    out = plan_turn("is everything ok?", _pack(), None, {"ufw"}, FRIENDLY)
    assert out["kind"] == "template" and out["slot"] == "overview"


def test_change_theme_to_light_mode_is_a_theme_intent():
    """The real failing ask (owner 2026-10-30): the request fell through to
    the model, which returned an intent with an empty value, and the user
    saw 'not a page in this app'. Theme asks belong to the deterministic
    settings layer and never reach the model."""
    out = plan_turn("change theme to light mode", _pack(), None,
                    {"ufw"}, FRIENDLY)
    assert out["kind"] == "intent"
    assert out["intent"].action == "theme"
    assert out["intent"].value == "light"
    assert validate(out["intent"], {"ufw"}) is None


def test_dark_mode_without_the_word_theme_is_a_theme_intent():
    out = plan_turn("switch to dark mode", _pack(), None, {"ufw"}, FRIENDLY)
    assert out["kind"] == "intent" and out["intent"].action == "theme"
    assert out["intent"].value == "dark"


def test_look_phrasings_all_route_to_the_theme_intent():
    """The owner's dark request fell past the tight theme/mode patterns and
    the model answered with boilerplate ('The context pack does not
    provide…') — a request whose ask is the look routes to the theme."""
    for low, want in (("change it to dark", "dark"),
                      ("make it light again", "light"),
                      ("go back to dark", "dark"),
                      ("turn off dark mode", "light")):
        out = plan_turn(low, _pack(), None, {"ufw"}, FRIENDLY)
        assert out["kind"] == "intent" and out["intent"].action == "theme"
        assert out["intent"].value == want, low


def test_bare_theme_request_opens_settings():
    out = plan_turn("change the theme", _pack(), None, {"ufw"}, FRIENDLY)
    assert out["kind"] == "intent" and out["intent"].action == "open_page"
    assert out["intent"].value == "settings"


def test_colour_question_is_not_a_theme_intent():
    """'why is the light yellow?' reads like a question — it must answer
    from the pack, not try to switch the view."""
    out = plan_turn("why is the light yellow?", _pack(), None,
                    {"ufw"}, FRIENDLY)
    assert not (out["kind"] == "intent" and out["intent"].action == "theme")


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


DENY_ROW = {"tool": "appfw", "severity": "MEDIUM",
            "text": "deny <unknown> → 172.217.119.4:443 (answered: deny)",
            "ts": "2026-10-29T13:57:09+00:00"}


def test_followup_resolves_to_the_line_it_refers_to():
    """'what is that denied' after a listing must explain THE deny line —
    without an anchor it re-listed the newest events (same canned reply)."""
    rows = [DENY_ROW,
            {"tool": "appfw", "severity": "MEDIUM",
             "text": "appfw chromium → 192.179.30.141:443 allow",
             "ts": "2026-10-29T14:44:18+00:00"}]
    out = plan_turn("what is that denied", {"recent": rows}, None,
                    {"appfw"}, {"appfw": ("App firewall", "x")}, anchor=rows)
    assert out["kind"] == "template" and out["slot"] == "detail"
    assert "answered: deny" in out["text"]
    assert "App firewall" in out["text"]


def test_followup_without_anchor_still_lists():
    out = plan_turn("what is that denied", {"recent": [DENY_ROW]}, None,
                    {"appfw"}, {"appfw": ("App firewall", "x")})
    assert out["kind"] == "template" and out["slot"] == "explain_event"


def test_followup_verbatim_means_newest_shown_row():
    rows = [DENY_ROW]
    out = plan_turn("what does that mean?", {"recent": rows}, None,
                    {"appfw"}, {"appfw": ("App firewall", "x")}, anchor=rows)
    assert out["slot"] == "detail" and "answered: deny" in out["text"]


def test_followup_keyword_finds_the_row_even_outside_the_anchor():
    """'that denied' must reach the deny line even when it has scrolled
    out of the three rows the last listing showed."""
    rows = [{"tool": "appfw", "severity": "MEDIUM",
             "text": "appfw firefox-esr → 151.101.65.91:443 allow",
             "ts": "2026-10-29T14:54:13+00:00"},
            DENY_ROW]
    out = plan_turn("what is that denied", {"recent": rows}, None,
                    {"appfw"}, {"appfw": ("App firewall", "x")},
                    anchor=rows[:1])
    assert out["slot"] == "detail" and "answered: deny" in out["text"]
    assert "firefox-esr" not in out["text"]


def test_followup_denied_prefers_a_real_denial_over_an_armed_blurb():
    """'deny-once' in an engine-armed status line is not a denial. The
    strong forms ('answered: deny', a line starting with deny, DENIED)
    win before a bare substring can match."""
    armed = {"tool": "appfw", "severity": "MEDIUM",
             "text": "appfw engine armed — ask the dashboard popup; deny-once "
                     "when it is closed (headless fallback)",
             "ts": "2026-10-29T21:52:25+00:00"}
    rows = [armed, DENY_ROW]
    out = plan_turn("what is that denied", {"recent": rows}, None,
                    {"appfw"}, {"appfw": ("App firewall", "x")},
                    anchor=rows[:1])
    assert out["slot"] == "detail" and "answered: deny" in out["text"]


# ---- advice rung ----------------------------------------------------------

FULL_FRIENDLY = {
    "rkhunter": ("Rootkit scanner", "Hunts for hidden malware."),
    "ufw": ("Firewall", "Blocks unwanted connections."),
    "fail2ban": ("Intrusion blocker", "Locks out password guessers."),
}


def _advice_pack():
    return {"tools": [
        {"name": "ufw", "state": "RED", "installed": True, "paused": False},
        {"name": "fail2ban", "state": "GREEN", "installed": True,
         "paused": False},
        {"name": "rkhunter", "state": "GREEN", "installed": True,
         "paused": False},
    ], "recent": [
        {"tool": "rkhunter", "severity": "HIGH",
         "text": "Rootkit scanner is down and could not be repaired",
         "ts": _today_at(-2)},          # live clock: the priorities rung
        {"tool": "fail2ban", "severity": "HIGH",   # drops anything older
         "text": "fail2ban banned 203.0.113.9 (sshd)",   # than 24 hours
         "ts": _today_at(-2.1)},
    ], "status_line": "2 of 3 protections green, 1 need attention"}


def test_how_do_i_fix_a_named_tool_uses_the_advice_engine():
    out = plan_turn("how do I fix the rootkit scanner?", _advice_pack(), None,
                    set(FULL_FRIENDLY), FULL_FRIENDLY)
    assert out["kind"] == "template" and out["slot"] == "advice"
    assert "disagreement" in out["text"]        # green column, down in the log
    assert "Rootkit scan" in out["text"]        # the app's real action


def test_what_should_i_do_ranks_priorities():
    out = plan_turn("what should I do?", _advice_pack(), None,
                    set(FULL_FRIENDLY), FULL_FRIENDLY)
    assert out["slot"] == "advice"
    assert "Firewall" in out["text"]            # the stopped layer comes first
    assert out["text"].index("Firewall") < out["text"].index("Rootkit")


def test_how_do_i_fix_that_explains_the_anchored_row():
    pack = _advice_pack()
    anchor = [pack["recent"][1]]                # the fail2ban ban row
    out = plan_turn("how do I fix that?", pack, None, set(FULL_FRIENDLY),
                    FULL_FRIENDLY, anchor=anchor)
    assert out["slot"] == "advice"
    assert "locked out after repeated failed logins" in out["text"]
    assert "fail2ban banned 203.0.113.9" in out["text"]


def test_advice_never_takes_over_an_explicit_action():
    """'pause the firewall' is an action, not a help question, even though
    the pack is bad — the intent rung keeps priority."""
    out = plan_turn("pause the firewall", _advice_pack(), None,
                    set(FULL_FRIENDLY), FULL_FRIENDLY)
    assert out["kind"] == "intent"


def test_is_this_normal_reaches_advice():
    out = plan_turn("is this normal?", {"tools": [], "recent": [
        {"tool": "apparmor", "severity": "MEDIUM",
         "text": "AppArmor DENIED profile=lynis", "ts": "2026-10-29T13:50:00+00:00"}]},
        None, set(FULL_FRIENDLY), FULL_FRIENDLY)
    assert out["slot"] == "advice"
    assert "state column" in out["text"]


# ---- plain-language expansion (live 1.7B run, 2026-10-29) ----------------
#
# These are the live failures the owner hit with the real app data: the
# assistant did not explain the app's own vocabulary, treated an
# explanatory question ("why did the firewall stop?") as a command, lost
# track of the protection a pronoun referred to, answered "last night"
# with the newest row regardless of time, and matched 'quarantined'
# against nothing because the log says 'quarantine:'.

APP_FRIENDLY = {
    "ufw": ("Firewall", "Blocks unwanted connections."),
    "clamav": ("Antivirus", "Scans for viruses."),
    "net-watch": ("Network watcher", "Notes new connections."),
}


def _live_pack():
    return {"tools": [
        {"name": "ufw", "state": "GREEN", "installed": True, "paused": False},
        {"name": "clamav", "state": "GREEN", "installed": True,
         "paused": False},
        {"name": "net-watch", "state": "GREEN", "installed": True,
         "paused": False},
    ], "recent": [
        {"tool": "appfw", "severity": "MEDIUM",
         "text": "appfw <unknown> → 208.82.238.17:443 deny "
                 "[answered: deny]",
         "ts": "2026-10-29T16:07:32+00:00"},
    ], "status_line": "3 of 3 protections green, 0 need attention"}


def test_yellow_is_explained_not_reported_as_status():
    """'what does yellow mean?' came back as 'everything is green' from
    the overview template — accurate and useless to someone who does not
    know the colours."""
    out = plan_turn("what does yellow mean?", _live_pack(), None,
                    set(APP_FRIENDLY), APP_FRIENDLY)
    assert out["kind"] == "template" and out["slot"] == "concept"
    assert "needs attention" in out["text"]
    assert "green" in out["text"].lower()


def test_app_question_does_not_get_captured_by_the_followup_anchor():
    """'i dont understand what this app does' contains 'this', and the old
    ladder answered it with the newest deny line."""
    rows = _live_pack()["recent"]
    out = plan_turn("i dont understand what this app does", _live_pack(),
                    None, set(APP_FRIENDLY), APP_FRIENDLY, anchor=rows)
    assert out["slot"] == "concept"
    assert "GreyWatch" in out["text"]
    assert "answered: deny" not in out["text"]


def test_explanatory_why_is_not_a_pause_intent():
    """'why did the firewall stop?' names a pause verb and a tool; the
    confirm gate must never open for a question."""
    out = plan_turn("why did the firewall stop?", _live_pack(), None,
                    set(APP_FRIENDLY), APP_FRIENDLY)
    assert out["kind"] != "intent"


def test_pronoun_action_resolves_to_the_last_protection():
    out = plan_turn("turn it back on", _live_pack(), None,
                    set(APP_FRIENDLY), APP_FRIENDLY, last_tool="ufw")
    assert out["kind"] == "intent"
    assert out["intent"] == Intent("resume", "ufw")


def test_pronoun_action_without_an_antecedent_asks_which():
    out = plan_turn("turn it back on", _live_pack(), None,
                    set(APP_FRIENDLY), APP_FRIENDLY)
    assert out["kind"] == "template" and out["slot"] == "concept"
    assert "which protection" in out["text"].lower()


def test_stop_everything_is_refused_with_an_explanation():
    out = plan_turn("can you stop everything?", _live_pack(), None,
                    set(APP_FRIENDLY), APP_FRIENDLY)
    assert out["kind"] == "template"
    assert "one protection at a time" in out["text"]


def test_last_night_filters_events_by_time():
    # "last night" is yesterday 18:00 to today 06:00 (capped at now). A row
    # at yesterday noon is outside it at every hour of the day, whatever
    # TZ another test module left in the environment; a row at today 03:00
    # only is when the suite runs before dawn.
    pack = {"tools": [], "status_line": "0 tools", "recent": [
        {"tool": "appfw", "severity": "MEDIUM", "text": "yesterday noon allow",
         "ts": _today_at(-12)},
        {"tool": "appfw", "severity": "MEDIUM", "text": "last night deny",
         "ts": _today_at(-3)},
    ]}
    out = plan_turn("what happened last night?", pack, None, set(),
                    {"appfw": ("App firewall", "x")})
    assert out["kind"] == "template" and out["slot"] == "explain_event"
    assert "last night deny" in out["text"]
    assert "yesterday noon allow" not in out["text"]


def test_quarantined_followup_matches_the_quarantine_line():
    """The log says 'quarantine:', the question says 'quarantined'; exact
    word matching missed it and the answer became the newest deny line."""
    rows = [{"tool": "responderd", "severity": "HIGH",
             "text": "quarantine: /tmp/sample.bin (sha256:275a021b) "
                     "tmpfs:Eicar-Test-Signature — moved to quarantine",
             "ts": "2026-10-29T15:33:11+00:00"},
            {"tool": "appfw", "severity": "MEDIUM",
             "text": "appfw <unknown> → 208.82.238.17:443 deny "
                     "[answered: deny]",
             "ts": "2026-10-29T16:07:32+00:00"}]
    out = plan_turn("why was that quarantined?", {"recent": rows}, None,
                    {"responderd", "appfw"},
                    {"responderd": ("Auto-responder", "x"),
                     "appfw": ("App firewall", "y")}, anchor=rows)
    assert out["kind"] == "template" and out["slot"] == "detail"
    assert "quarantine" in out["text"]
    assert "Auto-responder" in out["text"]


def test_app_firewall_label_pins_appfw_not_ufw():
    """'app firewall' contains the bare 'firewall' label, and dict order
    made the question about the app firewall answer with ufw."""
    pack = {"tools": [
        {"name": "ufw", "state": "GREEN", "installed": True, "paused": False},
        {"name": "appfw", "state": "GREEN", "installed": True,
         "paused": False},
    ], "status_line": "2 of 2 protections green, 0 need attention"}
    friendly = {"ufw": ("Firewall", "Blocks unwanted connections."),
                "appfw": ("App firewall", "Asks before a program connects.")}
    out = plan_turn("what is the app firewall?", pack, None,
                    {"ufw", "appfw"}, friendly)
    assert "appfw" in out["text"]
    assert "asks before programs go online" in out["text"].lower()


def test_two_named_tools_are_both_explained():
    pack = {"tools": [
        {"name": "ufw", "state": "GREEN", "installed": True, "paused": False},
        {"name": "appfw", "state": "GREEN", "installed": True,
         "paused": False},
    ], "status_line": "2 of 2 protections green, 0 need attention"}
    friendly = {"ufw": ("Firewall", "Blocks unwanted connections."),
                "appfw": ("App firewall", "Asks before a program connects.")}
    out = plan_turn("what is the difference between the firewall and the "
                    "app firewall?", pack, None, {"ufw", "appfw"}, friendly)
    assert "(ufw)" in out["text"] and "(appfw)" in out["text"]
    assert out["text"].index("(ufw)") < out["text"].index("(appfw)")


def test_quarantine_is_explained_as_the_app_action():
    out = plan_turn("what does quarantine mean?", _live_pack(), None,
                    set(APP_FRIENDLY), APP_FRIENDLY)
    assert out["slot"] == "concept"
    assert "safe holding area" in out["text"]


def test_the_suggested_quarantine_followup_reads_the_line():
    """The concept answer tells the owner to ask 'explain the quarantined
    file'. That sentence used to match the concept branch again, so the
    assistant repeated its definition and never read the line it had just
    promised — a loop the owner hit live."""
    rows = [{"tool": "responderd", "severity": "HIGH",
             "text": "quarantine: /tmp/sample.bin (sha256:275a021b) "
                     "tmpfs:Eicar-Test-Signature — moved to quarantine",
             "ts": "2026-10-29T19:19:39+00:00"}]
    pack = {"recent": rows, "history": rows, "tools": [],
            "status_line": "1 of 1 protections green"}
    friendly = {"responderd": ("Auto-responder", "Reacts automatically.")}
    out = plan_turn("explain the quarantined file", pack, None,
                    {"responderd"}, friendly)
    assert out["slot"] == "explain_event"
    assert out["rows"] == rows
    assert "raw: quarantine: /tmp/sample.bin" in out["text"]
    assert "safe holding area" not in out["text"]   # the definition loop


def test_quarantine_line_question_with_no_rows_is_honest():
    pack = {"recent": [], "history": [], "tools": [],
            "status_line": "1 of 1 protections green"}
    out = plan_turn("explain the quarantined file", pack, None,
                    {"responderd"}, {})
    assert out["slot"] == "explain_event" and out["rows"] == []
    assert "No quarantine is recorded" in out["text"]


def test_advice_about_a_quarantined_file_reads_that_row():
    """'what should i do about the quarantined file?' matched the 'File
    integrity' label and answered 'nothing to do' about aide."""
    rows = [{"tool": "responderd", "severity": "HIGH",
             "text": "quarantine: /tmp/sample.bin moved to quarantine, "
                     "restorable",
             "ts": "2026-10-29T15:33:11+00:00"}]
    pack = {"tools": [
        {"name": "aide", "state": "GREEN", "installed": True, "paused": False},
        {"name": "responderd", "state": "GREEN", "installed": True,
         "paused": False},
    ], "recent": rows, "status_line": "2 of 2 protections green"}
    friendly = {"aide": ("File integrity", "Tripwire for system files."),
                "responderd": ("Auto-responder", "Reacts to danger.")}
    out = plan_turn("what should i do about the quarantined file?", pack,
                    None, set(friendly), friendly)
    assert out["slot"] == "advice"
    assert "quarantine" in out["text"].lower()
    assert "File integrity" not in out["text"]


def test_model_answer_that_invents_a_down_protection_is_dropped():
    from ui.assistant import contradicts_status
    pack = {"tools": [
        {"name": "ufw", "state": "GREEN", "installed": True, "paused": False},
    ]}
    assert contradicts_status(
        "The firewall is not running, which is why connections are blocked.",
        pack)
    assert not contradicts_status("Yellow means a protection needs "
                                  "attention.", pack)


def test_blocking_question_reads_deny_rows_not_newest_rows():
    """'why does my computer keep blocking connections?' used to answer
    with the three newest rows, which on a quiet minute are allows."""
    pack = {"tools": [{"name": "appfw", "state": "GREEN", "installed": True,
                       "paused": False}],
            "status_line": "1 of 1 protections green",
            "recent": [{"tool": "appfw", "severity": "MEDIUM",
                        "text": "appfw brave → 142.251.152.4:443 allow",
                        "ts": "2026-10-29T16:20:25+00:00"}],
            "history": [{"tool": "appfw", "severity": "MEDIUM",
                         "text": "appfw <unknown> → 208.82.238.225:443 "
                                 "deny [answered: deny]",
                         "ts": "2026-10-29T16:16:42+00:00"}]}
    friendly = {"appfw": ("App firewall", "Asks before a program connects.")}
    out = plan_turn("why does my computer keep blocking connections?", pack,
                    None, {"appfw"}, friendly)
    assert "208.82.238.225" in out["text"]
    assert "allow" not in out["text"].split("A deny line")[0]


def test_blocking_question_about_ufw_names_the_layer_that_denies():
    pack = {"tools": [{"name": "ufw", "state": "GREEN", "installed": True,
                       "paused": False},
                      {"name": "appfw", "state": "GREEN", "installed": True,
                       "paused": False}],
            "status_line": "2 of 2 protections green",
            "recent": [], "history": [
                {"tool": "appfw", "severity": "MEDIUM",
                 "text": "appfw <unknown> → 208.82.238.225:443 deny",
                 "ts": "2026-10-29T16:16:42+00:00"}]}
    friendly = {"ufw": ("Firewall", "Blocks unwanted connections."),
                "appfw": ("App firewall", "Asks before a program connects.")}
    out = plan_turn("why is the firewall blocking connections?", pack, None,
                    {"ufw", "appfw"}, friendly)
    assert "no denied connections from Firewall (ufw)" in out["text"]
    assert "(appfw)" in out["text"]


def test_breakin_howto_explains_signs_then_checks_the_log():
    pack = {"tools": [{"name": "appfw", "state": "GREEN", "installed": True,
                       "paused": False}],
            "status_line": "1 of 1 protections green",
            "recent": [{"tool": "appfw", "severity": "MEDIUM",
                        "text": "appfw <unknown> → 208.82.238.225:443 deny",
                        "ts": "2026-10-29T16:16:42+00:00"}],
            "history": []}
    friendly = {"appfw": ("App firewall", "Asks before a program connects.")}
    out = plan_turn("how can i tell if someone is trying to break in?", pack,
                    None, {"appfw"}, friendly)
    assert "signs that matter" in out["text"]
    assert "1 denied connections" in out["text"]
    assert "break-in" in out["text"]


def test_time_scoped_what_happened_summarizes_the_window():
    rows = [{"tool": "appfw", "severity": "MEDIUM",
             "text": "appfw brave → 142.251.152.4:443 allow",
             "ts": _today_at(0)}]
    pack = {"tools": [], "status_line": "0 of 0", "recent": [], "history": rows}
    out = plan_turn("explain what happened today in simple words?", pack, None,
                    set(), {})
    assert "routine records, not alarms" in out["text"]
    assert "raw:" not in out["text"]


# ---- 2026-10-29: the owner's live defects -------------------------------

_GREEN = {"tools": {"ufw": {"state": "GREEN", "installed": True}}}


def _green_pack(events=(), question="x"):
    from assistant.packer import build_pack
    return build_pack(_GREEN, list(events), question, registry=None,
                      history=[])


def test_blocked_program_question_is_not_the_app_introduction():
    """'should I worry about the program that was blocked?' contains the
    app's own noun ('program') and used to get the canned introduction."""
    out = plan_turn("should I worry about the program that was blocked?",
                    _pack(), None, {"ufw"}, FRIENDLY)
    assert "GreyWatch is a local security dashboard" not in out.get("text", "")


def test_which_program_was_blocked_names_the_program():
    """The owner asked 'what program was blocked' and got 'Yes — connections
    are being refused': the count, not the program (2026-10-29)."""
    pack = {"tools": [{"name": "appfw", "state": "GREEN", "installed": True,
                       "paused": False}],
            "status_line": "1 of 1 protections green",
            "recent": [{"tool": "appfw", "severity": "MEDIUM",
                        "text": "appfw /usr/bin/curl → 208.82.238.129:443 "
                                "deny [answered: deny]",
                        "ts": "2026-10-29T23:45:41+00:00"}],
            "history": []}
    friendly = {"appfw": ("App firewall", "Asks before programs go online.")}
    out = plan_turn("what program was blocked?", pack, None,
                    {"appfw"}, friendly)
    text = out["text"]
    assert text.startswith("The newest block is /usr/bin/curl")
    assert not text.startswith("Yes")
    assert "App firewall" in text


def test_which_program_was_blocked_admits_the_log_has_no_name():
    """appfw writes <unknown> when it cannot resolve the process. Inventing
    a program would be worse than saying so."""
    pack = {"tools": [{"name": "appfw", "state": "GREEN", "installed": True,
                       "paused": False}],
            "status_line": "1 of 1 protections green",
            "recent": [], "history": [
                {"tool": "appfw", "severity": "MEDIUM",
                 "text": "appfw <unknown> → 208.82.238.129:443 "
                         "deny [answered: deny]",
                 "ts": "2026-10-29T23:45:41+00:00"}]}
    friendly = {"appfw": ("App firewall", "Asks before programs go online.")}
    out = plan_turn("what program was blocked?", pack, None,
                    {"appfw"}, friendly)
    text = out["text"]
    assert text.startswith("The log does not name the program")
    assert "identity card" in text
    assert not text.startswith("Yes")


def test_which_program_was_blocked_on_a_ufw_line_does_not_claim_unknown():
    """ufw rules log addresses, not processes. Saying 'the program field
    reads <unknown>' about a ufw line would be a made-up field."""
    pack = {"tools": [{"name": "ufw", "state": "GREEN", "installed": True,
                       "paused": False}],
            "status_line": "1 of 1 protections green",
            "recent": [{"tool": "ufw", "severity": "MEDIUM",
                        "text": "BLOCK IN=eth0 SRC=45.155.205.233 "
                                "DST=192.168.1.5 PROTO=TCP DPT=23",
                        "ts": "2026-10-29T23:45:41+00:00"}],
            "history": []}
    friendly = {"ufw": ("Firewall", "Controls network connections.")}
    out = plan_turn("what program was blocked?", pack, None,
                    {"ufw"}, friendly)
    text = out["text"]
    assert "records addresses and ports" in text
    assert "<unknown>" not in text
    assert "45.155.205.233" in text


def test_connection_target_reads_the_newest_block_for_the_picture_strip():
    pack = {"recent": [], "history": [
        {"tool": "appfw", "severity": "MEDIUM",
         "text": "appfw /usr/bin/curl → 208.82.238.129:443 deny",
         "ts": "2026-10-29T23:45:41+00:00"}]}
    assert _connection_target(pack, {}) == ("/usr/bin/curl", "208.82.238.129")


def test_connection_target_never_invents_a_program_from_an_unknown_line():
    pack = {"recent": [], "history": [
        {"tool": "appfw", "severity": "MEDIUM",
         "text": "appfw <unknown> → [2606:4700::6810:1]:443 deny",
         "ts": "2026-10-29T23:45:41+00:00"}]}
    assert _connection_target(pack, {}) == ("", "2606:4700::6810:1")


def test_connection_target_reads_address_only_firewalls():
    pack = {"recent": [
        {"tool": "ufw", "severity": "MEDIUM",
         "text": "BLOCK IN=eth0 SRC=45.155.205.233 DST=192.168.1.5 "
                 "PROTO=TCP DPT=23",
         "ts": "2026-10-29T23:45:41+00:00"}], "history": []}
    assert _connection_target(pack, {}) == ("", "45.155.205.233")


def test_connection_target_ignores_a_row_about_no_destination():
    pack = {"recent": [
        {"tool": "rkhunter", "severity": "HIGH",
         "text": "Warning: hidden file /tmp/.evil", "ts": ""}]}
    assert _connection_target(pack, {}) is None


def test_why_question_about_blocking_does_not_open_with_yes():
    """'why does my computer keep blocking connections?' is not a yes/no
    question; 'Yes —' answered a question nobody asked."""
    pack = {"tools": [{"name": "appfw", "state": "GREEN", "installed": True,
                       "paused": False}],
            "status_line": "1 of 1 protections green",
            "recent": [], "history": [
                {"tool": "appfw", "severity": "MEDIUM",
                 "text": "appfw <unknown> → 208.82.238.129:443 deny",
                 "ts": "2026-10-29T23:45:41+00:00"}]}
    friendly = {"appfw": ("App firewall", "Asks before programs go online.")}
    out = plan_turn("why does my computer keep blocking connections?", pack,
                    None, {"appfw"}, friendly)
    assert out["text"].startswith("Connections are being refused")
    yes = plan_turn("are connections being blocked?", pack, None,
                    {"appfw"}, friendly)
    assert yes["text"].startswith("Yes — connections are being refused")


def test_why_is_my_machine_safe_is_a_verdict_not_a_repair_list():
    """Bare 'why is …' used to count as a fix request in every context."""
    out = plan_turn("why is my machine safe right now?", _green_pack(),
                    None, {"ufw"}, FRIENDLY)
    text = out.get("text", "")
    assert "most important first" not in text
    assert "Short answer" in text


def test_under_attack_question_gets_the_evidence_verdict():
    out = plan_turn("am i under attack?", _pack(), None, {"ufw"}, FRIENDLY)
    assert out["kind"] == "template" and out["slot"] == "advice"
    assert "Short answer" in out["text"]
    assert "What the log holds" in out["text"]


def test_explain_this_alert_prefers_a_serious_line_over_a_newer_allow():
    rows = [{"from_tool": "appfw", "severity": "HIGH",
             "text": "appfw brave → 203.0.113.9:443 deny [answered: deny]",
             "ts": "2026-10-29T08:00:00+00:00"},
            {"from_tool": "appfw", "severity": "MEDIUM",
             "text": "appfw brave → 66.85.137.107:443 allow",
             "ts": "2026-10-29T16:00:00+00:00"}]
    out = plan_turn("explain this alert", _green_pack(rows, "explain this"),
                    None, {"ufw"}, FRIENDLY)
    assert "deny" in out["text"]
    assert "allow" not in out["text"]


def test_priorities_ignore_the_test_fixture_quarantine():
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    rows = [{"from_tool": "responderd", "severity": "HIGH",
             "text": "quarantine: /tmp/pytest-of-grey/pytest-34/"
                     "test_yara_hit_test0/sample.bin (sha256:275a021b) "
                     "tmpfs:Eicar-Test-Signature — moved to quarantine",
             "ts": now}]
    out = plan_turn("what needs attention?", _green_pack(rows, "attention"),
                    None, {"ufw"}, FRIENDLY)
    text = out.get("text", "")
    assert "test fixtures" in text
    assert "1. " not in text          # no ranked item was invented


def test_crash_question_with_no_crash_lines_says_so():
    rows = [{"from_tool": "appfw", "severity": "MEDIUM",
             "text": "appfw chrome → 1.2.3.4:443 allow",
             "ts": "2026-10-29T16:00:00+00:00"}]
    out = plan_turn("is it bad that chrome crashed?",
                    _green_pack(rows, "crash"), None, {"ufw"}, FRIENDLY)
    assert "no crashed lines" in out["text"]
    assert "A program allowed" not in out["text"]


def test_crash_question_with_a_crash_row_finds_that_row():
    rows = [{"from_tool": "appfw", "severity": "MEDIUM",
             "text": "appfw chrome → 1.2.3.4:443 allow",
             "ts": "2026-10-29T16:00:00+00:00"},
            {"from_tool": "auditd", "severity": "MEDIUM",
             "text": "ANOM_ABEND auid=1000 comm=chrome",
             "ts": "2026-10-29T15:00:00+00:00"}]
    out = plan_turn("is it bad that chrome crashed?",
                    _green_pack(rows, "crash"), None, {"ufw"}, FRIENDLY)
    assert out["slot"] == "detail"
    assert "crash" in out["text"].lower()


def test_scan_requests_are_deterministic_intents():
    """"scan for rootkits" asks the app to act; it must reach the confirm
    gate without the model guessing, and it must name the app's own scan
    button (rkhunter), never a command."""
    cases = {
        "scan for rootkits": "rkhunter",
        "run a full antivirus scan": "clamav",
        "check my file integrity": "aide",
        "run a security audit": "lynis",
        "do a quick scan": "yara-tmp-scan",
        "scan my computer": "scan-all",
        "can you scan for malware": "clamav",
    }
    for question, key in cases.items():
        out = plan_turn(question, _pack(), None, {"ufw"}, FRIENDLY)
        assert out["kind"] == "intent", question
        assert out["intent"] == Intent("scan", key), question


def test_scan_questions_are_not_scan_requests():
    """"the scan finished?" and "how do I scan?" are questions. Staging a
    scan for them would act on a question the user did not ask."""
    for question in ("the scan finished?", "did it scan for rootkits?",
                     "how do I scan for rootkits?", "should I run a scan?",
                     "does the rootkit scan run daily?"):
        out = plan_turn(question, _pack(), None, {"ufw"}, FRIENDLY)
        assert out["kind"] != "intent", question


def test_scan_howto_and_history_are_answered_not_acted_on():
    """"How do I scan for rootkits?" must explain the confirm box, and
    "did it scan?" must read the scanner state — neither may stage an
    action."""
    how = plan_turn("how do I scan for rootkits?", _pack(), None, {"ufw"},
                    FRIENDLY)
    assert how["kind"] == "template" and how["slot"] == "concept"
    assert "scan for rootkits" in how["text"]
    assert "confirm" in how["text"].lower()

    did = plan_turn("did it scan for rootkits?", _pack(), None, {"ufw"},
                    FRIENDLY)
    assert did["kind"] == "template"


def test_spyware_request_maps_to_the_antivirus_scan():
    out = plan_turn("please check my machine for spyware", _pack(), None,
                    {"ufw"}, FRIENDLY)
    assert out["kind"] == "intent"
    assert out["intent"] == Intent("scan", "clamav")


# --- settings intents: the assistant may work the window's own controls --

def test_firewall_and_learning_reach_the_confirm_gate():
    out = plan_turn("turn on the app firewall", _pack(), None, {"ufw"},
                    FRIENDLY)
    assert out["kind"] == "intent"
    assert out["intent"] == Intent("firewall", value="on")
    out = plan_turn("disable learning mode", _pack(), None, {"ufw"}, FRIENDLY)
    assert out["intent"] == Intent("learning", value="off")


def test_list_trust_and_page_requests_are_deterministic():
    assert plan_turn("update the block lists", _pack(), None, set(), FRIENDLY)[
        "intent"] == Intent("update_lists")
    assert plan_turn("trust example.com", _pack(), None, set(), FRIENDLY)[
        "intent"] == Intent("trust_site", value="example.com")
    assert plan_turn("trust the program /usr/bin/foo", _pack(), None, set(),
                     FRIENDLY)["intent"] == Intent("trust_program",
                                                  value="/usr/bin/foo")
    assert plan_turn("open the logs", _pack(), None, set(), FRIENDLY)[
        "intent"] == Intent("open_page", value="logs")


def test_turn_everything_back_on_is_allowed_but_off_is_refused():
    out = plan_turn("turn everything back on", _pack(), None, {"ufw"},
                    FRIENDLY)
    assert out["kind"] == "intent" and out["intent"].action == "enable_all"
    out = plan_turn("turn everything off", _pack(), None, {"ufw"}, FRIENDLY)
    assert out["kind"] == "template"
    assert "not switch every protection off" in out["text"]


def test_a_question_about_the_firewall_is_not_a_firewall_change():
    out = plan_turn("why did the firewall stop?", _pack(), None, {"ufw"},
                    FRIENDLY)
    assert out["kind"] != "intent"


# --- unblocking: the ask must act on the block the log shows -------------

def _deny_pack():
    """Newest event is an app-firewall denial, like the owner's session:
    'appfw chromium → 52.92.36.48:443 deny' (owner 2026-10-30)."""
    return {"tools": {}, "recent": [
        {"tool": "appfw", "severity": "MEDIUM", "ts": _today_at(10),
         "text": "appfw chromium → 52.92.36.48:443 deny [ask]"},
        {"tool": "appfw", "severity": "MEDIUM", "ts": _today_at(9),
         "text": "appfw chromium → 52.94.8.11:443 deny [ask]"}]}


def test_unblock_last_blocked_site_offers_the_allow_intent():
    """The real failing ask (owner 2026-10-30): it fell through to the
    locking advice — the same refusal explanation every time — instead of
    the confirm-gated allow the trust list already supports."""
    out = plan_turn("unblock last blocked site", _deny_pack(), None,
                    set(), FRIENDLY)
    assert out["kind"] == "intent"
    assert out["intent"] == Intent("trust_site", value="52.92.36.48")
    assert validate(out["intent"], set()) is None


def test_unblock_pronoun_resolves_to_the_newest_denial():
    out = plan_turn("unblock it", _deny_pack(), None, set(), FRIENDLY)
    assert out["kind"] == "intent"
    assert out["intent"].value == "52.92.36.48"      # newest, not the one below


def test_unblock_it_prefers_the_rows_the_conversation_show():
    anchor = [{"tool": "appfw", "severity": "MEDIUM", "ts": _today_at(12),
               "text": "appfw firefox → 3.14.15.9:443 deny [ask]"}]
    out = plan_turn("unblock that site", _deny_pack(), None, set(),
                    FRIENDLY, anchor=anchor)
    assert out["kind"] == "intent"
    assert out["intent"].value == "3.14.15.9"


def test_allow_the_last_blocked_site_routes_the_same_way():
    out = plan_turn("allow the last blocked site", _deny_pack(), None,
                    set(), FRIENDLY)
    assert out["kind"] == "intent"
    assert out["intent"] == Intent("trust_site", value="52.92.36.48")


def test_unblock_a_named_site_needs_no_log_line():
    out = plan_turn("unblock example.com", _pack(), None, set(), FRIENDLY)
    assert out["kind"] == "intent"
    assert out["intent"] == Intent("trust_site", value="example.com")


def test_how_do_i_unblock_is_still_advice_not_an_action():
    out = plan_turn("how do I unblock the last blocked site?", _deny_pack(),
                    None, set(), FRIENDLY)
    assert out["kind"] != "intent"


def test_no_logged_denial_leaves_the_ask_unrouted():
    out = plan_turn("unblock the last blocked site", _pack(), None,
                    set(), FRIENDLY)
    assert out["kind"] != "intent"


def test_fail2ban_ban_is_not_silently_unblocked():
    """The trust list steers the app firewall only; a fail2ban ban is not
    lifted by allowing a site, so the rung refuses and the advice covers
    the tool that holds the block."""
    pack = {"tools": {}, "recent": [
        {"tool": "fail2ban", "severity": "HIGH", "ts": _today_at(10),
         "text": "Ban 203.0.113.7"}]}
    out = plan_turn("unblock the last blocked site", pack, None,
                    set(), FRIENDLY)
    assert out["kind"] != "intent"


def test_advice_offers_the_one_action_the_app_can_take():
    pack = build_pack_for_tests()
    tool = {"name": "lynis", "state": "YELLOW", "label": "Lynis (audit)",
            "installed": True, "paused": False}
    pack["tools"] = pack["tools"] + [tool]
    friendly = dict(FRIENDLY, lynis=("Lynis", "Scores security."))
    out = plan_turn("how do I fix lynis?", pack, None, {"lynis"}, friendly)
    assert out["slot"] == "advice"
    assert out["suggest"] == Intent("scan", "lynis")
    tool["paused"] = True
    out = plan_turn("how do I fix lynis?", pack, None, {"lynis"}, friendly)
    assert out["suggest"] == Intent("resume", "lynis")
