from ui.plain import sentence, without_mark


def test_npm_style_path_shows_the_program_not_a_fragment():
    ev = {"from_tool": "tetragon",
          "text": "exec /opt/node/lib/node_modules/demo-cli/bin/demo.exe "
                  "pid=1 -rn X"}
    shown = without_mark(sentence(ev))
    assert shown == "demo.exe started running."


def test_trailing_slash_never_yields_an_empty_program():
    ev = {"from_tool": "tetragon", "text": "exec /tmp/somedir/ pid=7"}
    assert without_mark(sentence(ev)) == "somedir started running."


def test_new_external_listener_is_said_in_plain_words():
    ev = {"from_tool": "responderd", "severity": "HIGH",
          "text": "firewall_drop: new external listener 0.0.0.0:8795 "
                  "— external access blocked"}
    shown = sentence(ev)
    assert "port 8795" in shown
    assert "firewall blocked" in shown
    assert "0.0.0.0" not in shown
