from ui.settings import TrustList
from appfw.base import Conn
from appfw.policy import Policy, decide
from appfw import rules as R


def _conn(**kw):
    c = Conn()
    c.process_path = kw.get("process_path", "/usr/bin/curl")
    c.dst_host = kw.get("dst_host", "")
    c.dst_ip = kw.get("dst_ip", "")
    c.dst_port = kw.get("dst_port", 0)
    c.process_args = list(kw.get("process_args", []))
    return c


def test_trust_roundtrip(tmp_path):
    tp = tmp_path / "trust.json"
    tl = TrustList(tp)
    assert tl.add("example.com", "allow")
    assert tl.add("tracker.example", "block")
    tl2 = TrustList(tp)
    assert "example.com" in tl2.allow and "tracker.example" in tl2.block


def test_a_stale_instance_cannot_erase_the_wizards_site(tmp_path):
    tp = tmp_path / "trust.json"
    settings_view = TrustList(tp)          # loaded at app start
    wizard = TrustList(tp)                 # the wizard's instance
    assert wizard.add("from-wizard.example", "allow")
    assert settings_view.add("from-settings.example", "allow")
    fresh = TrustList(tp)
    assert fresh.allow == {"from-wizard.example", "from-settings.example"}


def test_trust_suffix_match():
    tl = TrustList()
    tl.allow = {"example.com"}
    assert tl.decide("www.example.com") == "allow"
    assert tl.decide("example.com") == "allow"
    assert tl.decide("notexample.com") is None


def test_trust_block_wins_over_allow():
    tl = TrustList()
    tl.allow = {"example.com"}
    tl.block = {"ads.example.com"}
    assert tl.decide("ads.example.com") == "block"
    assert tl.decide("www.example.com") == "allow"


def test_trust_rejects_bad_entries():
    tl = TrustList()
    assert not tl.add("", "allow")
    assert not tl.add("bad space in", "allow")
    assert not tl.add("ok.com", "frobnicate")


def test_policy_auto_allow_no_dialog(tmp_path):
    tl = TrustList()
    tl.add("google.com", "allow")
    tl.add("telemetry.example", "block")
    got = []
    policy = Policy(tmp_path, trust_list=tl)
    act, dur, note, op = decide(_conn(dst_host="www.google.com"), policy,
                                ask=lambda s: got.append(s) or ("deny", "once"))
    assert (act, dur) == ("allow", "always") and op == "www.google.com"
    assert not got                       # NO dialog for trusted site
    act, dur, note, op = decide(_conn(dst_host="telemetry.example"),
                                policy, ask=lambda s: got.append(s) or ("deny", "once"))
    assert (act, dur) == ("deny", "always")
    assert not got


def test_answer_keys_a_site_or_program_operator(tmp_path):
    policy = Policy(tmp_path)
    act, dur, note, op = decide(_conn(dst_host="www.google.com"), policy,
                                ask=lambda s: ("allow", "always", "google.com"))
    rule = R.rule_from_decision(_conn(dst_host="www.google.com"),
                                act, dur, host=op)
    assert rule.op_kind == "dst.host" and rule.op_value == "google.com"
    r2 = R.rule_from_decision(_conn(process_path="/usr/bin/curl"),
                              "deny", "once", host=None)
    assert r2.op_kind == "process.path"
    assert r2.op_value == "/usr/bin/curl"
    assert r2.created > 0


def test_learning_mode_is_time_boxed_and_off_by_default(tmp_path):
    from ui.settings import LearningStore
    ls = LearningStore(tmp_path / "learning.json")
    assert not ls.active()
    assert ls.start(60)
    assert ls.active()
    assert ls.stop()
    assert not ls.active()


def test_learning_allows_once_and_records_the_pair(tmp_path):
    import time, json as _json
    (tmp_path / "learning.json").write_text(
        _json.dumps({"until": time.time() + 60}))
    tl = TrustList(tmp_path / "trust.json")
    tl.add("blocked.example", "block")
    policy = Policy(tmp_path, trust_list=tl)
    act, dur, note, op = decide(_conn(dst_host="example.org", dst_port=443),
                                policy)
    assert (act, dur) == ("allow", "once")
    ledger = (tmp_path / "learning-seen.jsonl").read_text()
    assert "example.org" in ledger
    act, dur, note, op = decide(_conn(dst_host="blocked.example"), policy)
    assert (act, dur) == ("deny", "always")   # explicit block not learned away
    lines = (tmp_path / "learning-seen.jsonl").read_text().splitlines()
    assert len(lines) == 1


def test_the_chain_sees_a_trust_edit_without_a_restart(tmp_path):
    tl = TrustList(tmp_path / "trust.json")
    policy = Policy(tmp_path, trust_list=tl)
    c = _conn(dst_host="late-trust.example")
    assert decide(c, policy, ask=lambda s: ("deny", "once"))[0] == "deny"
    tl.add("late-trust.example", "allow")
    assert decide(c, policy)[0] == "allow"


def test_block_unknown_is_a_real_persisted_mode(tmp_path):
    from ui.settings import FirewallModeStore
    path = tmp_path / "mode.json"
    st = FirewallModeStore(path)
    assert not st.block_unknown
    assert st.set_block_unknown(True)
    assert FirewallModeStore(path).block_unknown


def test_block_unknown_denies_and_records_but_trusted_still_wins(tmp_path):
    from ui.settings import FirewallModeStore
    FirewallModeStore(tmp_path / "firewall-mode.json").set_block_unknown(True)
    tl = TrustList(tmp_path / "trust.json")
    tl.add("allowed.example", "allow")
    policy = Policy(tmp_path, trust_list=tl)
    act, dur, note, op = decide(_conn(dst_host="new.example"), policy)
    assert (act, dur) == ("deny", "once")
    ledger = (tmp_path / "learning-seen.jsonl").read_text()
    assert "new.example" in ledger
    act, dur, *_ = decide(_conn(dst_host="www.allowed.example"), policy)
    assert (act, dur) == ("allow", "always")


def test_downloaded_blocklist_denies_but_trust_can_override(tmp_path):
    from ui import blocklist
    path = tmp_path / "bl.txt"
    path.write_text("0.0.0.0 ads.example\n")
    bl = blocklist.BlockList(path)
    tl = TrustList(tmp_path / "trust.json")
    policy = Policy(tmp_path, trust_list=tl, blocklist=bl)
    act, dur, note, op = decide(_conn(dst_host="x.ads.example"), policy)
    assert (act, dur) == ("deny", "once")
    tl.add("ads.example", "allow")
    act, dur, note, op = decide(_conn(dst_host="x.ads.example"), policy)
    assert (act, dur) == ("allow", "always")


def test_owner_local_services_are_not_intercepted(tmp_path):
    got = []
    policy = Policy(tmp_path)
    for port in (8888, 8899):
        c = _conn(dst_ip="127.0.0.1", dst_port=port)
        act, dur, note, op = decide(c, policy,
                                    ask=lambda s: got.append(s) or ("deny", "once"))
        assert (act, dur) == ("allow", "once")
    assert not got                          # no prompt, no decision needed
    other = _conn(dst_ip="127.0.0.1", dst_port=9999)
    assert decide(other, policy,
                  ask=lambda s: got.append(s) or ("deny", "once"))[0] == "deny"
    remote = _conn(dst_ip="203.0.113.9", dst_port=8888)
    assert decide(remote, policy,
                  ask=lambda s: got.append(s) or ("deny", "once"))[0] == "deny"


def test_trusted_folder_covers_interpreter_run_tools(tmp_path):
    tl = TrustList(tmp_path / "trust.json")
    assert tl.add_app("/opt/search-helper/")
    assert tl.decide_app(
        "/usr/bin/python3",
        ["/opt/search-helper/portal/serve.py"]) == "allow"
    assert tl.decide_app("/usr/bin/python3", ["/tmp/evil.py"]) is None
    assert tl.add_app("/usr/local/bin/ollama")
    assert tl.decide_app("/usr/local/bin/ollama") == "allow"


def test_policy_passes_script_arguments_to_the_trust_check(tmp_path):
    tl = TrustList(tmp_path / "trust.json")
    tl.add_app("/opt/agent-suite/")
    policy = Policy(tmp_path, trust_list=tl)
    c = _conn(dst_host="search.example", dst_port=443)
    c.process_args = ["/opt/agent-suite/lib/scraper/gatherer_mcp.py"]
    act, dur, note, op = decide(c, policy)
    assert (act, dur) == ("allow", "always")
