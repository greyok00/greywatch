"""Round-3 audit regression pins.

Each test here was a probe the round-3 auditors ran when they found the
defect; the fix lands with the pin so the defect stays fixed:
Firefox grants in milliseconds, an AI reply that is JSON but not an
object, a flush that must retry rather than drop, a poll that must
rotate when the port goes quiet, an inbox that walks past a capture
whose mtime never settles, IPv6 hosts that survive HAR parsing, and a
persistence subject that changes when a new line is planted.
"""
import datetime as _dt
import json
import os
import sqlite3
import pathlib
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hunter import browsers, engine, explain, main, store, web, watch

from appfw import base, config as appfw_config, engine as appfw_engine
from appfw import policy as appfw_policy, rules as appfw_rules
from appfw import sites as appfw_sites
from appfw.askgate import AskGate


# ------------------------------------------------- Firefox grants in ms

def _fx_db(tmp_path, modification_ms):
    db = tmp_path / "permissions.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE moz_perms (origin TEXT, type TEXT,"
                 " permission INTEGER, modificationTime INTEGER)")
    conn.execute("INSERT INTO moz_perms VALUES"
                 " ('https://pushy.example', 'desktop-notification', 1, ?)",
                 (modification_ms,))
    conn.commit()
    conn.close()
    return db


def test_firefox_notification_grant_reads_milliseconds(tmp_path):
    # modificationTime is ms since the epoch: a grant made a moment ago
    # reads ~1.8e12. Under the old microseconds arithmetic its age was
    # ~20,700 days and every real Firefox grant was skipped as ancient.
    fresh_ms = int(time.time() * 1000)
    db = _fx_db(tmp_path, fresh_ms)
    found = browsers._notification_rows(db, "firefox")
    assert len(found) == 1
    assert "pushy.example" in json.dumps(found[0])


def test_firefox_grant_really_old_stays_silent(tmp_path):
    old_ms = int(time.time() * 1000) - 400 * 86_400_000
    assert browsers._notification_rows(_fx_db(tmp_path, old_ms),
                                       "firefox") == []


# --------------------------------------- AI reply that is not an object

def test_ai_reply_that_is_not_an_object_fails_clean(monkeypatch):
    cfg = {"enabled": True, "endpoint": "http://stub/", "model": "m",
           "per_hour": 5, "timeout": 5}

    class R:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"[]"          # valid JSON, not an object

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: R())
    budget = {"used": 0, "fails": 0, "per_hour": 5}
    assert explain.explain({"rule": "x", "title": "t", "severity": "HIGH"},
                           cfg, budget) is None
    assert budget["fails"] == 1      # booked as a failure, not a crash


def _planted_autostart(tmp_path, lines=1):
    home = tmp_path / "home"
    start = home / ".config" / "autostart"
    start.mkdir(parents=True, exist_ok=True)
    body = "[Desktop Entry]\nType=Application\n" + \
        "".join(f"Exec=/tmp/one-{i}.sh\n" for i in range(lines))
    (start / "scratch.desktop").write_text(body)
    return str(home)


def test_bad_ai_reply_does_not_strand_the_state_write(
        tmp_path, monkeypatch):
    home = _planted_autostart(tmp_path)
    monkeypatch.setattr(web, "_crontab_lines", lambda: [])
    monkeypatch.setattr(main, "_ai_one",
                        lambda *a, **k: 1 // 0)   # the stub: never OK

    # Tick 1 plants the read position at the end of an existing (marker)
    # events file: the first look never replays history, so a marker row
    # must exist BEFORE tick 1, and the real row only becomes fresh when
    # it is appended after tick 1's position landed.
    placeholder = json.dumps({"ts": "2026-11-04T00:00:00",
                              "from_tool": "auditd", "text": "warm-up",
                              "severity": "INFO"}) + "\n"
    (tmp_path / "events.jsonl").write_text(placeholder)
    main.tick(tmp_path, home, ai_enabled=True, intel_enabled=False)
    # Tick 2: the appended row is fresh, h_host_scan sweeps the planted
    # autostart, the finding appends, and THEN the AI stub explodes.
    line = json.dumps({"ts": "2026-11-04T00:01:00", "from_tool": "auditd",
                       "text": "denied ptrace for /usr/bin/tee", "severity":
                       "INFO"}) + "\n"
    with (tmp_path / "events.jsonl").open("a") as fh:
        fh.write(line)

    second = main.tick(tmp_path, home, ai_enabled=True, intel_enabled=False)
    assert second is not None
    assert len(store.read_findings(tmp_path, limit=50)) == 1
    # Tick 3: without the F3 fix the offset never advances, so the same
    # row re-fires the same subject (an empty seen map rides along) and
    # the feed floods. With it, nothing is new.
    third = main.tick(tmp_path, home, ai_enabled=True, intel_enabled=False)
    assert third["new_this_cycle"] == 0
    assert len(store.read_findings(tmp_path, limit=50)) == 1


# ------------------------------------------------- rotation write safety

def _event(method, rid, url="https://stub.example/a.js"):
    return {"method": method, "params": {
        "requestId": rid, "request": {"url": url, "method": "GET"}}}


def test_flush_keeps_the_batch_when_every_name_is_taken(tmp_path):
    inbox = store.inbox_dir(str(tmp_path))
    inbox.mkdir(parents=True, exist_ok=True)
    for i in range(999):
        (inbox / f"cdp-live-{i + 1:05d}.har").write_text("{}")
    w = watch.Watcher(inbox)
    w.queue.extend([_event("Network.requestWillBeSent", f"r{i}")
                    for i in range(5)])
    assert w.flush() is None
    assert len(w.queue) == 5, "the batch stays queued, not dropped"


def test_flush_keeps_the_batch_on_a_write_failure(tmp_path):
    inbox = store.inbox_dir(str(tmp_path))
    inbox.mkdir(parents=True, exist_ok=True)
    w = watch.Watcher(inbox)
    w.queue.extend([_event("Network.requestWillBeSent", "r1")])
    os.chmod(inbox, 0o555)
    try:
        assert w.flush() is None, f"the write failed on {inbox}"
        assert len(w.queue) == 1, "the batch stays queued"
    finally:
        os.chmod(inbox, 0o755)
    f = w.flush()
    assert f is not None and f.is_file()
    assert w.queue == []


def test_flush_trims_only_the_consumed_batch(tmp_path):
    inbox = store.inbox_dir(str(tmp_path))
    inbox.mkdir(parents=True, exist_ok=True)
    w = watch.Watcher(inbox)
    w.queue.extend([_event("Network.requestWillBeSent", f"r{i}")
                    for i in range(watch.MAX_EVENTS + 20)])
    out = w.flush()
    assert out is not None
    assert w.docs == 1
    assert len(w.queue) == 20       # the tail stayed for the next rotate


def test_poll_rotates_when_the_port_goes_quiet(tmp_path):
    inbox = store.inbox_dir(str(tmp_path))
    inbox.mkdir(parents=True, exist_ok=True)
    w = watch.Watcher(inbox)
    w.queue.extend([_event("Network.requestWillBeSent", "r1")])
    w.last_rotate = time.monotonic() - 1000.0
    assert w.poll(0)["state"] == "off"
    assert w.docs == 1, "a pending batch outlives the port"
    assert w.queue == []
    assert len(list(inbox.glob("cdp-live-*.har"))) == 1


def test_poll_rotates_after_a_failed_reconnect(tmp_path):
    inbox = store.inbox_dir(str(tmp_path))
    inbox.mkdir(parents=True, exist_ok=True)
    w = watch.Watcher(inbox)
    w.queue.extend([_event("Network.requestWillBeSent", "r1")])
    w.last_rotate = time.monotonic() - 1000.0
    assert w.poll(59996)["state"] == "down"
    assert w.docs == 1, "the end of a session is when the tail must land"


# --------------------------------------------------------- inbox walking

def test_inbox_walks_past_a_capture_that_never_settles(tmp_path):
    data_dir = tmp_path
    inbox = store.inbox_dir(data_dir)
    inbox.mkdir(parents=True, exist_ok=True)
    future = time.time() + 3600.0
    for name in ("0-a", "0-b", "0-c"):     # names sorting ahead of it
        (inbox / f"{name}.har").write_text("{}")
        os.utime(inbox / f"{name}.har", (future, future))
    good = inbox / "1-real.har"
    good.write_text("{}")
    old = time.time() - (main.INBOX_STABLE_S + 5.0)
    os.utime(good, (old, old))
    names = [p.name for p in main._har_inbox(data_dir)]
    assert names == ["1-real.har"], \
        "a never-stable capture cannot hold the lane hostage"


def test_inbox_answers_the_watchers_own_fresh_doc_at_once(tmp_path):
    data_dir = tmp_path
    inbox = store.inbox_dir(data_dir)
    inbox.mkdir(parents=True, exist_ok=True)
    fresh = inbox / "cdp-live-00001.har"
    fresh.write_text("{}")               # mtime = now
    assert [p.name for p in main._har_inbox(data_dir)] \
        == ["cdp-live-00001.har"]


def test_inbox_holds_a_young_external_capture(tmp_path):
    data_dir = tmp_path
    inbox = store.inbox_dir(data_dir)
    inbox.mkdir(parents=True, exist_ok=True)
    fresh = inbox / "hand-dropped.har"
    fresh.write_text("{}")               # seconds old, external producer
    assert main._har_inbox(data_dir) == []


# --------------------------------------------------------- HAR IPv6 host

def test_har_host_parses_ipv6_literals(tmp_path):
    doc = {"log": {"entries": [{
        "request": {"url": "http://[2001:db8::5]:8443/login",
                    "method": "GET"},
        "response": {"status": 200, "headers": []},
        "content": {},
    }]}}
    path = tmp_path / "v6.har"
    path.write_text(json.dumps(doc))
    parsed = web.parse_har(path)
    assert parsed["entries"][0]["host"] == "2001:db8::5"
    assert web.is_raw_ip(parsed["entries"][0]["host"])


# ------------------------------------- persistence subject line changes

def test_persistence_new_line_is_a_new_subject(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "_crontab_lines", lambda: [])
    home = _planted_autostart(tmp_path, lines=1)
    first = web.persistence_findings(home)
    assert first, "the planted entry is found"
    _planted_autostart(tmp_path, lines=2)
    second = web.persistence_findings(home)
    s1 = engine.subject_of(first[0])
    s2 = engine.subject_of(second[0])
    assert s1 != s2, "a genuinely new entry must fire, not hide"
    # ... and a second run with no change keeps the same subject, so the
    # suppression window still applies to an unchanged surface.
    third = web.persistence_findings(home)
    assert engine.subject_of(third[0]) == s2
    assert any(str(fact).startswith("path=")
               for fact in second[0].get("facts") or [])


# ============================== round-3 appfw / recovery / symbolic pins ===

# ------------------------------------------------------- rule-store flip (F1)

def test_rule_flip_wins_instead_of_vanishing(tmp_path):
    d = tmp_path / "rules"
    store = appfw_rules.RuleStore(d)
    store.add(appfw_rules.validate("appfw-site-bad.example", "deny",
                                   "always", "dst.host", "bad.example"))
    # The owner flips the verdict: the older aim must lose everywhere -
    # in memory AND on disk - not just get a second row the engine
    # consults too late (round-3 audit R3-F1).
    store.add(appfw_rules.validate("appfw-site-bad.example", "allow",
                                   "always", "dst.host", "bad.example"))
    live = {(r.op_kind, r.op_value.lower()): r.action
            for r in store.all_rules()}
    assert live[("dst.host", "bad.example")] == "allow"
    assert json.loads((d / "allow-always.json").read_text())["rules"]
    # the old aim is wiped from disk: the emptied bucket leaves no file
    deny_disk = (json.loads((d / "deny-always.json").read_text())["rules"]
                 if (d / "deny-always.json").exists() else [])
    assert not deny_disk, "the old aim is wiped from disk"


def test_rule_same_pair_is_not_stored_twice(tmp_path):
    d = tmp_path / "rules"
    store = appfw_rules.RuleStore(d)
    store.add(appfw_rules.validate("a", "allow", "always", "dst.port", "443"))
    store.add(appfw_rules.validate("a-again", "allow", "always",
                                   "dst.port", "443"))
    assert len(store.all_rules()) == 1


def test_add_after_another_process_wrote_keeps_the_other_rule(tmp_path):
    d = tmp_path / "rules"
    store = appfw_rules.RuleStore(d)
    # A second process (the popup, the wizard) wrote a decision straight
    # to the file; without the freshen this store's next add() rewrote
    # the file from its OWN stale bucket and erased it (round-3 audit).
    doc = {"kind": "allow-always", "rules": [
        {"name": "popup-app", "action": "allow", "duration": "always",
         "op_kind": "process.path", "op_value": "/usr/bin/vlc", "created": 5}]}
    (d / "allow-always.json").write_text(json.dumps(doc))
    store.add(appfw_rules.validate("appfw-app-vlc2", "deny", "always",
                                   "process.path", "/usr/bin/vlc2"))
    live = {r.op_value: r.action for r in store.all_rules()}
    assert live["/usr/bin/vlc"] == "allow", "the other process wins"
    assert live["/usr/bin/vlc2"] == "deny"
    disk = json.loads((d / "allow-always.json").read_text())["rules"]
    assert any(x["op_value"] == "/usr/bin/vlc" for x in disk)


# -------------------------------------------------- decide order (R2) + ask

def test_decide_newest_created_rule_wins(tmp_path):
    d = tmp_path / "rules"
    store = appfw_rules.RuleStore(d)
    hi = appfw_rules.validate("hi", "deny", "always", "dst.ip",
                              "203.0.113.5")
    hi.created = 999
    lo = appfw_rules.validate("lo", "allow", "always", "dst.port", "443")
    lo.created = 10
    store.add(hi)
    store.add(lo)
    got = store.decide(base.Conn(dst_ip="203.0.113.5", dst_port=443))
    assert got.name == "hi", "newest-created first, and the pin says so"


def test_corrupt_rules_file_is_quarantined_not_wiped(tmp_path):
    d = tmp_path / "rules"
    d.mkdir(parents=True)
    corrupt = '{"kind": "allow-al", "ru'
    (d / "allow-always.json").write_text(corrupt)
    store = appfw_rules.RuleStore(d)
    assert store.load_errors, "the unreadable file is reported, not silent"
    copies = list((d / "legacy-backup").glob("allow-always.corrupt-*"))
    assert copies and copies[0].read_text() == corrupt
    assert not (d / "allow-always.json").exists()
    # The engine can keep adding rules: the empty bucket is real now.
    store.add(appfw_rules.validate("n", "allow", "always", "dst.port", "443"))
    assert len(json.loads((d / "allow-always.json").read_text())
               ["rules"]) == 1


# -------------------------------------------------------- fallback verdicts

def test_headless_fallback_follows_the_config(tmp_path):
    (tmp_path / "config.json").write_text('{"headless_ask": "allow-once"}')
    pol = appfw_policy.Policy(tmp_path)
    assert pol.headless_ask() == "allow-once"
    assert pol._fallback_answer() == "allow"
    pol2 = appfw_policy.Policy(tmp_path)
    (tmp_path / "config.json").write_text('{"headless_ask": "junk"}')
    assert pol2.headless_ask() == "deny-once"
    assert pol2._fallback_answer() == "deny"


def test_decide_end_of_chain_labels_the_configured_fallback(tmp_path):
    (tmp_path / "config.json").write_text('{"headless_ask": "allow-once"}')
    verdict = appfw_policy.decide(base.Conn(dst_ip="203.0.113.7",
                                            dst_port=4444),
                                  appfw_policy.Policy(tmp_path),
                                  store=None, ask=None)
    assert verdict == ("allow", "once",
                       "default allow-once (no dialog wired)", None)
    (tmp_path / "config.json").write_text('{"headless_ask": "deny-once"}')
    verdict = appfw_policy.decide(base.Conn(dst_ip="203.0.113.7",
                                            dst_port=4444),
                                  appfw_policy.Policy(tmp_path),
                                  store=None, ask=None)
    assert verdict == ("deny", "once",
                       "default deny-once (no dialog wired)", None)


def test_decide_chain_error_answers_and_labels():
    class Broken:
        pass

    verdict = appfw_policy.decide(base.Conn(dst_ip="203.0.113.7"),
                                  Broken(), store=None, ask=None)
    # A chain error is a greywatch fault, never a policy choice: the
    # historical fail-open allow stands (tests' "never a lockout" pins).
    assert verdict[0] == "allow" and "chain error" in verdict[2]


# ------------------------------------------------- sites deny-first + config

def test_ip_verdict_deny_wins_over_allow(tmp_path):
    (tmp_path / "appfw").mkdir()
    # The cache maps entry name -> its resolved addresses; the verdict
    # consults the ADDRESS the packet carries. Both lists name the same
    # site, so the block must out-rank the allow (tie goes to deny).
    (tmp_path / "appfw" / "site-ips.json").write_text(
        json.dumps({"entries": {"both.example": ["1.2.3.4"]}}))
    got = appfw_sites.ip_verdict(tmp_path, "1.2.3.4",
                                 ["both.example"], ["both.example"])
    assert got == "deny", "the blocklist must out-rank the allowlist"
    assert appfw_sites.ip_verdict(tmp_path, "1.2.3.4",
                                  ["both.example"], ()) == "allow"
    assert appfw_sites.ip_verdict(tmp_path, "198.51.100.9", [], []) \
        is None


def test_sanitize_drops_the_drop_all_exempt(tmp_path):
    cfg = appfw_config._sanitize(
        {"always_exempt": ["0.0.0.0", "10.0.0.5", "not-an-ip"]})
    assert cfg["always_exempt"] == ["10.0.0.5"]


def test_loopback_ports_parse_from_config_single_source():
    assert appfw_config.loopback_ports(
        appfw_config.DEFAULTS) == frozenset({8888, 8899})
    assert appfw_config.loopback_ports({"loopback_allow": []}) == frozenset()
    assert appfw_config.loopback_ports({}) == frozenset({8888, 8899})
    assert appfw_config.loopback_ports({"loopback_allow": "junk"}) == \
        frozenset({8888, 8899})
    odd = appfw_config.loopback_ports({"loopback_allow": [{"port": "7999"},
                                                          {"port": 0},
                                                          {"port": 70000}]})
    assert odd == frozenset({7999})


def test_policy_loopback_ports_read_the_owner_config(tmp_path):
    p = appfw_policy.Policy(tmp_path)
    (tmp_path / "config.json").write_text(
        json.dumps({"loopback_allow": [{"port": 7000}]}))
    assert p.loopback_ports() == frozenset({7000})
    # no readable config: the documented defaults, not an empty permit
    assert appfw_policy.Policy(tmp_path / "nadir").loopback_ports() == \
        frozenset({8888, 8899})


# ------------------------------------------------------------------- askgate

def test_askgate_dst_less_asks_dedupe_on_app_identity():
    calls = [0]

    def ask(spec):
        calls[0] += 1
        return None

    gate = AskGate("deny-once", window=300.0, ask=ask, clock=lambda: 10.0)
    first = gate.ask({"app_name": "vlc", "pid": 7, "dst_port": 443,
                      "protocol": "tcp"})
    again = gate.ask({"app_name": "vlc", "pid": 7, "dst_port": 443,
                      "protocol": "tcp"})
    assert first == again and calls[0] == 1, \
        "a dst-less ask dedupes on the app facts (audit R13)"
    gate.ask({"app_name": "vlc", "pid": 7, "dst_port": 8080,
              "protocol": "tcp"})
    assert calls[0] == 2, "another app fact is a different ask"


def test_askgate_seen_cap_drops_the_oldest_entry():
    calls = [0]

    def ask(spec):
        calls[0] += 1
        return None

    gate = AskGate("deny-once", window=300.0, ask=ask, clock=lambda: 10.0)
    # SEEN_CAP + 1 inserts: eviction fires when the map is already at the
    # cap, so the final insert is what drops the oldest entry ("…0").
    for i in range(gate.SEEN_CAP + 1):
        gate.ask({"dst_ip": f"198.51.100.{i}"})
    ask_gate = gate.ask({"dst_ip": "198.51.100.0"})
    assert ask_gate == ("deny", "once", None)
    assert calls[0] == gate.SEEN_CAP + 2, \
        "the evicted oldest entry is asked again"
    assert len(gate._seen) <= gate.SEEN_CAP
    # a still-cached destination is answered from the map, not re-asked
    gate.ask({"dst_ip": "198.51.100.400"})
    assert calls[0] == gate.SEEN_CAP + 2


# ---------------------------------------------------------- engine recovery

def test_watchdog_respawns_when_the_reader_thread_dies(tmp_path,
                                                       monkeypatch):
    eng = appfw_engine.Engine(tmp_path)
    monkeypatch.setattr(eng, "_worker_healthy", lambda: True)
    monkeypatch.setattr(eng, "table_present", lambda: True)
    monkeypatch.setattr(eng, "_bind_worker", lambda: None)
    monkeypatch.setattr(eng, "_query_backlog", lambda: 0)
    seen = []
    monkeypatch.setattr(eng, "on_event", lambda msg: seen.append(msg))
    eng.running = True
    dead = threading.Thread(target=lambda: None, daemon=True)
    dead.start()
    dead.join()
    eng._reader = dead
    assert eng._watchdog_step() is True
    assert any("reader thread is gone" in m for m in seen)
    blocker = threading.Event()
    alive = threading.Thread(target=blocker.wait, daemon=True)
    alive.start()
    eng._reader = alive
    seen.clear()
    eng._watchdog_step()
    assert not any("reader thread is gone" in m for m in seen)
    blocker.set()
    alive.join()


# --------------------------------------------------------- scan request (A9)

def test_take_request_moves_rejected_bytes(tmp_path):
    import scan_session as ss
    s = ss.ScanService(str(tmp_path))
    req = ss.request_path(tmp_path)
    req.write_text("{not json")
    assert s._take_request() is None
    assert not req.exists()
    assert (tmp_path / "scan-request.json.rejected").exists(), \
        "moved aside, not destroyed (recovery audit A9)"
    good = ss.request_path(tmp_path)
    good.write_text('{"id": "20261104T010203-abcd", "key": "full"}')
    got = s._take_request()
    assert got == ("20261104T010203-abcd", "full")
    assert not good.exists()


# --------------------------------------------------------------- cve refresh

def test_cve_refresh_payload_is_never_sliced_and_loads_back(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "cve_refresh_mod", pathlib.Path(__file__).resolve().parents[1]
        / "cve-refresh.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    cache = tmp_path / "cve-cache.json"
    mod.refresh(base_url="http://dead.invalid", cache_path=cache,
                queries=["a"])
    doc = json.loads(cache.read_text())     # loads back whole (audit A8)
    assert doc["reason"] == "offline or fetch failed/timeout"
    assert set(doc) == {"fetched_utc", "queries", "entries", "reason"}


# ---------------------------------------------------------- hunter window (A6)

def test_read_events_declares_rows_skipped_by_the_window(tmp_path):
    path = tmp_path / "events.jsonl"
    rows = [json.dumps({"ts": "2026-11-04T00:00:00", "from_tool": "auditd",
                        "text": f"e{i}", "severity": "INFO"})
            for i in range(2050)]
    path.write_text("\n".join(rows) + "\n")
    st = path.stat()
    saved = {"inode": st.st_ino, "offset": len(rows[0]) + 1}
    fresh, position = engine.read_events(path, saved)
    assert len(fresh) == 2000
    assert position["skipped"] == 49, "the dropped older rows are declared"
    small, position2 = engine.read_events(path, dict(position))
    assert small == [] and position2.get("skipped", 0) == 0


# ------------------------------------------------------------- scan strip (SM3)

def test_scan_strip_says_it_looks_stopped_when_updates_stopped():
    from ui.scanview import status_line
    old = (_dt.datetime.now(_dt.timezone.utc)
           - _dt.timedelta(seconds=120)).isoformat()
    stale = {"state": "running",
             "scanners": {"clamav": {"state": "running"}},
             "updated": old}
    assert "stopped" in status_line(stale, "below")
    fresh = dict(stale, updated=_dt.datetime.now(_dt.timezone.utc).isoformat())
    assert "Scanning: clamav" in status_line(fresh, "below")
    # a doc without the stamp behaves exactly as before: running with no
    # live scanners still reads "Finishing the scan…" and never the
    # staleness wording (the gate judges only an explicit updated stamp)
    plain = status_line({"state": "running"}, "below")
    assert "Finishing the scan" in plain and "stopped" not in plain
    legacy = {"state": "running",
              "scanners": {"clamav": {"state": "running"}}}
    assert "Scanning: clamav" in status_line(legacy, "below")


# ------------------------------------------------------------ doctor (R14)

def test_doctor_repair_never_touches_owner_policy():
    import doctor as doctor_mod
    cfg = {"strict_mode": True, "fail_open": False, "ipv6_enabled": True,
           "nfqueue_num": "junk",
           "always_exempt": ["1.1.1.1", "not-an-ip", "0.0.0.0/0",
                             "10.0.0.5"]}
    fixed = doctor_mod._default_repair(cfg)
    assert cfg["nfqueue_num"] == 111 and any("nfqueue_num" in f
                                             for f in fixed)
    assert "not-an-ip" not in cfg["always_exempt"]
    assert "0.0.0.0/0" not in cfg["always_exempt"]
    assert "10.0.0.5" in cfg["always_exempt"]
    assert cfg["strict_mode"] is True and cfg["fail_open"] is False
    assert cfg["ipv6_enabled"] is True


# ------------------------------------------------------- assistant pack fixes

def test_short_security_tokens_reach_log_search(tmp_path, monkeypatch):
    import assistant.packer as packer
    monkeypatch.setattr(packer.gwpaths, "data_dir", lambda *a, **k: tmp_path)
    (tmp_path / "events.jsonl").write_text(
        json.dumps({"ts": "2026-11-04T00:00:00", "from_tool": "auditd",
                    "text": "an ssh session over the vpn was denied",
                    "severity": "INFO"}) + "\n")
    assert packer.search_events(["ssh", "vpn"]) != [], \
        "4-letter and 3-letter security terms must reach the log (R9)"
    assert packer.search_events(["the", "was"]) == []


def test_detail_reassurance_is_count_aware():
    from assistant import templates as tpl
    row = {"from_tool": "apparmor", "severity": "INFO", "text": "denied",
           "ts": "2026-11-04T00:00:00+00:00", "count": 90}
    out = tpl.answer_detail(row)
    assert "90" in out and "one-off" in out, "no fake comfort on a repeat"
    single = tpl.answer_detail(dict(row, count=1))
    assert "single event like this is usually normal" in single


def test_pack_prompt_declares_when_docs_matched_nothing():
    from ui.assistant import _pack_prompt
    pack = {"status_line": "0 of 0", "tools": [], "recent": [],
            "snippets": [], "history": []}
    prompt = _pack_prompt(pack, "why did x fail?")
    assert "no help page matched" in prompt


def test_ask_freshness_reaches_past_the_daemon_timeout():
    import ui.decisions as decisions
    assert decisions.DecisionBroker.ASK_FRESH_SECONDS >= 30.0