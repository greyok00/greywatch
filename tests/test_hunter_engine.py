"""The hunter's engine and resident loop, deterministic end to end.

Nothing here needs the model: read_events pins the forward-only tail
semantics (first run and rotations start at the end — the past is never
replayed as new), the dedupe windows pin the “active but not noisy”
contract, and a full tick in tmp dirs proves findings land in
findings.jsonl with stable ids, rule notes land in defender.jsonl, live
state stays consistent, an answered HAR capture retires itself, and the
read pointer lives in config.json where the user owns it."""
import json
import os
import pathlib
import time
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hunter import engine, main, store, web  # noqa: E402


def _event(tool, text, ts="2026-11-03T12:00:00+00:00"):
    return {"from_tool": tool, "severity": "INFO", "text": text, "ts": ts}


def _line(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def _no_crontab(monkeypatch) -> None:
    """The developer's own crontab must not leak into fixture verdicts."""
    monkeypatch.setattr(web, "_crontab_lines", lambda: [])


def _good_har() -> dict:
    return {"log": {"entries": [
        {"request": {"url": "https://e.example/f"},
         "response": {"status": 200, "headers": [
             {"name": "Content-Disposition",
              "value": "attachment; filename=a.pdf.exe"}],
                      "content": {"mimeType": "application/x-msdownload"}}}]}}


# ------------------------------------------------------------- read_events

def test_read_events_first_run_sees_nothing_but_marks_position(tmp_path):
    """First look never replays history as new — the noise rule."""
    p = tmp_path / "events.jsonl"
    p.write_text(_line(_event("clamav", "FOUND /old/bad")) * 3)
    rows, pos = engine.read_events(p, {})
    assert rows == []
    assert pos["inode"] == p.stat().st_ino
    assert pos["offset"] == p.stat().st_size


def test_read_events_delivers_only_what_comes_after(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text(_line(_event("lynis", "old")))
    _, pos = engine.read_events(p, {})
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(_line(_event("clamav", "FOUND /a")))
        fh.write(_line(_event("clamav", "FOUND /b")))
    rows, new_pos = engine.read_events(p, pos)
    assert [r["text"] for r in rows] == ["FOUND /a", "FOUND /b"]
    assert new_pos["offset"] == p.stat().st_size


def test_read_events_treats_rotation_as_first_run(tmp_path):
    """A new inode means a fresh file: whatever history it holds is never
    re-alerted, and the position follows the replacement."""
    p = tmp_path / "events.jsonl"
    p.write_text(_line(_event("lynis", "old")))
    _, pos = engine.read_events(p, {})
    p.unlink()
    p.write_text(_line(_event("clamav", "FOUND /new")))
    rows, rot_pos = engine.read_events(p, pos)
    assert rows == []
    assert rot_pos["inode"] == p.stat().st_ino


def test_read_events_survives_bad_lines_and_bad_save(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text(_line(_event("clamav", "FOUND /a")) + "{broken\n")
    _, pos = engine.read_events(p, {})
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("{still broken\n")
        fh.write(_line(_event("clamav", "FOUND /b")))
    rows, _ = engine.read_events(p, pos)
    assert [r["text"] for r in rows] == ["FOUND /b"]
    # A save pointing past EOF, or at a foreign inode, reads nothing new.
    rows2, pos2 = engine.read_events(
        p, {"inode": p.stat().st_ino, "offset": p.stat().st_size + 999})
    assert rows2 == [] and pos2["offset"] == p.stat().st_size
    rows3, _ = engine.read_events(p, {"inode": 7, "offset": 1})
    assert rows3 == []
    # A missing file answers empty and keeps whatever save was given.
    rows4, saved = engine.read_events(tmp_path / "absent.jsonl", {"offset": 4})
    assert rows4 == [] and saved == {"offset": 4}


# ----------------------------------------------------------------- dedupe

def _finding_of(rule, subject):
    return {"rule": rule, "title": "t", "what": "w", "next": "n",
            "severity": "LOW", "facts": [f"path={subject}"],
            "evidence": []}


def test_dedupe_drops_repeat_within_window():
    subject = "/x/a.exe"
    key = store.dedup_key("download-executable", subject)
    seen = {key: engine._iso()}
    kept, _ = engine.apply_dedupe(
        dict(seen), [_finding_of("download-executable", subject)])
    assert kept == []
    # A different subject on the same rule still fires.
    kept2, _ = engine.apply_dedupe(
        dict(seen), [_finding_of("download-executable", "/x/b.exe")])
    assert len(kept2) == 1


def test_dedupe_lets_age_out_of_the_window():
    subject = "/u1/invoice.pdf.exe"
    seen = {store.dedup_key("har-double-extension", subject):
            "2025-01-01T00:00:00+00:00"}
    kept, _ = engine.apply_dedupe(
        dict(seen), [_finding_of("har-double-extension", subject)])
    assert len(kept) == 1  # 24h elapsed: the lead may re-raise


def test_zero_window_means_never_suppressed_for_signature_hits():
    subject = "/sig-hit-path"
    seen = {store.dedup_key("malware-detected", subject): engine._iso()}
    kept, _ = engine.apply_dedupe(
        dict(seen), [_finding_of("malware-detected", subject)])
    assert len(kept) == 1


def test_persisted_scan_summary_does_not_re_announce(tmp_path):
    """scan-positive's subject file persists on disk, so unlike a one-shot
    signature event it must have a real window — or every cycle re-announces
    the same finished run into the notes."""
    assert engine.SUPPRESS_HOURS["scan-positive"] > 0
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "old.json").write_text(json.dumps(
        {"scan_id": "old-run", "state": "done", "real_findings": 2}))
    refire = {"rule": "scan-positive", "title": "t", "what": "w",
              "next": "n", "severity": "MEDIUM",
              "facts": ["scan_id=old-run"], "evidence": []}
    subject = store.dedup_key("scan-positive", engine.subject_of(refire))
    seen = {subject: engine._iso()}
    kept, _ = engine.apply_dedupe(dict(seen), [refire])
    assert kept == []


def test_subject_of_prefers_paths_then_urls_then_title():
    by_fact = engine.subject_of({"facts": ["path=/d/f.exe",
                                           "scan_id=s1"], "evidence": []})
    by_url = engine.subject_of({"facts": ["real_findings=3"],
                                "evidence": [{"url": "https://h/x"}]})
    by_fs = engine.subject_of({"evidence": [{"source": "fs",
                                             "path": "/d/g.exe"},
                                            {"url": "https://h2/y"}]})
    fallback = engine.subject_of({"rule": "r", "title": "t"})
    assert by_fact == "/d/f.exe" and by_url == "https://h/x"
    assert by_fs == "/d/g.exe" and fallback == "r:t"


# -------------------------------------------------------------- hypotheses

def test_malware_detections_translate_verbatim_high():
    rows = [_event("clamav", "FOUND /home/u/Downloads/bad.exe"),
            _event("rkhunter", "Warning: hidden file /etc/.hide"),
            _event("lynis", "notice - routine")]
    found = engine.h_malware_hit(rows, "/home", "/tmp/d")
    rules = [f["rule"] for f in found]
    assert "malware-detected" in rules and "rootkit-warning" in rules
    hit = [f for f in found if f["rule"] == "malware-detected"][0]
    assert hit["severity"] == "HIGH" and hit["status"] == "confirmed"
    assert hit["facts"] == ["path=/home/u/Downloads/bad.exe"]
    assert "bad.exe" in hit["what"]


def test_scan_positive_reads_recent_summaries(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "old.json").write_text(json.dumps(
        {"scan_id": "old-run", "state": "done", "real_findings": 2}))
    (scans / "still.json").write_text(json.dumps(
        {"scan_id": "run-2", "state": "running", "real_findings": 0}))
    found = engine.h_scan_positive([], "/home", str(tmp_path))
    assert [f["rule"] for f in found] == ["scan-positive"]
    hit = found[0]
    assert hit["facts"][0] == "scan_id=old-run"
    assert hit["severity"] == "MEDIUM"
    # The scan id, not the title, is the dedupe subject.
    assert engine.subject_of(hit) == "old-run"
    # Nothing on disk means nothing to say.
    assert engine.h_scan_positive([], "/home", str(tmp_path / "nope")) == []


def test_host_scan_hypothesis_combines_the_three_sources(tmp_path,
                                                         monkeypatch):
    _no_crontab(monkeypatch)
    home = tmp_path / "home"
    (home / "Downloads").mkdir(parents=True)
    (home / "Downloads" / "Faktura.pdf.exe").write_text("MZ")
    rows = [_event("auditd", "execve /home/u/Downloads/loader.bin started")]
    found = engine.h_host_scan(rows, str(home), str(tmp_path))
    rules = [f["rule"] for f in found]
    assert "download-double-extension" in rules
    assert "download-executed" in rules


# ----------------------------------------------------------- the full tick

def test_tick_records_findings_notes_and_live(tmp_path, monkeypatch):
    _no_crontab(monkeypatch)
    data = tmp_path / "data"
    home = tmp_path / "home"
    (home / "Downloads").mkdir(parents=True)
    data.mkdir(parents=True)

    # The tail file exists from the start: its history is never replayed.
    (data / "events.jsonl").write_text(_line(_event("lynis", "routine")))

    doc = main.tick(data, str(home), ai_enabled=False)
    assert doc["hunter"] == 1 and doc["new_this_cycle"] == 0
    # The per-tick flag is quiet; the config default still reports enabled.
    assert doc["ai"]["enabled"] is True
    assert doc["ai"]["used_hour"] == 0

    # New evidence: a detection in the tail + a hazard in Downloads.
    with open(data / "events.jsonl", "a", encoding="utf-8") as fh:
        fh.write(_line(_event("clamav", "FOUND /home/u/x/bad.exe")))
    (home / "Downloads" / "receipt.pdf.exe").write_text("MZ")

    doc = main.tick(data, str(home), ai_enabled=False)
    assert doc["new_this_cycle"] == 2
    findings = store.read_findings(data, limit=50)
    assert len(findings) == 2
    for f in findings:
        assert f["id"] == store.dedup_key(f["rule"], engine.subject_of(f))
        assert f["hunter"] == "1"
    assert {f["rule"] for f in findings} == {"malware-detected",
                                             "download-double-extension"}
    notes = store.read_defender(data, limit=50)
    assert len(notes) == 2
    assert all(n["kind"] == "rule" and n["text"] and n["hint"]
               for n in notes)
    assert doc["unread"] == 2
    assert doc["latest"] == [f["id"] for f in findings[-3:]]

    # Same evidence again: deduped, nothing new, nothing re-noted.
    doc = main.tick(data, str(home), ai_enabled=False)
    assert doc["new_this_cycle"] == 0
    assert doc["findings_total"] == 2
    assert len(store.read_defender(data, limit=50)) == 2


def test_tick_answers_the_inbox_and_handles_the_request(tmp_path,
                                                        monkeypatch):
    _no_crontab(monkeypatch)
    data = tmp_path / "data"
    home = tmp_path / "home"
    data.mkdir(parents=True)
    inbox = store.inbox_dir(data)

    store.request_path(data).write_text("{}\n")
    inbox.joinpath("bad.har").write_text("{not json")
    inbox.joinpath("good.har").write_text(json.dumps(_good_har()))
    # The inbox answers only captures past the producer-hold (a capture
    # still being written waits a full cycle rather than being retired
    # as junk), so age these ones past the hold for this same cycle.
    old = time.time() - (main.INBOX_STABLE_S + 5.0)
    for name in ("bad.har", "good.har"):
        os.utime(inbox.joinpath(name), (old, old))

    doc = main.tick(data, str(home), ai_enabled=False)
    assert doc["har"] == {"processed": 1, "rejected": 1}
    assert any(f["rule"] == "har-double-extension"
               for f in store.read_findings(data, limit=50))
    assert not list(inbox.glob("*"))
    assert len(list(store.processed_dir(data).glob("*"))) == 2
    state = store.read_state(data)
    assert state.get("last_hunt_requested")
    assert not store.request_path(data).exists()
    assert doc["unread"] >= 1
    assert doc["latest"]


def test_marked_read_pointer_clears_the_unread_count(tmp_path, monkeypatch):
    """The read pointer lives in config.json (user-owned); live.json must
    count against it, or every tick would re-count the same notes as
    unread and the panel badge would never clear."""
    _no_crontab(monkeypatch)
    data = tmp_path / "data"
    home = tmp_path / "home"
    data.mkdir(parents=True)
    scans = data / "scans"
    scans.mkdir()
    (scans / "run.json").write_text(json.dumps(
        {"scan_id": "r1", "state": "done", "real_findings": 1}))
    main.tick(data, str(home), ai_enabled=False)
    assert main.tick(data, str(home), ai_enabled=False)["unread"] == 1

    # The user caught up: the pointer moves past every note...
    cfg_path = store.config_path(data)
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
    cfg["read_until"] = "2027-01-01T00:00:00+00:00"
    cfg["custom_key"] = 7
    cfg_path.write_text(json.dumps(cfg))

    import hunter.explain as explain
    assert explain.read_pointer(data) == "2027-01-01T00:00:00+00:00"
    doc = main.tick(data, str(home), ai_enabled=False)
    assert doc["unread"] == 0
    # ...and the tick's own config round-trips never drop the foreign key.
    assert json.loads(cfg_path.read_text()).get("custom_key") == 7

# ------------------------------------------------- the web-wave lanes

def test_browser_config_lane_reads_real_browser_state(tmp_path):
    home = tmp_path / "home"
    (home / ".mozilla" / "firefox" / "p.default").mkdir(parents=True)
    (home / ".mozilla" / "firefox" / "p.default" / "prefs.js").write_text(
        'user_pref("browser.startup.homepage", '
        '"https://search-guard.example/lock");\n')
    found = engine.h_browser_config([], str(home), str(tmp_path))
    assert any(f["rule"] == "ff-hijack" for f in found)


def test_web_patterns_lane_fires_on_a_processed_har(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    har = {"log": {"entries": [
        {"request": {"url": "https://kit-1-800-support.example/fix",
                     "method": "GET"},
         "response": {"status": 200, "headers": [],
                      "content": {"mimeType": "text/html"}}}]}}
    (store.processed_dir(data) / "kit.har").write_text(json.dumps(har))
    found = engine.h_web_patterns([], str(tmp_path), str(data))
    assert any(f["rule"] == "pat-tech-support-scam" for f in found)


def test_pattern_docs_carry_history_titles(tmp_path):
    home = tmp_path / "home"
    prof = home / ".mozilla" / "firefox" / "p.default"
    prof.mkdir(parents=True)
    import sqlite3
    db = sqlite3.connect(prof / "places.sqlite")
    db.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, "
               "url TEXT, title TEXT, last_visit_date INTEGER)")
    db.execute("INSERT INTO moz_places (url, title, last_visit_date) "
               "VALUES ('https://verify.example/step', "
               "'Press & Hold to Verify You Are Human', 1730000000)")
    db.commit()
    db.close()
    found = engine.h_web_patterns([], str(home), tmp_path)
    assert any(f["rule"] == "pat-fake-captcha" for f in found)


def test_intel_lane_joins_cached_feed_hits(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    idir = data / "hunter" / "intel"
    idir.mkdir(parents=True)
    (idir / "phishing-army.json").write_text(json.dumps({
        "feed": "phishing-army", "fetched": engine._iso(), "rows": [
            {"value": "kit-drop.example", "kind": "host"}]}))
    har = {"log": {"entries": [
        {"request": {"url": "https://kit-drop.example/payload.exe",
                     "method": "GET"},
         "response": {"status": 200, "headers": [],
                      "content": {"mimeType": "application/octet-stream"}}}]}}
    (store.processed_dir(data) / "kit.har").write_text(json.dumps(har))
    found = engine.h_intel_join([], str(tmp_path), str(data))
    hits = [f for f in found if f["rule"] == "intel-feed-match"]
    assert hits and "phishing-army" in hits[0]["what"]
    assert "feed-age=" in hits[0]["facts"][2]


def test_new_rules_carry_their_suppression_windows():
    windows = engine.SUPPRESS_HOURS
    for rule in ("ff-history-double-extension", "ff-history-executable",
                 "ff-hijack", "cfg-search-hijack", "cfg-notification-grant",
                 "intel-feed-match", "pat-fake-captcha",
                 "pat-tech-support-scam", "pat-fake-update"):
        assert windows.get(rule), rule
    assert windows["cfg-new-extension"] >= 24 * 365, (
        "a first-seen extension must never repeat")


def test_hypotheses_carry_the_three_new_lanes():
    names = [name for name, _fn, _needs in engine.HYPOTHESES]
    assert names == ["events-detections", "scan-summaries",
                     "downloads-and-persistence", "browser-history",
                     "browser-config", "web-patterns", "intel-join"]


# -------------------------------------------------- the wiring in main

def test_tick_watches_the_configured_port_and_reports(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    cfg = store.config_path(data)
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"cdp_port": 59998, "intel_enabled": False}))
    doc = main.tick(data, str(data), ai_enabled=False)
    assert doc["watcher"]["state"] == "down", (
        "nothing listens on the port the config named")
    assert doc["intel"]["enabled"] is False


def test_tick_pulls_intel_when_enabled(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    import hunter.intel as intel
    import tests.test_hunter_intel as fixtures
    monkeypatch.setattr(intel, "fetch_body", lambda u, c, t=20.0: {
        "phishing": fixtures._PHISHING_ARMY_TXT,
        "openphish": fixtures._OPENPHISH_TXT}[u.split("/")[2].split(".")[0]])
    cfg = store.config_path(data)
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"intel_enabled": True}))
    doc = main.tick(data, str(data), ai_enabled=False)
    assert not doc["intel"].get("errors"), doc["intel"]
    assert doc["intel"]["last_ok"]
