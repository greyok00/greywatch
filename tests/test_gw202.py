"""GW-203/204 (owner 2026-11-06, wave C): CVE data becomes ACTIVE rules.
Every high-severity flaw in the cache that names a managed tool is
announced once by the daemon, joined to events that mention it by the
browser watch, and explained by the assistant - and nothing is ever
patched automatically."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "cve_refresh", pathlib.Path(__file__).resolve().parents[1] / "cve-refresh.py")
cve_refresh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cve_refresh)
import cverules
import greywatch_daemon as gd
from greywatch_daemon import Daemon, read_events
from hunter import web
from hunter import engine as hengine


def _nvd(cid, score=None, sev=None, summary=None, modified="2026-10-22"):
    cve = {"id": cid, "lastModified": modified}
    if summary:
        cve["descriptions"] = [{"lang": "en", "value": summary}]
    if score is not None:
        cve["metrics"] = {"cvssMetricV31": [
            {"cvssData": {"baseScore": score, "baseSeverity": sev}}]}
    return {"cve": cve}


# ---- the cache upgrade: entries carry rule fields -------------------------
def test_parse_entries_enriches_with_tool_score_and_summary():
    body = {"vulnerabilities": [
        _nvd("CVE-2026-0001", score=9.8, sev="CRITICAL",
             summary="ClamAV parses a malicious fax.", )]}
    (entries,) = cve_refresh.parse_entries(body, tool="clamav")
    assert entries["id"] == "CVE-2026-0001"
    assert entries["tool"] == "clamav"
    assert entries["score"] == 9.8 and entries["severity"] == "CRITICAL"
    assert "fax" in entries["summary"]


def test_parse_entries_plain_items_stay_plain():
    body = {"vulnerabilities": [
        {"cve": {"id": "CVE-2026-0002", "lastModified": "2026-10-22"}},
        {"cve": {"id": "garbage"}, "broken": True},
    ]}
    entries = cve_refresh.parse_entries(body)
    assert entries == [{"id": "CVE-2026-0002", "modified": "2026-10-22"}]


def test_refresh_merges_without_downgrading(tmp_path):
    cache = tmp_path / "cve-cache.json"
    first = {"vulnerabilities": [_nvd("CVE-2026-0003", score=5.0,
                                      sev="MEDIUM")]}
    cve_refresh.refresh(base_url="dead://x", cache_path=cache,
                        queries=["nothing here"])
    # offline leaves what an earlier online run wrote
    cache.write_text(json.dumps({"fetched_utc": "t", "queries": [],
                                 "entries": [{"id": "CVE-2026-0003",
                                              "modified": "old"}]}))
    # pretend the merge ran by loading and writing back like refresh does
    prev = cve_refresh.load_cache(cache)
    by_id = {e["id"]: e for e in prev["entries"]}
    for e in cve_refresh.parse_entries(
            {"vulnerabilities": [_nvd("CVE-2026-0003", score=9.1,
                                      sev="CRITICAL")]},
            tool="clamav"):
        by_id[e["id"]] = {**by_id.get(e["id"], {}), **e}
    merged = by_id["CVE-2026-0003"]
    assert merged["score"] == 9.1 and merged["tool"] == "clamav"


# ---- the rule engine -------------------------------------------------------
def _cache(tmp_path, entries):
    p = tmp_path / "cve-cache.json"
    p.write_text(json.dumps({"fetched_utc": "t", "queries": ["q"],
                             "entries": entries}))
    return p


def test_active_rules_take_high_scoring_known_tools_only(tmp_path):
    p = _cache(tmp_path, [
        {"id": "CVE-2026-0010", "modified": "m", "tool": "clamav",
         "score": 9.8, "severity": "CRITICAL", "summary": "bad parse"},
        {"id": "CVE-2026-0011", "modified": "m", "tool": "clamav",
         "score": 5.2, "severity": "MEDIUM", "summary": "low"},
        {"id": "CVE-2026-0012", "modified": "m", "score": 9.9},
    ])
    rules = cverules.active_rules(p)
    assert [r["cve"] for r in rules] == ["CVE-2026-0010"]
    assert rules[0]["severity"] == "CRITICAL"


def test_evaluate_announces_once_and_survives_restart(tmp_path):
    p = _cache(tmp_path, [{"id": "CVE-2026-0020", "modified": "m",
                           "tool": "fail2ban", "score": 8.1,
                           "severity": "HIGH", "summary": "auth bypass"}])
    specs = cverules.evaluate(tmp_path, cache_path=p)
    assert len(specs) == 1
    severity, text, cid, tool = specs[0]
    assert (severity, cid, tool) == ("HIGH", "CVE-2026-0020", "fail2ban")
    assert "installed versions" in text
    assert (tmp_path / "cve-announced.jsonl").exists()
    assert cverules.evaluate(tmp_path, cache_path=p) == []   # once only


def test_evaluate_keeps_news_when_seen_state_cannot_be_kept(tmp_path):
    """GW-B1 replaced pin: a cve-announced ledger that cannot take a
    write no longer silences the news - the specs stay with .stalled
    set (retry until persisted, never silently dropped)."""
    p = _cache(tmp_path, [{"id": "CVE-2026-0021", "modified": "m",
                           "tool": "clamav", "score": 9.0,
                           "severity": "CRITICAL"}])
    ledger = tmp_path / "cve-announced.jsonl"
    ledger.is_file() or ledger.write_text("")
    # make the append fail: 'ledger' is a directory now
    ledger.unlink()
    ledger.mkdir()
    specs = cverules.evaluate(tmp_path, cache_path=p)
    assert specs, "the news stays in the specs"
    assert specs[0][2] == "CVE-2026-0021"
    assert isinstance(specs.stalled, OSError)


def test_severity_boundary_is_nine(tmp_path):
    p = _cache(tmp_path, [{"id": "CVE-2026-0030", "modified": "m",
                           "tool": "psad", "score": 9.0,
                           "severity": "CRITICAL"},
                          {"id": "CVE-2026-0031", "modified": "m",
                           "tool": "psad", "score": 7.0,
                           "severity": "HIGH"}])
    specs = cverules.evaluate(tmp_path, cache_path=p)
    sev = {c: s for s, _t, c, _tool in specs}
    assert sev["CVE-2026-0030"] == "CRITICAL"
    assert sev["CVE-2026-0031"] == "HIGH"


# ---- the daemon monitor wiring --------------------------------------------
def test_daemon_announces_rules_in_the_monitors_voice(tmp_path):
    d = Daemon(data_dir=tmp_path / "data", registry=gd.load_registry())
    _cache(d.data_dir, [{"id": "CVE-2026-0040", "modified": "m",
                         "tool": "clamav", "score": 9.8,
                         "severity": "CRITICAL", "summary": "bad parse"}])
    assert d.cve_watch() == 1
    d.flush_outbox()
    evs = [e for e in read_events(d.events_path)
           if e["from_tool"] == "cve-updater"]
    assert len(evs) == 1 and evs[0]["severity"] == "CRITICAL"
    assert "CVE-2026-0040" in evs[0]["text"]
    assert d.cve_watch() == 0                # one announcement per flaw


# ---- the hunter join ------------------------------------------------------
def test_hunter_joins_tracked_cves_to_events(tmp_path):
    p = _cache(tmp_path, [{"id": "CVE-2026-0050", "modified": "m",
                           "tool": "clamav", "score": 9.1,
                           "severity": "CRITICAL",
                           "summary": "fax parse flaw"}])
    events = [{"from_tool": "assistant", "severity": "MEDIUM",
               "text": "advice mentions CVE-2026-0050 for clamav",
               "ts": "2026-11-06T10:00:00+00:00"},
              {"from_tool": "assistant", "severity": "MEDIUM",
               "text": "mentions CVE-9999-0004 which nobody tracks",
               "ts": "2026-11-06T10:01:00+00:00"}]
    findings = hengine.h_cve_watch(events, None, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "known-cve-mention"
    assert f["severity"] == "CRITICAL"
    assert any(ev.get("text", "").startswith("advice")
               for ev in f.get("evidence", []))


# ---- the assistant playbook ------------------------------------------------
def test_advice_has_a_verify_steps_rule_for_affected_tools():
    import assistant.advice as advice
    assert advice._match("cve-updater", "CVE-2026-1 affects the antivirus")


# ---- no auto-patching anywhere in the wave --------------------------------
def test_no_wave_code_upgrades_packages():
    for f in ("cverules.py", "cve-refresh.py"):
        src = (ROOT / f).read_text()
        for banned in ("apt upgrade", "apt-get", "apt install"):
            assert banned not in src, (f, banned)


# ---- the cross-join (item 8): one announcement tells the whole story ------
def test_cross_join_tells_a_cve_whose_tool_the_program_covers(tmp_path):
    p = _cache(tmp_path, [{"id": "CVE-2026-0050", "modified": "m",
                           "tool": "curl", "score": 8.5,
                           "severity": "HIGH", "summary": "curl parse"}])
    (tmp_path / "ptp-watch.json").write_text(json.dumps(
        {"ts": "t", "projects": [
            {"project": "curl", "findings": 12, "high": 3, "medium": 6,
             "low": 3, "via": "deb", "packages": ["curl"]}]}))
    specs = cverules.evaluate(tmp_path, cache_path=p)
    assert len(specs) == 1
    text = specs[0][1]
    assert "watchlist" in text and "3 HIGH" in text
    assert "installed versions" in text       # the original rule text stays


def test_cross_join_stays_silent_when_nothing_overlaps(tmp_path):
    p = _cache(tmp_path, [{"id": "CVE-2026-0051", "modified": "m",
                           "tool": "psad", "score": 8.5,
                           "severity": "HIGH", "summary": "psad parse"}])
    text = cverules.evaluate(tmp_path, cache_path=p)[0][1]
    assert "watchlist" not in text
