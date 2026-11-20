"""The intel updater: pull-only feeds, caps, and the join to local docs.

Fetches are monkeypatched ``intel.fetch_body`` calls - no test touches
the network. Fixtures build the ``hunter/intel/`` cache files by hand.
"""
import json

import pytest

from hunter import intel


@pytest.fixture()
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d


_PHISHING_ARMY_TXT = (
    "# Phishing Army | Community phishing domain blocklist\n"
    "# Generated: 2026-11-04T05:00:30Z\n"
    "panel-1.badguy.example\n"
    "https://not-a-domain.example/ignored\n")

_OPENPHISH_TXT = "https://phish-open.example/login\n"


def test_feed_table_has_the_keyless_sources():
    assert set(intel.FEEDS) == {"openphish", "phishing-army"}
    assert all(str(u).startswith("http") for u in intel.FEEDS.values())


def test_refresh_caches_what_the_feeds_gave(data_dir, monkeypatch):
    monkeypatch.setattr(intel, "fetch_body", lambda url, cap, timeout=20.0: {
        "phishing": _PHISHING_ARMY_TXT,
        "openphish": _OPENPHISH_TXT}[url.split("/")[2].split(".")[0]])
    intel.refresh(data_dir, {}, now=intel._now())
    for feed in intel.FEEDS:
        cache = intel.intel_dir(data_dir) / f"{feed}.json"
        assert cache.is_file(), feed
        doc = json.loads(cache.read_text())
        assert doc["feed"] == feed
        assert doc["rows"], feed
    status = intel.read_status(data_dir)
    assert status.get("last_ok")
    assert set(status.get("ages", {})) == set(intel.FEEDS)


def test_oversize_feeds_are_rejected(data_dir, monkeypatch):
    monkeypatch.setattr(intel, "FEED_MAX_BYTES", 64)
    monkeypatch.setattr(intel, "fetch_body", lambda url, cap, timeout=20.0:
                        "x" * 4096)
    intel.refresh(data_dir, {}, now=intel._now())
    status = intel.read_status(data_dir)
    assert status.get("errors", {}).get("openphish") == "oversize"
    assert not (intel.intel_dir(data_dir) / "openphish.json").exists()


def test_broken_parsing_is_rejected_not_cached(data_dir, monkeypatch):
    monkeypatch.setattr(intel, "fetch_body", lambda url, cap, timeout: "")
    intel.refresh(data_dir, {}, now=intel._now())
    status = intel.read_status(data_dir)
    assert status.get("errors"), "every feed must record an error"


def test_refresh_respects_the_interval(data_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(intel, "fetch_body", lambda u, c, t=20.0:
                        calls.append(u) or {
                            "phishing": _PHISHING_ARMY_TXT,
                            "openphish": _OPENPHISH_TXT}[
                                u.split("/")[2].split(".")[0]])
    intel.refresh(data_dir, {}, now=intel._now())
    assert calls, "first refresh must fetch"
    calls.clear()
    intel.refresh(data_dir, {}, now=intel._now() + intel.INTERVAL_S - 1)
    assert calls == [], "inside the interval nothing is fetched"
    intel.refresh(data_dir, {}, now=intel._now() + intel.INTERVAL_S + 60)
    assert calls, "past the interval the feeds are fetched again"


def test_join_matches_hosts_and_prefixes_once_each(data_dir):
    intel_dir = intel.intel_dir(data_dir)
    intel_dir.mkdir(parents=True)
    (intel_dir / "phishing-army.json").write_text(json.dumps({
        "feed": "phishing-army", "fetched": intel._iso(), "rows": [
            {"value": "panel-1.badguy.example", "kind": "host"},
            {"value": "http://panel-1.badguy.example/deliver.sh",
             "kind": "url"}]}), encoding="utf-8")
    (intel_dir / "openphish.json").write_text(json.dumps({
        "feed": "openphish", "fetched": intel._iso(), "rows": [
            {"value": "https://cdn-drop.example/payload.exe", "kind":
             "url"}]}), encoding="utf-8")
    docs = [
        {"url": "http://panel-1.badguy.example/step1", "host":
         "panel-1.badguy.example"},
        {"url": "http://panel-1.badguy.example/step2", "host":
         "panel-1.badguy.example"},
        {"url": "https://cdn-drop.example/payload.exe",
         "host": "cdn-drop.example"},
        {"url": "https://clean.example/", "host": "clean.example"},
    ]
    found = intel.join_findings(data_dir, docs)
    hosts = sorted({f["facts"][0].split("=", 1)[1].split(",")[0]
                    for f in found})
    assert hosts == ["cdn-drop.example", "panel-1.badguy.example"]
    assert len(found) == 2, "one finding per unique host"
    for f in found:
        assert f["rule"] == "intel-feed-match"
        assert "phishing-army" in f["what"] or "openphish" in f["what"]


def test_join_uses_the_real_downloads_paths_as_candidates(data_dir):
    intel_dir = intel.intel_dir(data_dir)
    intel_dir.mkdir(parents=True)
    (intel_dir / "phishing-army.json").write_text(json.dumps({
        "feed": "phishing-army", "fetched": intel._iso(), "rows": [
            {"value": "dropper-host.example", "kind": "host"}]}),
        encoding="utf-8")
    docs = [{"url": "https://dropper-host.example/setup.exe",
             "host": "dropper-host.example"}]
    found = intel.join_findings(data_dir, docs)
    assert found and "phishing-army" in found[0]["what"]


def test_join_with_no_cache_is_quiet(data_dir):
    assert intel.join_findings(data_dir, [
        {"url": "https://panel-1.badguy.example/", "host":
         "panel-1.badguy.example"}]) == []