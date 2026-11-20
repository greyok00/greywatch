"""The delivery-pattern corpus: seed rules over normalized web docs.

Docs are the shapes the other lanes feed: HAR entries, history rows, and
live-CDP summaries. Rules match substrings; nothing is fetched, nothing
executed.
"""
import json
import pathlib

import pytest

from hunter import patterns

RULES_PATH = pathlib.Path(__file__).resolve().parents[1] / "hunter" \
    / "patterns-rules.json"


@pytest.fixture(scope="module")
def seed():
    _version, rules = patterns.load_rules()
    return rules


def doc(**kw):
    base = {"url": "", "host": "", "title": "", "mime": "", "cdp": False,
            "source": "har"}
    base.update(kw)
    return base


def test_seed_version_is_pinned():
    version, rules = patterns.load_rules()
    # v2 retired the two can-never-fire rules (cloak-flip, base64-page);
    # v3 retired drive-by-kit the same round the audits proved no
    # producer can satisfy its needs (patterns.py carries the story).
    assert version == 3
    assert len(rules) >= 6


def test_every_seed_rule_carries_the_full_schema(seed):
    rules = seed
    required = {"id", "title", "severity", "confidence", "what", "next",
                "window_hours"}
    for r in rules:
        assert required <= set(r), r.get("id")
        assert r["severity"] in ("HIGH", "MEDIUM", "LOW"), r["id"]
        assert r["window_hours"] in (24, 168), r["id"]
        m = r.get("match") or {}
        keys = set(m) if isinstance(m, dict) else set()
        assert keys <= {"host", "url", "title", "mime"}, r["id"]


def test_fake_captcha_page_fires(seed):
    found = patterns.apply_rules(
        [doc(url="https://human-verify.example/hold", host="human-verify.example",
             title="Verify you are human - press & hold")], seed)
    assert len(found) == 1
    f = found[0]
    assert f["rule"] == "pat-fake-captcha"
    assert f["severity"] == "HIGH"
    assert f["status"] == "lead"
    assert any("human-verify.example" in fact or "hold" in fact
               for fact in f["facts"])


def test_tech_support_scam_fires_on_the_number_shape(seed):
    found = patterns.apply_rules(
        [doc(url="https://error-page.support/1-800-need-help-now",
             host="error-page.support",
             title="A page on this site says to call support")], seed)
    rules_hit = [f["rule"] for f in found]
    assert "pat-tech-support-scam" in rules_hit


def test_drive_by_kit_is_retired_v3(seed):
    # Round 3 retired pat-drive-by-kit (F2): the rule required a download
    # count and a content-disposition flag no producer could ever record
    # on a live-captured document, so nothing - in ten cycles of real
    # captures - could ever satisfy it. Retirement is pinned, not the
    # never-fire: exactly this traffic stays silent instead of firing.
    plain = doc(url="https://ads.example/x", host="ads.example")
    live = doc(url="https://ads.example/x", host="ads.example", cdp=True,
               iframes=3, downloads=1)
    assert patterns.apply_rules([plain], seed) == []
    assert patterns.apply_rules([live], seed) == []
    assert "pat-drive-by-kit" not in seed


def test_benign_docs_fire_nothing(seed):
    benign = [
        doc(url="https://www.google.com/search?q=weather",
            host="www.google.com", title="weather - Google Search"),
        doc(url="https://en.wikipedia.org/wiki/Windows_Defender",
            host="en.wikipedia.org", title="Windows Defender - Wikipedia"),
        doc(url="https://example.com/files/notes.pdf", host="example.com",
            mime="application/pdf", title="Quarterly notes"),
    ]
    assert patterns.apply_rules(benign, seed) == []


def test_repeats_collapse_in_the_engine_seen_map(seed):
    from hunter import engine
    d = doc(url="https://update-now.example/", host="update-now.example",
            title="Update required")
    first = patterns.apply_rules([d], seed)
    assert len(first) >= 1
    seen = {}
    kept, seen = engine.apply_dedupe(seen, first)
    again, _ = engine.apply_dedupe(seen, patterns.apply_rules([d], seed))
    assert len(kept) == 1 and again == []


def test_malformed_rules_and_docs_are_skipped():
    broken = [{"id": "x"}, {"id": "y", "title": "t", "severity": "HIGH"},
              "not-a-dict", {"id": "z", "severity": "HIGH", "title": "tt",
                             "match": {"host": ["example"]},
                             "what": "missing keys everywhere"}]
    assert patterns.apply_rules([doc(host="example.com")], broken) == []


def test_rules_file_stays_strict_json():
    doc = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    assert isinstance(doc, dict) and doc["version"] == 3
    assert len(doc["rules"]) >= 6