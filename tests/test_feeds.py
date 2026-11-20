"""feeds: capped validated pulls, deny-or-annotate only (plan Task 2, LAW-4).

A pulled list is UNTRUSTED input crossing into the enforcement path.
Every pull is capped, format-validated and hashed; a failed or hostile
pull keeps yesterday's set. apply_verdict() has no "allow" return by
construction: a feed can only ever contribute a DENY or an annotation.
"""
from __future__ import annotations

import json
import pathlib

import pytest

import feeds

FIX = pathlib.Path(__file__).parent / "fixtures" / "feeds"


# ---------------------------------------------------------------- parse


def test_hagezi_snippet_parses_to_domains():
    text = (FIX / "hagezi.txt").read_text()
    assert "doubleclick.net" in feeds.parse(text, feeds.FEEDS["hagezi-multi-normal"])


def test_urlhaus_snippet_parses_host_column():
    text = (FIX / "urlhaus.txt").read_text()
    got = feeds.parse(text, feeds.FEEDS["urlhaus"])
    assert "malware-domain.test" in got
    assert "c2.badhost.example" in got


def test_phishing_army_snippet_parses_domains():
    text = (FIX / "phishing-army.txt").read_text()
    assert "phish-armed.example" in feeds.parse(text, feeds.FEEDS["phishing-army"])


def test_html_error_page_rejected():
    text = (FIX / "html-error.html").read_text()
    with pytest.raises(feeds.ParseError):
        feeds.parse(text, feeds.FEEDS["hagezi-multi-normal"])


def test_oversized_lines_rejected():
    text = ("ok-domain.test\n" + "x" * 600 + ".test\n")
    with pytest.raises(feeds.ParseError):
        feeds.parse(text, feeds.FEEDS["hagezi-multi-normal"])


def test_row_cap_rejected():
    spec = feeds.FeedSpec(name="cap-probe", url="http://x/y", category="ads",
                          max_bytes=4096, max_rows=5, cadence_s=86400,
                          parser="hosts")
    text = "".join(f"host{i}.test\n" for i in range(10))
    with pytest.raises(feeds.ParseError):
        feeds.parse(text, spec)


def test_garbage_lines_dropped_not_fatal():
    text = "good.test\nnot a domain !!!\n999.999.999.999\nbad-.test\nok2.test\n"
    got = feeds.parse(text, feeds.FEEDS["hagezi-multi-normal"])
    assert got == ["good.test", "ok2.test"]


# ---------------------------------------------------------------- fetch


def test_pullresult_records_sha_and_time(tmp_path):
    calls = []

    def fake_urlopen(url, timeout=0):
        calls.append(url)
        return _Body(b"good.test\n")

    spec = feeds.FEEDS["hagezi-multi-normal"]
    result = feeds.fetch_one(spec, now=1700000000.0, client=fake_urlopen,
                             cache_dir=tmp_path)
    assert result.rows == ["good.test"]
    assert calls == [spec.url]
    assert result.sha256 is not None and len(result.sha256) == 64
    assert result.fetched_at == 1700000000.0
    stored = tmp_path / "hagezi-multi-normal.txt"
    assert stored.read_text() == "good.test\n"
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest[spec.name]["sha256"] == result.sha256
    assert manifest[spec.name]["fetched_at"] == 1700000000.0
    assert manifest[spec.name]["state"] == "ok"


class _Body:
    """Minimal urlopen stand-in: context manager + chunked text.
    First read() returns the payload; the next read returns b'' (EOF),
    as a real terminating stream does."""

    def __init__(self, payload: bytes):
        self._payload = payload
        self._done = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        if self._done:
            return b""
        self._done = True
        return self._payload


def test_oversize_body_rejected_before_parse(tmp_path):
    spec_spec_named = feeds.FeedSpec(
        name="big", url="http://x/y", category="ads", max_bytes=32,
        max_rows=100, cadence_s=86400, parser="hosts")
    big = _Body(b"a" * 64)   # 2x the cap
    result = feeds.fetch_one(spec_spec_named, now=1.0, client=lambda *a, **k: big,
                             cache_dir=tmp_path)
    assert result.state == "rejected"
    assert result.reason and "size cap" in result.reason
    assert not (tmp_path / "big.txt").exists()


def test_failed_pull_keeps_yesterdays_set(tmp_path):
    (tmp_path / "urlhaus.txt").write_text("old-c2.example\n")
    manifest = {"urlhaus": {"state": "ok", "fetched_at": 1.0,
                            "rows": 1, "sha256": "0" * 64}}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))

    def boom(url, timeout=0):
        raise OSError("network down")

    result = feeds.fetch_one(feeds.FEEDS["urlhaus"], now=2.0, client=boom,
                             cache_dir=tmp_path)
    assert result.state == "failed"
    assert result.kept_yesterday is True
    assert (tmp_path / "urlhaus.txt").read_text() == "old-c2.example\n"
    stored = json.loads((tmp_path / "manifest.json").read_text())
    assert stored["urlhaus"]["state"] == "failed"
    assert stored["urlhaus"]["rows"] == 1
    assert stored["urlhaus"].get("error")


# ---------------------------------------------------------------- cache


def test_cache_set_round_trip(tmp_path):
    (tmp_path / "urlhaus.txt").write_text("a.example\nb.example\n")
    entries = feeds.cache_set(tmp_path)
    assert entries["urlhaus"] == {"a.example", "b.example"}


def test_cache_set_missing_file_is_empty(tmp_path):
    assert feeds.cache_set(tmp_path).get("urlhaus") == set()


# ---------------------------------------------------------------- verdict


@pytest.fixture()
def cache(tmp_path):
    (tmp_path / "urlhaus.txt").write_text("malware-domain.test\n")
    (tmp_path / "phishing-army.txt").write_text("bait-site.example\n")
    (tmp_path / "hagezi-multi-normal.txt").write_text("ads.example\n")
    return tmp_path


def test_apply_verdict_hits_malware(cache):
    category, feed = feeds.apply_verdict("malware-domain.test", cache)
    assert category == "malware"
    assert feed == "urlhaus"


def test_apply_verdict_hits_tracker(cache):
    category, feed = feeds.apply_verdict("ads.example", cache)
    assert category == "ads"
    assert feed == "hagezi-multi-normal"


def test_apply_verdict_clean_destination(cache):
    assert feeds.apply_verdict("ubuntu.com", cache) == (None, None)


def test_apply_verdict_no_cache_dir(tmp_path):
    assert feeds.apply_verdict("anything.test", tmp_path) == (None, None)


def test_feeds_registry_matches_design_seven():
    names = set(feeds.FEEDS)
    assert names == {"hagezi-multi-normal", "oisd-small", "urlhaus",
                     "phishing-army", "openphish", "firehol-l1"}
