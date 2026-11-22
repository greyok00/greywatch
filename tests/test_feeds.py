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


def test_ipv6_bad_ip_rows_are_kept_not_smuggled():
    spec = feeds.FeedSpec(name="v6-probe", url="http://x/y", category="bad-ip",
                          max_bytes=4096, max_rows=100, cadence_s=86400,
                          parser="ips", kind="ip")
    got = feeds.parse("2001:db8::9\n192.0.2.7\nnot-an-ip\n", spec)
    assert got == ["2001:db8::9", "192.0.2.7"]


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


# -------------------------------------------------- parser repairs (GW-05/06)

def test_oisd_wildcard_rows_strip_the_asterisk():
    got = feeds.parse("*.doubleclick.net\n*.bad-ads.test\nplain.test\n",
                      feeds.FEEDS["oisd-small"])
    assert got == ["doubleclick.net", "bad-ads.test", "plain.test"]


def test_bare_asterisk_row_is_dropped():
    assert feeds.parse("*\nreal.test\n", feeds.FEEDS["oisd-small"]) == ["real.test"]


def test_netset_parses_cidr_and_bare_ip():
    got = feeds.parse("192.0.2.0/24\n198.51.100.7\n203.0.113.0/24\n"
                      "2001:db8::/32\nnot-a-net\n", feeds.FEEDS["spamhaus-drop"])
    assert got == ["192.0.2.0/24", "198.51.100.7", "203.0.113.0/24",
                   "2001:db8::/32"]


def test_netset_annotation_after_semicolon_is_noise():
    got = feeds.parse("192.0.2.0/24 ; SBL12345\n198.51.100.7 ; RIR junk\n",
                      feeds.FEEDS["spamhaus-drop"])
    assert got == ["192.0.2.0/24", "198.51.100.7"]


def test_dshield_rows_become_cidrs():
    text = "# Title: DShield Shield List\n222.186.30.0\t222.186.30.255\t24\n" \
           "1.2.3.0\t1.2.3.255\t24\n"
    assert feeds.parse(text, feeds.FEEDS["dshield"]) == \
        ["222.186.30.0/24", "1.2.3.0/24"]


def test_dnsmasq_local_rows_parse_to_domains():
    text = "local=/pl-ebok.bad-tif.test/\nlocal=/second-one.test/\n"
    assert feeds.parse(text, feeds.FEEDS["hagezi-tif"]) == \
        ["pl-ebok.bad-tif.test", "second-one.test"]


def test_dnsmasq_address_rows_parse_too():
    got = feeds.parse("address=/another.test/\n", feeds.FEEDS["hagezi-tif"])
    assert got == ["another.test"]


def test_zero_row_guard_rejects_format_drift():
    # GW-07: 60 well-formed-looking-but-wrong lines must not record an ok
    # pull that empties the blocklist
    text = "\n".join(f"line-{i}-$$$.test" for i in range(60)) + "\n"
    with pytest.raises(feeds.ParseError, match="60 non-comment lines"):
        feeds.parse(text, feeds.FEEDS["hagezi-multi-normal"])


def test_tiny_zero_row_body_still_tolerated():
    # short garbage stays a drop-everything pull, not a rejection
    assert feeds.parse("junk $$$\n", feeds.FEEDS["hagezi-multi-normal"]) == []


# ---------------------------------------------------------------- fetch


def test_fetch_writes_group_readable_when_gid_passed(tmp_path, monkeypatch):
    # GW-03: the cache must be 0640 root:<ui-group> so the unprivileged
    # GUI lane's intel matching can read it; here we prove the 0640 side
    # (the root:grey half is the daemon lane's real-euid business).
    import os
    import pwd
    import stat as stat_mod
    import sys
    sys.path.insert(0, str(pathlib.Path(feeds.__file__).parent))
    own_gid = pwd.getpwuid(os.geteuid()).pw_gid
    monkeypatch.setattr("status.ui_gid", lambda: own_gid)
    spec = feeds.FEEDS["urlhaus"]
    result = feeds.fetch_one(spec, now=1.0, client=lambda *a, **k: _Body(b"good.test\n"),
                             cache_dir=tmp_path)
    assert result.state == "ok"
    mode = stat_mod.S_IMODE((tmp_path / "urlhaus.txt").stat().st_mode)
    assert mode == 0o640, oct(mode)
    man_mode = stat_mod.S_IMODE((tmp_path / "manifest.json").stat().st_mode)
    assert man_mode == 0o640, oct(man_mode)


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
    (tmp_path / "urlhaus.txt").write_text("malware-domain.test\n2001:db8::9\n")
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


def test_apply_verdict_hits_ipv6_without_a_parent_lookup(cache):
    category, feed = feeds.apply_verdict("2001:db8::9", cache)
    assert category == "malware" and feed == "urlhaus"


def test_apply_verdict_clean_destination(cache):
    assert feeds.apply_verdict("ubuntu.com", cache) == (None, None)


def test_apply_verdict_no_cache_dir(tmp_path):
    assert feeds.apply_verdict("anything.test", tmp_path) == (None, None)


def test_feeds_registry_matches_wot_design():
    names = set(feeds.FEEDS)
    assert names == {"hagezi-multi-normal", "hagezi-tif", "oisd-small",
                     "urlhaus", "stevenblack", "onehosts-lite",
                     "phishing-army", "openphish", "spamhaus-drop",
                     "cins-army", "blocklist-de", "dshield", "firehol-l1"}
    tier2 = {n for n, s in feeds.FEEDS.items() if s.tier == 2}
    assert tier2 == {"onehosts-lite", "firehol-l1"}
    # every IP feed validates on the IP path, none on the hostname path
    for name, spec in feeds.FEEDS.items():
        if spec.category == "bad-ip":
            assert spec.kind == "ip", name


# ---------------------------------------------------------- web of trust


def test_tier1_rows_enforce_alone(tmp_path):
    (tmp_path / "spamhaus-drop.txt").write_text("192.0.2.0/24\n")
    rows, report = feeds.enforced_rows(tmp_path)
    assert rows["spamhaus-drop"] == {"192.0.2.0/24"}
    assert report["sources"]["spamhaus-drop"]["enforced"] == 1
    assert report["totals"]["held"] == 0


def test_tier2_single_source_entry_is_held(tmp_path):
    (tmp_path / "onehosts-lite.txt").write_text("lone-tracker.test\n")
    rows, report = feeds.enforced_rows(tmp_path)
    assert rows["onehosts-lite"] == set()
    src = report["sources"]["onehosts-lite"]
    assert src["rows"] == 1 and src["enforced"] == 0 and src["held"] == 1
    assert report["totals"]["held"] == 1


def test_tier2_corroborated_entry_is_enforced(tmp_path):
    (tmp_path / "onehosts-lite.txt").write_text("lone-tracker.test\n")
    (tmp_path / "hagezi-multi-normal.txt").write_text("lone-tracker.test\n")
    rows, report = feeds.enforced_rows(tmp_path)
    assert rows["onehosts-lite"] == {"lone-tracker.test"}
    assert report["sources"]["onehosts-lite"]["held"] == 0


def test_same_curator_never_corroborates(tmp_path):
    # two hagezi feeds: the second voice is the same curator, not a witness
    (tmp_path / "hagezi-tif.txt").write_text("hagezi-only.test\n")
    (tmp_path / "hagezi-multi-normal.txt").write_text("hagezi-only.test\n")
    rows, report = feeds.enforced_rows(tmp_path)
    assert rows["hagezi-tif"] == {"hagezi-only.test"}   # tier 1: fine alone
    assert rows["hagezi-multi-normal"] == {"hagezi-only.test"}  # tier 1 too
    # prove the corroboration bar itself via a tier-2 clone curator case:
    spec = feeds.FEEDS["hagezi-multi-normal"]
    other = feeds.FeedSpec(name="probe-t2", url="http://x/y", category="ads",
                           max_bytes=1000, max_rows=100, cadence_s=3600,
                           parser="domains", tier=2, curator="hagezi")
    assert feeds._independent(other, spec) is False


def test_firehol_never_corroborates_its_upstreams(tmp_path):
    assert feeds._independent(feeds.FEEDS["firehol-l1"],
                              feeds.FEEDS["spamhaus-drop"]) is False
    assert feeds._independent(feeds.FEEDS["firehol-l1"],
                              feeds.FEEDS["dshield"]) is False
    assert feeds._independent(feeds.FEEDS["firehol-l1"],
                              feeds.FEEDS["cins-army"]) is False
    # but firehol still corroborates a feed it does not derive from
    assert feeds._independent(feeds.FEEDS["firehol-l1"],
                              feeds.FEEDS["blocklist-de"]) is True


def test_firehol_tier2_rows_need_independent_witness(tmp_path):
    # spamhaus lists the netblock; firehol (an aggregator OF spamhaus)
    # repeating it must not count as the second voice for its own copy
    (tmp_path / "spamhaus-drop.txt").write_text("203.0.113.0/24\n")
    (tmp_path / "firehol-l1.txt").write_text("203.0.113.0/24\n")
    rows, report = feeds.enforced_rows(tmp_path)
    assert rows["firehol-l1"] == set()          # firehol's copy held back
    assert report["sources"]["firehol-l1"]["held"] == 1
    # the netblock is still enforced — by spamhaus itself, tier 1
    assert rows["spamhaus-drop"] == {"203.0.113.0/24"}
    # a row only firehol and an independent feed share DOES enforce
    (tmp_path / "blocklist-de.txt").write_text("198.51.100.0/24\n")
    (tmp_path / "firehol-l1.txt").write_text("203.0.113.0/24\n198.51.100.0/24\n")
    rows, report = feeds.enforced_rows(tmp_path)
    assert rows["firehol-l1"] == {"198.51.100.0/24"}
