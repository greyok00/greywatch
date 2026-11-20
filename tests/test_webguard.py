"""webguard: dnsmasq render + reload (plan Task 3, design §6.1 stage [3]).

Site questions (ads/trackers/malware/phishing domains) are answered at
the resolver — browser-independent. The renderer is pure: it renders a
dnsmasq conf-file snippet atomically from the feed cache; IP rows are
NOT rendered here (they belong to nft sets, plan Task 4).
"""
from __future__ import annotations

import os
import signal

import webguard


def test_render_dedupes_counts_and_formats(tmp_path):
    cache = {"hagezi-multi-normal": {"ads.example", "common.test"},
             "urlhaus": {"common.test", "malware-domain.test"}}
    out = tmp_path / "webguard-blocklist.conf"
    count = webguard.render_dnsmasq(cache, out)
    text = out.read_text()
    lines = [ln for ln in text.splitlines() if ln.startswith("address=")]
    assert count == len(lines) == 3          # deduped across feeds
    assert "address=/ads.example/" in text
    assert "address=/common.test/" in text   # exactly once
    assert lines.count("address=/common.test/") == 1
    assert "address=/malware-domain.test/" in text
    assert text.startswith("# greywatch webguard")


def test_render_is_atomic_no_stray_tmp_files(tmp_path):
    cache = {"urlhaus": {"c2.example"}}
    out = tmp_path / "block.conf"
    webguard.render_dnsmasq(cache, out)
    # atomic_replace stages in a sibling .root-tmp/ dir (repo standard):
    # what must NOT happen is a stray *.new data file beside the target.
    stray = [p.name for p in tmp_path.iterdir()
             if p.name != "block.conf" and p.name != ".root-tmp"]
    assert stray == []
    assert out.read_text().startswith("# greywatch webguard")


def test_render_excludes_ip_rows_they_belong_to_nft(tmp_path):
    cache = {"firehol-l1": {"203.0.113.7", "198.51.100.0/24"},
             "urlhaus": {"c2.example"}}
    out = tmp_path / "block.conf"
    count = webguard.render_dnsmasq(cache, out)
    text = out.read_text()
    assert count == 1
    assert "203.0.113.7" not in text
    assert "198.51.100.0" not in text


def test_render_double_checks_tokens_drops_invalid(tmp_path):
    cache = {"urlhaus": {"good.test", "bad token with spaces",
                         "trailing/slash.test"}}
    out = tmp_path / "block.conf"
    count = webguard.render_dnsmasq(cache, out)
    text = out.read_text()
    assert count == 1 and "address=/good.test/" in text


def test_render_punycode_kept(tmp_path):
    cache = {"phishing-army": {"xn--80ak6aa92e.com"}}
    out = tmp_path / "block.conf"
    assert webguard.render_dnsmasq(cache, out) == 1
    assert "address=/xn--80ak6aa92e.com/" in out.read_text()


def test_reload_with_missing_pidfile_is_false_not_crash(tmp_path):
    assert webguard.reload_dnsmasq(pidfile=tmp_path / "absent.pid") is False


def test_reload_sends_sighup_and_reports(tmp_path, monkeypatch):
    pidfile = tmp_path / "dnsmasq.pid"
    pidfile.write_text("4242\n")
    sent = []
    monkeypatch.setattr(os, "kill",
                        lambda pid, sig: sent.append((pid, sig)))
    assert webguard.reload_dnsmasq(pidfile=pidfile) is True
    assert sent == [(4242, signal.SIGHUP)]


def test_reload_false_when_pidfile_garbage(tmp_path):
    pidfile = tmp_path / "dnsmasq.pid"
    pidfile.write_text("not-a-pid")
    assert webguard.reload_dnsmasq(pidfile=pidfile) is False


def test_blocked_by_guard(tmp_path):
    out = tmp_path / "block.conf"
    webguard.render_dnsmasq({"urlhaus": {"c2.example"}}, out)
    assert webguard.blocked_by_guard("c2.example", out) is True
    assert webguard.blocked_by_guard("clean.example", out) is False
