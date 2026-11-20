"""Pins for the DNS monitor store (build order item c).

The store derives from the resolver's query log and flags hits against
the blocklist the wall actually serves. The standing law: no DNS near
the pump - nothing here reads or writes the daemon's status beat; every
number lands in one state file the slow lane owns.
"""

from __future__ import annotations

import json

from core import dnslog


_SAMPLE = "\n".join([
    "2026-11-15T09:00:01+00:00 host dnsmasq[9]: query[A] ads.example.com"
    " from 127.0.0.1",
    "2026-11-15T09:00:02+00:00 host dnsmasq[9]: query[AAAA] ads.example.com"
    " from 127.0.0.1",
    "2026-11-15T09:00:03+00:00 host dnsmasq[9]: query[A] img.ads.example.com"
    " from 10.0.0.7",
    "2026-11-15T09:00:04+00:00 host dnsmasq[9]: query[A] greywatch.local"
    " from 10.0.0.7",
    "unparseable journal noise stays a non-event",
])

# the wall as build() wants it: the parsed domain set + one provenance
# line (the file path in real runs)
_WALL = ({"example.com", "other.net"}, "test blocklist")


def test_query_rows_parse_and_count():
    rep = dnslog.build(journal=_SAMPLE, blocklist=_WALL)
    assert rep["counts"]["queries"] == 4
    ads = rep["domains"]["ads.example.com"]
    assert ads["queries"] == 2
    assert ads["clients"] == ["127.0.0.1"]


def test_parent_domain_of_a_wall_row_counts_blocked():
    rep = dnslog.build(journal=_SAMPLE, blocklist=_WALL)
    # the wall holds example.com; img.ads.example.com is swallowed
    assert rep["domains"]["img.ads.example.com"]["blocked"] is True
    assert rep["domains"]["greywatch.local"]["blocked"] is False
    assert rep["counts"]["blocked_hits"] == 2


def test_empty_journal_says_the_honest_thing():
    rep = dnslog.build(journal="", blocklist=_WALL)
    assert rep["counts"]["queries"] == 0
    assert "resolver keeps no query log" in rep["note"] or \
        rep["log_queries_enabled"] is False


def test_store_rolls_oldest_out_at_the_cap():
    journal = "\n".join(
        f"2026-11-15T0{i % 10}:00:0{i % 10}+00:00 h dnsmasq[9]: query[A] "
        f"d{i:04d}.test from 127.0.0.1" for i in range(4400))
    rep = dnslog.build(journal=journal, blocklist=_WALL)
    assert rep["capped"] is True
    assert rep["counts"]["domains"] == dnslog._DOMAIN_CAP
    # the newest stamps survive the roll
    assert "d4399.test" in rep["domains"]


def test_persist_round_trip(tmp_path):
    rep = dnslog.build(journal=_SAMPLE, blocklist=_WALL)
    out = dnslog.persist(rep, data_dir=tmp_path)
    assert out.name == "dnslog.json"
    reload = json.loads(out.read_text())
    assert reload["counts"] == rep["counts"]
    human = dnslog.human(reload)
    assert "blocked" in human.lower() or "queries" in human.lower()


def test_human_speaks_blocked_hits_plainly():
    rep = dnslog.build(journal=_SAMPLE, blocklist=_WALL)
    text = dnslog.human(rep)
    assert "BLOCKED" in text
    assert "greywatch.local" in text
    assert "BLOCKED" not in text.split("greywatch.local")[1][:40]
