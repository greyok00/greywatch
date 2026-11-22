"""netmon: the GW-01/GW-04/GW-09 regressions — a real event reader,
the arpwatch fingerprint store, and subnet-aware intel matching.
"""
from __future__ import annotations

import json
import pathlib

import core.netmon as netmon


def _seed_events(data_dir: pathlib.Path, rows: list[dict]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    with (data_dir / "events.jsonl").open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_build_sees_events_not_zeroes(tmp_path):
    # GW-01: _rows used to import events.read_events (wrong module) and
    # swallow the AttributeError — the build saw 0 events forever.
    _seed_events(tmp_path, [
        {"ts": "2026-11-21T10:00:00+00:00", "from_tool": "psad",
         "text": "scan from 203.0.113.7 port 22"}])
    report = netmon.build(tmp_path, arpwatch_dir=str(tmp_path / "no-dat"))
    assert "203.0.113.7" in report["ips"]
    assert "psad" in report["ips"]["203.0.113.7"]["flagged_by"]


def test_missing_events_file_is_an_empty_read_not_a_crash(tmp_path):
    report = netmon.build(tmp_path, arpwatch_dir=str(tmp_path / "no-dat"))
    assert report["counts"]["ips"] == 0


def test_dat_fingerprints_become_devices(tmp_path):
    # GW-04: the persistent arpwatch store holds devices the journal
    # never re-reports; they were invisible to the devices list.
    dat = tmp_path / "arpwatch"
    dat.mkdir()
    (dat / "wlp0s20f3.dat").write_text(
        "aa:bb:cc:dd:ee:ff\t192.0.2.50\t1700000000\t0\twlp0s20f3\n"
        "junk without tabs\n"
        "ab:cd:ef:01:23:45\t192.0.2.51\tbad-epoch\t0\twlp0s20f3\n")
    report = netmon.build(tmp_path, arpwatch_dir=str(dat))
    assert "aa:bb:cc:dd:ee:ff" in report["devices"]
    row = report["devices"]["aa:bb:cc:dd:ee:ff"]
    assert "192.0.2.50" in row["ips"]
    assert "fingerprint" in row["what"][0]["what"]
    # a bad epoch is tolerated: device kept, timestamp honest (None)
    assert "ab:cd:ef:01:23:45" in report["devices"]


def test_cidr_feed_row_matches_member_ip(tmp_path):
    # GW-09: exact-string matching could never match a CIDR row
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "spamhaus-drop.txt").write_text("203.0.113.0/24\n")
    _seed_events(tmp_path, [
        {"ts": "2026-11-21T10:00:00+00:00", "from_tool": "psad",
         "text": "probe from 203.0.113.99"}])
    report = netmon.build(tmp_path, arpwatch_dir=str(tmp_path / "no-dat"))
    flagged = report["ips"]["203.0.113.99"]["flagged_by"]
    assert "intel:spamhaus-drop" in flagged


def test_exact_feed_row_still_matches(tmp_path):
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "blocklist-de.txt").write_text("198.51.100.23\n")
    _seed_events(tmp_path, [
        {"ts": "2026-11-21T10:00:00+00:00", "from_tool": "psad",
         "text": "probe from 198.51.100.23"}])
    report = netmon.build(tmp_path, arpwatch_dir=str(tmp_path / "no-dat"))
    assert "intel:blocklist-de" in report["ips"]["198.51.100.23"]["flagged_by"]


def test_feed_cidr_does_not_match_outside_member(tmp_path):
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "spamhaus-drop.txt").write_text("203.0.113.0/24\n")
    _seed_events(tmp_path, [
        {"ts": "2026-11-21T10:00:00+00:00", "from_tool": "psad",
         "text": "probe from 203.0.114.99"}])
    report = netmon.build(tmp_path, arpwatch_dir=str(tmp_path / "no-dat"))
    row = report["ips"]["203.0.114.99"]
    assert not [b for b in row["flagged_by"] if b.startswith("intel:")]


def test_build_counts_are_consistent(tmp_path):
    _seed_events(tmp_path, [
        {"ts": "2026-11-21T10:00:00+00:00", "from_tool": "arpwatch",
         "text": "new station aa:bb:cc:dd:ee:ff (192.0.2.9)"}])
    report = netmon.build(tmp_path, arpwatch_dir=str(tmp_path / "no-dat"))
    assert report["counts"]["devices"] == 1
    assert report["counts"]["ips"] == 1
    assert report["built_at"]
