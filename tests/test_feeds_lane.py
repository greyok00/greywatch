"""feeds_lane pins: skip-fresh logic, keep-yesterday exit semantics
(GW-08), the web-of-trust pass (filtered render + intelwall + report).
"""
from __future__ import annotations

import json

import pytest

import feeds
import feeds_lane


@pytest.fixture(autouse=True)
def _sandbox_env(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    # the trust layer must never touch the real resolver or wall in tests
    monkeypatch.setattr(feeds_lane, "INSTALLED_DNSMASQ_CONF", "")
    return tmp_path


@pytest.fixture()
def _no_reload(tmp_path, monkeypatch):
    import webguard
    monkeypatch.setattr(webguard, "reload_dnsmasq", lambda: "skipped")


def test_lane_skips_fresh_feeds_and_updates_render(tmp_path, monkeypatch,
                                                   _no_reload):
    cache = tmp_path / "feeds"
    cache.mkdir()
    (cache / "manifest.json").write_text(json.dumps(
        {"urlhaus": {"fetched_at": 9_999_999_999.0, "state": "ok"}}))
    called = []
    monkeypatch.setattr(feeds_lane.feeds, "fetch_one",
                        lambda *a, **k: called.append(a) or
                        feeds_lane.feeds.PullResult("x", "ok", rows=[]))
    rc = feeds_lane.main()
    pulled = [spec.name for (spec, *_rest) in called]
    assert "urlhaus" not in pulled            # fresh enough: skipped
    assert set(pulled) == set(feeds.FEEDS) - {"urlhaus"}
    assert rc == 0


def test_lane_pulls_stale_and_lists_failures_but_exits_0(tmp_path,
                                                         monkeypatch,
                                                         capsys,
                                                         _no_reload):
    # GW-08: a transient pull keeps yesterday's set and must NOT fail
    # the unit — the lane exits 0, the failure is on stderr for the log
    (tmp_path / "feeds").mkdir()
    monkeypatch.setattr(feeds_lane.feeds, "fetch_one",
                        lambda *a, **k: feeds_lane.feeds.PullResult(
                            "x", "failed", reason="network down"))
    rc = feeds_lane.main()
    assert rc == 0
    err = capsys.readouterr().err
    assert "network down" in err


def test_lane_writes_intel_web_report(tmp_path, monkeypatch, capsys,
                                      _no_reload):
    (tmp_path / "feeds").mkdir()
    monkeypatch.setattr(feeds_lane.feeds, "fetch_one",
                        lambda *a, **k: feeds_lane.feeds.PullResult(
                            "x", "ok", rows=[]))
    feeds_lane.main()
    report = json.loads((tmp_path / "intel-web.json").read_text())
    assert set(report["sources"]) == set(feeds.FEEDS)
    assert "enforced" in report["totals"] and "held" in report["totals"]
    assert report["dnsmasq"]["reload"] == "skipped"


def test_lane_firewall_layer_runs_and_is_recorded(tmp_path, monkeypatch,
                                                  _no_reload):
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "spamhaus-drop.txt").write_text("192.0.2.0/24\n")
    (tmp_path / "feeds" / "manifest.json").write_text("{}")
    monkeypatch.setattr(feeds_lane.feeds, "fetch_one",
                        lambda *a, **k: feeds_lane.feeds.PullResult(
                            "x", "ok", rows=[]))
    feeds_lane.main()
    report = json.loads((tmp_path / "intel-web.json").read_text())
    wall = report["firewall"]
    assert wall["count"] >= 1 and wall["loaded"] is False  # non-root: stored only
    body = (tmp_path / "gw-intel.nft").read_text()
    assert "192.0.2.0/24" in body


def test_lane_rejects_wildcard_rows_from_the_resolver_render(tmp_path,
                                                             monkeypatch,
                                                             _no_reload):
    # a tier-2 held row must not reach dnsmasq; an enforced one must
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "onehosts-lite.txt").write_text("lone-tracker.test\n")
    (tmp_path / "feeds" / "urlhaus.txt").write_text("corroborated.test\n")
    (tmp_path / "feeds" / "manifest.json").write_text(json.dumps(
        {"urlhaus": {"fetched_at": 9_999_999_999.0, "state": "ok"},
         "onehosts-lite": {"fetched_at": 9_999_999_999.0, "state": "ok"}}))
    monkeypatch.setattr(feeds_lane.feeds, "fetch_one",
                        lambda *a, **k: feeds_lane.feeds.PullResult(
                            "x", "ok", rows=[]))
    feeds_lane.main()
    body = (tmp_path / "webguard-blocklist.conf").read_text()
    assert "corroborated.test" in body
    assert "lone-tracker.test" not in body


def test_lane_trust_layer_crash_still_writes_report(tmp_path, monkeypatch,
                                                    capsys):
    (tmp_path / "feeds").mkdir()
    monkeypatch.setattr(feeds_lane.feeds, "fetch_one",
                        lambda *a, **k: feeds_lane.feeds.PullResult(
                            "x", "ok", rows=[]))
    import webguard
    monkeypatch.setattr(webguard, "render_dnsmasq",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("disk full")))
    with pytest.raises(RuntimeError):
        feeds_lane.main()
    report = json.loads((tmp_path / "intel-web.json").read_text())
    assert "disk full" in report["error"]
