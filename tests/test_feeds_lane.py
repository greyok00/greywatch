"""feeds_lane pins (plan Task 7): skip-fresh logic + failures list.
(Red-first was impractical: the lane exists to give the unit an
ExecStart; these are regression pins, recorded as such in the ledger.)
"""
from __future__ import annotations

import json
import pathlib

import pytest

import feeds_lane


@pytest.fixture(autouse=True)
def _sandbox_env(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def test_lane_skips_fresh_feeds_and_updates_render(tmp_path, monkeypatch):
    import feeds
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
    assert set(pulled) == set(feeds_lane.feeds.FEEDS) - {"urlhaus"}
    assert rc == 0


def test_lane_pulls_stale_and_lists_failures(tmp_path, monkeypatch, capsys):
    cache = tmp_path / "feeds"
    cache.mkdir()
    (cache / "manifest.json").write_text("{}")
    monkeypatch.setattr(feeds_lane.feeds, "fetch_one",
                        lambda *a, **k: feeds_lane.feeds.PullResult(
                            "x", "failed", reason="network down"))
    rc = feeds_lane.main()
    assert rc == 1
    err = capsys.readouterr().err
    assert "network down" in err
