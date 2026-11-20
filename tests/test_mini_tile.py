"""Headless coverage for the mini status tile's pure logic: every tool,
watcher and pending decision must appear; healthy rows stay quiet while
problems name themselves; unreadable and stale states stay honest; the
opt-in setting round-trips without losing other settings."""
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from ui.minitile import (build_rows, is_stale, load_status,  # noqa: E402
                         set_tile_wanted, tile_wanted)


def sample_status(stale=False):
    stamp = datetime.now(timezone.utc)
    if stale:
        stamp -= timedelta(seconds=120)
    return {
        "updated": stamp.isoformat(),
        "pending_decisions": 1,
        "appfw_engine": "off (owner switch)",
        "components": {
            "tail:auditd": {"state": "running", "restarts": 2},
            "tail:ufw": {"state": "stopped", "restarts": 0},
        },
        "tools": {
            "aide": {"label": "AIDE (integrity check)", "state": "GREEN",
                     "last_event": None, "unit_state": "active",
                     "installed": True},
            "appfw": {"label": "App Firewall", "state": "AMBER",
                      "last_event": "2026-10-26T10:14:41+00:00",
                      "unit_state": "active", "installed": True},
            "ufw": {"label": "UFW (firewall)", "state": "RED",
                    "last_event": None, "unit_state": "failed",
                    "installed": True},
            "tetragon": {"label": "Tetragon (kernel eBPF)", "state": "GREEN",
                         "last_event": None, "unit_state": "active",
                         "installed": False},
        },
    }


def test_every_tool_watcher_engine_and_pending_appear():
    rows = "\n".join(build_rows(sample_status()))
    assert "decision(s) waiting" in rows
    assert "· watching (daemon)" in rows
    assert "tail:auditd" in rows
    assert "2 restarts" in rows
    assert "tail:ufw" in rows
    assert "appfw-engine off (owner switch)" in rows
    assert "· protections" in rows
    for tool in ("aide", "appfw", "ufw", "tetragon"):
        assert tool in rows


def test_healthy_rows_stay_quiet_problems_name_themselves():
    rows = "\n".join(build_rows(sample_status()))
    assert '<span color="#3fb950">●</span> aide' in rows
    assert " appfw amber" in rows
    assert " ufw red" in rows
    assert " tetragon not installed" in rows


def test_unreadable_store_is_honest_never_empty():
    rows = build_rows(None)
    assert len(rows) == 1
    assert "not readable" in rows[0]
    assert "🟢" not in rows[0]


def test_stale_is_true_for_old_missing_or_broken_timestamp():
    assert not is_stale(sample_status())
    assert is_stale(sample_status(stale=True))
    assert is_stale({"tools": {}})
    assert is_stale({"updated": "not-a-stamp"})


def test_setting_roundtrip_keeps_other_keys(tmp_path):
    p = tmp_path / "settings.json"
    assert tile_wanted(p) is False
    p.write_text('{"theme": "console"}', encoding="utf-8")
    assert tile_wanted(p) is False
    set_tile_wanted(True, p)
    assert json.loads(p.read_text(encoding="utf-8")) == {
        "theme": "console", "mini_tile": True}
    set_tile_wanted(False, p)
    assert tile_wanted(p) is False
    assert json.loads(p.read_text(encoding="utf-8"))["theme"] == "console"


def test_broken_settings_file_defaults_to_off(tmp_path):
    p = tmp_path / "settings.json"
    p.write_text('{not json', encoding="utf-8")
    assert tile_wanted(p) is False


def test_live_snapshot_if_present():
    status = load_status()
    if status is None:
        pytest.skip("no live snapshot on this machine")
    assert isinstance(status, dict)
    assert "tools" in status or "components" in status