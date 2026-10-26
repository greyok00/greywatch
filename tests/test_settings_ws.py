"""tests/test_settings_ws.py — the dashboard workspace preference (Pass 4)."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.settings import ws_pref, ws_set

DATA = ROOT / "data"


def test_default_is_three_without_a_file(tmp_path):
    assert ws_pref(tmp_path) == 3              # the owner's standing rule


def test_save_and_read_roundtrip(tmp_path):
    assert ws_set(tmp_path, 4)
    assert ws_pref(tmp_path) == 4
    assert ws_set(tmp_path, 1)
    assert ws_pref(tmp_path) == 1


def test_corrupt_file_falls_back_to_three(tmp_path):
    p = tmp_path / "workspace.json"
    p.write_text("{corrupt")
    assert ws_pref(tmp_path) == 3
    p.write_text(json.dumps({"ws": 99}))
    assert ws_pref(tmp_path) == 3              # out of range clamps back
    assert ws_set(tmp_path, 0) is False        # refused, nothing written
    assert ws_set(tmp_path, 7) is False


def test_atomic_write_leaves_no_tmp(tmp_path):
    assert ws_set(tmp_path, 2)
    assert list(tmp_path.glob("*.tmp")) == []
    assert pathlib.Path.exists(tmp_path / "workspace.json")