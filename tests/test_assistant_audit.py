# tests/test_assistant_audit.py
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import assistant.audit as audit


def test_record_writes_to_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    p = audit.record("pause", "ufw", True)
    assert p == tmp_path / "assistant-actions.jsonl"
    line = json.loads(p.read_text().strip())
    assert line["via"] == "assistant" and line["action"] == "pause"
    assert line["tool"] == "ufw" and line["ok"] is True and line["ts"]


def test_record_falls_back_to_state_dir(tmp_path, monkeypatch):
    locked = tmp_path / "noperm"
    locked.mkdir()
    (locked / "assistant-actions.jsonl").write_text("")
    locked.chmod(0o444)
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(locked))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    p = audit.record("resume", "apparmor", True)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    p = audit.record("resume", "apparmor", True)
    assert p is not None and p.read_text().strip()
    locked.chmod(0o644)
