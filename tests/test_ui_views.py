import json
from ui import pageutil


def test_signature_changes_when_a_state_file_changes(tmp_path, monkeypatch):
    from ui import cliapi
    monkeypatch.setattr(cliapi, "state_path",
                        lambda name: str(tmp_path / name))
    (tmp_path / "posture.json").write_text(json.dumps({"score": 1}))
    first = pageutil.signature("posture.json", "missing.json")
    (tmp_path / "posture.json").write_text(json.dumps({"score": 2}))
    second = pageutil.signature("posture.json", "missing.json")
    assert first != second
    assert "missing.json:-" in first
