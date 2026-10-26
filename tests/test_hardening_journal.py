import base64
import json

from hardening import journal


def test_two_entries_newest_first(tmp_path):
    path = tmp_path / "journal.jsonl"
    p = tmp_path / "svc.conf"
    p.write_text("a")
    assert journal.write_entry(path, "e1", {"svc.conf": {"path": str(p)}}, ["step1"])
    p.write_text("bb")
    assert journal.write_entry(path, "e2", {"svc.conf": {"path": str(p)}}, ["step2"])
    latest = journal.read_latest(path)
    assert latest["id"] == "e2"
    assert latest["plan"] == ["step2"]
    assert "ts" in latest
    assert path.read_bytes().endswith(b"\n")


def test_corrupt_line_skipped(tmp_path):
    path = tmp_path / "journal.jsonl"
    entry = {"id": "ok", "ts": "x", "before": {}, "plan": []}
    lines = ["{not json", json.dumps(entry)]
    path.write_text("\n".join(lines) + "\n")
    latest = journal.read_latest(path)
    assert latest["id"] == "ok"
    assert journal.read_entry(path, "ok") == entry
    assert journal.read_entry(path, "missing") is None


def test_read_latest_empty_or_missing(tmp_path):
    assert journal.read_latest(tmp_path / "none.jsonl") is None
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n")
    assert journal.read_latest(empty) is None


def test_blob_roundtrip(tmp_path):
    path = tmp_path / "journal.jsonl"
    before = {"svc.service": {"path": "/etc/systemd/system/svc.service", "mode": 420,
                              "blob": base64.b64encode(b"bytes\xff\x00").decode()}}
    assert journal.write_entry(path, "b1", before, ["restore b1"])
    line = path.read_text().splitlines()[0]
    assert json.loads(line)["before"]["svc.service"]["blob"].endswith("AA==")
    out = journal.read_entry(path, "b1")
    assert base64.b64decode(out["before"]["svc.service"]["blob"]) == b"bytes\xff\x00"
    assert out["before"]["svc.service"]["mode"] == 420
