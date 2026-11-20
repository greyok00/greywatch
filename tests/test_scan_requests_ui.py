"""The UI's scan request writer: one valid file per press, atomically,
no subprocess, refused nonsense, and the max-speed alias."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def test_request_scan_writes_a_valid_request(tmp_path):
    from scan_session import request_path, validate_request
    from ui import scanrequests as SR

    ok, note = SR.request_scan(tmp_path, "full")
    assert ok and "requested" in note
    doc = json.loads(request_path(tmp_path).read_text())
    rid, key = validate_request(doc)
    assert key == "full"

    # the write is atomic: no temp residue
    assert not list(tmp_path.glob("*.tmp"))


def test_request_alias_and_refusals(tmp_path):
    from scan_session import request_path, validate_request
    from ui import scanrequests as SR

    ok, _note = SR.request_scan(tmp_path, "max-speed")
    assert ok and validate_request(
        json.loads(request_path(tmp_path).read_text()))[1] == "full"

    ok, note = SR.request_scan(tmp_path, "format-c:")
    assert not ok and "not a scan" in note
