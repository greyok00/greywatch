"""GW-198 (owner 2026-11-06): "i also cant purge threats just quarantine
them for good". Put it back was broken in production too: the decision
handed the helper the full original path while the script wanted a
quarantine folder plus a bare file name, so restoring exited 64. The
quarantine helpers now take the original path and read the responderd
ledger, and every quarantine ask offers Delete permanently (one
confirm, password as usual)."""
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SCRIPTS = {
    "delete-quarantine": ROOT / "apply" / "delete-quarantine.sh",
    "restore-quarantine": ROOT / "apply" / "restore-quarantine.sh",
}


def _run_helper(name, arg, env=None):
    return subprocess.run(["/bin/bash", str(SCRIPTS[name]), arg],
                          capture_output=True, text=True,
                          env=dict(os.environ, **(env or {})))


def _manifest(tmp_path, copy_path, extra=b""):
    man = tmp_path / "quarantine.jsonl"
    man.write_text(json.dumps(
        {"ts": "2026-11-01T01:01:01+00:00", "orig": "/tmp/Docs.zip",
         "file": str(copy_path)}) + "\n" + extra.decode("utf-8", "replace"))
    return man


def test_delete_removes_newest_copy_and_records_it(tmp_path, monkeypatch):
    copy = tmp_path / "quar" / "Docs.zip.20261101-010101.quar"
    copy.parent.mkdir()
    copy.write_bytes(b"EICAR")
    man = _manifest(tmp_path, copy)
    monkeypatch.setenv("GW_QUAR_MANIFEST", str(man))
    rc = _run_helper("delete-quarantine", "/tmp/Docs.zip").returncode
    assert rc == 0, _run_helper("delete-quarantine", "/tmp/Docs.zip").stderr
    assert not copy.exists()
    assert '"action": "deleted"' in man.read_text()


def test_delete_twice_is_clean_but_unknown_path_errors(tmp_path, monkeypatch):
    man = _manifest(tmp_path, tmp_path / "gone.quar")
    monkeypatch.setenv("GW_QUAR_MANIFEST", str(man))
    assert _run_helper("delete-quarantine", "/tmp/Docs.zip").returncode == 0
    again = _run_helper("delete-quarantine", "/tmp/Docs.zip")
    assert again.returncode == 0, "the second purge is a no-op, not a crash"
    alien = _run_helper("delete-quarantine", "/tmp/NeverQuarantined.exe")
    assert alien.returncode == 65, "a path that was never quarantined errors"


def test_delete_after_restore_refuses_because_nothing_is_locked_away(tmp_path,
                                                                     monkeypatch):
    """2026-11-06 deb-verification probe: after Put it back the
    quarantined copy no longer exists (restore moves it home), so a purge
    must refuse instead of writing a false 'deleted' record."""
    man = tmp_path / "quarantine.jsonl"
    man.write_text(json.dumps(
        {"ts": "t1", "orig": "/tmp/Docs.zip",
         "file": str(tmp_path / "gone.quar"),
         "action": "restored"}) + "\n")
    monkeypatch.setenv("GW_QUAR_MANIFEST", str(man))
    out = _run_helper("delete-quarantine", "/tmp/Docs.zip")
    assert out.returncode == 65, out.stderr
    assert "put back" in out.stderr


def test_delete_uses_the_newest_matching_copy(tmp_path, monkeypatch):
    old = tmp_path / "quar" / "Docs.zip.20261101-010101.quar"
    new = tmp_path / "quar" / "Docs.zip.20261102-010101.quar"
    old.parent.mkdir()
    old.write_text("old"); new.write_text("new")
    man = tmp_path / "quarantine.jsonl"
    man.write_text(
        json.dumps({"ts": "t1", "orig": "/tmp/Docs.zip",
                    "file": str(old)}) + "\n"
        + json.dumps({"ts": "t2", "orig": "/tmp/Docs.zip",
                      "file": str(new)}) + "\n")
    monkeypatch.setenv("GW_QUAR_MANIFEST", str(man))
    _run_helper("delete-quarantine", "/tmp/Docs.zip")
    assert not new.exists(), "the newest copy goes"
    assert old.exists(), "an older copy of the same file stays"


def test_restore_moves_the_copy_home(tmp_path, monkeypatch):
    dest = tmp_path / "home" / "Docs.zip"
    copy = tmp_path / "quar" / "Docs.zip.20261101-010101.quar"
    copy.parent.mkdir()
    copy.write_text("payload")
    man = tmp_path / "quarantine.jsonl"
    man.write_text(json.dumps({"ts": "2026-11-01T01:01:01+00:00",
                               "orig": str(dest), "file": str(copy)})
                   + "\n")
    monkeypatch.setenv("GW_QUAR_MANIFEST", str(man))
    rc = _run_helper("restore-quarantine", str(dest)).returncode
    assert rc == 0
    assert not copy.exists()
    assert dest.parent.is_dir() and dest.read_text() == "payload"
    assert '"action": "restored"' in man.read_text()


def test_restore_without_a_ledger_errors_not_crashes(tmp_path, monkeypatch):
    monkeypatch.setenv("GW_QUAR_MANIFEST",
                       str(tmp_path / "does-not-exist.jsonl"))
    out = _run_helper("restore-quarantine", "/tmp/Docs.zip")
    assert out.returncode == 66, out.stderr
    assert "no quarantine ledger" in out.stderr


def test_quarantine_asks_offer_delete_and_the_allowlist_allows_it():
    from events import Event
    from decisions_factory import HELPERS, interaction_for
    assert "delete-quarantine" in HELPERS
    assert "file-action" in HELPERS
    ev = Event("responderd", "HIGH",
               "quarantine: /tmp/Docs.zip (sha256:abcd) "
               "tmpfs:Win.Trojan.Suspect-34 [act: real signature in user "
               "data] — moved to quarantine, restorable",
               "2026-11-06T01:00:00+00:00")
    spec = interaction_for(ev)
    opts = {o["id"]: o for o in spec["options"]}
    assert opts["delete"]["label"] == "Delete permanently"
    assert opts["delete"]["helper"] == "delete-quarantine"
    assert opts["delete"]["args"] == ["/tmp/Docs.zip"]
    assert opts["keep"]["tone"] == "primary", "keep stays the safe pick"
    assert opts["restore"]["tone"] != "danger", "putting back is a repair"


def test_usage_errors_keep_their_own_codes(tmp_path):
    man = tmp_path / "quarantine.jsonl"
    man.write_text('{"orig": "/tmp/x", "file": "/tmp/y"}\n')
    env = dict(os.environ, GW_QUAR_MANIFEST=str(man))
    no_args = subprocess.run(["/bin/bash", str(SCRIPTS["delete-quarantine"])],
                             capture_output=True, env=env)
    assert no_args.returncode == 64
