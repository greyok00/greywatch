"""Quarantine row buttons must run a helper polkit authorizes, and the
delete button must change real state.

Root causes (checked 2026-11-13):
  * the GUI pkexec'd the checkout's apply/*.sh, while the policy pins
    /usr/lib/greywatch/apply/*.sh — no action matched, so the buttons
    never ran (pkexec on the checkout path hung);
  * delete-quarantine and purge-quarantine had NO policy action at all.
"""
import json
import os
import pathlib
import stat

import cli
import ui.auditlog as auditlog


def _rec():
    return {"ts": "2026-11-13T00:00:00+00:00", "orig": "/home/grey/x.zip",
            "file": "/home/grey/security-hardening/quarantine/x.zip.1.quar",
            "tag": "onaccess:Eicar"}


def test_row_offers_a_working_delete_option():
    opts = auditlog.ActivityLogPage._quar_opts(_rec())
    by_id = {o["id"]: o for o in opts}
    assert by_id["wipe"]["helper"] == "delete-quarantine"
    assert by_id["wipe"]["args"] == ["/home/grey/x.zip"]
    assert by_id["restore"]["helper"] == "restore-quarantine"
    assert by_id["keep"]["helper"] == "keep-quarantine"


def test_helper_script_prefers_the_installed_copy(monkeypatch, tmp_path):
    lib = tmp_path / "lib"
    (lib / "apply").mkdir(parents=True)
    installed = lib / "apply" / "delete-quarantine.sh"
    installed.write_text("#!/bin/sh\n")
    monkeypatch.setenv("GREYWATCH_LIB_DIR", str(lib))
    monkeypatch.setattr(cli, "LIB_DIR", lib)
    assert cli.helper_script("delete-quarantine") == installed


def test_policy_authorizes_every_quarantine_helper():
    text = pathlib.Path("apply/polkit/greywatch.apply.policy").read_text()
    for helper in ("delete-quarantine", "restore-quarantine",
                   "keep-quarantine", "purge-quarantine"):
        assert f"com.greywatch.apply.{helper}" in text, (
            f"{helper} has no polkit action: pkexec falls back to a "
            f"generic prompt and the button cannot run")
        assert f"__GW_LIB__/apply/{helper}.sh" in text


def test_delete_button_removes_the_file_and_records_it(tmp_path,
                                                        monkeypatch):
    qdir = tmp_path / "quarantine"
    qdir.mkdir()
    copy = qdir / "x.zip.1.quar"
    copy.write_text("payload")
    ledger = tmp_path / "quarantine.jsonl"
    ledger.write_text(json.dumps({"orig": "/home/grey/x.zip",
                                  "file": str(copy),
                                  "ts": "2026-11-13"}) + "\n")
    stub = tmp_path / "helper.sh"
    stub.write_text("#!/bin/sh\nhelper=$1; shift\n"
                    "exec bash \"$GREYWATCH_REPO/apply/$helper.sh\" \"$@\"\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("GREYWATCH_HELPER_CMD", str(stub))
    monkeypatch.setenv("GREYWATCH_REPO", str(pathlib.Path.cwd()))
    monkeypatch.setenv("GW_QUAR_MANIFEST", str(ledger))
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "test")
    rc = cli.helper_exec("delete-quarantine", ["/home/grey/x.zip"])
    assert rc == 0, cli.helper_last_err()
    assert not copy.exists(), "the delete button did not remove the copy"
    last = json.loads(ledger.read_text().splitlines()[-1])
    assert last["action"] == "deleted" and last["orig"] == "/home/grey/x.zip"
