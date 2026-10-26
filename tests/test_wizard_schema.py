from __future__ import annotations

import json
import pathlib
import tempfile

from wizard import changeset as cs

ID = "gw-unit-hardening"  # a real id from data/hardening-controls.json
FAKE = "gw-not-a-control"
JID = "20261025-140532"

CONTROLS = [{"id": ID}, {"id": "gw-kernel-controls"}]


def base(**over):
    doc = {"version": 1, "journal_id": JID,
           "changes": [{"control_id": ID, "action": "apply",
                        "backup_path": "data/harden/journal/%s/%s.json"
                                       % (JID, ID)}]}
    doc.update(over)
    return doc


def errs(doc) -> list[str]:
    return cs.validate(doc, CONTROLS)



def test_schema_json_loads_with_grammar():
    schema = json.loads(
        (pathlib.Path(cs.__file__).with_name("schema.json")).read_text())
    assert schema["version"] == 1
    assert schema["fields"]["journal_id"]["pattern"] == \
        cs.JOURNAL_ID_RE.pattern
    assert set(schema["fields"]["changes"]["items"]["fields"]["action"]
               ["enum"]) == set(cs.ACTIONS)
    assert cs.ACTIONS == frozenset({"apply", "verify", "rollback"})



def test_valid_changeset_passes():
    assert errs(base()) == []


def test_build_roundtrip_validates():
    doc = cs.build(JID, [{"control_id": ID}])
    assert doc == base()
    assert errs(doc) == []


def test_build_defaults_action_to_apply_and_all_actions_accepted():
    for action in sorted(cs.ACTIONS):
        doc = base(changes=[{"control_id": ID, "action": action,
                             "backup_path": "data/harden/journal/%s/%s.json"
                                            % (JID, ID)}])
        assert errs(doc) == [], action
    built = cs.build(JID, [{"control_id": ID}])
    assert built["changes"][0]["action"] == "apply"          # default
    assert built["changes"][0]["backup_path"] == \
        "data/harden/journal/%s/%s.json" % (JID, ID)
    assert errs(built) == []


def test_build_accepts_id_key_and_card_objects():
    class Card:
        control_id = "gw-kernel-controls"

    doc = cs.build(JID, [{"id": ID}, Card()])
    assert errs(doc) == []
    assert doc["changes"] == [
        {"control_id": ID, "action": "apply",
         "backup_path": "data/harden/journal/%s/%s.json" % (JID, ID)},
        {"control_id": "gw-kernel-controls", "action": "apply",
         "backup_path": "data/harden/journal/%s/%s.json"
                        % (JID, "gw-kernel-controls")}]


def test_build_rejects_anonymous_card():
    import pytest
    with pytest.raises(ValueError):
        cs.build(JID, [{"action": "apply"}])



def test_non_object_changeset():
    assert errs([1, 2]) == ["changeset: expected a JSON object"]


def test_missing_and_unknown_keys():
    out = errs({"version": 1, "changes": []})
    assert any("missing required key 'journal_id'" in e for e in out)
    doc = base(extra=1)
    assert any("unknown key 'extra'" in e for e in errs(doc))
    doc2 = base()
    doc2.pop("version")
    out2 = errs(doc2)
    assert any("missing required key 'version'" in e for e in out2)


def test_version_must_be_one():
    assert any("unsupported version 2" in e for e in errs(base(version=2)))
    assert any("version must be the integer 1" in e
               for e in errs(base(version="1")))



def test_journal_id_exact_shape():
    doc = base(journal_id="2026-10-25 14:05:32")
    out = errs(doc)
    assert any("whitespace or control characters" in e for e in out)
    assert not any(e.startswith("journal_id: expected the form")
                   for e in out)  # shape note stays off when a smuggle fires
    assert not errs(base(journal_id="19991231-235959"))


def test_journal_id_newline_smuggle():
    out = errs(base(journal_id=f"{JID}\nrm -rf /"))
    assert any("journal_id: whitespace or control characters" in e
               for e in out), out


def test_journal_id_absolute_path_smuggle():
    out = errs(base(journal_id="/etc/harden/journal"))
    assert any("journal_id: path-like values are rejected" in e
               for e in out), out



def test_control_id_newline_smuggle():
    payload = "gw-unit-hardening\nundo_all"
    out = errs(base(changes=[{"control_id": payload, "action": "apply"}]))
    assert any(
        "changes[0].control_id: whitespace or control characters" in e
        for e in out), out


def test_control_id_absolute_path_smuggle():
    for payload in ("/etc/passwd", "gw-x/../../../etc", "C:\\Windows"):
        out = errs(base(changes=[{"control_id": payload,
                                  "action": "apply"}]))
        assert any("changes[0].control_id: path-like values are rejected"
                   in e for e in out), payload


def test_control_id_metachar_smuggle():
    for payload in ("gw-x; rm -rf /", "gw-x$(id)", "gw-x`id`",
                    "gw-x|echo", "gw-x&&id", "*", "a`b"):
        out = errs(base(changes=[{"control_id": payload,
                                  "action": "apply"}]))
        assert any(
            "changes[0].control_id: characters outside the allowed set"
            in e for e in out), payload


def test_control_id_non_string_and_leading_dot():
    out = errs(base(changes=[{"control_id": 7, "action": "apply"}]))
    assert any("control_id: expected a string" in e for e in out)
    out = errs(base(changes=[{"control_id": ".hidden", "action": "apply"}]))
    assert any("path-like values are rejected" in e for e in out)



def test_unknown_control_id_rejected():
    out = errs(base(changes=[{"control_id": FAKE, "action": "apply"}]))
    assert any(f"changes[0].control_id: '{FAKE}' is not in the loaded "
               f"controls" in e for e in out), out


def test_unknown_action_rejected():
    for bad in ("APPLY", "run", "", None, ["apply"]):
        out = errs(base(changes=[{"control_id": ID, "action": bad}]))
        assert any("changes[0].action" in e and
                   "not an executable action" in e for e in out), bad


def test_object_controls_list_also_accepted():
    class Ctrl:
        id = ID

    assert errs(base()) == []  # dicts
    assert cs.validate(base(), [Ctrl()]) == []  # attribute objects


def test_control_id_from_schema_needs_to_match_real_controls():
    real = json.loads(
        (pathlib.Path(__file__).resolve().parent.parent /
         "data" / "hardening-controls.json").read_text())["controls"]
    for entry in real:
        assert cs.CONTROL_ID_RE.fullmatch(entry["id"]), entry["id"]
        assert cs.validate(cs.build(JID, [{"control_id": entry["id"]},
                                          ]),
                           real) == []


def test_duplicate_control_id_changeset_refused():
    doc = base(changes=[{"control_id": ID, "action": "apply"},
                        {"control_id": ID, "action": "rollback"}])
    es = errs(doc)
    assert any("duplicate" in e and "changes[1]" in e for e in es), es


def test_backup_path_required_per_pass_layout():
    doc = base()
    assert errs(doc) == []
    missing = base(changes=[{"control_id": ID, "action": "apply"}])
    assert any("missing required key 'backup_path'" in e for e in errs(missing))
    bad = base(changes=[{"control_id": ID, "action": "apply",
                         "backup_path": "data/harden/journal/x/../"
                                        "20261025-140532/" + ID + ".json"}])
    assert any("..' segments are rejected" in e for e in errs(bad))
    for shape in ("/tmp/x;y.json", "/tmp/outside-pf.json",
                  "pf.json"):
        doc = base(changes=[{"control_id": ID, "action": "apply",
                             "backup_path": shape}])
        es = errs(doc)
        assert any("backup_path" in e for e in es), (shape, es)


def test_write_document_validates_then_writes():
    class _C:                                     # control-object form
        id = ID
    ok = {"version": 1, "journal_id": JID,
          "changes": [{"control_id": ID, "action": "apply",
                       "backup_path": "data/harden/journal/%s/%s.json"
                                      % (JID, ID)}]}
    with tempfile.TemporaryDirectory() as td:
        dest = pathlib.Path(td) / "cs.json"
        assert cs.write_document(ok, [_C()], dest) == []
        text = dest.read_text(encoding="utf-8")
        assert json.loads(text) == ok
        assert text.endswith("\n")
        bad = {"version": 1, "journal_id": JID,
               "changes": [{"control_id": ID, "action": "apply"},
                           {"control_id": ID, "action": "rollback"}]}
        assert cs.write_document(bad, [_C()], dest) != []
        assert json.loads(dest.read_text()) == ok
