# tests/test_hardening_controls.py
import json
import pathlib
import re

from hardening.controls import load_controls

def test_controls_load_and_schema():
    cs = load_controls(pathlib.Path(__file__).resolve().parents[1] / "data")
    assert cs and all(isinstance(c.what, str) and c.nist for c in cs)
    assert {c.group for c in cs} >= {"kernel", "network-services",
                                     "systemd-unit", "privacy"}

def test_no_machine_specific_values():
    text = (pathlib.Path(__file__).resolve().parents[1]
            / "data" / "hardening-controls.json").read_text()
    for banned in ("192.168.0.", "/home/" + pathlib.Path.home().name,
                   "21A355", "REDACTED-MAC"):
        assert banned not in text
    # "grey" is banned as a machine name; the PRODUCT word "greywatch"
    # (e.g. the firewall-frontend control text) is not a user-path leak.
    assert re.search(r"grey(?!watch)", text) is None


def test_file_ships_with_a_single_trailing_newline():
    p = pathlib.Path(__file__).resolve().parents[1] / "data" / "hardening-controls.json"
    text = p.read_text()
    assert text.endswith("\n")
    assert not text.endswith("\n\n")


def test_every_control_carries_the_wizard_schema_fields():
    """Master-prompt schema (family/nist_family/cis_ref/break_risk/
    default/persist/condition) is present on EVERY control, loaded.
    Existing fields stay untouched; the loader tolerates files that omit
    the new ones (see test_minimal_control_tolerates_missing_fields)."""
    import json as _json
    p = pathlib.Path(__file__).resolve().parents[1] / "data" / "hardening-controls.json"
    raw = _json.loads(p.read_text())["controls"]
    assert raw and all(set(c) >= {
        "family", "nist_family", "cis_ref", "break_risk",
        "default", "persist", "condition"} for c in raw)
    cs = load_controls(p.parent)
    by_id = {c.id: c for c in cs}
    assert by_id
    for ctrl in by_id.values():
        assert ctrl.family and ctrl.nist_family
        assert ctrl.break_risk in {"low", "medium", "high", "none"}
        assert ctrl.default is True or ctrl.default is False \
            or ctrl.default == "FLAG-ONLY"
        assert isinstance(ctrl.persist, bool)
        assert ctrl.condition == "always" \
            or ctrl.condition == "fresh-install" \
            or ctrl.condition.startswith("not-installed:")


def test_flag_only_semantics():
    """default == "FLAG-ONLY" marks an advisory, never-applied control;
    everything else that defaults on/off uses a plain bool."""
    cs = load_controls(pathlib.Path(__file__).resolve().parents[1] / "data")
    by_id = {c.id: c for c in cs}
    for cid in ("updates-backlog", "ufw-frontend-role",
                "mac-in-repo", "arp-policy-doc"):
        assert by_id[cid].default == "FLAG-ONLY"
        assert by_id[cid].advisory is True
    assert by_id["updates-backlog"].fix == []
    for ctrl in cs:
        if ctrl.default == "FLAG-ONLY":
            assert ctrl.advisory is True
        elif ctrl.advisory:
            # advisory cards may also default plain false (e.g. SI-3
            # ClamAV off, offered as an install prompt) — but never
            # silently on.
            assert ctrl.default is False
        else:
            assert isinstance(ctrl.default, bool)


def test_fresh_install_condition_parsing():
    """The fresh-install SC-7(5) control exists, defaults ON, and its
    condition parses as "fresh-install"; the not-installed:<pkg> form
    parses out the package name."""
    cs = load_controls(pathlib.Path(__file__).resolve().parents[1] / "data")
    by_id = {c.id: c for c in cs}
    ipv6 = by_id["ipv6-block-all"]
    assert ipv6.condition == "fresh-install"
    assert ipv6.default is True and ipv6.nist == ["SC-7(5)", "SC-7"]
    clam = by_id["clamav-installed"]
    pkg = clam.condition.split(":", 1)[1]
    assert pkg == "clamav" and clam.default is False and clam.advisory is True
    assert "install prompt" in clam.what or "install-prompt" in clam.what


def test_default_and_condition_normalization():
    """`default` and `condition` are normalized at load: sentinel
    spellings and case variants collapse to the canonical value, unknown
    spellings fail closed (False / "always") rather than loading as a
    third unrecognized state a caller can branch on unpredictably."""
    from hardening.controls import _norm_condition, _norm_default
    assert _norm_default("flag-only") == "FLAG-ONLY"
    assert _norm_default("FLAG_ONLY") == "FLAG-ONLY"
    assert _norm_default("FLAG-ONLY") == "FLAG-ONLY"
    assert _norm_default("true") is True and _norm_default(True) is True
    assert _norm_default("false") is False and _norm_default(False) is False
    assert _norm_default("yes") is False          # unknown string
    assert _norm_default("") is False
    assert _norm_default(None) is False           # missing -> fail closed
    assert _norm_condition("fresh_install") == "fresh-install"
    assert _norm_condition("FRESH-INSTALL") == "fresh-install"
    assert _norm_condition("fresh install") == "always"   # unrecognized
    assert _norm_condition("weird") == "always"
    assert _norm_condition(None) == "always" and _norm_condition("") == "always"
    assert _norm_condition("not-installed:clamav") == "not-installed:clamav"
    assert _norm_condition("NOT-INSTALLED: clamav") == "not-installed:clamav"


def test_minimal_control_tolerates_missing_fields():
    """A lean controls file with only the original required keys must
    still load — new schema fields fall back to neutral defaults."""
    import json as _json
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "hardening-controls.json").write_text(
            _json.dumps({"controls": [{
                "id": "x", "group": "g", "what": "w", "severity": "LOW"}]}))
        cs = load_controls(pathlib.Path(d))
    assert len(cs) == 1
    c = cs[0]
    assert c.family is None and c.nist_family is None
    assert c.cis_ref is None and c.break_risk is None
    assert c.default is False and c.persist is False
    assert c.condition == "always"


def test_updates_backlog_flags_never_forces():
    """Owner addendum: the package-updates gap is advisory — the card
    explains the risk in plain words and the manual choice; no
    pkg-upgrade ever enters a plan."""
    cs = load_controls(pathlib.Path(__file__).resolve().parents[1] / "data")
    upd = {c.id: c for c in cs}["updates-backlog"]
    assert upd.advisory is True
    assert upd.fix == []
    assert "never forced" in upd.what and "manual choice" in upd.what
    # and the ufw-frontend-role card exists, advisory, explains why an
    # inactive UFW is the designed state
    ufw = {c.id: c for c in cs}["ufw-frontend-role"]
    assert ufw.advisory is True
    assert "nftables tables are the working host firewall" in ufw.what
    assert "ufw status" in ufw.probe and "nft list tables" in ufw.probe

def test_action_norm_falls_back_to_none(tmp_path):
    """W4's latent minor closed: a hand-edited/unknown control.action
    loads as None (with the loader's noted fallback), never as an
    unvalidated verb. A known action loads lowercased."""
    base = {"controls": [
        {"id": "a", "group": "g", "what": "w", "severity": "LOW",
         "action": " Install-Prompt "},
        {"id": "b", "group": "g", "what": "w", "severity": "LOW",
         "action": "purge-everything"},
        {"id": "c", "group": "g", "what": "w", "severity": "LOW",
         "action": 7},
        {"id": "d", "group": "g", "what": "w", "severity": "LOW"},
    ]}
    (tmp_path / "hardening-controls.json").write_text(
        json.dumps(base) + "\n", encoding="utf-8")
    got = {c.id: c.action for c in load_controls(tmp_path)}
    assert got == {"a": "install-prompt", "b": None, "c": None, "d": None}
