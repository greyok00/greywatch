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
    assert re.search(r"grey(?!watch)", text) is None


def test_file_ships_with_a_single_trailing_newline():
    p = pathlib.Path(__file__).resolve().parents[1] / "data" / "hardening-controls.json"
    text = p.read_text()
    assert text.endswith("\n")
    assert not text.endswith("\n\n")


def test_every_control_carries_the_wizard_schema_fields():
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
            assert ctrl.default is False
        else:
            assert isinstance(ctrl.default, bool)


def test_fresh_install_condition_parsing():
    cs = load_controls(pathlib.Path(__file__).resolve().parents[1] / "data")
    by_id = {c.id: c for c in cs}
    ipv6 = by_id["ipv6-block-all"]
    assert ipv6.condition == "fresh-install"
    assert ipv6.default is True and ipv6.nist == ["SC-7(5)", "SC-7"]
    clam = by_id["clamav-installed"]
    pkg = clam.condition.split(":", 1)[1]
    assert pkg == "clamav" and clam.default is False and clam.advisory is True
    assert "install prompt" in clam.what or "install-prompt" in clam.what
    # The card text describes the check, never a fixed missing state: the
    # pack must hold no claim that a named protection is not installed.
    assert "is not installed" not in clam.what
    for ctrl in cs:
        assert "is not installed" not in ctrl.what


def test_default_and_condition_normalization():
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
    cs = load_controls(pathlib.Path(__file__).resolve().parents[1] / "data")
    upd = {c.id: c for c in cs}["updates-backlog"]
    assert upd.advisory is True
    assert upd.fix == []
    assert "never forced" in upd.what and "manual choice" in upd.what
    ufw = {c.id: c for c in cs}["ufw-frontend-role"]
    assert ufw.advisory is True
    assert "nftables tables are the working host firewall" in ufw.what
    assert "ufw status" in ufw.probe and "nft list tables" in ufw.probe

def test_action_norm_falls_back_to_none(tmp_path):
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


def test_detail_and_advisory_descriptors_load(tmp_path):
    doc = {"controls": [
        {"id": "updates", "group": "updates", "what": "Updates",
         "severity": "INFO", "advisory": True, "probe": "false",
         "detail": "apt-get -s upgrade | tail -n 1",
         "advisory_action": {"kind": "updates"}},
        {"id": "clam", "group": "malware", "what": "ClamAV",
         "severity": "INFO", "advisory": True, "probe": "false",
         "advisory_action": {"kind": "install", "package": "clamav"}},
        {"id": "doc", "group": "docs", "what": "MAC",
         "severity": "INFO", "advisory": True, "probe": "true",
         "advisory_action": {"kind": "manual",
                             "command": "grep -r apparmor /etc"}},
    ]}
    (tmp_path / "hardening-controls.json").write_text(json.dumps(doc))
    got = {c.id: c for c in load_controls(tmp_path)}
    assert got["updates"].detail.startswith("apt-get -s upgrade")
    assert got["updates"].advisory_action == {"kind": "updates"}
    assert got["clam"].advisory_action == {"kind": "install",
                                           "package": "clamav"}
    assert got["doc"].advisory_action["kind"] == "manual"


def test_bad_action_descriptors_are_dropped_not_guessed(tmp_path):
    doc = {"controls": [
        {"id": "a", "group": "g", "what": "A", "severity": "LOW",
         "advisory_action": {"kind": "shell", "command": "rm -rf /"}},
        {"id": "b", "group": "g", "what": "B", "severity": "LOW",
         "advisory_action": {"kind": "install",
                             "package": "../etc/passwd"}},
        {"id": "c", "group": "g", "what": "C", "severity": "LOW",
         "advisory_action": {"kind": "updates",
                             "command": "curl x | sh"}},
        {"id": "d", "group": "g", "what": "D", "severity": "LOW",
         "detail": "sudo cat /etc/shadow"},
    ]}
    (tmp_path / "hardening-controls.json").write_text(json.dumps(doc))
    got = {c.id: c for c in load_controls(tmp_path)}
    assert got["a"].advisory_action is None
    assert got["b"].advisory_action is None
    assert got["c"].advisory_action == {"kind": "updates"}  # extras dropped
    assert got["d"].detail == ""                            # never escalate


def test_shipped_probes_test_values_not_exit_codes():
    root = pathlib.Path(__file__).resolve().parents[1]
    got = {c.id: c for c in load_controls(root / "data")}
    userns = got["sysctl-userns"]
    assert userns.probe == \
        'test "$(sysctl -n kernel.unprivileged_userns_clone)" = "0"'
    bpf = got["sysctl-bpf"]
    assert bpf.probe == \
        'test "$(sysctl -n kernel.unprivileged_bpf_disabled)" -ge 1'
    assert "sysctl -n kernel.unprivileged_bpf_disabled" in bpf.detail
    for cid, unit in (("sshd-running", "ssh"),
                      ("avahi-running", "avahi-daemon")):
        probe = got[cid].probe
        assert probe.startswith("!")
        assert f"is-enabled --quiet {unit}" in probe
        assert f"is-active --quiet {unit}" in probe
        assert got[cid].probe_invert is False
        assert "disabled at boot" in got[cid].baseline.lower()
    assert "{{unit}}" not in got["gw-unit-hardening"].detail


def test_every_advisory_has_an_action_or_a_reason():
    root = pathlib.Path(__file__).resolve().parents[1]
    for ctrl in load_controls(root / "data"):
        if not ctrl.advisory:
            continue
        assert ctrl.advisory_action or ctrl.baseline, ctrl.id
        assert ctrl.fix == [], ctrl.id     # advisories never enter a plan
        if ctrl.advisory_action and ctrl.advisory_action["kind"] == "install":
            assert ctrl.advisory_action["package"] == "clamav"


def test_unit_templates_resolve_at_load():
    root = pathlib.Path(__file__).resolve().parents[1]
    unit = {c.id: c for c in load_controls(root / "data")}["gw-unit-hardening"]
    assert "{{unit}}" not in unit.probe
    assert "greywatch.service" in unit.probe
    step = unit.fix[0]
    assert step[0] == "unit-install"
    assert step[1] == "/etc/systemd/system/greywatch.service"
    shipped = (root / "doc" / "greywatch.service").read_text(encoding="utf-8")
    from gwpaths import data_dir
    from gwpaths import ui_user
    expected = (shipped
                .replace("__GW_LIB__", str(root))
                .replace("__GW_DATA__", str(data_dir()))
                .replace("__GW_UI_USER__", ui_user()))
    assert step[2] == expected
    assert "__GW_LIB__" not in str(step[2])
    assert "__GW_DATA__" not in str(step[2])
    assert "__GW_UI_USER__" not in str(step[2])
    assert "TRANCHE" not in " ".join(str(x) for x in step)
