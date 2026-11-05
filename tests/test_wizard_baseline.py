import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hardening.controls import Control, load_controls  # noqa: E402
from wizard.baseline import (  # noqa: E402
    BREAK_RISK_SENTENCE, DONE_ACTION, EXISTING_INSTALL_NOTE, FLAG_ACTION,
    INSTALL_PROMPT_ACTION, UFW_SENTENCE, generate,
    IPv6_DONE_NOTE, NOT_INSTALLED_UNKNOWN_NOTE, FRESH_UNKNOWN_NOTE, UFW_UNKNOWN_NOTE,
)

DATA_DIR = pathlib.Path(__file__).resolve().parents[1] / "data"


def _ctrl(**kw):
    base = dict(id="c1", group="g", what="what text", severity="LOW")
    base.update(kw)
    return Control(**base)


def _cards(scan, controls, profile="workstation"):
    return generate(scan, controls, profile)


def _by_id(cards):
    return {c["control_id"]: c for c in cards}


def test_profile_must_be_a_known_role():
    for bad in ("server", "", "WORKSTATION"):
        try:
            generate({}, [], bad)
        except ValueError as exc:
            assert "profile" in str(exc)
        else:
            raise AssertionError(f"profile {bad!r} accepted")
    for good in ("workstation", "hardened", "custom"):
        assert generate({}, [], good) == []


def _rule_scan(**over):
    scan = {
        "packages": {"openssh-server": True, "clamav": False},
        "fresh_install": True,
        "wireless": True,
        "ufw_status": "inactive",
        "ipv6_disable": "0",
    }
    scan.update(over)
    return scan


def _rule_controls():
    return [
        _ctrl(id="sshd-running", group="network-services",
              probe="systemctl is-active ssh", nist=["CM-7"], cis=[],
              severity="MEDIUM", break_risk="medium", default=True),
        _ctrl(id="clamav-installed", group="malware-scanning",
              condition="not-installed:clamav", action="install-prompt",
              nist=["SI-3"], cis=[], severity="MEDIUM", break_risk="none",
              default=False),
        _ctrl(id="wifi-hardening", group="wireless-hardening",
              nist=["SC-40"], cis=[], break_risk="low", default=True),
        _ctrl(id="ufw-frontend-role", group="firewall-frontend",
              probe="ufw status", nist=["SC-7"], cis=[],
              severity="INFO", default="FLAG-ONLY"),
        _ctrl(id="ipv6-block-all", group="firewall",
              probe="sysctl -n net.ipv6.conf.all.disable_ipv6",
              nist=["SC-7(5)"], cis=[], severity="HIGH",
              break_risk="medium", default=True, condition="fresh-install"),
        _ctrl(id="sysctl-userns", group="kernel", nist=["AC-4"], cis=[],
              severity="HIGH", break_risk="medium", default=True),
        _ctrl(id="avahi-running", group="network-services", nist=["CM-7"],
              cis=[], severity="MEDIUM", break_risk="low", default=True),
    ]


def test_clamav_absent_emits_install_prompt_card():
    cards = _by_id(_cards(_rule_scan(), _rule_controls()))
    card = cards["clamav-installed"]
    assert card["action"] == INSTALL_PROMPT_ACTION == "install-prompt"
    assert card["nist"] == ["SI-3"]


def test_clamav_present_means_no_card():
    scan = _rule_scan(packages={"openssh-server": True, "clamav": True})
    ids = {c["control_id"] for c in _cards(scan, _rule_controls())}
    assert "clamav-installed" not in ids


def test_ssh_not_installed_skips_ssh_cards_entirely():
    scan = _rule_scan(packages={"openssh-server": False, "clamav": False})
    ids = {c["control_id"] for c in _cards(scan, _rule_controls())}
    assert "sshd-running" not in ids
    assert "avahi-running" in ids


def test_ssh_probe_unknown_keeps_the_card():
    scan = _rule_scan(packages={"clamav": False})
    ids = {c["control_id"] for c in _cards(scan, _rule_controls())}
    assert "sshd-running" in ids


def test_no_wifi_hardware_skips_wireless_cards():
    scan = _rule_scan(wireless=False)
    ids = {c["control_id"] for c in _cards(scan, _rule_controls())}
    assert "wifi-hardening" not in ids


def test_wifi_unknown_keeps_wireless_cards():
    scan = _rule_scan(wireless=None)
    assert "wifi-hardening" in _by_id(_cards(scan, _rule_controls()))


def test_ufw_active_flags_not_removes_with_verbatim_sentence():
    scan = _rule_scan(ufw_status="active")
    card = _by_id(_cards(scan, _rule_controls()))["ufw-frontend-role"]
    assert card["action"] == FLAG_ACTION
    assert card["checked"] is False
    assert card["note"] == UFW_SENTENCE


def test_ufw_status_unknowable_is_a_white_card_with_its_own_note():
    scan = _rule_scan(ufw_status=None)
    card = _by_id(_cards(scan, _rule_controls()))["ufw-frontend-role"]
    assert card["state"] == "CANT-CHECK"
    assert card["action"] == FLAG_ACTION
    assert card["note"] == UFW_UNKNOWN_NOTE
    assert "package" not in card["note"]  # no install wording here


def test_ufw_inactive_carries_current_fact_into_generic_card():
    scan = _rule_scan(ufw_status="inactive")
    card = _by_id(_cards(scan, _rule_controls()))["ufw-frontend-role"]
    assert card["action"] == FLAG_ACTION
    assert card["current"] == "UFW inactive"
    assert card["recommended"]


def test_ipv6_already_disabled_is_done_not_a_toggle():
    scan = _rule_scan(ipv6_disable="1")
    card = _by_id(_cards(scan, _rule_controls()))["ipv6-block-all"]
    assert card["action"] == DONE_ACTION
    assert card["checked"] is False
    assert card["note"] == IPv6_DONE_NOTE


def test_ipv6_fresh_install_auto_checked():
    scan = _rule_scan(ipv6_disable="0", fresh_install=True)
    card = _by_id(_cards(scan, _rule_controls()))["ipv6-block-all"]
    assert card["action"] == "apply"
    assert card["checked"] is True


def test_ipv6_existing_install_is_flagged_never_flipped():
    scan = _rule_scan(ipv6_disable="0", fresh_install=False)
    card = _by_id(_cards(scan, _rule_controls()))["ipv6-block-all"]
    assert card["action"] == FLAG_ACTION
    assert card["checked"] is False
    assert card["note"] == EXISTING_INSTALL_NOTE


def test_fresh_install_unknown_is_a_white_hedged_note():
    scan = _rule_scan(ipv6_disable="0", fresh_install=None)
    card = _by_id(_cards(scan, _rule_controls()))["ipv6-block-all"]
    assert card["state"] == "CANT-CHECK"
    assert card["checked"] is False
    assert card["note"] == FRESH_UNKNOWN_NOTE
    assert "Existing install" not in card["note"]


def test_break_risk_medium_plus_unchecked_with_warning():
    cards = _by_id(_cards(_rule_scan(), _rule_controls()))
    for cid in ("sysctl-userns",):  # generic medium-risk control
        card = cards[cid]
        assert card["checked"] is False
        assert BREAK_RISK_SENTENCE in card["risk"]
        assert "may break your workflow" in card["risk"]


def test_low_risk_defaults_respect_control_default():
    cards = _by_id(_cards(_rule_scan(), _rule_controls()))
    assert cards["avahi-running"]["checked"] is True
    assert cards["wifi-hardening"]["checked"] is True


def test_flag_only_and_advisory_cards_never_auto_apply():
    cards = _by_id(_cards(_rule_scan(), [sc for sc in _rule_controls()
                                         if sc.id.startswith("ufw")]))
    assert all(c["action"] == FLAG_ACTION and c["checked"] is False
               for c in cards.values())


class _PR:
    def __init__(self, state, value=None):
        self.state = state
        self.value = value


def test_probresult_scan_values_and_cant_honesty():
    scan = {
        "packages": {"clamav": _PR("FAIL", None)},
        "fresh_install": _PR("CANT-CHECK"),
        "wireless": False,
    }
    controls = [
        _ctrl(id="clamav-installed", condition="not-installed:clamav",
              action="install-prompt", nist=["SI-3"], cis=[]),
        _ctrl(id="ipv6-block-all", group="firewall", nist=["SC-7(5)"],
              condition="fresh-install",
              probe="sysctl -n net.ipv6.conf.all.disable_ipv6"),
    ]
    cards = _by_id(_cards(scan, controls))
    assert cards["clamav-installed"]["state"] == "CANT-CHECK"
    assert cards["clamav-installed"]["action"] == FLAG_ACTION
    assert cards["clamav-installed"]["note"] == NOT_INSTALLED_UNKNOWN_NOTE
    assert cards["ipv6-block-all"]["state"] == "CANT-CHECK"
    with_pass = {"packages": {"clamav": _PR("PASS", False)}}
    card = _by_id(_cards(with_pass, controls))["clamav-installed"]
    assert card["action"] == INSTALL_PROMPT_ACTION


def test_real_clamav_control_banks_the_install_prompt():
    controls = load_controls(DATA_DIR)
    clam = next(c for c in controls if c.condition == "not-installed:clamav")
    assert clam.action == "install-prompt"
    scan = {"packages": {"clamav": False}}
    cards = _by_id(_cards(scan, controls))
    assert cards["clamav-installed"]["action"] == "install-prompt"
    assert cards["clamav-installed"]["current"] == "clamav: not installed"
    assert cards["clamav-installed"]["recommended"] == \
        "Install with your one click"
    no_scan = {"packages": {"clamav": True}}
    assert "clamav-installed" not in _by_id(_cards(no_scan, controls))


def test_cards_carry_nist_cis_tags_and_plain_english_risk():
    controls = load_controls(DATA_DIR)
    cards = generate({"packages": {}, "fresh_install": True}, controls)
    for card in cards:
        assert isinstance(card.get("nist"), list)
        assert card.get("nist_family") or card.get("cis_ref")
        assert isinstance(card.get("risk"), str) and card["risk"]


def test_no_hardware_identifiers_in_cards():
    import re
    controls = load_controls(DATA_DIR)
    dump = repr(generate(_rule_scan(), controls))
    assert not re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", dump)
    for banned in ("/home/", "GREY", "serial", "uuid"):
        assert banned not in dump


def test_changeset_build_accepts_generated_cards():
    from wizard.changeset import build
    cards = [c for c in _cards(_rule_scan(), _rule_controls())
             if c["checked"] and c["action"] == "apply"]
    assert cards, "fresh-install scenario must pre-check at least one card"
    doc = build("20261025-120000", cards)
    assert doc["version"] == 1
    assert all(ch["action"] == "apply" for ch in doc["changes"])


def test_generate_is_pure_over_controls():
    controls = _rule_controls()
    scan = _rule_scan()
    first = _cards(scan, controls)
    second = _cards(scan, controls)
    assert first == second


def test_ssh_skip_works_through_the_ssd_alias_too():
    scan = _rule_scan(packages={"sshd": False, "clamav": False})
    ids = {c["control_id"] for c in _cards(scan, _rule_controls())}
    assert "sshd-running" not in ids
    scan = _rule_scan(packages={"sshd": False})
    ids = {c["control_id"] for c in _cards(scan, _rule_controls())}
    assert "sshd-running" not in ids
    scan = _rule_scan(packages={"clamav": False})
    assert "sshd-running" in _by_id(_cards(scan, _rule_controls()))
    scan = _rule_scan(packages={"sshd": True, "clamav": False})
    assert "sshd-running" in _by_id(_cards(scan, _rule_controls()))


def test_step3_columns_present_on_every_card():
    cards = _cards(_rule_scan(), _rule_controls())
    for card in cards:
        assert isinstance(card.get("current"), str)
        assert isinstance(card.get("recommended"), str) and card["recommended"]
    done = _by_id(_cards(_rule_scan(ipv6_disable="1"),
                         _rule_controls()))["ipv6-block-all"]
    assert done["current"] == "IPv6 disabled kernel-wide (value 1)"
    assert done["recommended"] == "Nothing to do: already in place"


def test_wireless_row_synthetic_when_hardware_present():
    wlan = _ctrl(id="wifi-wpa-harden", group="wireless-hardening",
                 what="WPA posture for the wireless NIC",
                 nist=["SC-40"], cis=[], severity="MEDIUM",
                 break_risk="low", default=True)
    scan = _rule_scan(wireless=True)
    card = _by_id(_cards(scan, [wlan]))["wifi-wpa-harden"]
    assert card["checked"] is True
    assert card["action"] == "apply"
    assert card["nist"] == ["SC-40"]
    scan = _rule_scan(wireless=False)
    assert "wifi-wpa-harden" not in _by_id(_cards(scan, [wlan]))


def test_module_newline():
    src = (pathlib.Path(__file__).resolve().parents[1] / "wizard"
           / "baseline.py")
    text = src.read_text()
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
