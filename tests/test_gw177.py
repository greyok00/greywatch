"""GW-177: one standing privilege grant, not a password per click.

The owner: "it's asking for sudo prompts way too much for that. every
single time it requires sudo. you can make a confirmation for each but i
need a way to ... [load it] with permissions to fix things." Every
greywatch helper already sat behind a com.greywatch.apply.* action with
its own auth_admin(keep) default, so polkit treated each helper as a
separate question and asked again. The fix ships one polkit rules.d file
that answers every action under the com.greywatch prefix for the local,
active member of sudo/wheel - the ownership boundary - while every other
subject keeps the policy defaults and the app keeps its own per-action
Continue/Cancel confirmations.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
RULES = ROOT / "apply" / "polkit" / "51-greywatch.rules"
POLICY = ROOT / "apply" / "polkit" / "greywatch.apply.policy"


def test_rules_file_pins_the_single_grant():
    text = RULES.read_text()
    # the grant is the prefix, local+active, admin group - nothing wider
    assert 'action.id.indexOf("com.greywatch.") !== 0' in text
    assert "subject.local" in text
    assert "subject.active" in text
    assert 'subject.isInGroup("sudo")' in text
    assert 'subject.isInGroup("wheel")' in text
    assert "polkit.Result.YES" in text
    # no per-action exceptions and no blanket user rule
    assert "action.id ===" not in text
    assert "subject.user ==" not in text


def test_every_policy_action_sits_inside_the_granted_prefix():
    ids = re.findall(r'action id="([^"]+)"', POLICY.read_text())
    assert ids
    outside = [i for i in ids if not i.startswith("com.greywatch.")]
    assert not outside, \
        f"an action escaped the com.greywatch prefix: {outside}"


def test_install_and_uninstall_and_check_carry_the_rules():
    sh = (ROOT / "install.sh").read_text()
    assert "RULES_TPL=" in sh and "RULES_SYS=" in sh
    # deploy_files takes the rules destination as its third path so a
    # --root staged run steers it into the stage like the policy
    assert 'install -Dm 0644 "$RULES_TPL" "$3"' in sh
    assert 'deploy_files "$STAGE/$UNIT_REL" "$STAGE/$POLICY_REL" ' \
           '"$STAGE/$RULES_REL"' in sh
    assert 'deploy_files "$UNIT_SYS" "$POLICY_SYS" "$RULES_SYS"' in sh
    assert 'rm -f "$UNIT_SYS" "$HUNIT_SYS" "$POLICY_SYS" "$RULES_SYS"' in sh
    assert "check_rules_file" in sh


def test_the_deb_payload_ships_the_rules_file():
    bd = (ROOT / "packaging" / "build-deb.sh").read_text()
    assert "etc/polkit-1/rules.d/51-greywatch.rules" in bd
    assert "51-greywatch.rules" in (
        ROOT / "tests" / "test_package.py").read_text()
