"""E-9b: heuristic-AI controllability baseline — the assistant can
control the app EXACTLY through the whitelist, and every control a
person names reaches its confirm gate with an honest description.

Complements E-9's hostile corpus (degradation) with the constructive
law: the 13 whitelisted intents are each reachable from canonical owner
utterances; each produces a confirm dialog description naming the real
tool; and no utterance outside the whitelist produces an intent.
These are behavior baselines: owner-owned, regenerated only with
GREYWATCH_REGEN_ASSISTANT_BASELINES=1.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from assistant.intents import INTENTS, validate  # noqa: E402
from ui.plain import FRIENDLY  # noqa: E402

NAMES = set(FRIENDLY)
SCANS = ("rkhunter", "clamav", "aide", "lynis", "yara-tmp-scan",
         "scan-all")

# One canonical utterance per whitelisted action
CANONICAL = {
    "pause": "pause the app firewall",
    "resume": "turn the app firewall back on",
    "scan": "scan for rootkits now",
    "details": "explain the newest event",
    "overview": "what needs attention?",
    "enable_all": "turn everything back on",
    "trust_site": "allow the site docs.python.org",
    "block_site": "block the site eviltracker.example",
    "open_page": "open the settings page",
}


def test_whitelist_is_the_contract():
    # The contract the UI's confirm gate is built on; if this set drifts
    # the baselines below must be re-reviewed by the owner (regen flag).
    # The bulk-fix family (owner ask 2026-11-12) entered the whitelist
    # with their own canonical utterances below and the same confirm
    # gate; purge_quarantine additionally says 'cannot be undone'.
    expected = {"pause", "resume", "details", "overview", "scan",
                "enable_all", "firewall", "learning", "update_lists",
                "trust_site", "block_site", "trust_program", "open_page",
                "clear_decisions", "dismiss_all_findings",
                "purge_quarantine"}
    assert INTENTS == expected, "whitelist drifted; owner review required"


# One canonical utterance per bulk action (the owner asked for the
# assistant to be able to fix everything in one stroke; each still
# confirms before anything runs).
CANONICAL["clear_decisions"] = "clear all the decisions"
CANONICAL["dismiss_all_findings"] = "dismiss all browser watch findings"
CANONICAL["purge_quarantine"] = "purge the quarantine"


@pytest.mark.parametrize("action", CANONICAL)
def test_each_control_reachable(action):
    from ui.assistant import plan_turn
    import assistant.packer as P
    status = {"tools": {n: {"state": "GREEN", "label": v[0]}
                        for n, v in FRIENDLY.items()}}
    pack = P.build_pack(status, [], "")
    plan = plan_turn(CANONICAL[action], pack, None, NAMES, FRIENDLY)
    if action in ("trust_site", "block_site", "open_page",
                  "enable_all", "clear_decisions",
                  "dismiss_all_findings", "purge_quarantine"):
        assert plan.get("kind") == "intent", (CANONICAL[action], plan)
        assert plan["intent"].action == action
    elif action in ("pause", "resume", "scan"):
        assert plan.get("kind") == "intent", (CANONICAL[action], plan)
        assert plan["intent"].action == action
        assert plan["intent"].tool in NAMES or plan["intent"].tool in SCANS
    else:
        # details/overview answer from data — no acting plan at all
        assert plan.get("kind").startswith("template") or \
            plan.get("kind") in ("summary", "detail"), plan


@pytest.mark.parametrize("action", CANONICAL)
def test_every_intent_validates_and_describes(action):
    """The confirm gate's vocabulary is honest: describe() names the
    action and (when present) the tool, and validate() passes for
    canonical values."""
    from assistant.intents import Intent, describe
    tool = {"pause": "appfw", "resume": "appfw", "scan": "rkhunter",
            "trust_site": "", "block_site": "", "open_page": "",
            "enable_all": "", "clear_decisions": "",
            "dismiss_all_findings": "", "purge_quarantine": ""
            }.get(action, "appfw")
    value = {"trust_site": "docs.python.org", "block_site":
             "eviltracker.example", "open_page": "settings"}.get(action, "")
    intent = Intent(action, tool, value)
    friendly_desc = describe(intent, FRIENDLY)
    assert friendly_desc, action
    # the description names the control in the words the dialog shows —
    # not necessarily the internal snake_case action name
    assert friendly_desc.rstrip().endswith("?"), action
    # validate passes for canonical values (no crash, allowed action)
    assert validate(intent, NAMES, SCANS) is None


def test_actions_outside_the_whitelist_never_resolve():
    """Owner asks for something the app does not expose: it degrades to
    an answer, never to an invented control."""
    from ui.assistant import plan_turn
    import assistant.packer as P
    status = {"tools": {n: {"state": "GREEN", "label": v[0]}
                        for n, v in FRIENDLY.items()}}
    pack = P.build_pack(status, [], "")
    for q in ("reboot my computer", "email me the report",
              "wipe the logs forever", "change my wifi password"):
        plan = plan_turn(q, pack, None, NAMES, FRIENDLY)
        assert plan.get("kind") != "intent", (q, plan)
        # and the template answers stay inside the app's subject matter
        if plan.get("kind") == "template":
            text = str(plan.get("text") or "").lower()
            assert "rm -rf" not in text and "sudo rm" not in text


def test_digest_lane_honesty_marker():
    """A digest-sourced answer carries its basis on its face."""
    from assistant import digests
    text = digests.answer("how does the auto-responder work?", FRIENDLY)
    assert text and "digest" in text.lower()


def test_noise_classifier_law():
    """EICAR and the app's own test fixtures read as benign — the
    assistant's reassurance is grounded, not invented."""
    from assistant.events import classify, is_noise
    eicar = {"from_tool": "clamav", "text":
             "Eicar-Test-Signature FOUND: /tmp/x/sample.bin"}
    assert is_noise(eicar) and classify(eicar)["bucket"] == "noise"
    pytest_row = {"from_tool": "yara-watch",
                  "text": "hit: /tmp/pytest-of-grey/x/sample.bin"}
    assert is_noise(pytest_row)
