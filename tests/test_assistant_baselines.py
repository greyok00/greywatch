"""Assistant behavior baselines (heuristic tier) — the BackstopJS
analogue for the assistant: pinned question -> verified answer shape.

Like E-6's pixels, these baselines are OWNER-OWNED: regenerate ONLY with
GREYWATCH_REGEN_ASSISTANT_BASELINES=1 after an owner-approved behavior
change. Between regens, every replayed question must produce the pinned
shape (kind/slot/tool) and answer invariants (no secrets, no invented
actions, honesty markers present/not present).

What is pinned per scenario:
- the PLAN the ladder produces (kind, slot, tool) — routing must not
  drift, because every surface renders these plans;
- answer invariants — the deterministic contract the owner reads:
  honesty markers ("I answered from", "not a threat", "sudo" lines),
  forbidden content (a raw helper call, a URL scheme, invented actions).
"""
from __future__ import annotations

import json
import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys_path = str(ROOT)
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)

from ui.assistant import plan_turn  # noqa: E402
from assistant.packer import build_pack  # noqa: E402
from ui.plain import FRIENDLY  # noqa: E402


# ---- the fixture world: one stable machine the questions live in ---------

STATUS = {
    "tools": {
        "appfw": {"state": "GREEN", "label": "App Firewall",
                  "installed": True},
        "rkhunter": {"state": "YELLOW", "label": "RootKit Hunter",
                     "installed": True},
        "clamav": {"state": "GREEN", "label": "ClamAV",
                   "installed": True},
        "fail2ban": {"state": "RED", "label": "Fail2ban",
                     "installed": True},
        "lynis": {"state": "UNKNOWN", "label": "Lynis",
                  "installed": False},
    },
    "appfw_engine": "armed",
    "pending_decisions": 3,
}

EVENTS = [
    {"from_tool": "rkhunter", "severity": "MEDIUM", "ts": "2026-11-11T22:14:00+00:00",
     "text": "[ Warning ] file /usr/bin/ssh: checksum changed"},
    {"from_tool": "clamav", "severity": "HIGH", "ts": "2026-11-11T21:50:00+00:00",
     "text": "Win.Trojan.Suspect-34 FOUND: /home/owner/Downloads/Docs.zip"},
    {"from_tool": "fail2ban", "severity": "MEDIUM", "ts": "2026-11-11T21:02:00+00:00",
     "text": "Ban 203.0.113.9 (sshd)"},
    {"from_tool": "yara", "severity": "LOW", "ts": "2026-11-11T20:58:00+00:00",
     "text": "Eicar-Test-Signature hit: /tmp/pytest-of-grey/x/sample.bin"},
]

REGISTRY = [{"name": n, "label": FRIENDLY[n][0]} for n in
            ("appfw", "rkhunter", "clamav", "fail2ban", "lynis")]

# ---- the scenarios: owner-language -> expected plan + invariants ---------

SCENARIOS = [
    # (id, question, kind, slot/tool (None = not asserted), invariants dict)
    ("overview-floor", "what is the state of my machine?",
     "template", "overview", {"contains": ["protections green"],
                              "not_contains": ["sudo rm", "http://"]}),
    ("attack-fear", "am I under attack?",
     "template", "advice", {"contains": [], "not_contains": ["http://"]}),
    ("tool-red", "why is fail2ban red?",
     "template", "advice", {"contains_fail2ban": True, "not_contains": ["http://"]}),
    ("quarantine-explain", "what happened to Docs.zip?",
     "template", "detail", {"contains": ["docs.zip"],
                            "not_contains": ["http://"]}),
    ("noise-explained", "what is the EICAR hit in tmp?",
     "template", "concept", {"contains": ["cannot run"]}),
    ("pause-intent", "pause the app firewall",
     "intent", None, {"intent_action": "pause", "intent_tool": "appfw"}),
    ("resume-followup", "turn it back on",
     "intent", None, {"intent_action": "resume",
                      "intent_tool": "appfw"}),
    ("scan-intent", "scan for rootkits now",
     "intent", None, {"intent_action": "scan"}),
    ("settings-pointer", "open the settings page",
     "intent", None, {"intent_action": "open_page",
                      "intent_value": "settings"}),
    ("digest-question", "how does quarantine actually work?",
     "template", "concept", {"contains": ["responderd digest"],
                             "digest_pinned": "responderd"}),
    ("no-target-action", "turn it off",
     "template", "concept", {"contains": ["which"]}),
    ("block-site", "block the site eviltracker.example",
     "intent", None, {"intent_action": "block_site"}),
]


def _pack():
    return build_pack(STATUS, EVENTS, "", registry=REGISTRY, history=[])


def _plan(question):
    # llm=None forces the heuristic tier: exactly the tier that ships
    # with the app and runs without any model load. friendly carries the
    # production (label, description) plates from ui.plain — the ladder
    # reads plate[0], so a bare string would degenerate to a first
    # character and match every question.
    friendly = {t["name"]: FRIENDLY[t["name"]] for t in REGISTRY}
    return plan_turn(question, _pack(), None,
                     {t["name"] for t in REGISTRY}, friendly)


def _text_of(plan):
    return str(plan.get("text") or "")


def _slot_of(plan):
    return plan.get("slot") or plan.get("tool") or ""


@pytest.mark.parametrize("sid", [s[0] for s in SCENARIOS])
def test_assistant_baseline(sid, tmp_path, monkeypatch):
    """The heuristic tier's answer plan + invariants hold for the
    owner's canonical questions — the assistant's behavior baseline."""
    if os.environ.get("GREYWATCH_REGEN_ASSISTANT_BASELINES") == "1":
        pytest.skip("regen run: baselines are being rewritten, not checked")
    BASE = ROOT / "tests" / "baselines" / "assistant.json"
    sc = [s for s in SCENARIOS if s[0] == sid][0]
    _sid, question, kind, slottool, invariants = sc
    last_tool = "appfw" if sid == "resume-followup" else None
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path / "data"))
    (tmp_path / "data").mkdir(exist_ok=True)
    # the panel passes the conversation's last protection so a pronoun
    # ('turn it back on') resolves; the baseline replays that state.
    friendly = {t["name"]: FRIENDLY[t["name"]] for t in REGISTRY}
    plan = plan_turn(question, _pack(), None,
                     {t["name"] for t in REGISTRY}, friendly,
                     last_tool=last_tool)
    observed = {"kind": plan.get("kind"),
                "slottool": (_slot_of(plan) if plan.get("kind")
                             != "intent" else None),
                "intent": ({"action": plan["intent"].action,
                            "tool": plan["intent"].tool,
                            "value": plan["intent"].value}
                           if plan.get("kind") == "intent" else None),
                "text": _text_of(plan)}
    if not BASE.exists():
        BASE.write_text(json.dumps({}, indent=1))
    pin = json.loads(BASE.read_text())
    key = f"{sid}"
    want = pin.get(key)
    if want is None:
        pin[key] = {"kind": observed["kind"],
                    "slottool": observed["slottool"],
                    "intent": observed["intent"]}
        BASE.write_text(json.dumps(pin, indent=1, sort_keys=True))
        want = pin[key]
    # routing must not drift
    assert observed["kind"] == want["kind"], \
        f"{sid}: plan kind drifted: {observed['kind']} != {want['kind']}"
    if want.get("slottool"):
        assert observed["slottool"] == want["slottool"], \
            f"{sid}: slot/tool drifted"
    if want.get("intent"):
        assert observed["intent"] and \
            observed["intent"]["action"] == want["intent"].get("action") \
            if isinstance(want["intent"], dict) else True
    # invariants hold against the answer text itself
    text = observed["text"].lower()
    for needle in invariants.get("contains", []):
        assert needle.lower() in text, f"{sid}: answer lacks {needle!r}"
    for needle in invariants.get("not_contains", []):
        assert needle.lower() not in text, \
            f"{sid}: answer must not contain {needle!r}"
    if invariants.get("contains_fail2ban"):
        assert "fail2ban" in text
    if invariants.get("digest_pinned"):
        from assistant import digests
        assert digests.tool_of(question) == invariants["digest_pinned"]
    if invariants.get("intent_action"):
        assert plan.get("kind") == "intent" and \
            plan["intent"].action == invariants["intent_action"]
        if invariants.get("intent_tool"):
            assert plan["intent"].tool == invariants["intent_tool"]
        if invariants.get("intent_value"):
            assert plan["intent"].value == invariants["intent_value"]
