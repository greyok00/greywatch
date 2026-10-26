"""Tests for the apply planner: filtering, advisory split, run_pass mapping."""
from hardening.apply import build_plan, plan_document, run_pass
from hardening.controls import Control
from hardening.detector import Finding

PASS = "PASS"
GAP = "GAP"
CANT = "CANT-CHECK"


def f(cid, state):
    return Finding(cid, state, "old-value", "")


CONTROLS = [
    Control("gw-unit-hardening", "systemd-unit", "harden the unit",
            fix=[["sh", "echo hardening-unit"]], severity="HIGH"),
    Control("sysctl-bpf", "kernel", "lock unprivileged bpf",
            fix=[["sysctl-set", "kernel.unprivileged_bpf_disabled", "1"]]),
    Control("mac-in-repo", "repo", "review macs by hand",
            fix=[["sh", "echo nope"]], advisory=True),
    Control("pkg-stale", "updates", "upgrade packages",
            fix=[["pkg-upgrade"]], severity="HIGH"),
    Control("sshd-running", "network", "stop ssh",
            fix=[["service-off", "ssh"]], probe_invert=True),
]


def test_mixed_scan_filters_correctly():
    findings = [f("gw-unit-hardening", GAP), f("sysctl-bpf", CANT),
                f("pkg-stale", GAP), f("mac-in-repo", GAP)]
    plan, advisories = build_plan(findings, CONTROLS)
    assert [p["id"] for p in plan] == ["gw-unit-hardening", "pkg-stale"]
    assert advisories and advisories[0].control_id == "mac-in-repo"


def test_advisory_never_in_plan_even_on_pass_states():
    findings = [f("mac-in-repo", CANT), f("gw-unit-hardening", PASS)]
    plan, advisories = build_plan(findings, CONTROLS)
    assert plan == []
    assert [a.control_id for a in advisories] == ["mac-in-repo"]


def test_unknown_verb_raises():
    bad = CONTROLS + [Control("bad-verb-control", "misc", "decorative knob",
                              fix=[["frobnicate", "x"]])]
    findings = [f("bad-verb-control", GAP)]
    try:
        build_plan(findings, bad)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown verb")


def test_pass_findings_never_enter_plan():
    findings = [f("sshd-running", GAP), f("gw-unit-hardening", PASS)]
    plan, advisories = build_plan(findings, CONTROLS)
    assert [p["id"] for p in plan] == ["sshd-running"]
    assert advisories == []


def test_plan_document_is_plain_english():
    findings = [f("gw-unit-hardening", GAP)]
    plan, _ = build_plan(findings, CONTROLS)
    doc = plan_document(plan)
    assert "gw-unit-hardening" in doc
    assert "harden the unit" in doc
    assert "old-value" in doc


def test_run_pass_maps_states():
    findings = [f("gw-unit-hardening", GAP), f("pkg-stale", GAP)]
    plan, _ = build_plan(findings, CONTROLS)

    def helper(line):
        return 0, line

    def reverify(cid):
        return {"gw-unit-hardening": "PASS", "pkg-stale": "FAIL-PERSISTED"}[cid]

    out = run_pass(plan, helper, reverify)
    assert out == [("gw-unit-hardening", 0, "GREEN"), ("pkg-stale", 0, "RED")]


def test_run_pass_cant_check_maps_amber():
    findings = [f("gw-unit-hardening", GAP)]
    plan, _ = build_plan(findings, CONTROLS)
    out = run_pass(plan, lambda line: (0, line),
                   lambda _cid: "CANT-CHECK")
    assert out == [("gw-unit-hardening", 0, "AMBER")]


def test_run_pass_collects_helper_rc():
    findings = [f("gw-unit-hardening", GAP), f("pkg-stale", GAP)]
    plan, _ = build_plan(findings, CONTROLS)

    calls = []

    def helper(line):
        calls.append(line)
        return 1 if "pkg" in line else 0, ""

    def reverify(_cid):
        return "PASS"

    out = run_pass(plan, helper, reverify)
    rc_by_id = {cid: rc for cid, rc, _ in out}
    assert rc_by_id["gw-unit-hardening"] == 0
    assert rc_by_id["pkg-stale"] == 1
    assert calls, "helper must be invoked"
