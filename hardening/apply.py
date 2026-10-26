"""hardening/apply.py — build the remediation plan, run it, re-verify.

stdlib only. Filtering contract: only GAP findings on non-advisory
controls whose first fix verb is allowlisted may enter the plan; any
other state (PASS, FAIL, CANT-CHECK), any advisory control, and any fix
in no other verb is kept out. An unknown verb on a non-advisory GAP
control raises ValueError — that is the decorative-knob bug class the
planner exists to catch, not to paper over.
"""
from __future__ import annotations

ALLOWED_VERBS = frozenset(
    {"sh", "unit-install", "sysctl-set", "service-off", "pkg-upgrade"})

GREEN, RED, AMBER = "GREEN", "RED", "AMBER"


def _first_verb(control):
    fix = getattr(control, "fix", None) or []
    for entry in fix:
        if isinstance(entry, (list, tuple)) and entry:
            return str(entry[0])
        if isinstance(entry, str) and entry.strip():
            return entry.split()[0]
    return ""


def build_plan(findings, controls) -> tuple[list[dict], list]:
    """Split findings into an actionable plan and an advisories list.

    plan: one dict per control — id, group, what, baseline, current,
    severity, fix. advisories: findings for advisory controls, verbatim.
    """
    by_id = {}
    for ctrl in controls:
        cid = getattr(ctrl, "id", None)
        if cid:
            by_id[cid] = ctrl

    plan: list[dict] = []
    advisories: list = []
    for fnd in findings:
        ctrl = by_id.get(fnd.control_id)
        if ctrl is None or bool(getattr(ctrl, "advisory", False)):
            advisories.append(fnd)
            continue
        if fnd.state != "GAP":
            continue
        verb = _first_verb(ctrl)
        if verb not in ALLOWED_VERBS:
            raise ValueError(
                f"control {fnd.control_id}: fix verb {verb!r} is not "
                f"allowlisted {sorted(ALLOWED_VERBS)}")
        plan.append({
            "id": ctrl.id,
            "group": ctrl.group,
            "what": ctrl.what,
            "baseline": ctrl.baseline,
            "current": fnd.current,
            "severity": ctrl.severity,
            "fix": ctrl.fix,
        })
    return plan, advisories


# post-plan consolidation: plan_document is preview-only today (the GUI
# renders its own card lines); it stays because the plain-CLI path should
# converge on it — see run_pass below.
def plan_document(plan: list[dict]) -> str:
    """Plain-English preview: one line per planned change."""
    lines = [f"{e['id']}: {e['what']} (was {e['current'] or 'unknown'})"
             for e in plan]
    if not lines:
        return "No automated changes are planned; all checks passed or are advisory."
    return "\n".join(lines) + "\n"


def _run_fix(entry, helper_runner):
    """Run one fix step. Returns the helper's return code."""
    if isinstance(entry, (list, tuple)):
        line = " ".join(str(part) for part in entry)
    else:
        line = str(entry)
    rc, _out = helper_runner(line)
    return int(rc)


# post-plan consolidation: route Apply through run_pass once a
# stdout-returning run_helper lands in wiz/common — today the GUI goes
# through ui/harden.py + apply/harden.sh's own APPLY/VERBIFY parsing, so
# this runner is test-only; keep the two paths honest until they merge
# (a reviewer flagged exactly this drift).
def run_pass(plan, helper_runner, reverify) -> list[tuple]:
    """Execute each planned fix, then re-verify via detector re-scan.

    helper_runner(line) performs the change; reverify(control_id) must
    return "PASS" | "FAIL-PERSISTED" | "CANT-CHECK". Mapped to
    GREEN / RED / AMBER; any other answer is treated as AMBER — an
    unverifiable fix is never reported GREEN (honesty rule).
    """
    results: list[tuple] = []
    for entry in plan:
        cid = entry["id"]
        rc = 0
        for step in entry.get("fix") or []:
            step_rc = _run_fix(step, helper_runner)
            if step_rc != 0 and rc == 0:
                rc = step_rc
        state = reverify(cid)
        if state == "PASS":
            verify = GREEN
        elif state == "FAIL-PERSISTED":
            verify = RED
        else:  # CANT-CHECK or anything unexpected: report uncertainty
            verify = AMBER
        results.append((cid, rc, verify))
    return results
