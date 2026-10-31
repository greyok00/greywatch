from __future__ import annotations

ALLOWED_VERBS = frozenset(
    {"sh", "unit-install", "sysctl-set", "service-off", "pkg-upgrade",
     "pkg-install", "pending-restarts", "restart-units"})

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


def plan_document(plan: list[dict]) -> str:
    lines = [f"{e['id']}: {e['what']} (was {e['current'] or 'unknown'})"
             for e in plan]
    if not lines:
        return "No automated changes are planned; all checks passed or are advisory."
    return "\n".join(lines) + "\n"


def _run_fix(entry, helper_runner):
    if isinstance(entry, (list, tuple)):
        line = " ".join(str(part) for part in entry)
    else:
        line = str(entry)
    rc, _out = helper_runner(line)
    return int(rc)


def run_pass(plan, helper_runner, reverify) -> list[tuple]:
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
