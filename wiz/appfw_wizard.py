from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from appfw import rules as R          # noqa: E402
from appfw.rules import RuleStore     # noqa: E402

from gwpaths import data_dir as _gw_data
DATA = _gw_data()
LEDGER = DATA / "learning-seen.jsonl"


def store() -> RuleStore:
    return RuleStore(DATA / "appfw" / "rules")


def appfw_build(spec: dict) -> dict:
    kind = spec.get("kind", "")
    action = spec.get("action", "")
    value = str(spec.get("value", "")).strip()
    if kind == "program":
        if action not in ("allow", "deny"):
            raise R.ValidationError(f"action invalid: {action!r}")
        rule = R.validate(f"appfw-app-{pathlib.Path(value).name}",
                          action, "always", "process.path", value)
    elif kind == "site":
        if action not in ("allow", "deny"):
            raise R.ValidationError(f"action invalid: {action!r}")
        rule = R.validate(f"appfw-site-{value}", action, "always",
                          "dst.host", value)
    elif kind == "approve":
        rule = R.validate(f"appfw-app-{pathlib.Path(value).name}",
                          "allow", "always", "process.path", value)
    else:
        raise R.ValidationError(f"kind invalid: {kind!r}")
    human = {"always": "forever"}.get(rule.duration, rule.duration)
    what = {"process.path": "program", "dst.host": "site"}[rule.op_kind]
    preview = (f"{rule.action.upper()} {what} {rule.op_value} {human}; "
               f"stored as {rule.name}")
    return {"rule": R._to_dict(rule), "preview": preview}


def apply_spec(spec: dict) -> dict:
    built = appfw_build(spec)
    rule = R.validate(built["rule"]["name"], built["rule"]["action"],
                      built["rule"]["duration"], built["rule"]["op_kind"],
                      built["rule"]["op_value"])
    store().add(rule)
    return built


def learned_pairs(limit: int = 20) -> list:
    out = []
    try:
        lines = LEDGER.read_text().splitlines()[-limit * 2:]
    except OSError:
        return out
    for raw in reversed(lines):
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        pair = (rec.get("app", ""), rec.get("host", ""))
        if pair not in out:
            out.append(pair)
        if len(out) >= limit:
            break
    return [{"app": a, "host": h} for a, h in out if a or h]


def _human_list(store_obj: RuleStore) -> str:
    rules = store_obj.all_rules()
    if not rules:
        return "no rules stored"
    lines = []
    for r in rules:
        lines.append(f"{r.name}: {r.action} {r.op_kind}={r.op_value} "
                     f"({r.duration})")
    return "\n".join(lines)


def appfw_main(argv: list) -> int:
    usage = ("usage: greywatch rules appfw "
             "allow|deny PROGRAM | trust|block SITE | approve [APP] | "
             "list | remove NAME")
    if not argv or argv[0] in ("-h", "--help"):
        print(usage)
        return 0
    verb, rest = argv[0], argv[1:]
    s = store()
    if verb == "list":
        print(_human_list(s))
        return 0
    if verb == "remove":
        if not rest:
            print("remove needs a rule name", file=sys.stderr)
            return 1
        s.reload()
        if s.remove(rest[0]) == 0:
            print(f"no persisted rule {rest[0]!r}", file=sys.stderr)
            return 1
        print(f"removed {rest[0]}")
        return 0
    if verb == "approve":
        pairs = learned_pairs(10)
        if not pairs:
            print("nothing learned yet (learning window: Settings)")
            return 0
        approved = [p for p in pairs
                    if not rest or p["app"] == rest[0]]
        for p in approved:
            built = apply_spec({"kind": "approve", "value": p["app"]})
            print(built["preview"])
        return 0
    if verb == "pending":
        s.reload()
        for rule in s.pending_rules():
            print(f"{rule.name}: {rule.op_kind}={rule.op_value} "
                  f"(recorded {rule.created})")
        if not s.pending_rules():
            print("nothing pending approval")
        return 0
    if verb in ("promote", "revoke"):
        if not rest:
            print(f"{verb} needs a rule name (see 'pending')", file=sys.stderr)
            return 1
        s.reload()
        ok = s.approve_pending(rest[0]) if verb == "promote" \
            else s.revoke_pending(rest[0])
        if not ok:
            print(f"no pending rule {rest[0]!r}", file=sys.stderr)
            return 1
        print(f"{verb}ed {rest[0]}")
        return 0
    if verb in ("allow", "deny", "trust", "block"):
        if not rest:
            print(usage, file=sys.stderr)
            return 1
        spec = ({"kind": "program", "action": verb, "value": rest[0]}
                if verb in ("allow", "deny")
                else {"kind": "site",
                      "action": "allow" if verb == "trust" else "deny",
                      "value": rest[0]})
        try:
            built = apply_spec(spec)
        except R.ValidationError as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1
        print(built["preview"])
        return 0
    print(usage, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(appfw_main(sys.argv[1:2]))
