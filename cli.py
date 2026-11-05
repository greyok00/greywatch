"""greywatch CLI — L2, the full control plane (Task 6a; BUILT BEFORE the GUI).

    greywatch status
    greywatch events [--tool NAME] [--severity SEV] [--last N]
    greywatch tail                 (stream events.jsonl as they land)
    greywatch log TOOL [--grep PAT] [--tail N]
    greywatch decisions [--pending] | answer ID OPTION
    greywatch rules TOOL ...       (wizard builders — Task 8, same code)
    greywatch action {restart UNIT | drop-ip IP | unban JAIL IP}
    greywatch hunter [--hunt] [--notes]   (threat hunter read + one-shot)

stdlib only; zero privileged code of its own (user-unit restarts go through
systemctl --user, everything privileged through pkexec-helpers only). All
arguments validated: IPs, jail names, unit names from a fixed whitelist.
Unknown command/args → exit 2 + usage. Sharing helpers.py with the GUI is
what makes the GUI provably a skin (plan G3.3).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

import rules

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import greywatch_daemon as daemon_mod
from decisions_factory import pending_ids
from registry import load_registry
from status import load_status

ROOT = pathlib.Path(__file__).resolve().parent
DATA_DIR = daemon_mod.DATA_DIR

IP_RE = re.compile(rules.IP_RE)   # octet-bounded (from rules.py)
JAIL_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RESTART_WHITELIST = frozenset({
    "yara-tmp-scan.timer", "yara-watch.service",
    "clam-scan.timer", "aide-check.timer",
})
EXIT_OK, EXIT_ERR, EXIT_USAGE = 0, 1, 2


def _fail(msg: str, exit_code: int = EXIT_ERR):
    print(f"greywatch: {msg}", file=sys.stderr)
    sys.exit(exit_code)


def cmd_status(_args) -> int:
    snap = load_status(str(DATA_DIR / "status.json"))
    if not snap.get("tools"):
        print("greywatch: daemon has not written status yet - "
              "start `greywatch` (the unit) or wait one cycle.")
        return EXIT_OK
    pending = snap.get("pending_decisions", 0)
    badge = f"  ·  {pending} pending decision(s)" if pending else ""
    # : the UI prints local words ("today 14:20"), the CLI printed
    # the raw UTC ISO stamp - one clock across both surfaces.
    from ui import updates
    print(f"greywatch status - updated "
          f"{updates.human_stamp(snap.get('updated'))}  "
          f"[{snap.get('dropped', 0)} dropped]{badge}")
    for name, info in sorted(snap["tools"].items()):
        state = info["state"]
        extra = ""
        if name == "cve-updater" and updates.cve_list() is not None:
            state = "GREEN" if updates.cve_is_fresh() else "YELLOW"
            info_cve = updates.cve_list() or {}
            extra = (f"  fetched:{updates.human_stamp(info_cve.get('ts'))}")
        elif name == "freshclam":
            clam = updates.clamav_definitions() or {}
            if clam.get("ts"):
                extra = f"  updated:{updates.human_stamp(clam['ts'])}"
        mark = {"GREEN": "🟢", "YELLOW": "🟡", "RED": "🔴",
                "OFF": "⚫"}.get(state, "⚫")
        last = f"  last:{info['last_event']}" if info.get("last_event") else ""
        print(f"{mark} {name:<14} {state:<7}{last}{extra} - {info['label']}")
    return EXIT_OK


def _events_readable():
    path = DATA_DIR / "events.jsonl"
    if path.exists() and not os.access(path, os.R_OK):
        print("greywatch: events.jsonl is written by the root daemon and is "
              "not readable by this user (0600). Run the CLI as root or "
              "read events through the UI.", file=sys.stderr)
        return False
    return True


def _read_events():
    return daemon_mod.read_events(DATA_DIR / "events.jsonl")


def cmd_events(args) -> int:
    if not _events_readable():
        return EXIT_ERR
    evs = _read_events()
    if args.tool:
        evs = [e for e in evs if e.get("from_tool") == args.tool]
    if args.severity:
        evs = [e for e in evs if e.get("severity") == args.severity]
    for e in evs[-args.last:]:
        print(_render(e))
    return EXIT_OK


def _render(e: dict) -> str:
    mark = {"HIGH": "🔴", "CRITICAL": "🔴", "MEDIUM": "🟡", "INFO": "🟢"}
    cves = f" [{','.join(e.get('cves', []))}]" if e.get("cves") else ""
    ctl = ",".join(e.get("nist_control", []))
    # : the event line's stamp reads local words like the dashboard
    # ("today 14:20", else "Nov 04 14:20"), never a raw UTC ISO.
    from ui import updates
    return (f"{mark.get(e.get('severity'), '⚪')} "
            f"{updates.human_stamp(e.get('ts', ''))} "
            f"{e.get('from_tool'):<12} {e.get('severity'):<7} "
            f"{e.get('nist_func')}/{ctl or '–'}{cves}  {e.get('text', '')}")


def cmd_tail(args) -> int:
    import time
    path = DATA_DIR / "events.jsonl"
    if not path.exists():
        print("greywatch: no events yet (events.jsonl missing); run the daemon.")
        return EXIT_OK
    if not _events_readable():
        return EXIT_ERR
    with open(path, "rb") as f:
        for i, line in enumerate(f):
            if i >= args.skip:
                try:
                    print(_render(json.loads(line)))
                except ValueError:
                    pass
        while True:                      # follow
            line = f.readline()
            if line:
                try:
                    print(_render(json.loads(line)), flush=True)
                except ValueError:
                    pass
            time.sleep(0.1)


def cmd_log(args) -> int:
    tool = args.tool
    if not [t for t in load_registry() if t["name"] == tool]:
        _fail(f"unknown tool {tool!r}", EXIT_USAGE)
    if not _events_readable():
        return EXIT_ERR
    evs = _read_events()
    lines = [e.get("text", "") for e in evs if e.get("from_tool") == tool]
    if args.grep:
        try:
            pat = re.compile(args.grep)
        except re.error:
            _fail(f"bad --grep pattern {args.grep!r}", EXIT_USAGE)
        lines = [l for l in lines if pat.search(l)]
    for l in lines[-args.tail:]:
        print(l[:500])
    return EXIT_OK


def cmd_decisions(args) -> int:
    specs, answered = _gather_specs()
    if args.pending:
        specs = [s for s in specs if s["id"] not in answered]
    for s in specs:
        print(f"[{s['id']}] {s['question']}")
        for o in s["options"]:
            print(f"    {o['id']:<8} {o['label']}   (helper: {o['helper']})")
    return EXIT_OK


def _gather_specs():
    answered = pending_ids(DATA_DIR / "decisions.jsonl")
    specs, seen = [], set()
    for e in _read_events():
        spec = e.get("interaction")
        if spec and spec["id"] not in seen:
            seen.add(spec["id"])
            specs.append(spec)
    return specs, answered


def _validate_answer(spec_id: str, option: str):
    specs, answered = _gather_specs()
    spec = next((s for s in specs if s["id"] == spec_id), None)
    if spec_id in answered:
        _fail("already answered (answer-once enforced)")
    if spec is None:
        _fail(f"unknown decision id {spec_id!r}", EXIT_USAGE)
    opt = next((o for o in spec["options"] if o["id"] == option), None)
    if opt is None:
        _fail(f"option {option!r} not valid for {spec_id} "
              f"(choose one of: {', '.join(o['id'] for o in spec['options'])})")
    return opt


def cmd_answer(args) -> int:
    opt = _validate_answer(args.id, args.option)
    # Run the action BEFORE recording it. Answer-once means a
    # decision consumed by a failed helper can never be retried; the record
    # must therefore be the result of the action, not a prediction of it.
    print(f"running helper {opt['helper']}…", flush=True)
    rc = helper_exec(opt["helper"], opt.get("args", []))
    if rc != 0:
        print(f"greywatch: the action did not complete (helper {opt['helper']} "
              f"exited {rc}); the decision is still pending.", file=sys.stderr)
        return EXIT_ERR
    from decisions_factory import record_answer
    if not record_answer(DATA_DIR / "decisions.jsonl", args.id, opt["id"]):
        _fail("the action ran, but the decision was already recorded "
              "by another process")
    print(f"recorded {args.id} → {opt['id']} ({opt['helper']}); done.")
    return EXIT_OK


def _orig_text(spec_id):
    for e in _read_events():
        if e.get("interaction") and e["interaction"]["id"] == spec_id:
            return e.get("text", "")
    return ""


def helper_exec(helper: str, args_list):
    script = ROOT / "apply" / f"{helper}.sh"
    override = os.environ.get("GREYWATCH_HELPER_CMD")
    if override:
        cmd = [override, helper] + list(args_list)
    elif script.exists():
        cmd = ["pkexec", str(script)] + list(args_list)
    else:
        print(f"greywatch: helper {helper}.sh is missing from {script.parent}",
              file=sys.stderr)
        return EXIT_ERR
    try:
        return subprocess.run(cmd, capture_output=True, text=True).returncode
    except OSError as exc:
        print(f"greywatch: could not run helper {helper}: {exc}", file=sys.stderr)
        return EXIT_ERR


def helper_batch(items):
    """Apply several decision helpers under ONE polkit prompt.

    Every answer button ran pkexec on its own and polkit's exec action
    re-prompts each call; answering a backlog meant one password per
    row. The batch helper runs them all in one root pass and prints
    one {"rcs": [..]} line back, in the input order, so callers can
    match each rc to its row and record only the ones that exited 0.
    Returns the rc list, or all -1 when the batch could not run.
    """
    import tempfile
    doc = {"items": [{"helper": h, "args": list(a or [])} for h, a in items]}
    if not doc["items"]:
        return []
    fd, path = tempfile.mkstemp(prefix="greywatch-batch-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(doc))
    script = ROOT / "apply" / "batch.sh"
    override = os.environ.get("GREYWATCH_HELPER_CMD")
    if override:
        cmd = [override, "batch", path]
    elif script.exists():
        cmd = ["pkexec", str(script), path]
    else:
        print(f"greywatch: helper batch.sh is missing from {script.parent}",
              file=sys.stderr)
        os.unlink(path)
        return [-1] * len(items)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"greywatch: could not run the batch helper: {exc}",
              file=sys.stderr)
        os.unlink(path)
        return [-1] * len(items)
    os.unlink(path)
    if override:
        # Test mode keeps the single-helper contract: one exit code
        # stands for the whole batch.
        return [proc.returncode] * len(items)
    try:
        rcs = json.loads(proc.stdout.strip().splitlines()[-1])["rcs"]
        if isinstance(rcs, list) and len(rcs) == len(items):
            return [int(r) for r in rcs]
    except (ValueError, KeyError, IndexError, TypeError):
        pass
    return [-1] * len(items)


def cmd_rules(args) -> int:
    try:
        from rules import rules_main
    except ImportError:
        print("greywatch rules: builders arrive with Task 8 (wizards)")
        return EXIT_ERR
    return rules_main(args)


def _cli_version() -> str:
    try:
        import tomllib
        with open(ROOT / "pyproject.toml", "rb") as fh:
            return str(tomllib.load(fh)["project"]["version"])
    except Exception:
        return "0.0.0"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="greywatch", description=__doc__)
    ap.add_argument("--version", action="version",
                    version=f"greywatch {_cli_version()} (pyproject.toml)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ps_ = sub.add_parser("status", help="what the suite is doing right now")
    ps_.set_defaults(fn=cmd_status)

    pe = sub.add_parser("events", help="the audit trail, newest first")
    pe.add_argument("--tool", choices=sorted(t["name"] for t in load_registry()),
                    help="only one tool's rows (appfw, hunter, sentinel...)")
    pe.add_argument("--severity",
                    choices=["INFO", "MEDIUM", "HIGH", "CRITICAL"],
                    help="only rows at this severity or stronger")
    pe.add_argument("--last", type=int, default=50,
                    help="how many rows to print (default 50)")
    pe.set_defaults(fn=cmd_events)

    pt = sub.add_parser("tail", help="follow the audit trail live")
    pt.add_argument("--skip", type=int, default=0,
                    help="start this many lines down (rejoin a stopped tail)")
    pt.set_defaults(fn=cmd_tail)

    pl = sub.add_parser("log", help="one tool's own log file")
    pl.add_argument("tool", help="the tool's name (see `gw status`)")
    pl.add_argument("--grep", help="only lines containing this text")
    pl.add_argument("--tail", type=int, default=100,
                    help="how many lines to print (default 100)")
    pl.set_defaults(fn=cmd_log)

    pd = sub.add_parser("decisions", help="list decision specs (all or pending)")
    pd.add_argument("--pending", action="store_true",
                    help="only still-unanswered decisions")
    pd.set_defaults(fn=cmd_decisions)

    pa = sub.add_parser("answer", help="answer a pending decision by id")
    pa.add_argument("id", help="the decision id from `gw decisions --pending`")
    pa.add_argument("option", help="the option id to answer with")
    pa.set_defaults(fn=cmd_answer)

    pr = sub.add_parser("rules", help="config rule builders (wizards, Task 8)")
    pr.add_argument("tool", nargs="?", default="")
    pr.add_argument("rest", nargs=argparse.REMAINDER)
    pr.set_defaults(fn=cmd_rules)

    pact = sub.add_parser("action", help="restart a tool, or manage offenders")
    pact.add_argument("what",
                      choices=["restart", "drop-ip", "unban"],
                      help="restart TOOL, drop-ip IP (kill connections), "
                           "unban JAIL IP (fail2ban)")
    pd_ = sub.add_parser("doctor", help="diagnose + recover + verify all tools")
    pd_.add_argument("--fix", action="store_true", help="apply safe repairs")
    pd_.add_argument("--only", metavar="TOOL", help="doctor a single tool")
    ph = sub.add_parser("hunter", help="threat hunts: show findings, or run one")
    ph.add_argument("--hunt", action="store_true",
                    help="run one hunt cycle now (same work the resident "
                         "hunter does; the inbox HARs are answered here too)")
    ph.add_argument("--notes", action="store_true",
                    help="print the hunter's plain-language notes instead "
                         "of the raw findings")
    ph.add_argument("--no-ai", action="store_true",
                    help="one-hunt run with rules only (no model calls)")
    ps = sub.add_parser("setup", help="first-install tool audit + setup")
    # `unban` needs two positionals (JAIL IP) while `restart` and `drop-ip`
    # take one; argparse cannot vary arity by verb, so the second slot is
    # optional here and cmd_action enforces each verb's contract.
    pact.add_argument("target")
    pact.add_argument("extra", nargs="?", default=None)
    pact.set_defaults(fn=cmd_action)
    ps.set_defaults(fn=cmd_setup)
    pd_.set_defaults(fn=cmd_doctor)
    ph.set_defaults(fn=cmd_hunter)
    return ap


def cmd_hunter(args) -> int:
    """Read the hunter's files (default) or run one hunt in-process.

    The resident hunter is a separate user process; --hunt is the same
    single cycle it runs, for a shell check without waiting on the timer.
    """
    import hunter.store as store
    if args.hunt:
        from hunter import main as hunter_main
        doc = hunter_main.tick(str(DATA_DIR), str(pathlib.Path.home()),
                               ai_enabled=not bool(args.no_ai))
        print(f"hunted: {doc.get('new_this_cycle', 0)} new finding(s), "
              f"{doc.get('unread', 0)} unread")
        return EXIT_OK
    doc = store.read_live(DATA_DIR)
    total = doc.get("findings_total", 0)
    # : the stamp and the unread count come from the surfaces the
    # dashboard reads - a local clock time, and the read pointer, not
    # the frozen counter inside live.json a past hunt wrote.
    import datetime as dt
    from ui import updates
    when = None
    try:
        when = dt.datetime.fromisoformat(str(doc.get("ts") or "")).astimezone()
    except (TypeError, ValueError):
        pass
    stamp = (updates.human_stamp(when.isoformat()) if when
             else doc.get("ts", "-"))
    try:
        from hunter import explain
        pointer = explain.read_pointer(DATA_DIR)
        notes = store.read_defender(DATA_DIR, limit=100)
        unread = sum(1 for n in notes if explain.note_is_unread(n, pointer))
    except (OSError, ValueError):
        unread = doc.get("unread", 0)
    print(f"hunter: last hunt {stamp}, {total} finding(s), "
          f"{unread} unread note(s)")
    # : a stale stamp says so in words, with the dashboard's own
    # not-responding rule (2.5 hunt intervals) so both surfaces agree.
    try:
        if when:
            interval = max(60.0, float(doc.get("interval_s") or 300.0))
            age = (dt.datetime.now().astimezone() - when).total_seconds()
            if age > max(60.0, interval * 2.5):
                print(f"hunter not responding: last hunt was {age / 60:.0f} "
                      f"min ago and a hunt should run every {interval / 60:.0f}"
                      " min - check `greywatch doctor` for the hunter service")
    except (TypeError, ValueError):
        pass
    if args.notes:
        for row in store.read_defender(DATA_DIR, limit=15):
            print(f"[{row.get('severity', '?')}] {row.get('text', '')}"
                  f" -> {row.get('hint', '')}")
        return EXIT_OK
    for f in store.read_findings(DATA_DIR, limit=10):
        print(f"[{f.get('severity', '?')}] {f.get('rule', '?')}: "
              f"{f.get('title', '')}")
        if f.get("what"):
            print(f"    {f['what']}")
        if f.get("next"):
            print(f"    next: {f['next']}")
    return EXIT_OK


def cmd_doctor(args) -> int:
    import doctor as doctor_mod
    return doctor_mod.doctor(fix=args.fix, only=args.only)


def cmd_setup(args) -> int:
    import setup as setup_mod
    return setup_mod.run()


def cmd_action(args) -> int:
    if args.what != "unban" and args.extra is not None:
        _fail(f"action {args.what} takes one target, not two", EXIT_USAGE)
    if args.what == "restart":
        if args.target not in RESTART_WHITELIST:
            _fail(f"unit {args.target!r} is NOT restartable from greywatch. "
                  f"Whitelisted: {', '.join(sorted(RESTART_WHITELIST))}")
        out = subprocess.run(["systemctl", "--user", "restart", args.target],
                             capture_output=True, text=True)
        print(out.stdout or f"restarted {args.target} (user unit)")
        return EXIT_OK if out.returncode == 0 else EXIT_ERR
    if args.what == "drop-ip":
        if not IP_RE.match(args.target):
            _fail(f"{args.target!r} is not a valid IP (drop-ip wants A.B.C.D)",
                  EXIT_USAGE)
        return helper_exec("drop-listener", ["ufw", "deny", "from", args.target])
    if args.what == "unban":
        if not JAIL_RE.match(args.target):
            _fail(f"{args.target!r} is not a valid jail name", EXIT_USAGE)
        if not args.extra:
            _fail("action unban wants JAIL IP, e.g. "
                  "`greywatch action unban sshd 203.0.113.9`", EXIT_USAGE)
        if not IP_RE.match(args.extra):
            _fail(f"{args.extra!r} is not a valid IP (unban wants A.B.C.D)",
                  EXIT_USAGE)
        return helper_exec("unban-ip", [args.target, args.extra])
    return EXIT_USAGE


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    return args.fn(args) or EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
