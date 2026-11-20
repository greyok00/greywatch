#!/usr/bin/env python3
"""greywatch CLI — L2, the full control plane (Task 6a; BUILT BEFORE the GUI).

    greywatch status
    greywatch events [--tool NAME] [--severity SEV] [--last N]
    greywatch tail                 (stream events.jsonl as they land)
    greywatch log TOOL [--grep PAT] [--tail N]
    greywatch decisions [--pending] | answer ID OPTION
    greywatch rules TOOL ...       (wizard builders — Task 8, same code)
    greywatch action {restart UNIT | drop-ip IP | unban JAIL IP}
    greywatch run                  (run every detector now and print
                                    each tool's results as they land)
    greywatch assist "QUESTION"    (heuristics first, then knowledge base;
                                    the GPU model is never loaded here)

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
import time
import pathlib
import re
import subprocess
import sys
import threading

import baseline_apply
import rules

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import greywatch_daemon as daemon_mod
from decisions_factory import pending_ids, snapshot_pending
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

# One list for test/scratch paths. The quarantine sweep and the janitor
# must agree on what "test artifact" means.
JUNK_SEGMENTS = ("/pytest-of-grey/", "/pytest-tmp/", "gw-eicar",
                 "gw-live-files", "gw-live")


def _fail(msg: str, exit_code: int = EXIT_ERR):
    print(f"greywatch: {msg}", file=sys.stderr)
    sys.exit(exit_code)


TOOL_PAGES = {
    "firewall": {"tool": "ufw", "label": "Firewall (UFW)",
                 "digest": "ufw"},
    "appfw": {"tool": "appfw", "label": "Program Access",
              "digest": "appfw"},
    "yara": {"tool": "yara-watch", "label": "YARA file scanner",
             "digest": "yara", "also": ("yara-tmp-scan",)},
    "clamav": {"tool": "clamav", "label": "ClamAV antivirus",
               "digest": "clamav", "also": ("freshclam",)},
    "psad": {"tool": "psad", "label": "Port scan detector",
             "digest": "psad"},
    "fail2ban": {"tool": "fail2ban", "label": "Login banner",
                 "digest": "fail2ban"},
    "arpwatch": {"tool": "arpwatch", "label": "ARP watch",
                 "digest": "arpwatch"},
    "netwatch": {"tool": "net-watch", "label": "Connection watch",
                 "digest": "net-watch"},
}


def _digest_excerpt(name: str, lines: int = 8) -> str:
    """What the tool is, from its own digested documentation."""
    path = ROOT / "tool-digests" / f"{name}.md"
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return ""
    start = text.find("WHAT IT IS:")
    if start < 0:
        return ""
    body = text[start + len("WHAT IT IS:"):]
    for stop in ("WHAT ITS WARNINGS MEAN:", "WHAT THE STATE MEANS:",
                 "WHAT ITS EVENTS MEAN:", "HOW GREYWATCH USES IT:",
                 "HOW IT IS CONTROLLED:"):
        cut = body.find(stop)
        if cut >= 0:
            body = body[:cut]
    out = [ln.strip() for ln in body.splitlines() if ln.strip()]
    return " ".join(out[:lines])


def _page_controls(name: str, cfg: dict) -> list[str]:
    tool = cfg["tool"]
    out = [f"greywatch tool {tool} --events N   its state and own lines"]
    if name == "firewall":
        out += ["greywatch firewall \"let firefox through\"   allow a program",
                "greywatch firewall \"allow port 8080\"        UFW rule (root)"]
    elif name in ("appfw", "firewall"):
        out += ["greywatch appfw \"block firefox\"           deny a program"]
    elif name == "yara":
        out += ["greywatch yara scan now         restart the timed scanner",
                "greywatch yara matches           recent hits"]
    elif name == "clamav":
        out += ["greywatch clamav scan now       start the daily scan timer",
                "greywatch clamav definitions    how old the virus list is"]
    return out


def _find_program(words: list[str]) -> str:
    import shutil
    for word in words:
        found = shutil.which(word)
        if found:
            return found
    for word in words:
        if "/" in word and pathlib.Path(word).exists():
            return word
    return ""


def cmd_page(args) -> int:
    """One tool page: what it is, how it is doing, and plain-language control.

    Documentation comes from tool-digests, state from the daemon
    snapshot, and actions run the same CLI commands every other surface
    uses. Nothing from another tool is mixed in.
    """
    cfg = TOOL_PAGES[args.page]
    tool = cfg["tool"]
    snap = load_status(str(DATA_DIR / "status.json"))
    info = (snap.get("tools") or {}).get(tool) or {}
    reg = next((t for t in load_registry() if t["name"] == tool), {})
    print(f"{cfg['label']}  ({tool})")
    print(f"  state: {info.get('state', 'UNKNOWN')}   "
          f"unit: {reg.get('unit') or 'on demand'}")
    what = _digest_excerpt(cfg.get("digest", tool))
    if what:
        print(f"\n{what}")
    print("\nHow to control it:")
    for line in _page_controls(args.page, cfg):
        print(f"  {line}")
    print(f"  docs: {ROOT / 'doc' / 'tool-digests' / (cfg.get('digest', tool) + '.md')}")

    # A quoted request arrives as one argument: split it into words so
    # "allow port 8080" and "let firefox through" parse the same way.
    words = " ".join(str(w) for w in (getattr(args, "words", None) or [])).split()
    low = " ".join(words).lower()
    if not words:
        return EXIT_OK
    yes = bool(getattr(args, "yes", False))

    if args.page in ("firewall", "appfw"):
        prog = _find_program(words)
        verb = ("deny" if any(w in low for w in ("block", "deny", "stop"))
                else "allow")
        if prog:
            from types import SimpleNamespace
            plan = f"rules appfw {verb} {prog}"
            print(f"\nPlan: {plan}  (program access rule)")
            print("Nothing is changed until you add --yes.")
            if not yes:
                return EXIT_OK
            import rules as rules_mod
            rc = rules_mod.rules_main(SimpleNamespace(tool="appfw",
                                                      rest=[verb, prog]))
            if rc == 0:
                print("done. Program access is updated.")
            return rc
        port = next((w for w in words if w.isdigit()), "")
        ip = next((w for w in words if IP_RE.match(w)), "")
        if port:
            print(f"\nRoot command to run:\n  sudo ufw allow {port}")
            return EXIT_OK
        if ip:
            print(f"\nRoot command to run:\n  sudo ufw deny from {ip}")
            return EXIT_OK
        print("\nName a program (for example: let firefox through), a port, "
              "or an address.")
        return EXIT_OK

    if args.page == "yara":
        if any(w in low for w in ("scan", "run", "sweep")):
            plan = "action restart yara-tmp-scan.timer"
            print(f"\nPlan: {plan}")
            if not yes:
                print("Nothing is changed until you add --yes.")
                return EXIT_OK
            return cmd_action(argparse.Namespace(what="restart",
                                                 target="yara-tmp-scan.timer",
                                                 extra=None))
        if any(w in low for w in ("match", "hit", "found")):
            return cmd_tool(argparse.Namespace(name="yara-watch",
                                               events=args.events, json=False))
    return EXIT_OK


def cmd_baseline(args) -> int:
    """Build and show the app-gate baseline: what normal looks like per
    program and destination. This is the heuristic layer's floor."""
    import time as _time
    import baseline as baseline_mod
    profile = baseline_mod.build(DATA_DIR, now=_time.time())
    apps = sorted(profile.apps) if hasattr(profile, "apps") else []
    if getattr(args, "json", False):
        entries = []
        for a in apps:
            try:
                entries.append({"app": a,
                                "pairs": len(getattr(profile.apps[a],
                                                     "pairs", []) or [])})
            except Exception:           # noqa: BLE001
                entries.append({"app": a})
        print(json.dumps({"apps": len(apps), "entries": entries}))
        return EXIT_OK
    print(f"baseline built live: {len(apps)} known program(s)")
    checks = _baseline_verifier()
    armed = sum(1 for c in checks if c[2] in (
        "ENABLED", "PRESENT", "ARMED", "FRESH", "OFF-BY-DESIGN"))
    print(f"tool baseline: {armed}/{len(checks)} checks pass")
    for name, check_label, state, fix in checks:
        mark = {"ENABLED": "\U0001f7e2", "PRESENT": "\U0001f7e2",
                "ARMED": "\U0001f7e2", "FRESH": "\U0001f7e2",
                "OFF-BY-DESIGN": "\U0001f7e2"}.get(state, "\U0001f534")
        print(f"  {mark} {name:<16} {check_label:<40} {state}")
        if fix:
            print(f"       fix: {fix}")
    print()
    print()
    print("Detection lanes the service runs, with their last hits:")
    snap = load_status(str(DATA_DIR / "status.json"))
    tools = snap.get("tools") or {}
    HUNT_TOOLS = ["psad", "yara-watch", "yara-tmp-scan", "clamav", "aide",
                  "rkhunter", "lynis", "tetragon", "responderd"]
    evs = _read_events()
    by_tool = {}
    for e in evs:
        t = e.get("from_tool")
        if t in HUNT_TOOLS and not (e.get("text") or "").startswith("check-in"):
            by_tool.setdefault(t, []).append(e)
    for t in HUNT_TOOLS:
        info = tools.get(t) or {}
        rows = by_tool.get(t) or []
        hits = sum(1 for e in rows if (e.get("severity") or "")
                   in ("HIGH", "CRITICAL"))
        last = rows[-1] if rows else {}
        mark = {"GREEN": "\U0001f7e2", "YELLOW": "\U0001f7e1",
                "RED": "\U0001f534"}.get(info.get("state"), "\u26aa")
        print(f" {mark} {t:<14} "
              f"{str(info.get('state') or '?'):<8} {hits} find(s); "
              f"last: {(last.get('severity') or '-')}: "
              f"{(last.get('text') or '-')[:80]}")
    known = []
    for a in apps:
        try:
            n = len(getattr(profile.apps[a], "pairs", []) or [])
        except Exception:               # noqa: BLE001
            n = 0
        if n:
            known.append((a, n))
    if not known:
        print("no destination pairs recorded yet; programs appear here "
              "as they connect and are learned")
    else:
        print(f"{len(known)} program(s) with learned destinations:")
        for a, n in sorted(known, key=lambda kv: -kv[1])[:10]:
            print(f"  {a:<24} {n} pair(s)")
        if len(known) > 10:
            print(f"  ... and {len(known) - 10} more")
    print()
    print("Browser lane (profiles, extensions, downloads, persistence, HAR):")
    try:
        r = subprocess.run(["systemctl", "is-active",
                            "greywatch-hunter.service"],
                           capture_output=True, text=True, timeout=10)
        state = (r.stdout or "").strip() or "inactive"
    except Exception:                   # noqa: BLE001
        state = "?"
    bmark = "\U0001f7e2" if state == "active" else "\u26aa"
    print(f" {bmark} lane: running, read with: greywatch hunter")
    return EXIT_OK


def cmd_harden(args) -> int:
    """Scan, plan or apply the hardening control catalog. `fix` runs the
    pkexec helper that journals, applies and reverifies every step."""
    import gwpaths
    from hardening.controls import load_controls
    from hardening import detector, apply as harden_apply
    controls = load_controls(ROOT / "data")
    if not controls:
        controls = load_controls(gwpaths.data_dir())
    if getattr(args, "only", None):
        controls = [c for c in controls if getattr(c, "id", "") == args.only]
    if not controls:
        print("greywatch harden: no control catalog found "
              "(expected hardening-controls.json in the state dir)")
        return EXIT_ERR
    findings = detector.scan(controls)
    if getattr(args, "json", False):
        print(json.dumps([{"id": f.control_id, "state": f.state,
                           "current": f.current} for f in findings]))
        return EXIT_OK
    for f in findings:
        print(f"{getattr(f, 'state', '?'):<6} {getattr(f, 'control_id', '?'):<14} "
              f"{getattr(f, 'current', '')}")
    if args.verb == "scan":
        return EXIT_OK
    plan, advisories = harden_apply.build_plan(findings, controls)
    print(harden_apply.plan_document(plan))
    if args.verb == "plan":
        return EXIT_OK
    if not getattr(args, "yes", False):
        print("Dry run. Add --yes to apply through the pkexec helper.")
        return EXIT_OK
    import tempfile
    fd, path = tempfile.mkstemp(prefix="greywatch-harden-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps({"plan": plan}))
    script = helper_script("harden")
    if not script.exists():
        print(f"greywatch harden: helper {script} is missing", file=sys.stderr)
        return EXIT_ERR
    proc = subprocess.run(["pkexec", str(script), "apply", path],
                          capture_output=True, text=True, timeout=420)
    print((proc.stdout or "").strip())
    if (proc.stderr or "").strip():
        print((proc.stderr).strip()[-400:], file=sys.stderr)
    try:
        os.unlink(path)
    except OSError:
        pass
    return EXIT_OK if proc.returncode == 0 else EXIT_ERR


from baseline import baseline_verifier as _baseline_verifier
# the table lives in baseline.py so the root daemon (which cli # imports, and which therefore cannot import cli) computes the # same checks when it publishes the posture store

def cmd_verify(args) -> int:
    """Every tool, every check, one pass: the baseline verifier, the
    hardening catalog, and each unit's live state. Run with sudo to
    close the root-only checks."""
    checks = _baseline_verifier()
    fails = [c for c in checks if c[2] not in
             ("ENABLED", "PRESENT", "ARMED", "FRESH", "OFF-BY-DESIGN")]

    import gwpaths
    from hardening.controls import load_controls
    from hardening import detector
    controls = load_controls(ROOT / "data")
    if not controls:
        controls = load_controls(gwpaths.data_dir())
    findings = detector.scan(controls)
    gaps = [f for f in findings if f.state == "GAP"
            or getattr(f, "state", "") == "CANT-CHECK"]

    snap = load_status(str(DATA_DIR / "status.json"))
    tools_block = (snap or {}).get("tools")
    if isinstance(tools_block, dict) and tools_block:
        tool_rows = list(tools_block.items())
    else:
        raw = _status_json()
        tool_rows = [(t.get("name") or "?", t)
                     for t in (raw.get("tools") or [])
                     if isinstance(t, dict)]
    down = [(n, (i if isinstance(i, dict) else {}).get("state"))
            for n, i in tool_rows
            if (i if isinstance(i, dict) else {}).get("state")
            not in ("GREEN",)]
    green_n = len(tool_rows) - len(down)

    if getattr(args, "json", False):
        print(json.dumps({
            "tool_baseline": [{"tool": n, "check": l, "state": s,
                               "fix": f} for n, l, s, f in checks],
            "hardening": {
                "pass": len(findings) - len(gaps),
                "gaps": [{"control": str(getattr(f, "control_id", "?")),
                          "current": str(getattr(f, "current", ""))[:120],
                          "state": str(getattr(f, "state", ""))}
                         for f in findings]},
            "tools": {"green": green_n,
                      "attention": [{"tool": n, "state": s}
                                    for n, s in down]},
        }))
        return EXIT_OK if not (fails or gaps or down) else EXIT_ERR

    print("1. tool baseline:")
    for name, check_label, state, fix in checks:
        mark = "\U0001f7e2" if state in ("ENABLED", "PRESENT", "ARMED",
                                         "FRESH", "OFF-BY-DESIGN") \
            else "\U0001f534"
        print(f"  {mark} {name:<16} {state}")
        if fix:
            print(f"       fix: {fix}")

    print(f"2. hardening catalog: "
          f"{len(findings) - len(gaps)} pass, {len(gaps)} GAP/CANT-CHECK")
    for f in gaps:
        print(f"  \U0001f7e1 {getattr(f, 'control_id', '?'):<14} "
              f"{getattr(f, 'current', '')[:90]}")

    print(f"3. tool states: {green_n} green, {len(down)} attention")
    for n, s in down:
        print(f"  \U0001f534 {n}: {s}")

    if not fails and not gaps and not down:
        print("ALL CLEAR")
    else:
        print(f"attention: {len(fails) + len(gaps) + len(down)} item(s); "
              "fix with: harden plan/--yes, answer ID OPTION, "
              "or the fix lines above")
    return EXIT_OK if not (fails or gaps or down) else EXIT_ERR


def cmd_updates(args) -> int:
    """The intelligence data the heuristics must read, in one place:
    the CVE list, the virus definitions, the blocklists and the web of
    trust. Read-only; refreshes are separate commands."""
    from core import updates
    from core.settings import TrustList
    s = updates.summary()
    out = {"cve": s.get("cve") or {}, "clamav": s.get("clamav") or {},
           "blocklist": s.get("blocklist") or {}}
    try:
        tl = TrustList()
        out["trust"] = {"allow": len(tl.allow), "block": len(tl.block),
                        "apps": len(tl.apps_allow)}
    except Exception as exc:                        # noqa: BLE001
        out["trust_error"] = str(exc)
    try:
        import time as _time
        import datetime as _dt
        conf = pathlib.Path(str(DATA_DIR)) / "webguard-blocklist.conf"
        st = conf.stat()
        lines = 0
        with open(conf, errors="replace") as fh:
            for _l in fh:
                lines += 1
        stamp = _dt.datetime.fromtimestamp(
            st.st_mtime, _dt.timezone.utc).isoformat(timespec="seconds")
        out["feeds"] = {"lines": lines,
                        "age_s": max(0.0, _time.time() - st.st_mtime),
                        "updated": updates.human_stamp(stamp)}
    except OSError:
        # The rendered file exists but is root-only: say so and give what
        # is still readable, instead of claiming it was never rendered.
        try:
            conf = pathlib.Path(str(DATA_DIR)) / "webguard-blocklist.conf"
            st = conf.stat()
            out["feeds"] = {"rendered": True, "bytes": st.st_size,
                            "root_only": True}
        except OSError:
            out["feeds"] = {"lines": 0, "error": "conf not rendered"}
    if getattr(args, "json", False):
        print(json.dumps(out))
        return EXIT_OK
    cve = out["cve"]
    print(f"CVE list: {cve.get('count', 0)} entries, fetched "
          f"{updates.human_stamp(cve.get('ts'))}, fresh: "
          f"{'yes' if updates.cve_is_fresh() else 'NO'}")
    clam = out["clamav"]
    print(f"Virus definitions: {updates.human_stamp(clam.get('ts'))}")
    bl = out["blocklist"]
    print(f"Block list: {bl.get('count', 0)} domains, updated "
          f"{updates.human_stamp(bl.get('fetched_utc'))}")
    feeds = out.get("feeds") or {}
    if feeds.get("root_only"):
        print(f"Feeds: rendered ({feeds.get('bytes', 0)} bytes, root-only; "
              "refreshed by the feeds lane)")
    else:
        print(f"Feeds rendered: {feeds.get('lines', 0)} rules "
              f"({feeds.get('updated', 'never')})")
    tr = out.get("trust") or {}
    print(f"Web of trust: {tr.get('allow', 0)} auto-allow, "
          f"{tr.get('block', 0)} auto-block, {tr.get('apps', 0)} programs")
    return EXIT_OK


def cmd_tools(_args) -> int:
    """List every monitored tool by its exact token. One name, one tool."""
    for tool in load_registry():
        print(f"{tool['name']:<14} {tool.get('label', '')}")
    return EXIT_OK


def cmd_tool(args) -> int:
    """One tool only: its unit, state, last event, and its own recent lines.

    Nothing from another tool is mixed in. This is the per-tool surface the
    CLI was missing.
    """
    tool = next((t for t in load_registry() if t["name"] == args.name), None)
    if tool is None:
        _fail(f"unknown tool {args.name!r}; run: greywatch tools", EXIT_USAGE)
    snap = load_status(str(DATA_DIR / "status.json"))
    info = (snap.get("tools") or {}).get(args.name) or {}
    rows = []
    try:
        rows = [e for e in _read_events()
                if e.get("from_tool") == args.name][-args.events:]
    except OSError:
        pass
    if getattr(args, "json", False):
        print(json.dumps({"tool": args.name,
                          "label": tool.get("label", ""),
                          "unit": tool.get("unit"),
                          "state": info.get("state"),
                          "last_event": info.get("last_event"),
                          "events": rows}))
        return EXIT_OK
    print(f"{args.name}: {info.get('state', 'UNKNOWN')} - "
          f"{tool.get('label', '')}")
    print(f"  unit: {tool.get('unit') or 'on demand'}")
    if info.get("last_event"):
        print(f"  last: {info['last_event']}")
    for ev in rows:
        print(_render(ev))
    return EXIT_OK


# run: start every detector, then wait and PRINT RESULTS. The owner
# 2026-11-14: "I NEED TO SEE THE RESULTS." An output that only reports
# "started ..." and points at log files fails the command's job. A
# second `greywatch run` while scans are still going attaches to that
# run instead of starting a duplicate; a call after the scans finished
# digests that finished run; Ctrl-C leaves the scans running and says so.
_RUN_TOOLS = ("yara", "clamav", "aide", "rkhunter", "lynis")
_RUN_ROOT_TOOLS = ("rkhunter", "lynis")     # results held in /var/log
_RUN_POLL_SECONDS = 5.0
_RUN_BEAT_SECONDS = 60.0
_RUN_START_GRACE = 45.0     # a tool never seen counts as started after this
# two attach windows (owner 2026-11-14: a run that attached to the same
# two-hour-old history printed the same problems for six hours). In-flight
# runs keep the long window: the Ctrl-C recovery works all session. A
# FINISHED run is history after half an hour: the next call starts fresh.
_RUN_ATTACH_WINDOW = 6 * 3600.0
_RUN_DONE_ATTACH_WINDOW = 30 * 60.0
_RUN_TIMEOUTS = {"yara": 120.0, "clamav": 1800.0, "aide": 900.0,
                 "rkhunter": 900.0, "lynis": 900.0}
_RUN_LABELS = {"yara": "YARA", "clamav": "ClamAV", "aide": "AIDE",
               "rkhunter": "rkhunter", "lynis": "Lynis"}
_RUN_WHAT = {
    "yara": "suspicious file patterns in /tmp, /var/tmp and ~/Downloads",
    "clamav": "virus scan of the whole home folder (takes the longest)",
    "aide": "system files compared against its own snapshot",
    "rkhunter": "rootkit and backdoor signs",
    "lynis": "hardening score with advice",
}
_RUN_PROCESS_PATTERNS = {
    "yara": ("f", "yara-rules/index.yar"),
    "clamav": ("x", "clamscan"),
    "aide": ("f", "aide-scoped.conf"),
    "rkhunter": ("f", "rkhunter --check"),
    "lynis": ("f", "lynis audit"),
}


def _ui_home() -> pathlib.Path:
    """The desktop user's home (where the result files land), even when
    this CLI runs as root."""
    try:
        import pwd
        import gwpaths
        return pathlib.Path(pwd.getpwnam(gwpaths.ui_user()).pw_dir)
    except Exception:               # noqa: BLE001
        return pathlib.Path.home()


def _run_state_path() -> pathlib.Path:
    """Where the scan-now helper records each run's log offsets. Same
    tree resolution as helper_script(): the installed copy wins."""
    return helper_script("scan-now").parent.parent / "data" \
        / "run-scan-state.json"


def _read_run_state() -> dict:
    try:
        return json.loads(
            _run_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _scan_process_running(tool: str) -> bool:
    how, pattern = _RUN_PROCESS_PATTERNS[tool]
    try:
        r = subprocess.run(["pgrep", f"-{how}", pattern],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _run_helper_runner():
    """Start/digest go through the installed scan-now helper like every
    other root action. A root CLI calls it directly. GREYWATCH_HELPER_CMD
    overrides for tests, taking the helper name then args."""
    def runner(args_list, timeout=120):
        override = os.environ.get("GREYWATCH_HELPER_CMD")
        script = helper_script("scan-now")
        if override:
            cmd = [override, "scan-now"] + list(args_list)
        elif os.geteuid() == 0:
            cmd = ["bash", str(script)] + list(args_list)
        elif script.exists():
            cmd = ["pkexec", str(script)] + list(args_list)
        else:
            return 127, "", f"helper scan-now.sh missing at {script}"
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            return 124, "", "the helper call timed out"
        except OSError as exc:
            return 126, "", str(exc)
    return runner


def _read_run_segment(path: pathlib.Path | None, offset: int) -> str:
    """The bytes this run appended beyond the recorded offset."""
    if path is None or offset < 0:
        return ""
    try:
        if path.stat().st_size <= offset:
            return ""
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            return fh.read(2_000_000)
    except OSError:
        return ""


def _fresh_file(path: pathlib.Path | None, since_epoch: float) -> bool:
    try:
        return path is not None and path.stat().st_mtime >= since_epoch
    except OSError:
        return False


def cli_read_whole(path: str) -> str | None:
    try:
        return pathlib.Path(path).read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return None


def add_clam_journal(text: str, clam_log: str, start_epoch: float) -> str:
    """Fold the clam runner journal into the digest: when a scan died,
    its start/exit record names when and with which code."""
    journal = pathlib.Path(clam_log).parent / "clam-run.log"
    try:
        lines = journal.read_text(
            encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return text
    import datetime as dt
    latest_exit, latest_exit_ts = None, None
    for ln in lines:
        m = re.match(r"^(\S+) clamscan (start|exit rc=(-?\d+))", ln)
        if not m:
            continue
        try:
            ts = dt.datetime.fromisoformat(m.group(1)).timestamp()
        except ValueError:
            continue
        if ts < start_epoch - 30:
            continue
        if m.group(2).startswith("exit"):
            if latest_exit_ts is None or ts > latest_exit_ts:
                latest_exit, latest_exit_ts = m.group(3), ts
        elif latest_exit is None:
            latest_exit = "still running or killed before exit"
    if latest_exit:
        note = f"runner journal: "
        if latest_exit.startswith("still"):
            note += latest_exit
        else:
            rc = int(latest_exit)
            reason = {137: "killed (out of memory or SIGKILL)",
                      139: "crashed (segfault)"}.get(
                rc, f"exit code {rc}")
            note += (f"the scan exited with {reason}")
        det_lines = text.splitlines()
        text = text.rstrip("\n") if text else ""
        text = (text + "\n" if text else "") + note
    return text


def _yara_result(text: str, started: bool) -> tuple:
    """(mark, headline, details, findings) for the yara tmp-scan slice.

    Hits name a file: one may exist. Entries about files that are gone
    are history, not a present threat, and never count as findings."""
    import parsers
    rows = [ev.text for ev in (parsers.parse_yara_tmp_scan(line)
                               for line in text.splitlines()) if ev]
    live, gone = [], []
    for ev_text in rows:
        path = ""
        parts = ev_text.split(" matched ", 1)
        if len(parts) == 2:
            path = parts[1].split(" (", 1)[0].strip()
        if path and pathlib.Path(path).exists():
            live.append(ev_text)
        else:
            gone.append(ev_text)
    if live:
        head = (f"{_num(len(live), 'file')} matched suspicious patterns "
                "(see the matched files below)")
        det = list(live[:5])
        if gone:
            det.append(f"{_num(len(gone), 'older log entry')} mentioning "
                       "files that no longer exist")
        return "RED", head, det, len(live)
    if gone:
        return "GREEN", ("no suspicious file is on disk now; the log only "
                         "holds history"), \
            [f"old entry: {g}" for g in gone[:3]], 0
    if started:
        return "GREEN", "found nothing suspicious", [], 0
    return "YELLOW", "did not run", ["no YARA scan was confirmed"], 0


def _clamav_result(text: str, started: bool) -> tuple:
    from core import scan_whitelist
    wl = scan_whitelist.load()
    ignored_note = ""
    infected_rows, infected, total, open_errors = [], None, None, 0
    for line in text.splitlines():
        if line.endswith("FOUND"):
            if scan_whitelist.match(line.split(": ", 1)[0].strip(), wl):
                ignored_note = ("; whitelisted paths ignored this run "
                                "(greywatch whitelist list)")
                continue
            infected_rows.append(line[:200])
        m = re.match(r"Infected files: (\d+)", line)
        if m:
            infected = int(m.group(1))
        m = re.match(r"Total files: (\d+)", line)
        if m:
            total = int(m.group(1))
        if "Failed to open file" in line or "Can't open file" in line:
            open_errors += 1
    if infected_rows:
        n = len(infected_rows)
        head = f"{n} INFECTED FILE{'S' if n != 1 else ''}, paths below"
        head += ignored_note
        return "RED", head, infected_rows[:5], len(infected_rows)
    if infected == 0:
        head = "no viruses found"
        if total:
            head = f"no viruses found ({total:,} files scanned)"
        if open_errors:
            head = (f"{head}; {_num(open_errors, 'file')} could not be "
                    "opened (locked or no permission)")
        return "GREEN", head, [], 0
    if text.strip():
        return "YELLOW", ("this virus scan did not complete: it wrote no "
                          "summary line (it was likely stopped early)"), \
            text.splitlines()[-3:], 0
    if started:
        return "YELLOW", ("this virus scan did not complete: the log "
                          "stayed empty"), [], 0
    return "YELLOW", "did not run", ["no ClamAV scan was confirmed"], 0


_AIDE_SUMMARY = (("Added entries", "added"), ("Removed entries", "removed"),
                 ("Changed entries", "changed"))


def _aide_result(text: str, started: bool) -> tuple:
    if "found differences" in text:
        counts = {}
        for label, key in _AIDE_SUMMARY:
            m = re.search(label + r":\s*(\d+)", text)
            counts[key] = int(m.group(1)) if m else 0
        head = (f"{counts['changed']} system files changed, "
                f"{counts['added']} new, {counts['removed']} gone "
                "since its last snapshot")
        return "YELLOW", head, [], sum(counts.values())
    if "no differences" in text:
        return "GREEN", "no system file changes since its last snapshot", \
            [], 0
    if text.strip():
        return "YELLOW", ("the report has no summary block, so the check "
                          "may not have finished"), \
            text.splitlines()[-3:], 0
    if started:
        return "YELLOW", ("no report was written this run; the check may "
                          "still be finishing"), [], 0
    return "YELLOW", "did not run", ["no AIDE check was confirmed"], 0


def _rkhunter_result(text: str, started: bool) -> tuple:
    import parsers
    rows = [ev.text for ev in (parsers.parse_rkhunter(line)
                               for line in text.splitlines())
            if ev and str(ev.text).startswith("Warning")]
    if not rows:
        # the timestamped parser is strict; a bare "Warning:" line must
        # still reach the owner
        rows = [ln.strip() for ln in text.splitlines() if "Warning:" in ln]
    if rows:
        return "RED", (_num(len(rows), "warning") + " to look at"), \
            rows[:5], len(rows)
    if started:
        return "GREEN", "no warnings this run", [], 0
    return "YELLOW", "did not run", ["no rkhunter scan was confirmed"], 0


def _lynis_result(text: str, started: bool) -> tuple:
    index, warnings = None, []
    for line in text.splitlines():
        m = re.match(r"hardening_index=(\d+)", line)
        if m:
            index = int(m.group(1))
        elif line.startswith("warning[]="):
            parts = line[len("warning[]="):].split("|")
            if len(parts) >= 2:
                warnings.append(f"{parts[0]}: {parts[1]}")
            elif parts and parts[0].strip():
                warnings.append(parts[0].strip())
    if index is not None:
        head = f"hardening score {index} out of 100"
        if warnings:
            return "YELLOW", (head + f" ({_num(len(warnings), 'advice item')} "
                              "to read below)"), \
                warnings[:5], len(warnings)
        return "GREEN", head + ", no advice items", [], 0
    if warnings:
        return "YELLOW", f"{_num(len(warnings), 'advice item')} in the " \
            "report to read", \
            warnings[:5], len(warnings)
    if started:
        return "YELLOW", ("no hardening score in the report; the audit "
                          "may not have finished"), [], 0
    return "YELLOW", "did not run", ["no Lynis audit was confirmed"], 0


def _num(n, word) -> str:
    """Count in words a person can read once: "1 file", "3 files"."""
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _row(tool, mark, headline, details=(), findings=0, seconds=None) -> dict:
    secs_text = ""
    if seconds is not None:
        m, s = divmod(int(seconds), 60)
        secs_text = f"{m}m {s:02d}s" if m else f"{s:.0f}s"
    return {"tool": tool, "mark": mark, "headline": headline,
            "details": list(details), "findings": findings,
            "seconds": seconds, "seconds_text": secs_text}


def _render_run_row(res: dict) -> str:
    mark = {"GREEN": "\U0001f7e2", "YELLOW": "\U0001f7e1",
            "RED": "\U0001f534"}.get(res.get("mark"), "⚪")
    when = res.get("seconds_text") or ""
    row = f"  {mark} {res['tool']:<9} {when:>8}  {res['headline']}"
    for d in res.get("details") or []:
        row += f"\n         - {d}"
    return row


def _clam_progress(clam_log: str) -> str | None:
    """Live ClamAV scan progress for the waiting display: files scanned
    so far, a percent when a previous full count exists to divide by,
    and the path being scanned right now. None means no journal."""
    base = pathlib.Path(clam_log).parent
    try:
        lines = (base / "clam-progress.txt").read_text(
            encoding="utf-8", errors="replace").splitlines()[:2]
    except OSError:
        return None
    n = 0
    try:
        n = int(lines[0])
    except (ValueError, IndexError):
        return None
    now_at = lines[1].strip() if len(lines) > 1 else ""
    if now_at == "RESIDENT":
        return ("scanning via the resident ClamAV engine (fast path; the "
                "engine reports no per-file counts)")
    if now_at.startswith("FALLBACK"):
        return ("scanning via the standalone fallback: the resident "
                "engine is down - `greywatch doctor --fix` brings it "
                "back")
    if n == 0 and now_at != "DONE":
        return "just started"
    if now_at == "DONE":
        return f"{n:,} files scanned: complete" \
            if n else "resident scan finished (no file counts reported)"
    total = None
    try:
        for ln in pathlib.Path(clam_log).with_name(
                "clam-run.log").read_text(
                encoding="utf-8", errors="replace").splitlines():
            m = re.search(r"clamscan total=(\d+)", ln)
            if m and m.group(1) != "0":
                total = int(m.group(1))
    except OSError:
        pass
    pct = f" (~{100 * n // total}% of the last full size)" \
        if total else ""
    at = f", now at {now_at}" if now_at and re.match(
        r"^Scanning ", now_at) else ""
    return f"{n:,} files scanned{pct}{at}"


def _split_digest(out: str) -> dict:
    """'# TOOL <name>' separated raw sections from the helper digest."""
    sections, cur = {}, None
    for line in (out or "").splitlines():
        m = re.match(r"# TOOL (\S+)$", line)
        if m:
            cur = m.group(1)
            sections[cur] = []
        elif cur and line.strip():
            sections[cur].append(line)
    return sections


_RUN_NEXT_STEPS = {
    "clamav": "look at the infected file paths above: move, delete or "
              "quarantine them (`greywatch log clamav` shows every row)",
    "yara": "inspect the matched files listed above (`greywatch log "
            "yara-watch` keeps their history)",
    "rkhunter": "read the warnings above, then run `greywatch log "
                "rkhunter` for their history",
}


def _run_verdict(results: list) -> str:
    if not results:
        return ("No check produced a result. Call `greywatch run` again; "
                "if it happens every time, the scans never start and the "
                "helper says why.")
    clean = [r for r in results if r["mark"] == "GREEN"]
    threats = sorted(
        (r for r in results
         if r.get("findings") and r["tool"]
         in ("yara", "clamav", "rkhunter")),
        key=lambda r: len(r.get("details") or []), reverse=True)
    others = [r for r in results if r["mark"] != "GREEN"
              and r not in threats]
    if not threats and not others:
        n, total = len(clean), len(results)
        return (f"Nothing dangerous was found: {_num(n, 'check')} of "
                f"{total} came back clean.")
    _THREAT_BASE = {"yara": "file(s) matched suspicious rules",
                    "clamav": "infected file(s) found",
                    "rkhunter": "warning(s) to look at"}
    bits = []
    for r in threats:
        label = _RUN_LABELS[r["tool"]]
        bits.append(f"PROBLEM {label}: "
                    f"{r.get('findings')} {_THREAT_BASE[r['tool']]}")
    for r in others:
        bits.append(f"{_RUN_LABELS[r['tool']]}: {r['headline']}")
    tail = ""
    if len(clean) == 1:
        tail = "; 1 check came back clean"
    elif clean:
        tail = f"; {len(clean)} checks came back clean"
    return f"Result: {'. '.join(bits)}{tail}."


def run_every_detector(runner=None, running=None):
    """The full loop: start (or attach), wait, digest, render. Returns
    (results, exit_code). runner and running are test seams."""
    if runner is None:
        runner = _run_helper_runner()
    if running is None:
        running = _scan_process_running
    boot = time.monotonic()
    state = _read_run_state()
    anything_running = any(running(t) for t in _RUN_TOOLS)
    start_epoch = float(state.get("epoch") or 0) or time.time()
    finished_run = (not anything_running and state
                    and 60.0 < time.time() - start_epoch
                    < _RUN_DONE_ATTACH_WINDOW)
    attach = anything_running or finished_run

    if attach and finished_run:
        print("The scans from the last `greywatch run` have finished; "
              "showing their results.")
    elif attach:
        print("Scans from an earlier start are still running; attaching "
              "to that run instead of starting again.")

    if not attach:
        rc, out, err = runner(["start-all"], timeout=120)
        rows = [l.strip() for l in (out or "").splitlines() if l.strip()]
        launched = [l[len("started "):] for l in rows
                    if l.startswith("started ")]
        failed = [l for l in rows if l.startswith("start-failed ")]
        other = [l for l in rows if not l.startswith(
            ("started ", "start-failed ", "STATE ", "Did not launch"))]
        if launched:
            print(f"Launched: {', '.join(launched)}.")
        if failed:
            print("Did not launch: "
                  + ", ".join(f.replace("start-failed ", "")
                              for f in failed) + ".")
        for l in other:
            print(f"  {l}")
        note = (err or "").strip()[-200:] or ("start command failed"
                                              if rc else "")
        if note:
            print(f"  the helper said: {note}")
        state = _read_run_state()
        if not state:
            m = re.search(r"^STATE (\S+)$", out or "", re.M)
            if m:
                try:
                    state = json.loads(pathlib.Path(
                        m.group(1)).read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    state = {}
    start_epoch = float(state.get("epoch") or 0) or time.time()

    # keys match what scan-now.sh writes in run-scan-state.json
    paths = {"yara": state.get("yara_log"),
             "clamav": state.get("clam_log"),
             "aide": state.get("aide_report")}
    ui = _ui_home()
    paths["yara"] = paths["yara"] or str(
        ui / "security-hardening" / "yara-scan.log")
    paths["clamav"] = paths["clamav"] or str(
        ui / "security-hardening" / "clam-scan.log")
    paths["aide"] = paths["aide"] or str(
        ui / "security-reports" / "aide" / "last-check.txt")
    offsets = {"yara": int(state.get("yara_offset", 0) or 0),
               "clamav": int(state.get("clam_offset", 0) or 0)}
    stateless_attach = attach and not state

    info = {t: {"seen": False, "done": False} for t in _RUN_TOOLS}
    results: list = []
    digest_targets: list = []
    digest_done = False
    if finished_run:
        for t in _RUN_TOOLS:
            info[t]["seen"] = True

    print("What is running now, and what each check looks for:")
    for tool in _RUN_TOOLS:
        print(f"  {_RUN_LABELS[tool]:<9} {_RUN_WHAT[tool]}")
    print()
    if attach and not finished_run:
        print("A result line prints here as each one finishes. Control-C "
              "stops the WAIT only, never the scans.")
    else:
        print("A result line prints here as each one finishes. This takes "
              "a few minutes. Control-C stops the wait only: the scans "
              "keep running and calling `greywatch run` again later "
              "prints the results.")

    def elapsed(tool: str) -> float:
        return (time.time() - start_epoch) if attach \
            else (time.monotonic() - boot)

    def emit(res: dict) -> None:
        results.append(res)
        print(_render_run_row(res))

    def finish_client(tool: str) -> None:
        info[tool]["done"] = True
        secs = elapsed(tool)
        seg = lambda p, off: _read_run_segment(pathlib.Path(p), off)  # noqa: E731
        if tool == "yara":
            # the 3-second oneshot finishes before the first poll: the
            # log's own mtime is what proves the lane ran, not pgrep
            ran_recently = _fresh_file(pathlib.Path(paths["yara"]),
                                       start_epoch)
            mark, head, det, n = _yara_result(
                seg(paths["yara"], offsets["yara"]),
                info[tool]["seen"] or finished_run or ran_recently)
        elif tool == "clamav":
            if _fresh_file(pathlib.Path(paths["clamav"]), start_epoch):
                # clamscan rewrites its log each run: a fresh file is the
                # whole result, not an append to slice
                clam_text = cli_read_whole(paths["clamav"])
                if clam_text is None:
                    clam_text = ""
            else:
                clam_text = seg(paths["clamav"], offsets["clamav"])
                if offsets["clamav"] > 0 and _fresh_file(
                        pathlib.Path(paths["clamav"]),
                        start_epoch - _RUN_ATTACH_WINDOW) and not clam_text:
                    clam_text = cli_read_whole(paths["clamav"]) or ""
            clam_text = add_clam_journal(clam_text, paths["clamav"],
                                         start_epoch)
            mark, head, det, n = _clamav_result(
                clam_text, info[tool]["seen"] or finished_run)
        else:
            apath = pathlib.Path(paths["aide"])
            fresh = _fresh_file(apath, start_epoch)
            text = ""
            if fresh or (attach and apath.exists()):
                try:
                    text = apath.read_text(
                        encoding="utf-8", errors="replace")[:200_000]
                except OSError:
                    text = ""
            mark, head, det, n = _aide_result(
                text, info[tool]["seen"] or finished_run or bool(text))
            if attach and not fresh and text:
                head = "showing the last available report (not written " \
                       "by this attach)"
                mark = "YELLOW"
        emit(_row(tool, mark, head, det, n, secs))

    def finish_root(tool: str, saw_start: bool) -> None:
        info[tool]["done"] = True
        if saw_start:
            digest_targets.append(tool)
        else:
            emit(_row(tool, "YELLOW", "did not run",
                      [_RUN_WHAT[tool] + "; the scan was never confirmed "
                       "running"],
                      0, elapsed(tool)))

    last_beat = boot
    while True:
        for tool in _RUN_TOOLS:
            st = info[tool]
            if st["done"]:
                continue
            if running(tool):
                st["seen"] = True
                continue
            if not st["seen"] and not finished_run \
                    and time.monotonic() - boot < _RUN_START_GRACE:
                continue     # still launching
            if tool in _RUN_ROOT_TOOLS:
                finish_root(tool, st["seen"] or finished_run)
            else:
                finish_client(tool)

        # timeouts for tools that were seen but never finished
        for tool in _RUN_TOOLS:
            st = info[tool]
            if st["done"] or not st["seen"]:
                continue
            if elapsed(tool) > _RUN_TIMEOUTS.get(tool, 900.0):
                st["done"] = True
                emit(_row(tool, "YELLOW",
                          f"still running after "
                          f"{_RUN_TIMEOUTS.get(tool, 900.0) / 60:.0f} min. "
                          "It keeps going in the background; call "
                          "`greywatch run` again to see the result once "
                          "it lands",
                          seconds=elapsed(tool)))

        # one digest pass once every root tool is resolved
        root_open = [t for t in _RUN_ROOT_TOOLS if not info[t]["done"]]
        if not root_open and digest_targets and not digest_done:
            digest_done = True
            if stateless_attach:
                for tool in digest_targets:
                    emit(_row(tool, "YELLOW",
                              "this result could not be read: the run was "
                              "started outside `greywatch run`, so its log "
                              "section is unknown",
                              seconds=elapsed(tool)))
            else:
                rc, out, err = runner(["digest"] + digest_targets,
                                      timeout=120)
                sections = _split_digest(out)
                no_state = "NO-STATE" in (err or "")
                for tool in digest_targets:
                    text = "\n".join(sections.get(tool, []))
                    if no_state or "REPORT-UNAVAILABLE" in text:
                        emit(_row(tool, "YELLOW",
                                  "this result could not be read from the "
                                  "root log; call `greywatch run` again "
                                  "once the check finishes",
                                  seconds=elapsed(tool)))
                    elif tool == "rkhunter":
                        mark, head, det, n = _rkhunter_result(text, True)
                        emit(_row(tool, mark, head, det, n,
                                  elapsed(tool)))
                    else:
                        mark, head, det, n = _lynis_result(text, True)
                        emit(_row(tool, mark, head, det, n,
                                  elapsed(tool)))

        remaining = [t for t in _RUN_TOOLS if not info[t]["done"]]
        if not remaining:
            break
        now_mono = time.monotonic()
        if now_mono - last_beat >= _RUN_BEAT_SECONDS and remaining:
            parts = []
            for t in remaining:
                progress = _clam_progress(paths["clamav"]) \
                    if t == "clamav" else None
                if progress and t == "clamav":
                    parts.append(f"ClamAV: {progress}")
                else:
                    parts.append(f"{_RUN_LABELS[t]} "
                                 f"({elapsed(t):.0f}s so far)")
            print(f"  ... still working: {', '.join(parts)}")
            last_beat = now_mono
        try:
            time.sleep(_RUN_POLL_SECONDS)
        except KeyboardInterrupt:
            raise

    print()
    print(_run_verdict(results))
    threats_here = [r for r in results
                    if r.get("findings") and r["tool"]
                    in ("yara", "clamav", "rkhunter")]
    if threats_here:
        print(f"  What next: {_RUN_NEXT_STEPS[threats_here[0]['tool']]}")
    elif all(r["mark"] != "GREEN" for r in results):
        pass
    elif any("did not run" in r["headline"] for r in results):
        print("  What next: call `greywatch run` again so the missing "
              "checks actually produce a result.")
    else:
        print("  What next: nothing to do. The background service reruns "
              "these checks on its own schedule; `greywatch run` checks "
              "again any time you want fresh numbers.")
    print("  Full raw output is in: yara and ClamAV under "
          f"{ui / 'security-hardening'}; the AIDE report under "
          f"{ui / 'security-reports' / 'aide' / 'last-check.txt'}; "
          "rkhunter in /var/log/rkhunter.log; Lynis in /var/log/lynis.log. "
          "Read with: greywatch log TOOL")
    # issues that need addressing are surfaced, never hidden (owner
    # 2026-11-14): the doctor's clam lane rides the run summary
    try:
        import doctor as doctor_mod
        row = doctor_mod.row_clamav(DATA_DIR)
        if row["verdict"] in ("DEGRADED", "BROKEN"):
            print(f"  Issue to address: {row['text']}.")
            print("  Run `greywatch doctor` for the full check; "
                  "`greywatch doctor --fix` applies its safe repairs.")
    except Exception:               # noqa: BLE001
        pass
    never_started = any("did not run" in r["headline"] for r in results)
    return results, EXIT_ERR if never_started else EXIT_OK


def do_run_tests() -> tuple:
    """Kept name for any external caller; the run loop is above."""
    return run_every_detector()


def cmd_baseline_apply(args) -> int:
    """The install-time contract: one command arms every detector with
    the config verified on the owner's machine (baseline-configs.json),
    through the one journaled helper, with undo. Level 4 needs you to
    mean it; levels 1-3 are the working core."""
    if getattr(args, "json", False):
        plan = baseline_apply.build_level_plan(args.level)
        if plan is None:
            print(json.dumps({"error": "unknown level"}))
            return EXIT_USAGE
        doc, what = plan
        print(json.dumps({"what": what,
                          "entries": doc["entries"]}))
        return EXIT_OK
    return baseline_apply.apply_level(args.level, getattr(args, "yes",
                                                          False))




def cmd_posture(args) -> int:
    """The security posture score and its provenance (the ring's data)."""
    from core import posture
    rep = posture.compute(baseline_rows=_baseline_verifier())
    try:
        import gwpaths
        p = gwpaths.data_dir() / "posture.json"
        old = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        old = None
    if posture.should_replace(old, rep):
        out = posture.persist(rep)
    else:
        # This context read fewer inputs than the report on file: leave
        # the wider one in place and say so (owner 2026-11-16).
        out = "the wider report on file was kept"
        print(f"  ({out}; this context could not read every input)")
    if getattr(args, "json", False):
        print(json.dumps(rep))
        return EXIT_OK
    print(posture.human(rep))
    print(f"  report: {out}")
    return EXIT_OK


def cmd_network(args) -> int:
    """The network analytics store: devices, fingerprints, flagged ips."""
    from core import netmon
    rep = netmon.build()
    out = netmon.persist(rep)
    if getattr(args, "json", False):
        print(json.dumps(rep))
        return EXIT_OK
    print(netmon.human(rep))
    print(f"  store: {out}")
    return EXIT_OK


def cmd_dnslog(args) -> int:
    """The DNS monitor store: this machine's domain lookups, blocked
    hits named against the wall's blocklist. The daemon's slow lane
    writes it (no DNS near the pump); this verb reads the store, and
    only an explicit refresh (run as root) rebuilds it from the
    resolver's query log on the spot."""
    from core import dnslog
    if getattr(args, "refresh", False):
        rep = dnslog.build()
        out = dnslog.persist(rep)
        print(f"dnslog: rebuilt from the resolver's log (the store: "
              f"{out})")
        return EXIT_OK
    try:
        import gwpaths
        store = pathlib.Path(gwpaths.data_dir()) / dnslog.STORE_NAME
    except Exception:                    # noqa: BLE001
        store = pathlib.Path("/var/lib/greywatch/dnslog.json")
    try:
        rep = json.loads(store.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        rep = None
    if rep is None:
        print("dnslog: no store on file yet - the daemon's slow lane "
              "writes it every 15 minutes (the first pass lands five "
              "minutes in). Read it again soon.")
        return EXIT_OK
    if getattr(args, "json", False):
        print(json.dumps(rep))
        return EXIT_OK
    print(dnslog.human(rep))
    return EXIT_OK


def cmd_whitelist(args) -> int:
    """The scan-finding ignore list the owner rules on: what the
    scanners may flag but this machine will not act on or report."""
    from core import scan_whitelist as W
    if args.verb == "add":
        target = (args.target or "").strip()
        reason = (args.reason or "").strip() if getattr(args, "reason", None) else ""
        ok, msg = W.add(target, reason)
        print(msg)
        return EXIT_OK if ok else EXIT_ERR
    if args.verb == "remove":
        ok, msg = W.remove((args.target or "").strip())
        print(msg)
        return EXIT_OK if ok else EXIT_ERR
    doc = W.load()
    entries = doc["entries"]
    if getattr(args, "json", False):
        print(json.dumps(entries))
        return EXIT_OK
    if not entries:
        print("the whitelist is empty: every finding reports and any real "
              "find is auto-quarantined.")
        print("Add one: greywatch whitelist add /full/path [REASON]")
        return EXIT_OK
    print(f"{len(entries)} whitelisted path(s); matching findings are "
          "ignored and never auto-quarantined:")
    for e in entries:
        kind = "subtree" if e.get("subtree") else "file"
        why = f" - {e['reason']}" if e.get("reason") else ""
        print(f"  [{kind}] {e['target']}{why}"
              f"  (added {str(e.get('added', ''))[:10]})")
    return EXIT_OK


def cmd_run(args) -> int:
    """One press of the scan desk, on the request seam: this verb files
    the request and attaches to the live session - per-scanner progress
    as it happens and the summary at the end. The resident service runs
    the scanners (no password); Ctrl-C stops the wait, never the runs,
    and a rerun attaches instead of starting a second session."""
    import time as _time
    import scan_session
    try:
        import gwpaths
        ddir = gwpaths.data_dir()
    except Exception:                      # noqa: BLE001
        ddir = DATA_DIR
    live_path = scan_session.live_path(ddir)

    def read_live():
        try:
            return json.loads(live_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    live = read_live()
    if live.get("state") != "running":
        ok, note = scan_session.write_request(
            ddir, getattr(args, "scan", None) or "full")
        if not ok:
            print(note)
            return EXIT_ERR
        if getattr(args, "json", False):
            print(json.dumps({"requested": True}))
            return EXIT_OK
        print("The run was requested; this screen and the desk track "
              "its progress (Ctrl-C stops the wait, not the scans).")
    else:
        print("A scan session is already running - attaching to it "
              "(Ctrl-C stops the wait, never the scans).")
    try:
        _attach_live(live_path, read_live)
    except KeyboardInterrupt:
        print("\nWait stopped - the scans keep running. `greywatch run` "
              "attaches again.")
        return EXIT_OK
    final = read_live()
    if getattr(args, "json", False):
        print(json.dumps(final))
    _print_run_verdict(final)
    return EXIT_OK if final.get("state") == "done" else EXIT_ERR


def cmd_scan(args) -> int:
    """Pause, resume, cancel or inspect the one scan (owner 2026-11-19).

    The same control channel the window's buttons use. One scan at a time:
    a start while another runs is refused by the service, and this verb
    never starts a second one."""
    import scan_session
    try:
        import gwpaths
        ddir = gwpaths.data_dir()
    except Exception:                      # noqa: BLE001
        ddir = DATA_DIR
    try:
        live = json.loads(scan_session.live_path(ddir).read_text(
            encoding="utf-8"))
    except (OSError, ValueError):
        live = {}
    action = args.action
    if action == "status":
        if getattr(args, "json", False):
            print(json.dumps(live))
        else:
            print(_scan_status_line(live))
        return EXIT_OK
    active = (bool(live.get("external"))
              or str(live.get("state") or "") in ("running", "paused"))
    if not active:
        print("No scan is running.")
        return EXIT_ERR
    scan_id = live.get("scan_id") if live.get("scanners") else None
    ok, note = scan_session.write_control(ddir, action, scan_id)
    if getattr(args, "json", False):
        print(json.dumps({"ok": ok, "action": action,
                          "scan_id": scan_id}))
    else:
        print(note)
    return EXIT_OK if ok else EXIT_ERR


def cmd_patch(args) -> int:
    """Install the fixed versions of the packages behind open CVE rows.

    The helper is the only thing that runs apt; this verb records the
    from/to versions in the patch ledger so the exposure drops without
    waiting for the weekly tracker refresh."""
    import cve_data
    import datetime as _dt
    try:
        import gwpaths
        ddir = gwpaths.data_dir()
    except Exception:                      # noqa: BLE001
        ddir = DATA_DIR
    entries = []
    try:
        entries = json.loads(
            (pathlib.Path(ddir) / "cve-cache.json").read_text(
                encoding="utf-8")).get("entries") or []
    except (OSError, ValueError):
        entries = []
    before = cve_data.installed_packages()
    # A package name from the cache is data, never an option: refuse
    # anything that does not match Debian's name grammar before the list
    # reaches the root helper (review I9).
    import re
    _pkg_re = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
    if getattr(args, "affected", False):
        targets = sorted({str(e.get("package")) for e in entries
                          if e.get("package")
                          and _pkg_re.fullmatch(str(e.get("package")))})
        if not targets:
            print("no affected package is on file.")
            return EXIT_ERR
        rc = helper_exec("patch-packages", targets, timeout=3600,
                         may_have_changed=True)
        after = cve_data.installed_packages()
        packages = [p for p in targets if p in after
                    and before.get(p, {}).get("version")
                    != after[p].get("version")]
    elif getattr(args, "all", False):
        targets = sorted({str(e.get("package")) for e in entries
                          if e.get("package")})
        rc = helper_exec("patch-packages", ["--all"], timeout=1800,
                         may_have_changed=True)
        after = cve_data.installed_packages()
        packages = [p for p in targets if p in after
                    and before.get(p, {}).get("version")
                    != after[p].get("version")]
    else:
        packages = list(dict.fromkeys(str(p) for p in (args.packages or [])
                                      if p))
        if not packages:
            print("name at least one package to patch, or pass --affected "
                  "or --all.")
            return EXIT_ERR
        bad = [p for p in packages if not _pkg_re.fullmatch(p)]
        if bad:
            print("invalid package name: " + ", ".join(bad))
            return EXIT_ERR
        missing = [p for p in packages if p not in before]
        if missing:
            print("not installed: " + ", ".join(missing))
            return EXIT_ERR
        rc = helper_exec("patch-packages", packages, timeout=1800,
                         may_have_changed=True)
        after = cve_data.installed_packages()
    cves = {p: [] for p in packages}
    for entry in entries:
        package, cve_id = entry.get("package"), entry.get("id")
        if package in cves and cve_id and cve_id not in cves[package]:
            cves[package].append(cve_id)
    stamp = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    rows = [{"package": p, "from": before[p].get("version", ""),
             "to": (after.get(p) or {}).get("version", ""),
             "cves": cves[p], "ts": stamp, "rc": 0 if rc == 0 else rc}
            for p in packages]
    # A partial run still changed real packages: record every version
    # movement with the run's rc, whether or not the helper finished. A
    # failed or timed-out run that changed nothing writes no row.
    write_rows = rows if rc == 0 else [r for r in rows
                                       if r["from"] != r["to"]]
    if write_rows:
        try:
            ledger = pathlib.Path(ddir) / "cve-patched.jsonl"
            with ledger.open("a", encoding="utf-8") as fh:
                for row in write_rows:
                    fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            os.chmod(ledger, 0o644)
        except OSError as e:
            print("the ledger was not written: "
                  f"{type(e).__name__}", file=sys.stderr)
    if getattr(args, "json", False):
        print(json.dumps({"rc": rc, "packages": rows}))
    else:
        for row in rows:
            print(f"{row['package']}: {row['from']} -> {row['to']}")
        if rc != 0:
            print("the package helper failed: "
                  + (helper_last_err() or "no detail"), file=sys.stderr)
    return EXIT_OK if rc == 0 else EXIT_ERR


def _scan_status_line(live: dict) -> str:
    state = str(live.get("state") or "unknown")
    parts = [f"{live.get('scan_id') or 'no run'}: {state}"]
    for key, row in (live.get("scanners") or {}).items():
        bits = f"{key} {row.get('state')}"
        if row.get("count") is not None:
            bits += (f" {row.get('count')} "
                     f"{row.get('counter_label') or ''}").rstrip()
        if row.get("percent") is not None:
            bits += f" {int(round(float(row['percent']) * 100))}%"
        parts.append(bits)
    for row in live.get("external") or []:
        parts.append(f"external {row.get('tool')} pid {row.get('pid')}")
    return " · ".join(parts)


def _attach_live(live_path, read_live) -> None:
    """Follow the live document's per-scanner rows as the service writes
    them; print what changed; return at a terminal state."""
    import time as _time
    last = {}
    while True:
        live = read_live()
        if not live:
            print("The live document is not present yet; the service "
                  "writes it the moment the session starts.")
            return
        scanners = live.get("scanners") or {}
        for key in sorted(scanners):
            row = scanners.get(key) or {}
            stamp = (str(row.get("state")), str(row.get("count")),
                     str(row.get("current") or ""))
            if last.get(key) != stamp:
                name = scan_session.SCANNER_NAMES.get(key, key)
                count = f" {row.get('count')} {row.get('counter_label') or ''}" \
                    if row.get("count") is not None else ""
                print(f"  {name}: {row.get('state')}{count}"
                      f" {str(row.get('current') or '')[:70]}".rstrip())
                last[key] = stamp
        if str(live.get("state") or "") != "running":
            return
        _time.sleep(1.0)


def _print_run_verdict(final: dict) -> None:
    print(f"Run {final.get('scan_id') or ''}: {final.get('state')}")
    for key, row in (final.get("scanners") or {}).items():
        name = scan_session.SCANNER_NAMES.get(key, key)
        detail = f" - {row.get('detail')}" if row.get("detail") else ""
        print(f"  {name}: {row.get('state')}{detail}")

def cmd_status(_args) -> int:
    snap = load_status(str(DATA_DIR / "status.json"))
    if not snap.get("tools"):
        print("greywatch: daemon has not written status yet - "
              "start `greywatch` (the unit) or wait one cycle.")
        return EXIT_OK
    pending = snapshot_pending(snap)   # gw215: the ONE published list
    if getattr(_args, "json", False):
        tools = [{"name": n, "state": i.get("state"),
                  "label": i.get("label", ""),
                  "last_event": i.get("last_event")}
                 for n, i in sorted(snap["tools"].items())]
        print(json.dumps({"updated": snap.get("updated"),
                          "dropped": snap.get("dropped", 0),
                          "pending": pending, "tools": tools}))
        return EXIT_OK
    badge = f"  ·  {pending} pending decision(s)" if pending else ""
    # : the UI prints local words ("today 14:20"), the CLI printed
    # the raw UTC ISO stamp - one clock across both surfaces.
    from core import updates
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
        # The help says "or stronger"; filter at or above the chosen rung
        # instead of exact equality.
        rank = {"INFO": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        floor = rank.get(args.severity, 0)
        evs = [e for e in evs
               if rank.get(str(e.get("severity") or "").upper(), 0) >= floor]
    if getattr(args, "json", False):
        print(json.dumps(evs[-args.last:]))
        return EXIT_OK
    for e in evs[-args.last:]:
        print(_render(e))
    return EXIT_OK


def _render(e: dict) -> str:
    mark = {"HIGH": "🔴", "CRITICAL": "🔴", "MEDIUM": "🟡", "INFO": "🟢"}
    cves = f" [{','.join(e.get('cves', []))}]" if e.get("cves") else ""
    ctl = ",".join(e.get("nist_control", []))
    # : the event line's stamp reads local words like the dashboard
    # ("today 14:20", else "Nov 04 14:20"), never a raw UTC ISO.
    from core import updates
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
    if getattr(args, "json", False):
        print(json.dumps({"pending": specs,
                          "answered": sorted(answered)}))
        return EXIT_OK
    for s in specs:
        print(f"[{s['id']}] {s['question']}")
        for o in s["options"]:
            print(f"    {o['id']:<8} {o['label']}   (helper: {o['helper']})")
    return EXIT_OK


def _published_specs() -> list[dict]:
    """The decisions the daemon itself publishes. This is the source the
    dashboard reads, and it survives an event-log truncation: the event
    file no longer holds the asks, but the daemon still knows them."""
    snap = load_status(str(DATA_DIR / "status.json"))
    rows = snap.get("pending_list")
    if rows is None:
        rows = (snap.get("defense") or {}).get("asks") or []
    out = []
    for item in rows or []:
        spec = item.get("spec") if isinstance(item, dict) else None
        if isinstance(spec, dict) and spec.get("id"):
            out.append(spec)
    return out


def _gather_specs():
    answered = pending_ids(DATA_DIR / "decisions.jsonl")
    specs, seen = [], set()
    for spec in _published_specs():
        if spec["id"] not in seen:
            seen.add(spec["id"])
            specs.append(spec)
    if specs:
        return specs, answered
    # Fallback for a daemon that has not published a list yet.
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
        why = helper_last_err() or "no detail from the helper"
        print(f"greywatch: the action did not complete (helper {opt['helper']} "
              f"exited {rc}): {why}\nThe decision is still pending. Run it as "
              f"root if the prompt cannot appear:\n  sudo "
              f"{helper_script(opt['helper'])} "
              + " ".join(str(a) for a in opt.get("args", [])),
              file=sys.stderr)
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


# Thread-local stderr of the last helper this thread ran, plus its
# formatter (shared with wiz.common - the UI lanes quote it verbatim).
_helper_ctx = threading.local()
_ERR_KEEP = 400


def helper_last_err() -> str:
    return str(getattr(_helper_ctx, "err", "") or "")


# The polkit policy pins each action to ONE exec.path, and install.sh
# writes those to the installed tree. A GUI running from the checkout
# used to pkexec the checkout's copy, which matched no action: polkit
# fell back to the generic prompt and the helper never ran (owner
# 2026-11-13: "none of the buttons even work"). Prefer the installed
# path the policy authorizes; the checkout is the source-run fallback.
LIB_DIR = pathlib.Path(os.environ.get("GREYWATCH_LIB_DIR")
                       or "/usr/lib/greywatch")


def helper_script(helper: str) -> pathlib.Path:
    """The copy of a helper the polkit policy actually authorizes."""
    installed = LIB_DIR / "apply" / f"{helper}.sh"
    if installed.exists():
        return installed
    return ROOT / "apply" / f"{helper}.sh"


def helper_exec(helper: str, args_list, timeout=180, *,
                may_have_changed=False):
    # The stderr tail rides a thread-local so UI failure text can name
    # the real reason; per-thread storage is what keeps two answers
    # running at once from quoting each other's helper.
    script = helper_script(helper)
    override = os.environ.get("GREYWATCH_HELPER_CMD")
    _helper_ctx.err = ""
    if override:
        cmd = [override, helper] + list(args_list)
    elif script.exists():
        cmd = ["pkexec", str(script)] + list(args_list)
    else:
        print(f"greywatch: helper {helper}.sh is missing from {script.parent}",
              file=sys.stderr)
        _helper_ctx.err = f"helper {helper}.sh is missing"
        return EXIT_ERR
    try:
        # A polkit prompt that nobody answers must not hang the terminal
        # forever. The scan and patch helpers get a longer budget; the
        # ordinary actions keep 180 s.
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        _helper_ctx.err = (proc.stderr or "").strip()[-_ERR_KEEP:]
        return proc.returncode
    except subprocess.TimeoutExpired:
        if may_have_changed:
            print(f"greywatch: the helper was stopped after its "
                  f"{timeout} s budget. Packages may already have "
                  f"changed; the ledger records every version that did. "
                  f"If no password window appeared, run the helper "
                  f"yourself:\n  sudo " + " ".join(cmd), file=sys.stderr)
            _helper_ctx.err = (f"stopped after {timeout} s; packages may "
                               "have changed")
        else:
            print(f"greywatch: the root prompt was not answered within "
                  f"{timeout} s, so nothing changed. If no password window "
                  f"appeared, run the helper yourself:\n  sudo "
                  + " ".join(cmd), file=sys.stderr)
            _helper_ctx.err = "the root prompt was not answered"
        return EXIT_ERR
    except OSError as exc:
        print(f"greywatch: could not run helper {helper}: {exc}" +
              ("\n  run it as root instead: sudo " + " ".join(cmd)
               if isinstance(exc, FileNotFoundError) else ""),
              file=sys.stderr)
        _helper_ctx.err = type(exc).__name__
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
    script = helper_script("batch")
    override = os.environ.get("GREYWATCH_HELPER_CMD")
    if override:
        cmd = [override, "batch", path]
    elif script.exists():
        cmd = ["pkexec", str(script), path]
    else:
        print(f"greywatch: helper batch.sh is missing from {script.parent}",
              file=sys.stderr)
        os.unlink(path)
        _helper_ctx.err = "the batch helper script is missing"
        return [-1] * len(items)
    _helper_ctx.err = ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"greywatch: could not run the batch helper: {exc}",
              file=sys.stderr)
        _helper_ctx.err = type(exc).__name__
        os.unlink(path)
        return [-1] * len(items)
    _helper_ctx.err = (proc.stderr or "").strip()[-_ERR_KEEP:]
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


def cmd_ask(args) -> int:
    """Ask the local knowledge base. Retrieval only; no model required.

    Owner 2026-11-13: the KB ships with every install but only the GUI could
    reach it, so a headless box had 988 indexed passages it could not query.
    This is the same BM25 the assistant uses, with the source named, so an
    answer can be checked instead of trusted.
    """
    from core import kb
    q = " ".join(args.question).strip()
    if args.stats:
        st = kb.stats()
        print(f"knowledge base: {st['chunks']} passages from "
              f"{len(st['sources'])} sources")
        for src, n in sorted(st["sources"].items(), key=lambda kv: -kv[1])[:20]:
            print(f"  {n:5d}  {src}")
        return EXIT_OK
    if not q:
        print("greywatch ask: give a question", file=sys.stderr)
        return EXIT_ERR
    res = kb.answer(q, k=args.passages)
    if not res["found"]:
        print(f"nothing in the knowledge base matches: {q}", file=sys.stderr)
        return EXIT_ERR
    # plain-language framing (owner): the header states what this is and
    # where the words come from; the ranked rows keep their sources so
    # an answer can be checked instead of trusted
    st = kb.stats()
    print(f"From the knowledge library ({st['chunks']} passages in "
          f"{st['sources'] and len(st['sources']) or '?'} source files), "
          f"the {len(res['passages'])} closest matches for:")
    print(f"  {q}")
    print()
    for i, p2 in enumerate(res["passages"], 1):
        print(f"{i}. {p2['source']}" + (f"  ({p2['title']})"
                                        if p2['title'] and p2['title'] != p2['source'] else ""))
        print(p2["text"].strip())
        if i < len(res["passages"]):
            print()
    return EXIT_OK


def cmd_trust(args) -> int:
    """Show or edit the auto-allow / auto-block web of trust.

    The point (owner 2026-11-13): an entry the owner already vetted should
    be an automatic YES, not a question that interrupts them, and the same
    machinery must keep known-bad entries an automatic NO.
    """
    from core.settings import TrustList
    from core import weboftrust
    tl = TrustList()
    verb = args.verb or "list"
    if verb == "seed":
        added = weboftrust.apply_to(tl)
        print(f"web of trust: {added} known-good entries added "
              f"({len(tl.allow)} total auto-allow)")
        return EXIT_OK
    if verb == "conflicts":
        both = weboftrust.conflicts(tl)
        if not both:
            print("no host is in both lists")
            return EXIT_OK
        print("in BOTH auto-allow and auto-block (the block wins, so the "
              "allow is dead weight):")
        for e in both:
            print("  !", e)
        return EXIT_OK
    if verb == "list":
        both = set(weboftrust.conflicts(tl))
        print(f"auto-allow ({len(tl.allow)}):")
        for e in sorted(tl.allow):
            print("  +", e + ("   [CONFLICT: also blocked]" if e in both else ""))
        print(f"auto-block ({len(tl.block)}):")
        for e in sorted(tl.block):
            print("  -", e)
        print(f"trusted programs ({len(tl.apps_allow)}):")
        for e in sorted(tl.apps_allow):
            print("  *", e)
        return EXIT_OK
    if verb in ("allow", "block"):
        ok = tl.add(args.entry, "allow" if verb == "allow" else "block")
        if not ok:
            print(f"greywatch trust: {args.entry!r} is not a valid entry",
                  file=sys.stderr)
            return EXIT_ERR
        print(f"{verb}: {args.entry}")
        return EXIT_OK
    if verb == "remove":
        removed = False
        for bucket in (tl.allow, tl.block, tl.apps_allow):
            if args.entry in bucket:
                bucket.discard(args.entry)
                removed = True
        tl.save()
        print(("removed " if removed else "not present ") + args.entry)
        return EXIT_OK if removed else EXIT_ERR
    print(f"greywatch trust: unknown verb {verb!r}", file=sys.stderr)
    return EXIT_ERR


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
    sub = ap.add_subparsers(dest="cmd")     # no command = the friendly sheet
    ps_ = sub.add_parser("status", help="what the suite is doing right now")
    ps_.add_argument("--json", action="store_true")
    ps_.set_defaults(fn=cmd_status)

    # The short front door: four words a person can remember.
    for _name, _cfg in TOOL_PAGES.items():
        _p = sub.add_parser(_name, help=f"{_cfg['label']}: explain and control")
        _p.add_argument("words", nargs="*",
                        help="a plain-language request, for example: "
                             "\"let firefox through\"")
        _p.add_argument("--events", type=int, default=10)
        _p.add_argument("--yes", action="store_true",
                        help="really run a state-changing step")
        _p.set_defaults(fn=cmd_page, page=_name)

    pb = sub.add_parser("baseline", help="build, show and apply: what normal looks like plus the hardening catalog")
    pb.add_argument("--json", action="store_true")
    pb.set_defaults(fn=cmd_baseline)
    pba = sub.add_parser("baseline-apply",
                         help="arm every tool with the config that works "
                              "(levels 1-4, one journaled helper pass)")
    pba.add_argument("--level", default="1", choices=["1", "2", "3", "4"])
    pba.add_argument("--yes", action="store_true",
                     help="apply through the journaled helper")
    pba.add_argument("--json", action="store_true")
    pba.set_defaults(fn=cmd_baseline_apply)

    pwl = sub.add_parser("whitelist",
                         help="the scan-finding ignore list the owner rules on")
    pwl.add_argument("verb", nargs="?", choices=["list", "add", "remove"],
                     default="list")
    pwl.add_argument("target", nargs="?", default="")
    pwl.add_argument("reason", nargs="?", default="")
    pwl.add_argument("--json", action="store_true")
    pwl.set_defaults(fn=cmd_whitelist)

    ppo = sub.add_parser("posture",
                         help="the security posture score and its inputs")
    ppo.add_argument("--json", action="store_true")
    ppo.set_defaults(fn=cmd_posture)

    pnet = sub.add_parser("network",
                          help="the network analytics store (devices, ips)")
    pnet.add_argument("--json", action="store_true")
    pnet.set_defaults(fn=cmd_network)

    ph3 = sub.add_parser("harden", help="hardening catalog: scan, plan or fix")
    ph3.add_argument("verb", nargs="?", choices=["scan", "plan", "fix"], default="scan")
    ph3.add_argument("--only")
    ph3.add_argument("--yes", action="store_true", help="apply via the pkexec helper")
    ph3.add_argument("--json", action="store_true")
    ph3.set_defaults(fn=cmd_harden)
    pv = sub.add_parser("verify", help="every tool and check in one pass")
    pv.add_argument("--json", action="store_true")
    pv.set_defaults(fn=cmd_verify)

    pup = sub.add_parser("updates", help="CVE list, definitions, blocklists, "
                                         "web of trust in one look")
    pup.add_argument("--json", action="store_true")
    pup.set_defaults(fn=cmd_updates)

    pr = sub.add_parser("run", help="file a scan request and attach to "
                                    "its live progress (the resident "
                                    "service runs it; no password)")
    pr.add_argument("--scan", default="full",
                    help="which run: full (default) or one of "
                         "yara-tmp-scan, clamav, rkhunter, lynis, aide")
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(fn=cmd_run)

    psc = sub.add_parser("scan", help="pause, resume, cancel or inspect "
                                      "the one scan (no second run can "
                                      "start beside it)")
    psc.add_argument("action",
                     choices=["status", "pause", "resume", "cancel"])
    psc.add_argument("--json", action="store_true")
    psc.set_defaults(fn=cmd_scan)

    ppt = sub.add_parser("patch", help="install the fixed versions of "
                                        "packages named by open CVE rows")
    ppt.add_argument("packages", nargs="*",
                     help="installed package names, for example openssl")
    ppt.add_argument("--all", action="store_true",
                     help="install every available package update")
    ppt.add_argument("--affected", action="store_true",
                     help="install the fixed versions of the packages "
                          "with open CVE rows")
    ppt.add_argument("--json", action="store_true")
    ppt.set_defaults(fn=cmd_patch)

    ptl = sub.add_parser("tools", help="list every monitored tool")
    ptl.set_defaults(fn=cmd_tools)

    pto = sub.add_parser("tool", help="one tool only: state, unit, its lines")
    pto.add_argument("name", help="the exact token from `greywatch tools`")
    pto.add_argument("--events", type=int, default=10,
                     help="how many recent lines (default 10)")
    pto.add_argument("--json", action="store_true")
    pto.set_defaults(fn=cmd_tool)

    ph_ = sub.add_parser("help", aliases=["commands"], help="the short list")
    ph_.add_argument("--all", action="store_true",
                     help="every command and option")
    ph_.set_defaults(fn=cmd_sheet)

    pdns = sub.add_parser("dnslog", help="the DNS monitor store: this "
                                        "machine's domain lookups, "
                                        "blocked hits named")
    pdns.add_argument("--refresh", action="store_true",
                      help="rebuild from the resolver's query log right "
                           "now (run as root)")
    pdns.add_argument("--json", action="store_true")
    pdns.set_defaults(fn=cmd_dnslog)

    pshow = sub.add_parser("show", help="what is wrong right now (status)")
    pshow.set_defaults(fn=cmd_show)

    pwhy = sub.add_parser("why", help="explain one tool and what to do")
    pwhy.add_argument("about", nargs="*", help="the tool name, or a question")
    pwhy.set_defaults(fn=cmd_why)

    pclr = sub.add_parser("clear", help="the waiting decisions: list them, "
                                        "or answer each one yourself")
    pclr.add_argument("--keep", action="store_true",
                      help="bulk: keep every quarantined file (needs --yes)")
    pclr.add_argument("--restore", action="store_true",
                      help="bulk: put every file back (needs --yes)")
    pclr.add_argument("--delete", action="store_true",
                      help="bulk: delete every file (needs --yes)")
    pclr.add_argument("--interactive", "-i", action="store_true",
                      help="walk each ask and choose keep, restore, delete")
    pclr.add_argument("--yes", action="store_true")
    pclr.set_defaults(fn=cmd_clear)

    pe = sub.add_parser("events", help="the audit trail, newest first")
    pe.add_argument("--tool", choices=sorted(t["name"] for t in load_registry()),
                    help="only one tool's rows (appfw, hunter, sentinel...)")
    pe.add_argument("--severity",
                    choices=["INFO", "MEDIUM", "HIGH", "CRITICAL"],
                    help="only rows at this severity or stronger")
    pe.add_argument("--last", type=int, default=50,
                    help="how many rows to print (default 50)")
    pe.add_argument("--json", action="store_true")
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
    pd.add_argument("--json", action="store_true")
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
    paq = sub.add_parser("ask", help="ask the local knowledge base "
                                     "(retrieval, no model needed)")
    paq.add_argument("question", nargs="*", help="the question")
    paq.add_argument("--passages", type=int, default=3,
                     help="how many passages to show (default 3)")
    paq.add_argument("--stats", action="store_true",
                     help="show what is ingested instead of answering")
    paq.set_defaults(fn=cmd_ask)

    pas = sub.add_parser("assist", help="ask the local assistant: heuristics "
                                        "and knowledge base first, no model")
    pas.add_argument("question", nargs="*", help="the question")
    pas.set_defaults(fn=cmd_assist)

    pdo = sub.add_parser("do", help="carry out a task in plain words "
                                    "(plans first; --yes runs state changes)")
    pdo.add_argument("task", nargs="*", help="the task, in plain words")
    pdo.add_argument("--yes", action="store_true",
                     help="actually run the state-changing steps")
    pdo.set_defaults(fn=cmd_do)
    ptr = sub.add_parser("trust", help="show or edit the web of trust "
                                       "(auto-allow / auto-block)")
    ptr.add_argument("verb", nargs="?",
                     choices=["list", "allow", "block", "remove",
                              "seed", "conflicts"],
                     default="list")
    ptr.add_argument("entry", nargs="?", default="",
                     help="the host or program path")
    ptr.set_defaults(fn=cmd_trust)
    pq = sub.add_parser("quarantine", help="what is in quarantine; "
                                          "expire stale ledger rows")
    pq.add_argument("verb", nargs="?", choices=["list", "prune", "junk"],
                    default="list")
    pq.add_argument("--yes", action="store_true",
                    help="for junk: really delete the test copies")
    pq.add_argument("--dry-run", action="store_true",
                    help="say what would be expired, write nothing")
    pq.add_argument("--stale-days", type=float, default=7.0,
                    help="age at which a live row expires (default 7)")
    pq.add_argument("--json", action="store_true")
    pq.set_defaults(fn=cmd_quarantine)
    return ap


def cmd_quarantine(args) -> int:
    """Show what is really in quarantine, or expire stale ledger rows.

    The ledger is append-only. `prune` appends "expired" markers for rows
    whose copy is gone, whose original was a test scratch path, or that
    are older than --stale-days; it never deletes a file or rewrites a
    line. The UI reads the same live-row view, so the tab stops showing
    580 year-old test artifacts as live threats.
    """
    import gwpaths
    import quarantine as Q
    path = gwpaths.data_dir() / "quarantine.jsonl"
    rows = Q.read_rows(path)
    if (args.verb or "list") == "list":
        live = Q.live_rows(rows)
        if getattr(args, "json", False):
            print(json.dumps({"count": len(live), "rows": live}))
            return EXIT_OK
        print(f"{len(live)} file(s) in quarantine  ({path})")
        for r in live[:20]:
            print(f"  {str(r.get('ts', ''))[:19]}  {r.get('tag', '')}  "
                  f"{r.get('orig', '')}")
        if len(live) > 20:
            print(f"  ... and {len(live) - 20} more")
        return EXIT_OK
    if (args.verb or "list") == "junk":
        # The 2026-11-14 finding: 627 of 637 quarantine rows were the test
        # suite's own scratch files. Prune only closes the ledger rows and
        # leaves the copies on disk; this removes them for real.
        junk_segs = JUNK_SEGMENTS
        live = Q.live_rows(rows)
        targets = [r for r in live
                   if any(s in str(r.get("orig") or "") for s in junk_segs)]
        copies = [r for r in targets
                  if r.get("file") and pathlib.Path(str(r["file"])).exists()]
        print(f"{len(targets)} test-artifact row(s); {len(copies)} copy(ies) "
              "still on disk")
        if not getattr(args, "yes", False):
            for r in copies[:10]:
                print(f"  would delete {r.get('file')}")
            if len(copies) > 10:
                print(f"  ... and {len(copies) - 10} more")
            print("Dry run. Add --yes to delete them and record it.")
            return EXIT_OK
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        markers, deleted, closed = [], 0, 0
        on_disk = {id(r) for r in copies}
        for r in copies:
            copy = pathlib.Path(str(r["file"]))
            try:
                copy.unlink()
            except OSError as exc:
                print(f"  could not delete {copy}: {exc}", file=sys.stderr)
                continue
            deleted += 1
            markers.append({"ts": now, "action": "deleted",
                            "orig": r.get("orig", ""),
                            "reason": "test artifact"})
        # Rows whose copy is already gone still render as live quarantine.
        # Nothing on disk can be lost, so close them too; that is what made
        # the list read as hundreds of never-ending quarantine entries.
        for r in targets:
            if id(r) in on_disk:
                continue
            closed += 1
            markers.append({"ts": now, "action": "deleted",
                            "orig": r.get("orig", ""),
                            "reason": "test artifact (copy already gone)"})
        n = Q.append_markers(path, markers) if markers else 0
        print(f"deleted {deleted} test copy(ies); closed {closed} already-gone "
              f"row(s); recorded {n} marker(s); real quarantined files were "
              "not touched")
        return EXIT_OK
    markers = Q.prune_markers(rows, stale_days=args.stale_days)
    if args.dry_run:
        print(f"would expire {len(markers)} stale ledger row(s) "
              f"(dry run; nothing written)")
    else:
        n = Q.append_markers(path, markers)
        print(f"expired {n} stale ledger row(s); nothing on disk was "
              f"deleted")
    for m in markers[:10]:
        print(f"  {m['reason']}: {m['orig']}")
    if len(markers) > 10:
        print(f"  ... and {len(markers) - 10} more")
    return EXIT_OK


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
    from core import updates
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
    rc = doctor_mod.doctor(fix=args.fix, only=args.only)
    try:
        # GW-D3: the CLI run leaves the same health truth the daemon
        # publishes, best-effort; a read-only disk skips silently and
        # the exit code is untouched.
        doctor_mod.persist_snapshot(doctor_mod.DATA_DIR,
                                    doctor_mod.health_snapshot(
                                        doctor_mod.DATA_DIR))
    except Exception:
        pass
    return rc


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


SHORT_LIST = """GREYWATCH - the short list

  greywatch                  this list
  greywatch show             what is wrong right now
  greywatch why psad         explain one tool and what to do
  greywatch clear            list the waiting decisions; change nothing
  greywatch clear -i         choose keep/restore/delete for each one
  greywatch events           the newest log lines
  greywatch run              run every detector and wait, printing each
                             tool's results as they land
  greywatch hunt             every hunting lane and its last hits
  greywatch baseline         what normal looks like per program
  greywatch harden scan      the system hardening catalog (plan/fix)
  greywatch decisions        the waiting asks, with their ids
  greywatch do "TASK"        anything else, in plain words
  greywatch help --all       every command and option

Plain-words examples that work today:

  greywatch do "restart yara-watch"
  greywatch do "prune quarantine"
  greywatch do "update the lists"
  greywatch do "why is psad red"
  greywatch do "pause psad"

Root commands are printed, never attempted:

  sudo truncate -s 0 /var/lib/greywatch/events.jsonl    clear the log
  sudo systemctl stop psad.service                      pause a protection
  sudo freshclam                                        update definitions
"""


def cmd_sheet(args) -> int:
    """The short list. This is what running `greywatch` with nothing else
    prints, so the commands are always one word away."""
    if getattr(args, "all", False):
        print(build_parser().format_help())
        return EXIT_OK
    print(SHORT_LIST)
    return EXIT_OK


def cmd_show(_args) -> int:
    """Everything that needs you in one look: the tool states, then the
    waiting notifications with the file each one is about."""
    rc = cmd_status(None)
    specs = _pending_specs()
    if specs:
        print(f"\nWaiting on you ({len(specs)}):")
        for i, spec in enumerate(specs[:8], 1):
            print(f"  {i}. {spec.get('subject') or spec.get('id')}")
            detail = str(spec.get("detail") or "").strip()
            if detail:
                print(f"     {detail[:140]}")
        if len(specs) > 8:
            print(f"  ... and {len(specs) - 8} more")
        print("  List them all: greywatch clear")
        print("  Choose per file: greywatch clear -i")
    else:
        print("\nNothing is waiting for you.")
    return rc


def cmd_why(args) -> int:
    q = " ".join(getattr(args, "about", None) or []).strip()
    return cmd_assist(argparse.Namespace(question=(q or
                                                   "what should I do first").split()))


def _answer_one(spec: dict, policy: str) -> bool:
    """Run one decision's helper and record the answer."""
    from decisions_factory import record_answer
    opts = [o for o in (spec.get("options") or []) if isinstance(o, dict)]
    opt = next((o for o in opts if o.get("id") == policy), None)
    if opt is None or not opt.get("helper"):
        print(f"  {spec.get('id')}: no '{policy}' option", file=sys.stderr)
        return False
    try:
        rc = helper_exec(opt["helper"], list(opt.get("args") or []))
        if rc != 0:
            why = helper_last_err() or "no detail"
            print(f"  {spec.get('id')}: helper {opt['helper']} exited {rc}: "
                  f"{why}\n    root fallback: sudo {helper_script(opt['helper'])} "
                  + " ".join(str(a) for a in opt.get("args") or [])
                  + "\n    the decision stays pending",
                  file=sys.stderr)
            return False
        return bool(record_answer(DATA_DIR / "decisions.jsonl",
                                  str(spec.get("id")), opt["id"]))
    except Exception as exc:                          # noqa: BLE001
        print(f"  {spec.get('id')}: {exc}", file=sys.stderr)
        return False


def _pending_specs() -> list[dict]:
    """Everything still waiting: the daemon's published list first, the
    decisions file as the fallback."""
    specs = _published_specs()
    if specs:
        return specs
    from decisions_factory import pending_spec_pairs
    return [s for s, _t in pending_spec_pairs(DATA_DIR)
            if isinstance(s, dict) and s.get("id")]


def cmd_clear(args) -> int:
    """The waiting decisions. Nothing is answered unless you say how.

    The old behaviour answered every ask with 'keep', which decided for
    the owner. Each file deserves its own choice, so the default is a
    list, --interactive walks them, and a bulk policy must be named.
    """
    specs = _pending_specs()
    if not specs:
        print("Nothing is pending.")
        return EXIT_OK
    policies = [p for p in ("keep", "restore", "delete")
                if getattr(args, p, False)]
    if len(policies) > 1:
        print("greywatch clear: pick ONE of --keep, --restore or --delete",
              file=sys.stderr)
        return EXIT_USAGE

    if getattr(args, "interactive", False):
        done = failed = 0
        total = len(specs)
        for i, spec in enumerate(specs, 1):
            print(f"\n[{i}/{total}] {spec.get('subject') or spec.get('id')}")
            detail = str(spec.get("detail") or "").strip()
            if detail:
                print(f"  {detail[:220]}")
            opts = [str(o.get("id")) for o in spec.get("options") or []
                    if isinstance(o, dict)]
            print(f"  options: {', '.join(opts)}")
            try:
                pick = input("  choose (k)eep / (r)estore / (d)elete / "
                             "(s)kip / (q)uit: ").strip().lower()
            except EOFError:
                break
            table = {"k": "keep", "r": "restore", "d": "delete"}
            if pick == "q":
                break
            if pick not in table:
                print("  skipped")
                continue
            ok = _answer_one(spec, table[pick])
            done, failed = (done + 1, failed) if ok else (done, failed + 1)
            print("  done" if ok else "  failed")
        print(f"\ndone: {done} answered, {failed} failed")
        return EXIT_OK if failed == 0 else EXIT_ERR

    if not policies:
        print(f"{len(specs)} decision(s) are waiting. Nothing has been "
              f"changed.\n")
        for i, spec in enumerate(specs, 1):
            print(f"{i}. [{spec.get('id')}] "
                  f"{spec.get('subject') or 'a quarantined file'}")
            detail = str(spec.get("detail") or "").strip()
            if detail:
                print(f"   {detail[:160]}")
            opts = [str(o.get("id")) for o in spec.get("options") or []
                    if isinstance(o, dict)]
            print(f"   options: {', '.join(opts)}")
        print("\nAnswer one:   greywatch answer ID keep|restore|delete")
        print("Walk them:    greywatch clear --interactive")
        print("One policy:   greywatch clear --keep|--restore|--delete --yes")
        return EXIT_OK

    policy = policies[0]
    print(f"Plan: answer all {len(specs)} decision(s) with '{policy}', under "
          "ONE password prompt.")
    if not getattr(args, "yes", False):
        print("Dry run. Add --yes to run it.")
        return EXIT_OK
    from decisions_factory import record_answer
    work, kept = [], []
    for spec in specs:
        opts = [o for o in (spec.get("options") or []) if isinstance(o, dict)]
        opt = next((o for o in opts if o.get("id") == policy), None)
        if opt is None or not opt.get("helper"):
            kept.append((spec, None))
            continue
        work.append((spec, opt))
        kept.append((spec, opt))
    items = [(opt["helper"], list(opt.get("args") or []))
             for _spec, opt in work]
    rcs = helper_batch(items) if items else []
    rc_by_id = {}
    for (spec, opt), rc in zip(work, rcs):
        rc_by_id[str(spec.get("id"))] = rc
    done = failed = 0
    for spec, opt in kept:
        sid = str(spec.get("id"))
        rc = rc_by_id.get(sid)
        ok = (rc == 0 and opt is not None
              and bool(record_answer(DATA_DIR / "decisions.jsonl", sid,
                                     opt["id"])))
        done, failed = (done + 1, failed) if ok else (done, failed + 1)
        print(f"  {sid}: {'done' if ok else 'failed'}")
    if failed and helper_last_err():
        print(f"last helper error: {helper_last_err()}", file=sys.stderr)
    print(f"done: {done} answered, {failed} failed")
    return EXIT_OK if failed == 0 else EXIT_ERR


def cmd_do(args) -> int:
    """Carry out a task described in plain words.

    The planner is local and deterministic (no model): it recognises the
    jobs this CLI can actually do, prints its plan, and only runs a
    state-changing step with --yes. Privileged steps are printed as the
    exact root command instead of being attempted.
    """
    task = " ".join(getattr(args, "task", None) or []).strip()
    low = task.lower()
    yes = bool(getattr(args, "yes", False))
    if not task:
        print("greywatch do: give a task, for example 'clear the decisions', "
              "'restart yara-watch', 'prune quarantine', 'why is psad red'",
              file=sys.stderr)
        return EXIT_USAGE

    # 1. The decision backlog: answer every pending ask with the safe
    # option (keep = the quarantined file stays locked away).
    if any(p in low for p in ("clear decision", "clear the decision",
                              "clear decisions", "clear the decisions",
                              "answer all", "answer the decision",
                              "answer every decision", "clear the backlog",
                              "dismiss decision", "clear these decision")):
        # Never decide for the owner. A policy must be named, or the ask
        # list is shown and the owner answers them one by one.
        policy = next((p for p in ("keep", "restore", "delete")
                       if p in low), "")
        if not policy:
            print("I will not pick for you. Run `greywatch clear` to see the "
                  "asks, `greywatch clear --interactive` to choose each one, "
                  "or name the policy: greywatch do \"clear the decisions "
                  "with delete\".")
            return EXIT_OK
        return cmd_clear(argparse.Namespace(
            keep=policy == "keep", restore=policy == "restore",
            delete=policy == "delete", interactive=False, yes=yes))

    # 1b. "test system" / "run tests": run every detector now.
    if any(w in low for w in ("test system", "run tests", "test all tools",
                              "run the tests", "run now")):
        targets, out = [], []
        # user lane: run directly
        yr = subprocess.run(["bash", str(ROOT / "apply" / "scan-now.sh"), "yara"],
                            capture_output=True, text=True, timeout=60)
        out.append(("yara", "user lane started", yr.returncode))
        # root lanes: one pkexec pass
        for tool in ("clamav", "aide", "rkhunter", "lynis"):
            script = helper_script("scan-now")
            pr = subprocess.run(["pkexec", str(script), tool],
                                capture_output=True, text=True, timeout=120)
            out.append((tool, (pr.stdout or pr.stderr or "").strip()[:80],
                        pr.returncode))
        print("Run-now across the detectors:")
        for tool, result, rc in out:
            print(f"  {tool:<10} rc={rc} {result}")
        print("Results land in: yara-scan.log, clam-scan.log, "
              "aide, /var/log/rkhunter.log, /var/log/lynis.log; "
              "read them with: greywatch log TOOL")
        return EXIT_OK if all(rc == 0 for _t, _r, rc in out) else EXIT_ERR

    # 2. Restart a user unit the CLI is allowed to touch.
    if "restart" in low:
        parts = task.split("restart", 1)[1].split()
        target = parts[0] if parts else ""
        if not target:
            print("greywatch do: name the unit to restart", file=sys.stderr)
            return EXIT_USAGE
        # A person says "yara-watch", the unit is "yara-watch.service".
        if target not in RESTART_WHITELIST:
            for suffix in (".service", ".timer"):
                if target + suffix in RESTART_WHITELIST:
                    target += suffix
                    break
        return cmd_action(argparse.Namespace(what="restart", target=target,
                                             extra=None))

    # 3. Expire stale quarantine ledger rows (never deletes a file).
    if "quarantine" in low and any(w in low for w in ("prune", "expire", "stale")):
        return cmd_quarantine(argparse.Namespace(verb="prune",
                                                 dry_run=not yes,
                                                 stale_days=7.0))

    # 4. Refresh the lists: privileged, so print the exact commands.
    if any(w in low for w in ("update the lists", "update lists",
                              "refresh the lists", "update definitions")):
        print("Run these as root:\n"
              "  sudo freshclam\n"
              "  sudo systemctl start greywatch-feeds.service")
        return EXIT_OK

    # 5. Pause / resume a protection: privileged, print the command.
    for verb in ("pause", "stop", "resume", "start"):
        if low.startswith(verb + " ") or f" {verb} " in low:
            target = task.split(verb, 1)[1].split()[0] if task.split(verb, 1)[1].split() else ""
            if target:
                act = "stop" if verb in ("pause", "stop") else "start"
                print(f"Run as root:\n  sudo systemctl {act} {target}.service")
                return EXIT_OK

    # 6. Plain questions fall through to the assistant tiers.
    if any(w in low for w in ("why", "explain", "what is", "how do i fix")):
        return cmd_assist(argparse.Namespace(question=task.split()))
    return cmd_status(None)


def cmd_assist(args) -> int:
    """Ask the local assistant from the terminal.

    The tiers answer in order: the heuristic advice engine first, then the
    plain templates, then the stored knowledge base. The GPU model is NOT
    loaded here: the tier law keeps every load on the dashboard's explicit
    switch. The printed tier line says which tier answered.
    """
    from assistant import advice, packer, templates
    from registry import load_registry

    q = " ".join(getattr(args, "question", None) or []).strip()
    snap = load_status(str(DATA_DIR / "status.json"))
    evs = _read_events()
    pack = packer.build_pack(snap, evs, q, registry=load_registry())
    tools = [str(t.get("name") or "") for t in pack.get("tools") or []]
    low = q.lower()
    hit = next((t for t in tools
                if t and (t in low or t.replace("-", " ") in low)), "")
    answer, tier = "", ""
    if any(w in low for w in ("priorit", "what needs", "what should",
                              "attention", "focus", "first")):
        answer, tier = advice.advise_priorities(pack) or "", "heuristic: priorities"
    elif any(w in low for w in ("attack", "breach", "compromis")):
        answer, tier = advice.advise_attack(pack) or "", "heuristic: attack"
    elif hit:
        answer = advice.advise_tool(pack, hit) or ""
        tier = f"heuristic: {hit}"
    elif not q or any(w in low for w in ("status", "state", "health", "doing")):
        answer, tier = templates.compose("overview", pack) or "", "template: overview"
    if not answer:
        top = (pack.get("snippets") or [])[:2]
        if top:
            answer = "From the stored references:\n" + "\n\n".join(
                f"{s.get('title', '')} ({s.get('source', '')}): "
                f"{s.get('text', '')[:500]}" for s in top)
            tier = "knowledge base"
        else:
            answer, tier = (templates.compose("overview", pack) or "",
                            "template: overview")
    print(answer or "Nothing to say yet: the daemon has not published a snapshot.")
    print(f"\n(tier: {tier or 'none'}; the local model is not loaded by the CLI)")
    return EXIT_OK


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if getattr(args, "fn", None) is None:
        return cmd_sheet(args)
    try:
        rc = args.fn(args) or EXIT_OK
        # Flush inside the guard: with a closed pipe the failure surfaces
        # here, not as an "Exception ignored" at interpreter shutdown.
        sys.stdout.flush()
        return rc
    except BrokenPipeError:
        # `greywatch decisions | head` closes stdout. Exit quietly like
        # every unix filter instead of printing a BrokenPipe traceback
        # and exiting 120.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
