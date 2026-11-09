from __future__ import annotations

import datetime as _dt
import json
import pathlib
import subprocess
import sys
import time

import setup as setup_mod
import greywatch_daemon

from registry import default_iface, load_registry

ROOT = setup_mod.ROOT
DATA_DIR = setup_mod.DATA_DIR

SAFE_USER_UNITS = {
    "yara-tmp-scan.timer", "yara-watch.service",
    "clam-scan.timer", "aide-check.timer",
}
SAFE_SYSTEM_UNITS = {           # observe-only services, no network path
    "responderd.service", "tetragon.service", "auditd.service",
    "arpwatch@" + default_iface() + ".service", "apparmor.service",
}
SAFE_TIMERS_ENABLE = {          # autostart to repair (NOT the network path)
    "greywatch-cve.timer": "system",
}


def recoverable_tools() -> list:
    return [t["name"] for t in _registry()]


def _registry():
    return load_registry()


def unit_needs_autostart(unit) -> bool:
    return unit in SAFE_TIMERS_ENABLE and subprocess.run(
        ["systemctl", "is-enabled", unit],
        capture_output=True, text=True).stdout.strip() != "enabled"


def recover(name: str) -> dict:
    done, failed = [], []
    spec = next((t for t in _registry() if t["name"] == name), None)
    if spec is None:
        return {"name": name, "ok": False, "error": "unknown tool"}

    unit = str(spec.get("unit") or "")
    if unit in SAFE_USER_UNITS:
        r = _run(["systemctl", "--user", "restart", unit])
        (done if r == 0 else failed).append(f"restart {unit} (user)")
    elif unit in SAFE_SYSTEM_UNITS:
        r = _run(["systemctl", "restart", unit])
        (done if r == 0 else failed).append(f"restart {unit} (system)")

    if name == "aide":
        db = pathlib.Path("/var/lib/aide/aide.db")
        if not db.exists():
            failed.append("aide db: rebuild needs root (greywatch-full-battery.sh step 1)")
    if name == "rkhunter":
        log = pathlib.Path("/var/log/rkhunter.log")
        if not log.exists() or log.stat().st_size == 0:
            r = subprocess.run(["pkexec", "/bin/bash", str(ROOT / "apply" / "scan-now.sh"),
                                "rkhunter"], capture_output=True, text=True)
            (done if r.returncode == 0 else failed).append(
                "rkhunter first scan via scan-now.sh" )

    if unit in SAFE_TIMERS_ENABLE:
        scope = SAFE_TIMERS_ENABLE[unit]
        extra = [] if scope == "system" else ["--user"]
        _run(["systemctl", "enable", *extra, unit])
        r = _run(["systemctl", "start", *extra, unit])
        (done if r == 0 else failed).append(f"enable+start {unit} ({scope})")

    if name == "appfw":
        from appfw import config
        cfg = config.load(DATA_DIR)
        fixed = _default_repair(cfg)
        if fixed:
            config.save(DATA_DIR, cfg)
            done.extend(fixed)

    verify = setup_mod.probe_tool(spec)
    return {"name": name, "ok": not failed, "done": done, "failed": failed,
            "verdict_after": verify["verdict"]}


def _default_repair(cfg: dict) -> list:
    # Repair strictly to the engine's own definition of "unusable"
    # (config.sanitize: a bad queue number or a non-IP exempt entry both
    # kept the nft ruleset from every arming). Owner policy - the
    # whitelist stance, fail_open, IPv6, the headless ask verdict - is
    # never rewritten here: doctor used to silently restore defaults
    # over deliberate choices while calling the damage "restored"
    # (round-3 audit R14).
    from appfw import config as appfw_config
    fixed = []
    clean = appfw_config._sanitize(dict(cfg))
    if cfg.get("nfqueue_num") != clean["nfqueue_num"]:
        cfg["nfqueue_num"] = clean["nfqueue_num"]
        fixed.append("appfw config: nfqueue_num was unusable - "
                     f"set to {clean['nfqueue_num']}")
    if cfg.get("always_exempt") != clean["always_exempt"]:
        cfg["always_exempt"] = clean["always_exempt"]
        fixed.append("appfw config: always_exempt held non-IPv4 or "
                     "drop-all entries - cleaned (broke the nft arm)")
    return fixed


def _run(argv):
    return subprocess.run(argv, capture_output=True, text=True).returncode


# ---- GW-D2/D3: the honest service rows -----------------------------------
# The doctor is only as trustworthy as its rows: every builder below may
# report READY, DEGRADED, BROKEN, or NEUTRAL - and "could not check" is
# always NEUTRAL, never green.

SERVICE_UNIT = "greywatch.service"
STALE_S = 90.0                # the dashboard's own staleness contract
BACKLOG_LIMIT = 20            # pending decisions above this is DEGRADED


def _probe(argv) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _row(lane: str, verdict: str, text: str) -> dict:
    return {"lane": lane, "verdict": verdict, "text": text,
            "ts": _now_iso()}


def _read_int_status(data_dir, key):
    """A status.json integer field, or None when unreadable/absent."""
    try:
        doc = json.loads((pathlib.Path(data_dir)
                          / "status.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    got = doc.get(key)
    return got if isinstance(got, int) else None


def row_service(data_dir) -> dict:
    """(a) the daemon's unit and the dashboard snapshot's age, with the
    same 90 s staleness contract the dashboard itself uses."""
    state = _probe(["systemctl", "is-active", SERVICE_UNIT]).stdout.strip()
    if state == "not-found":
        return _row("service", "NEUTRAL",
                    f"no {SERVICE_UNIT} unit is installed here")
    try:
        age = max(0.0, time.time() - (
            pathlib.Path(data_dir) / "status.json").stat().st_mtime)
    except OSError:
        return _row("service", "BROKEN" if state != "active" else "NEUTRAL",
                    f"the unit reads {state or 'unknown'}, but the "
                    "dashboard snapshot cannot be read as this user")
    if state != "active":
        return _row("service", "BROKEN",
                    f"{SERVICE_UNIT} reads {state}; the dashboard "
                    f"snapshot is {age:.0f} s old")
    if age > STALE_S:
        return _row("service", "DEGRADED",
                    "the unit is active, but the dashboard snapshot is "
                    f"older than {int(STALE_S)} s - waiting for the daemon")
    return _row("service", "READY",
                f"the unit is active; the dashboard snapshot is "
                f"{age:.0f} s old")


def row_scan(data_dir) -> dict:
    """(b) the GUI's scan-request channel: what is waiting for how long
    (a request the daemon has not picked up is DEGRADED, never hidden),
    and .rejected carries the malformed bytes that were moved aside."""
    req = pathlib.Path(data_dir) / "scan-request.json"
    rej = pathlib.Path(str(req) + ".rejected")
    dir_probe = pathlib.Path(data_dir) / "status.json"
    try:
        mtime = req.stat().st_mtime
    except OSError:
        try:
            dir_probe.stat()
        except OSError:
            return _row("scan", "NEUTRAL",
                        "cannot read as this user; run as root for the "
                        "full check")
        return _row("scan", "READY", "no scan request is waiting")
    age = max(0.0, time.time() - mtime)
    text = f"a scan request is on disk ({age:.0f} s old, not yet picked up)"
    if rej.exists():
        text += "; a rejected malformed request sits beside it"
    if age > STALE_S:
        return _row(
            "scan", "DEGRADED",
            f"a scan request has waited {age:.0f} s - the daemon has not"
            " picked it up yet")
    return _row("scan", "READY", text)


def row_firewall(data_dir=None) -> dict:
    """(c) the block verifier's table - only NEUTRAL 'cannot check' when
    this user cannot ask nft, never a green claim over silence."""
    try:
        r = _probe(["nft", "list", "tables"])
    except OSError:
        return _row("firewall", "NEUTRAL",
                    "nft could not run as this user")
    if r.returncode != 0:
        return _row("firewall", "NEUTRAL",
                    "cannot check the firewall as this user; run as root"
                    " for the full check")
    if "greywatch_blocks" in (r.stdout or ""):
        return _row("firewall", "READY",
                    "the greywatch blocks table is present")
    return _row("firewall", "NEUTRAL",
                "nft answered, but no greywatch blocks table is present"
                " (nothing was ever blocked)")


def row_backlog(data_dir) -> dict:
    """(d) the pending-decision backlog out of the dashboard snapshot;
    unreadable is NEUTRAL, never READY."""
    n = _read_int_status(data_dir, "pending_decisions")
    if n is None:
        try:
            (pathlib.Path(data_dir) / "status.json").stat()
        except OSError:
            return _row("backlog", "NEUTRAL",
                        "cannot read as this user; run as root for the "
                        "full check")
        return _row("backlog", "NEUTRAL",
                    "the snapshot carries no pending-decision count yet")
    if n > BACKLOG_LIMIT:
        return _row("backlog", "DEGRADED",
                    f"{n} pending decisions are waiting (above "
                    f"{BACKLOG_LIMIT})")
    return _row("backlog", "READY",
                f"{n} pending decisions" if n else "no pending decisions")


def row_ledger(data_dir) -> dict:
    """(e) the event ledger's growth policy. The audit trail is capped
    (MAX_EVENTS lines) and the daemon trims it hourly; a ledger over cap
    says so instead of growing in silence - over cap means the running
    service predates the cap or the trim stopped. Unreadable is
    NEUTRAL, never READY."""
    events = pathlib.Path(data_dir) / "events.jsonl"
    size_mb = None
    try:
        size_mb = events.stat().st_size / (1024 * 1024)
    except OSError:
        return _row("ledger", "NEUTRAL",
                    "the event ledger cannot be read as this user; run "
                    "as root for the full check")
    try:
        total = greywatch_daemon.count_lines(events)
    except OSError:
        return _row("ledger", "NEUTRAL",
                    "the event ledger could not be counted as this "
                    "user; run as root for the full check")
    cap = greywatch_daemon.MAX_EVENTS
    if total > cap:
        return _row("ledger", "DEGRADED",
                    f"the event ledger holds {total} lines "
                    f"({size_mb:.1f} MB) against its {cap} cap; the "
                    "running service either predates the cap or its "
                    "trim stopped")
    return _row("ledger", "READY",
                f"the event ledger holds {total} lines ({size_mb:.1f} MB)"
                f", within its {cap} cap")


_HEALTH_BUILDERS = (row_service, row_scan, row_firewall, row_backlog,
                    row_ledger)


def health_snapshot(data_dir) -> list:
    """GW-D3: the doctor's per-lane rows, always available. The same
    builders run inside the daemon's write_status cycle, in the CLI
    doctor, and behind --machine; a row that itself raises reports
    one NEUTRAL row and never takes the check down."""
    rows = []
    for builder in _HEALTH_BUILDERS:
        try:
            rows.append(builder(data_dir))
        except Exception as e:
            rows.append(_row(
                builder.__name__.removeprefix("row_"), "NEUTRAL",
                f"this row could not run: {type(e).__name__}"))
    return rows


def persist_snapshot(data_dir, rows, gid=None):
    """GW-D3: the last health truth on disk beside status.json (0640,
    readable by the dashboard's group) so a daemon restart - or a doctor
    run from any terminal - leaves its check behind. Best-effort: a
    read-only disk skips silently; health never DEPENDS on this file."""
    try:
        from status import write_status as _atomic
        path = pathlib.Path(data_dir) / "doctor-last.json"
        _atomic(str(path), {"ts": _now_iso(), "rows": rows}, gid=gid)
        return path
    except Exception:
        return None


HUNTER_UNIT = "greywatch-hunter.service"


def hunter_service_row(fix: bool = False) -> dict:
    """: the deb route can leave the hunter never-started while
    everything else reports healthy, so the doctor checks the service
    itself: installed, enabled, active, and stamping (its live.json
    freshness uses the dashboard's 2.5-interval rule). With --fix the
    safe repair is our own enable+restart, the same pair postinst runs.
    """
    import datetime as dt
    import json

    def _out(argv):
        return subprocess.run(argv, capture_output=True, text=True)

    enabled = _out(["systemctl", "is-enabled", HUNTER_UNIT]).stdout.strip()
    state = _out(["systemctl", "is-active", HUNTER_UNIT]).stdout.strip()
    if enabled == "not-found" or state == "not-found":
        return {"name": HUNTER_UNIT.split(".")[0], "verdict": "OFFLINE",
                "stamp": "no unit", "actions": []}
    actions: list = []
    live = pathlib.Path(DATA_DIR) / "hunter" / "live.json"
    fresh = True
    stamp = "-"
    try:
        doc = json.loads(live.read_text(encoding="utf-8"))
        when = dt.datetime.fromisoformat(str(doc.get("ts") or "")).astimezone()
        age = (dt.datetime.now().astimezone() - when).total_seconds()
        interval = 300.0
        try:
            interval = float(doc.get("interval_s") or 300.0)
        except (TypeError, ValueError):
            pass
        stamp = f"last hunt {age / 60:.0f} min ago"
        fresh = age <= max(60.0, interval * 2.5)
    except (OSError, ValueError):
        stamp = "no live stamp"
        fresh = state != "active"     # fresh check only bites a running unit
    verdict = "READY" if (enabled == "enabled" and state == "active"
                          and fresh) else ("BROKEN" if state == "active"
                                           else "OFFLINE")
    if not fresh:
        stamp += " - stale"
    if fix:
        if enabled != "enabled":
            if _out(["systemctl", "enable", HUNTER_UNIT]).returncode == 0:
                actions.append(f"enabled {HUNTER_UNIT}")
        if state != "active" or not fresh:
            if _run(["systemctl", "restart", HUNTER_UNIT]) == 0:
                actions.append(f"restarted {HUNTER_UNIT} ({stamp})")
            else:
                actions.append(f"FAILED: restart {HUNTER_UNIT}")
    return {"name": "hunter.service", "verdict": verdict, "stamp": stamp,
            "actions": actions}


def doctor(fix: bool = False, only: str | None = None,
           machine: bool = False) -> int:
    tools = [t for t in _registry() if only is None or t["name"] == only]
    rows, n_bad = [], 0
    for spec in tools:
        before = setup_mod.probe_tool(spec)
        row = {"tool": spec["name"], "before": before["verdict"],
               "after": None, "actions": None}
        if fix and (before["verdict"] == "BROKEN" or before.get("remediation")
                    or unit_needs_autostart(spec.get("unit"))):
            if before["verdict"] != "BROKEN" and not unit_needs_autostart(
                    spec.get("unit")):
                after = before["verdict"]
            else:
                res = recover(spec["name"])
                after = res["verdict_after"]
                row["actions"] = res["done"] + [("FAILED: " + f) if f else ""
                                                for f in res["failed"]]
        row["after"] = after if row.get("actions") else before["verdict"]
        if before.get("remediation") and not fix:
            row["actions"] = [f"remedy available: {r}" for r in before["remediation"]]
        if before["verdict"] == "BROKEN" and not fix:
            n_bad += 1
        rows.append(row)
    print(f"{'TOOL':<14} {'BEFORE':<8} {'AFTER':<8} ACTIONS")
    for r in rows:
        bmark = {"READY": "🟢", "OFFLINE": "⚫", "BROKEN": "🔴"}[r["before"]]
        amark = {"READY": "🟢", "OFFLINE": "⚫", "BROKEN": "🔴",
                 None: "  "}.get(r["after"], "  ")
        acts = "; ".join(a for a in (r["actions"] or []) if a) or "-"
        print(f"{r['tool']:<14} {bmark} {r['before']:<8} {amark} "
              f"{r['after'] or '':<8} {acts}")
    # : the hunter's service itself, beside the tools - the deb
    # route used to leave it dead while every tool row said READY.
    hunter = hunter_service_row(fix)
    verdict = hunter["verdict"]
    mark = {"READY": "🟢", "OFFLINE": "⚫", "BROKEN": "🔴"}[verdict]
    acts = "; ".join(a for a in hunter["actions"] if a) or "-"
    print(f"{hunter['name']:<14} {mark} {verdict:<8}   "
          f"{hunter['stamp'] or '-':<28} {acts}")
    if not fix:
        print("\nrun `greywatch doctor --fix` to apply the safe repairs")
    # GW-D2: the honest service lanes, after the tool table - a doctor
    # that can say "could not check" is worth more than one that
    # pretends. Every row degrades alone if its builder raises.
    lanes = health_snapshot(DATA_DIR)
    marks = {"READY": "🟢", "DEGRADED": "🟡", "BROKEN": "🔴",
             "NEUTRAL": "⚪"}
    print(f"\n{'LANE':<14} {'HEALTH':<9} TEXT")
    for lane in lanes:
        print(f"{lane['lane']:<14} {marks.get(lane['verdict'], '⚪')} "
              f"{lane['verdict']:<9} {lane['text']}")
    # GW-D1: the machine-readable verdict line is printed in --machine
    # mode; RED gates the exit code, YELLOW is reported, NEUTRAL checks
    # neither count (they are honest absences, not failures).
    n_red = sum(1 for r in rows
                if (r["after"] or r["before"]) == "BROKEN") + (
        1 if hunter["verdict"] == "BROKEN" else 0) + sum(
        1 for lane in lanes if lane["verdict"] == "BROKEN")
    n_yellow = sum(1 for lane in lanes if lane["verdict"] == "DEGRADED")
    if machine:
        print(f"DOCTOR {n_red} {n_yellow}")
        return 0 if n_red == 0 else 3
    return 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    sys.exit(doctor(fix="--fix" in argv, machine="--machine" in argv))
