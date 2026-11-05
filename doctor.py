from __future__ import annotations

import pathlib
import subprocess
import sys

import setup as setup_mod

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


def doctor(fix: bool = False, only: str | None = None) -> int:
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
    return 0


if __name__ == "__main__":
    sys.exit(doctor(fix="--fix" in sys.argv))
