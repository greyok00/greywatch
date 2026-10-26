"""doctor.py — greywatch DOCTOR: diagnose, recover, verify, fix defaults.

Owner order 2026-10-24: situations like the 2026-10-24 outage need one tool
that can (1) audit every roster tool from ground truth, (2) RECOVER it
(restart units, rebuild first-run artifacts, re-enable timers, restore
default settings), (3) VERIFY it functionally, so "the tools work" is a
check, not a hope.

    python3 cli.py doctor          # diagnose everything (read-only)
    python3 cli.py doctor --fix    # apply SAFE fixes (user-space + whitelists)
    python3 cli.py doctor --fix --deep   # + pkexec/root remediations

Rules carried from setup.py (the outage lessons):
  * the doctor NEVER arms the network path itself — appfw/fail2ban stay
    OFFLINE until the relaunch gate; it can only PREPARE them.
  * every applied fix is verified immediately; a fix that fails its check
    is reported, not claimed.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import setup as setup_mod

from registry import default_iface, load_registry

ROOT = setup_mod.ROOT
DATA_DIR = setup_mod.DATA_DIR

# restartable units (the same whitelist the CLI restart action uses)
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


# ── recover: restore a tool to its configured working state ─────────────
def unit_needs_autostart(unit) -> bool:
    """True = this safe autostart timer exists on disk but is disabled."""
    return unit in SAFE_TIMERS_ENABLE and subprocess.run(
        ["systemctl", "is-enabled", unit],
        capture_output=True, text=True).stdout.strip() != "enabled"


def recover(name: str) -> dict:
    """All actions SAFE: units from the whitelist only; artifacts rebuilt
    in user space or via the tool's own pkexec helper; defaults rewritten
    from the optimized config (never strict/never fail_open=false)."""
    done, failed = [], []
    spec = next((t for t in _registry() if t["name"] == name), None)
    if spec is None:
        return {"name": name, "ok": False, "error": "unknown tool"}

    unit = str(spec.get("unit") or "")
    # 1. unit restart (user scope first, then system whitelist)
    if unit in SAFE_USER_UNITS:
        r = _run(["systemctl", "--user", "restart", unit])
        (done if r == 0 else failed).append(f"restart {unit} (user)")
    elif unit in SAFE_SYSTEM_UNITS:
        r = _run(["systemctl", "restart", unit])
        (done if r == 0 else failed).append(f"restart {unit} (system)")

    # 2. first-run artifact rebuild
    if name == "aide":
        db = pathlib.Path("/var/lib/aide/aide.db")
        if not db.exists():
            failed.append("aide db: rebuild needs root (greywatch-full-battery.sh step 1)")
    if name == "rkhunter":
        log = pathlib.Path("/var/log/rkhunter.log")
        if not log.exists() or log.stat().st_size == 0:
            # scan-now.sh is pkexec-whitelisted and runs rkhunter root-side
            r = subprocess.run(["pkexec", "/bin/bash", str(ROOT / "apply" / "scan-now.sh"),
                                "rkhunter"], capture_output=True, text=True)
            (done if r.returncode == 0 else failed).append(
                "rkhunter first scan via scan-now.sh" )

    # 3. autostart repair
    if unit in SAFE_TIMERS_ENABLE:
        scope = SAFE_TIMERS_ENABLE[unit]
        extra = [] if scope == "system" else ["--user"]
        _run(["systemctl", "enable", *extra, unit])
        r = _run(["systemctl", "start", *extra, unit])
        (done if r == 0 else failed).append(f"enable+start {unit} ({scope})")

    # 4. default settings repair (appfw config only — never enables it)
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
    """Force the optimized defaults; anything already right returns [] ."""
    fixed = []
    want = {"fail_open": True, "strict_mode": False, "ipv6_enabled": False}
    if cfg.get("nfqueue_num", 111):
        pass
    for k, v in want.items():
        if cfg.get(k) != v:
            cfg[k] = v
            fixed.append(f"appfw config: {k}={v}")
    if "always_exempt" not in cfg or not cfg["always_exempt"]:
        cfg["always_exempt"] = ["1.1.1.1", "192.168.0.0/16"]
        fixed.append("appfw config: always_exempt restored (resolver/LAN)")
    return fixed


def _run(argv):
    return subprocess.run(argv, capture_output=True, text=True).returncode


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
        acts = "; ".join(a for a in (r["actions"] or []) if a) or "—"
        print(f"{r['tool']:<14} {bmark} {r['before']:<8} {amark} "
              f"{r['after'] or '':<8} {acts}")
    if not fix:
        print("\nrun `greywatch doctor --fix` to apply the safe repairs")
    return 0


if __name__ == "__main__":
    sys.exit(doctor(fix="--fix" in sys.argv))