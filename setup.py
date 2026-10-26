from __future__ import annotations

import json
import pathlib
import subprocess
import sys

from registry import load_registry

ROOT = pathlib.Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"

INTENTIONAL_OFF = {"appfw", "fail2ban", "net-watch", "cve-updater"}

def _arpwatch_iface_file() -> str:
    hits = sorted(pathlib.Path("/etc/arpwatch").glob("*.iface"))
    return str(hits[0]) if hits else "/etc/arpwatch/none.iface"


ARTIFACTS = {   # tool -> list of (label, path, required)
    "tetragon": [("policies", "/etc/tetragon/tetragon.tp.d", True)],
    "aide": [("conf", "/etc/aide/aide.conf", True),
             ("baseline-db", "/var/lib/aide/aide.db", True)],
    "yara-watch": [("rules-index", str(pathlib.Path.home() / "security-hardening"
                  / "yara-rules" / "index.yar"), True)],
    "arpwatch": [("iface-env", _arpwatch_iface_file(), False)],
    "fail2ban": [("jails", "/etc/fail2ban/jail.d", True)],
    "cve-updater": [("cache", str(DATA_DIR / "cve-cache.json"), True)],
}

ON_DEMAND = {"clamav": "on-demand (clam-scan.timer daily)",
             "freshclam": "definition refresh only",
             "lynis": "manual/scan-now.sh", "rkhunter": "manual/scan-now.sh"}


def _unit_execstart(unit: str) -> tuple:
    for extra in ([], ["--user"]):
        cat = subprocess.run(["systemctl", *extra, "cat", unit],
                             capture_output=True, text=True).stdout
        for line in cat.splitlines():
            if line.startswith("ExecStart="):
                parts = line.split("=", 1)[1].split()
                paths = [p for p in parts if p.startswith("/")]
                exe = next((p for p in paths if pathlib.Path(p).exists()), None)
                return exe, "user" if extra else "sys"
    return None, "timer"


def probe_tool(tool: dict) -> dict:
    name = tool["name"]
    unit = str(tool.get("unit") or "")
    checks, remedy = {}, []

    status = "no-unit"
    if unit:
        exe, scope = _unit_execstart(unit)
        status = _state_for(unit)
        checks["exe"] = exe or "abstract/timer"
        if "inactive" in status and not _on_demand_ok(name):
            remedy.append(f"systemctl start {unit} (idle; on-demand scans "
                          "also valid — see scan-mode notes)")
    else:
        checks["exe"] = "by-design (manual: scan-now.sh)"

    arts, required_missing = [], False
    for label, path, required in ARTIFACTS.get(name, []):
        p = pathlib.Path(path)
        try:
            ok = p.exists()
        except PermissionError:
            ok = "root-only"
        arts.append((label, ok))
        if ok is False and required:
            required_missing = True
            remedy.append(f"generate {label}: {path} "
                          "( wiz builders / aide --init )")
    if arts:
        checks["artifacts"] = arts

    if name == "ufw":
        conf = pathlib.Path("/etc/ufw/ufw.conf")
        if "ENABLED=no" in conf.read_text(errors="replace"):
            checks["firewall"] = "OFF"
            verdict = "BROKEN"
            remedy.append("ufw enable — review /etc/ufw/user.rules first "
                          "(root); highest blast-radius step on this host")
        else:
            checks["firewall"] = "ON"
            verdict = "READY"
    elif name in INTENTIONAL_OFF:
        verdict = "OFFLINE"
    elif required_missing:
        verdict = "BROKEN"
    elif unit and not status.endswith(":active") and not _on_demand_ok(name):
        verdict = "BROKEN"
    else:
        verdict = "READY"
    return {"name": name, "verdict": verdict, "checks": checks,
            "remediation": remedy}


def _state_for(unit: str) -> str:
    st = _ctl(["systemctl", "--user", "is-active", unit])
    if st == "active":
        return "user:active"
    st2 = _ctl(["systemctl", "is-active", unit])
    if st2 == "active":
        return "sys:active"
    en = _ctl(["systemctl", "is-enabled", unit])
    enu = _ctl(["systemctl", "--user", "is-enabled", unit])
    user_file = pathlib.Path.home() / ".config/systemd/user" / unit
    sys_file = pathlib.Path("/etc/systemd/system") / unit
    if enu == "enabled" or user_file.exists():
        return f"user:{enu or 'on-disk'}"
    if en in ("enabled", "static") or sys_file.exists():
        return f"sys:{en}"
    return "NOT-FOUND"


def _ctl(argv) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True).stdout.strip()
    except OSError:
        return ""


def _on_demand_ok(name: str) -> bool:
    return name in ON_DEMAND


def run() -> int:
    results = [probe_tool(t) for t in load_registry(ROOT / "registry.json")]
    order = {"BROKEN": 0, "OFFLINE": 1, "READY": 2}
    results.sort(key=lambda r: order[r["verdict"]])
    n_broken = 0
    for r in results:
        mark = {"READY": "🟢", "OFFLINE": "⚫", "BROKEN": "🔴"}[r["verdict"]]
        unit = r["checks"].get("exe", "")
        arts = " ".join(f"{lab}={'OK' if ok is True else ('root-only' if ok=='root-only' else 'MISSING')}"
                        for lab, ok in (r["checks"].get("artifacts") or []))
        mode = ON_DEMAND.get(r["name"], "")
        print(f"{mark} {r['verdict']:<8} {r['name']:<14} unit={unit} {arts} {mode}")
        for rem in r["remediation"]:
            print(f"       ↳ {rem}")
        if r["verdict"] == "BROKEN":
            n_broken += 1
    report = DATA_DIR / "setup-report.json"
    report.write_text(json.dumps(
        {"generated_by": "cli setup", "results": results}, indent=1))
    print(f"\nreport: {report}")
    print("NOTE: appfw/fail2ban/net-watch/cve-updater OFFLINE by design — "
          "arming waits on an explicit on-switch (README, App Firewall).")
    return 0


if __name__ == "__main__":
    sys.exit(run())
