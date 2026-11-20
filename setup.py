from __future__ import annotations

import json
import pathlib
import subprocess
import sys

from registry import load_registry

ROOT = pathlib.Path(__file__).resolve().parent
from gwpaths import data_dir as _gw_data
DATA_DIR = _gw_data()

# appfw / net-watch / cve-updater run INSIDE the greywatch daemon, so a
# unit probe means nothing for them: the dashboard snapshot is their
# truth. fail2ban has a real unit and a real known gap, so it gets
# probed and repaired like every other tool (owner 2026-11-14).
INTENTIONAL_OFF = {"appfw", "net-watch", "cve-updater"}

def _arpwatch_iface_file() -> str:
    hits = sorted(pathlib.Path("/etc/arpwatch").glob("*.iface"))
    return str(hits[0]) if hits else "/etc/arpwatch/none.iface"


def _ui_home():
    """The desktop user's home tree. Running the tool with sudo must not
    turn every path into /root (that is what made yara-watch read
    BROKEN under `sudo greywatch doctor`, owner 2026-11-14)."""
    try:
        import pwd
        import gwpaths
        return pathlib.Path(pwd.getpwnam(gwpaths.ui_user()).pw_dir)
    except Exception:
        return pathlib.Path.home()


ARTIFACTS = {   # tool -> list of (label, path, required)
    "tetragon": [("policies", "/etc/tetragon/tetragon.tp.d", True)],
    "aide": [("conf", "/etc/aide/aide.conf", True),
             ("baseline-db", "/var/lib/aide/aide.db", True)],
    "yara-watch": [("rules-index", str(_ui_home() / "security-hardening"
                  / "yara-rules" / "index.yar"), True)],
    "arpwatch": [("iface-env", _arpwatch_iface_file(), False)],
    "fail2ban": [("jails", "/etc/fail2ban/jail.d", True)],
    "cve-updater": [("cache", str(DATA_DIR / "cve-cache.json"), True)],
}

ON_DEMAND = {"clamav": "on-demand (started from the desk or CLI; automatic scans off)",
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


def _dashboard_state(name: str) -> str:
    """A tool's state from the daemon-written snapshot, or ''."""
    try:
        snap = json.loads((pathlib.Path(str(DATA_DIR))
                           / "status.json").read_text(encoding="utf-8"))
        info = (snap.get("tools") or {}).get(name) or {}
        return str(info.get("state") or "")
    except (OSError, ValueError, AttributeError):
        return ""


def probe_tool(tool: dict) -> dict:
    name = tool["name"]
    unit = str(tool.get("unit") or "")
    checks, remedy = {}, []

    status = "no-unit"
    if unit:
        exe, scope = _unit_execstart(unit)
        status = _state_for(unit)
        checks["exe"] = exe or "abstract/timer"
        if name == "fail2ban" and "inactive" in status:
            remedy.append("arm the sshd jail (writes /etc/fail2ban/"
                          "jail.d/sshd.local, backend=systemd): "
                          "greywatch doctor --fix")
        if "inactive" in status and not _on_demand_ok(name):
            remedy.append(f"systemctl start {unit} (idle; on-demand scans "
                          "also valid - see scan-mode notes)")
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
            remedy.append("ufw enable - review /etc/ufw/user.rules first "
                          "(root); highest blast-radius step on this host")
        else:
            checks["firewall"] = "ON"
            verdict = "READY"
    elif name == "fail2ban" and unit:
        # owner 2026-11-14: a running fail2ban with no armed jail is
        # still the gap; the service state alone lies about it.
        armed = (pathlib.Path("/etc/fail2ban/jail.local").exists()
                 or pathlib.Path("/etc/fail2ban/jail.d/sshd.local").exists())
        if "inactive" in status:
            verdict = "BROKEN"
            remedy.append("arm the sshd jail (writes /etc/fail2ban/"
                          "jail.d/sshd.local, backend=systemd): "
                          "greywatch doctor --fix")
        elif not armed:
            verdict = "BROKEN"
            checks["jail"] = "no armed sshd jail"
            remedy.append("arm the sshd jail (writes /etc/fail2ban/"
                          "jail.d/sshd.local, backend=systemd): "
                          "greywatch doctor --fix")
        else:
            verdict = "READY"
            checks["jail"] = "sshd jail armed"
    elif name in INTENTIONAL_OFF:
        dash = _dashboard_state(name)
        if dash == "GREEN":
            verdict = "READY"
            checks["lane"] = "green inside the greywatch daemon"
        elif dash == "RED":
            verdict = "BROKEN"
            checks["lane"] = "red inside the greywatch daemon"
        else:
            verdict = "OFFLINE"
            checks["lane"] = ("no state from the daemon yet "
                              "(is greywatch running?)")
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
    user_file = _ui_home() / ".config/systemd/user" / unit
    sys_file = pathlib.Path("/etc/systemd/system") / unit
    if enu == "enabled" or user_file.exists():
        return f"user:{enu or 'on-disk'}"
    if en in ("enabled", "static") or sys_file.exists():
        return f"sys:{en}"
    return "NOT-FOUND"


def _ctl(argv) -> str:
    """Unit probes work from BOTH contexts: as root, user-manager
    commands (--user) must hop into the desktop user's manager, or the
    probe reports NOT-FOUND and every user-unit tool reads BROKEN (seen
    live 2026-11-14 under `sudo greywatch doctor`)."""
    try:
        import os
        if os.geteuid() == 0 and "--user" in argv:
            ui_user = None
            try:
                import gwpaths
                ui_user = gwpaths.ui_user()
            except Exception:
                ui_user = None
            ui_user = ui_user or "grey"
            import pwd
            uid = pwd.getpwnam(ui_user).pw_uid
            argv = (["runuser", "-u", ui_user, "--", "env",
                     f"XDG_RUNTIME_DIR=/run/user/{uid}",
                     f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"]
                    + list(argv))
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
    print("NOTE: appfw/fail2ban/net-watch/cve-updater OFFLINE by design - "
          "arming waits on an explicit on-switch (README, App Firewall).")
    return 0


if __name__ == "__main__":
    sys.exit(run())
