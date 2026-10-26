#!/usr/bin/env python3
"""W2 — Fail2ban wizard (plan 147): pattern → REAL sample lines → live regex
check → jail defaults 3600/600/3 → preview → apply (f2b-write helper) →
verify (`fail2ban-client status <jail>`) → rollback (backups + reload)."""
from rules import fail2ban_jail, fail2ban_filter, ValidationError
from wiz import common


def build(jail, logpath, pattern, bantime=3600, findtime=600, maxretry=3,
          filter_name=None):
    filter_name = filter_name or jail
    jail_lines = fail2ban_jail(jail, bantime, findtime, maxretry, logpath, filter_name)
    filter_lines = fail2ban_filter(pattern) if pattern else None
    return {"jail": jail_lines, "filter": filter_lines,
            "paths": {"jail": f"/etc/fail2ban/jail.d/{jail}.local",
                      "filter": f"/etc/fail2ban/filter.d/{filter_name}.conf"}}


def test_regex(pattern, sample_lines):
    """Live-regex gate: the pattern must match at least one REAL sample.
    <HOST> is a fail2ban placeholder, not regex — expand it first so the
    gate tests the pattern a jail will actually see (battery 2026-10-24)."""
    import re
    rx = re.compile(pattern.replace("<HOST>",
        r"(?P<host>[0-9]{1,3}(?:\.[0-9]{1,3}){3})"))
    return any(rx.search(l) for l in sample_lines)


def apply(build_dict):
    jail = build_dict["jail"][0][1:-1]               # strip [ ]
    filter_name = build_dict["jail"][2].split("=", 1)[1].strip()
    logpath = build_dict["jail"][3].split("=", 1)[1].strip()
    maxretry = build_dict["jail"][4].split("=", 1)[1].strip()
    findtime = build_dict["jail"][5].split("=", 1)[1].strip()
    bantime = build_dict["jail"][6].split("=", 1)[1].strip()
    regex = (build_dict["filter"] or ["failregex =  "])[0] \
        .split("=", 1)[1].strip().lstrip("^").rstrip("$")
    argv = [jail, logpath, maxretry, findtime, bantime, filter_name, regex]
    return common.run_helper("f2b-write", argv)


def verify(jail):
    import subprocess
    try:
        out = subprocess.run(["fail2ban-client", "status", jail],
                             capture_output=True, text=True, timeout=10)
        return out.returncode == 0
    except OSError:
        return False


def rollback(build_dict):
    """Restore the .bak jail/filter file and reload."""
    ok = common.restore_backup(build_dict["paths"]["jail"] + ".bak",
                               build_dict["paths"]["jail"])
    if build_dict["filter"]:
        ok = common.restore_backup(build_dict["paths"]["filter"] + ".bak",
                                   build_dict["paths"]["filter"]) and ok
    import subprocess
    try:
        subprocess.run(["fail2ban-client", "-x", "reload"],
                       capture_output=True, timeout=30)
    except OSError:
        pass
    return ok
