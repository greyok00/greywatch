# wizard/detector.py — Setup Wizard system-inventory probes.
# stdlib only. Reuses hardening.detector's runner-injection machinery and
# prod_runner (user-context, refuses privilege escalation) rather than
# duplicating it. Every probe is user-context and PATH-safe; every probe
# returns a ProbeResult whose value is a boolean, a list of scalar strings,
# or (for sysctl) a single scalar string — never freeform dumps.
#
# Honesty rule (carried from hardening.detector): a probe that cannot run
# yields CANT-CHECK, never a silent PASS or a fabricated default.
#
# Identifier rule: NO hardware identifiers leave these probes. Battery
# detection reports only "a battery is present" (laptop fact, boolean).
# Listener parsing keeps PORTS only — ss is called without -p, and no
# pids/process names/usernames are stored even if the tool printed them.
from __future__ import annotations

import pathlib
import shutil
from dataclasses import dataclass

from hardening.detector import CANT, FAIL, PASS, prod_runner

Result = tuple[int, str]

CANT_CHECK = CANT  # re-exported so wizard callers share the vocabulary

# What a battery directory looks like in /sys/class/power_supply (the
# BAT prefix is the kernel convention; no serial/uuid/MAC is ever read).
_BATTERY_PREFIX = "BAT"

_NO_PORT = 0  # ports are >= 1; 0 means "discard this token"


@dataclass
class ProbeResult:
    state: str  # PASS | FAIL | CANT-CHECK
    value: object = None  # bool | list[str] | list[int] | str | None
    note: str = ""


def _cant(exc):  # noqa: ANN001
    return ProbeResult(CANT, None, f"probe failed: {exc}")


def _run(runner, line: str) -> Result:
    """Run one probe line through the injected runner (shlex-safe args)."""
    return runner(line)


# ── package manager probes ──────────────────────────────────────────────
_PKG_MANAGERS = (
    ("dpkg", " -s {name}"),          # deb-family: dpkg -s pkg
    ("rpm", " -q {name}"),           # rpm-family
    ("pacman", " -Q {name}"),        # arch-family
)


def _manager_alive(runner, mgr: str) -> bool:
    """A manager is present when its version check runs (rc==0)."""
    try:
        rc, _ = runner(f"{mgr} --version")
    except Exception:  # noqa: BLE001
        return False
    return rc == 0


def pkg_has(name: str, runner=prod_runner) -> ProbeResult:
    """Is `name` installed? dpkg -s -> rpm -q -> pacman -Q fallback chain.

    True when any installed-state check succeeds (rc==0); False when a
    manager exists and reports the package absent; CANT-CHECK when no
    package manager is available or the query itself misfires. Only the
    boolean survives — command output is discarded.
    """
    pkg = str(name).strip()
    if not pkg or any(c in pkg for c in " \t\n\r;`$&|<>?!'\"%,/"):
        return ProbeResult(FAIL, None, "empty or malformed package name")
    notes: list[str] = []
    for mgr, tmpl in _PKG_MANAGERS:
        if not _manager_alive(runner, mgr):
            continue
        try:
            rc, _ = runner((mgr + tmpl.format(name=pkg)).strip())
        except Exception as exc:  # noqa: BLE001 - keep note, continue chain
            notes.append(f"{mgr}: probe failed: {exc}")
            continue
        if rc == 0:
            return ProbeResult(PASS, True)
        if rc == 1:
            # rc==1 is the manager's "not installed" outcome.
            return ProbeResult(PASS, False)
        return ProbeResult(FAIL, None, f"{mgr} query failed (rc={rc})")
    if notes:  # a manager existed but its query could not run
        return ProbeResult(CANT, None, "; ".join(notes))
    return ProbeResult(CANT, None, "no package manager found (dpkg/rpm/pacman)")


# ── systemd services ────────────────────────────────────────────────────
def services_running(runner=prod_runner) -> ProbeResult:
    """Running service unit names from `systemctl list-units
    --type=service --state=running --no-pager`.

    Extracts only the first column (unit names ending in .service) from
    plain listing lines. No pids, descriptions or cgroup paths are kept.
    """
    line = "systemctl list-units --type=service --state=running --no-pager"
    try:
        rc, out = _run(runner, line)
    except Exception as exc:  # noqa: BLE001
        return _cant(exc)
    if rc != 0:
        return ProbeResult(CANT, None, f"systemctl failed (rc={rc})")
    units = []
    for raw in out.splitlines():
        parts = raw.split()
        # Row shape: UNIT LOAD ACTIVE SUB DESCRIPTION[...]. The ACTIVE
        # (parts[2]) and SUB (parts[3]) columns say "active running".
        if (len(parts) >= 5 and parts[0].endswith(".service")
                and parts[2] == "active" and parts[3] == "running"):
            units.append(parts[0])
    return ProbeResult(PASS, sorted(set(units)))


# ── network listeners (ports only) ──────────────────────────────────────
def listeners(runner=prod_runner) -> ProbeResult:
    """Listening ports from `ss -tuln` — PORTS ONLY.

    The probe invokes ss WITHOUT -p (no process info is ever requested)
    and parsing stores only the numeric port of the local address. If the
    tool ever printed pids/names they are never parsed or retained.
    """
    try:
        rc, out = _run(runner, "ss -tuln")
    except Exception as exc:  # noqa: BLE001
        return _cant(exc)
    if rc != 0:
        return ProbeResult(CANT, None, f"ss failed (rc={rc})")
    ports = set()
    for raw in out.splitlines():
        cols = raw.split()
        if len(cols) < 5 or cols[0] in ("State", "Netid"):
            continue
        # Local Address:Port is the 5th column; IPv6 "[::]:22" still splits
        # cleanly on the FINAL colon.
        port = _safe_port(cols[4].rpartition(":")[2])
        if port:
            ports.add(port)
    return ProbeResult(PASS, sorted(ports))


def _safe_port(tok: str) -> int:
    try:
        p = int(tok)
    except ValueError:
        return _NO_PORT
    return p if 1 <= p <= 65535 else _NO_PORT


# ── firewall state ──────────────────────────────────────────────────────
def firewall_state(runner=prod_runner) -> ProbeResult:
    """Firewall posture as scalar strings: nft table names that exist and
    ufw's status word. Only names/words — never rules dumps or counters.
    """
    facts: list[str] = []
    notes: list[str] = []
    try:
        rc, out = _run(runner, "nft list tables")
    except Exception as exc:  # noqa: BLE001 - nft unreadable, ufw still asked
        notes.append(f"nft: probe failed: {exc}")
    else:
        if rc == 0:
            facts.extend(f"nft:{t.strip()}" for t in out.splitlines() if t.strip())
        # nft absent (rc!=0) is tolerated: ufw may still answer.
    ufw_ok = False
    try:
        rc, out = _run(runner, "ufw status")
    except Exception as exc:  # noqa: BLE001 - keep nft facts, note the miss
        notes.append(f"ufw: probe failed: {exc}")
    else:
        if rc == 0:
            if out.strip().startswith("Status:"):
                facts.append(f"ufw:{out.split(':', 1)[1].strip().lower()}")
                ufw_ok = True
            else:
                # rc==0 but unparsable output: honesty beats silence.
                notes.append("ufw: rc=0 but output unparsable")
        # ufw absent (rc!=0) is tolerated.
    if not facts and not ufw_ok:
        # No firewall tooling answered — posture is unknowable, not "none".
        return ProbeResult(CANT, None,
                           "; ".join(notes) or "no firewall state tool available")
    state = PASS if not notes else CANT  # partial failure keeps facts, flags note
    return ProbeResult(state, facts, "; ".join(notes))


# ── sysctl ──────────────────────────────────────────────────────────────
def sysctl_get(key: str, runner=prod_runner) -> ProbeResult:
    """One scalar sysctl value via `sysctl -n <key>`, validated key name."""
    if not key or not key.replace(".", "").replace("-", "").replace("_", "").isalnum() \
            or " " in key or key != key.strip():
        return ProbeResult(FAIL, None, "malformed sysctl key")
    try:
        rc, out = _run(runner, f"sysctl -n {key}")
    except Exception as exc:  # noqa: BLE001
        return _cant(exc)
    if rc != 0:
        return ProbeResult(CANT, None, f"sysctl read failed (rc={rc})")
    return ProbeResult(PASS, out.strip().splitlines()[0].strip() if out.strip() else "")


# ── disk encryption ─────────────────────────────────────────────────────
def disk_encrypted(runner=prod_runner,
                   crypttab_path=pathlib.Path("/etc/crypttab")) -> ProbeResult:
    """Is the disk encrypted? BOOLEAN ONLY.

    Keyed on the lsblk TYPE column (`lsblk -o TYPE` is used so mountpoint
    or label text like /data/crypto-backup can never trigger a false
    hit): true only when a trimmed row equals 'crypt'. /etc/crypttab being
    readable and non-empty also counts. No device names, uuids or mapping
    labels are returned — output is discarded after the check.
    """
    lsblk_ok = lsblk_hit = False
    try:
        rc, out = _run(runner, "lsblk -o TYPE")
    except Exception:  # noqa: BLE001 - lsblk failure falls back to crypttab
        rc, out = 1, ""
    if rc == 0:
        lsblk_ok = True
        lsblk_hit = any(line.strip().lower() == "crypt"
                        for line in (out or "").splitlines())
    try:
        text = crypttab_path.read_text(encoding="utf-8")
    except OSError:
        text = ""
    # A real mapping line is `name device [secret] [options]`. Fedora ships
    # a comments-only sample crypttab — comments/blank lines are NOT
    # encrypted volumes (the false "this disk is encrypted" bug). Only
    # lines with an ID and a device count.
    crypttab_hit = any(
        line.strip() and not line.strip().startswith("#")
        and len(line.strip().split()) >= 2
        for line in text.splitlines())
    if not lsblk_ok and not crypttab_hit and not text.strip():
        return ProbeResult(CANT, None,
                           "lsblk failed and /etc/crypttab unreadable — "
                           "encryption state unknowable")
    return ProbeResult(PASS, lsblk_hit or crypttab_hit)


# ── desktop environment ─────────────────────────────────────────────────
def desktop_env(env=None) -> ProbeResult:
    """XDG_CURRENT_DESKTOP as a scalar string (injectable for tests).

    The variable being UNSET is honest CANT-CHECK (the session may not be
    a graphical one); a set-but-empty value still passes as "".
    """
    import os
    if env is None:
        env = os.environ
    value = env.get("XDG_CURRENT_DESKTOP")
    if value is None:
        return ProbeResult(CANT, None, "XDG_CURRENT_DESKTOP is unset")
    return ProbeResult(PASS, str(value))


# ── form factor (laptop fact, identifiers-free) ─────────────────────────
def form_factor(runner=prod_runner,
                power_supply_dir=pathlib.Path("/sys/class/power_supply")) -> ProbeResult:
    """Laptop fact via battery-directory PRESENCE only.

    True when any entry name in /sys/class/power_supply starts with 'BAT'
    (a boolean fact — the directory listing itself is never returned, so
    no serial/manufacturer/model strings can leak).
    """
    try:
        entries = [p.name for p in power_supply_dir.iterdir()]
    except OSError as exc:
        return _cant(exc)
    is_laptop = any(n.startswith(_BATTERY_PREFIX) for n in entries)
    return ProbeResult(PASS, is_laptop)


# ── disk space for backup planning ──────────────────────────────────────
def disk_space(path="/",
               usage_fn=None) -> ProbeResult:
    """[total_gb, free_gb] via shutil.disk_usage — sizes, not device names.

    Returned as a LIST (not a tuple) so every probe value stays in the
    boolean-or-list shape the schema guarantees.
    """
    fn = usage_fn or shutil.disk_usage
    try:
        st = fn(path)
    except Exception as exc:  # noqa: BLE001
        return _cant(exc)
    gb = 1024 ** 3
    return ProbeResult(PASS, [round(st.total / gb, 2), round(st.free / gb, 2)])
