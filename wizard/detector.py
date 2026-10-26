from __future__ import annotations

import pathlib
import shutil
from dataclasses import dataclass

from hardening.detector import CANT, FAIL, PASS, prod_runner

Result = tuple[int, str]

CANT_CHECK = CANT  # re-exported so wizard callers share the vocabulary

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
    return runner(line)


_PKG_MANAGERS = (
    ("dpkg", " -s {name}"),          # deb-family: dpkg -s pkg
    ("rpm", " -q {name}"),           # rpm-family
    ("pacman", " -Q {name}"),        # arch-family
)


def _manager_alive(runner, mgr: str) -> bool:
    try:
        rc, _ = runner(f"{mgr} --version")
    except Exception:  # noqa: BLE001
        return False
    return rc == 0


def pkg_has(name: str, runner=prod_runner) -> ProbeResult:
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
            return ProbeResult(PASS, False)
        return ProbeResult(FAIL, None, f"{mgr} query failed (rc={rc})")
    if notes:  # a manager existed but its query could not run
        return ProbeResult(CANT, None, "; ".join(notes))
    return ProbeResult(CANT, None, "no package manager found (dpkg/rpm/pacman)")


def services_running(runner=prod_runner) -> ProbeResult:
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
        if (len(parts) >= 5 and parts[0].endswith(".service")
                and parts[2] == "active" and parts[3] == "running"):
            units.append(parts[0])
    return ProbeResult(PASS, sorted(set(units)))


def listeners(runner=prod_runner) -> ProbeResult:
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


def firewall_state(runner=prod_runner) -> ProbeResult:
    facts: list[str] = []
    notes: list[str] = []
    try:
        rc, out = _run(runner, "nft list tables")
    except Exception as exc:  # noqa: BLE001 - nft unreadable, ufw still asked
        notes.append(f"nft: probe failed: {exc}")
    else:
        if rc == 0:
            facts.extend(f"nft:{t.strip()}" for t in out.splitlines() if t.strip())
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
                notes.append("ufw: rc=0 but output unparsable")
    if not facts and not ufw_ok:
        return ProbeResult(CANT, None,
                           "; ".join(notes) or "no firewall state tool available")
    state = PASS if not notes else CANT  # partial failure keeps facts, flags note
    return ProbeResult(state, facts, "; ".join(notes))


def sysctl_get(key: str, runner=prod_runner) -> ProbeResult:
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


def disk_encrypted(runner=prod_runner,
                   crypttab_path=pathlib.Path("/etc/crypttab")) -> ProbeResult:
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
    crypttab_hit = any(
        line.strip() and not line.strip().startswith("#")
        and len(line.strip().split()) >= 2
        for line in text.splitlines())
    if not lsblk_ok and not crypttab_hit and not text.strip():
        return ProbeResult(CANT, None,
                           "lsblk failed and /etc/crypttab unreadable — "
                           "encryption state unknowable")
    return ProbeResult(PASS, lsblk_hit or crypttab_hit)


def desktop_env(env=None) -> ProbeResult:
    import os
    if env is None:
        env = os.environ
    value = env.get("XDG_CURRENT_DESKTOP")
    if value is None:
        return ProbeResult(CANT, None, "XDG_CURRENT_DESKTOP is unset")
    return ProbeResult(PASS, str(value))


def form_factor(runner=prod_runner,
                power_supply_dir=pathlib.Path("/sys/class/power_supply")) -> ProbeResult:
    try:
        entries = [p.name for p in power_supply_dir.iterdir()]
    except OSError as exc:
        return _cant(exc)
    is_laptop = any(n.startswith(_BATTERY_PREFIX) for n in entries)
    return ProbeResult(PASS, is_laptop)


def disk_space(path="/",
               usage_fn=None) -> ProbeResult:
    fn = usage_fn or shutil.disk_usage
    try:
        st = fn(path)
    except Exception as exc:  # noqa: BLE001
        return _cant(exc)
    gb = 1024 ** 3
    return ProbeResult(PASS, [round(st.total / gb, 2), round(st.free / gb, 2)])
