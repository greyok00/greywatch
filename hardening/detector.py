from __future__ import annotations

import json
import os
import pathlib
import shlex
import shutil
import subprocess
from dataclasses import dataclass

PASS, GAP, FAIL, CANT = "PASS", "GAP", "FAIL", "CANT-CHECK"


@dataclass
class Finding:
    control_id: str
    state: str  # PASS | GAP | FAIL | CANT-CHECK
    current: str
    note: str


def _get(ctrl, key, default=None):
    if isinstance(ctrl, dict):
        if key == "probe_invert":
            key = "invert"
        return ctrl.get(key, default)
    return getattr(ctrl, key, default)


_SBIN_DIRS = ("/usr/local/sbin", "/usr/sbin", "/sbin")


def _probe_env() -> dict:
    """Scrubbed probe environment: nothing from the calling session is
    inherited except a PATH that also covers the sbin trees, where
    sysctl, nft and friends live outside a desktop user's PATH."""
    path = os.environ.get("PATH") or "/usr/bin:/bin"
    missing = [d for d in _SBIN_DIRS if d not in path.split(os.pathsep)]
    if missing:
        path = os.pathsep.join([*missing, path])
    return {"PATH": path}


def prod_runner(line: str) -> tuple[int, str]:
    parts = shlex.split(line)
    if not parts:
        return 1, "empty probe command"
    if parts[0] in ("sudo", "su", "doas", "pkexec") or "sudo" in parts:
        raise RuntimeError(f"refusing privilege escalation: {parts[0]}")
    env = _probe_env()
    if shutil.which(parts[0], path=env["PATH"]) is None:
        raise RuntimeError(
            f"probe binary not found: {parts[0]} (is it installed?)")
    # /bin/sh -c: several shipped probe lines are compound (pipes and
    # redirects). That text is this repo's own controls file, user input
    # never reaches prod_runner, and the sudo/su/doas/pkexec refusal
    # above keeps every probe unprivileged.
    proc = subprocess.run(  # noqa: S603 - repo-owned probe text only
        ["/bin/sh", "-c", line], capture_output=True, text=True,
        shell=False, timeout=10, env=env,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def _detail_text(ctrl, runner) -> str:
    """Read-only display text: the detail command's stdout, trimmed.
    A failure here is cosmetic only and must never move the state."""
    line = _get(ctrl, "detail", "") or ""
    if not line:
        return ""
    try:
        rc, out = runner(line)
    except Exception:  # noqa: BLE001 - display text is optional
        return ""
    if rc != 0:
        return ""
    return out.strip()[:400]


def scan(controls, runner=prod_runner) -> list[Finding]:
    findings: list[Finding] = []
    for ctrl in controls:
        cid = _get(ctrl, "id", "?")
        probe = _get(ctrl, "probe", "")
        invert = bool(_get(ctrl, "probe_invert", False))
        try:
            rc, out = runner(probe)
        except Exception as exc:  # noqa: BLE001 - honesty over crash
            findings.append(Finding(cid, CANT, "", f"probe failed: {exc}"))
            continue
        current = _detail_text(ctrl, runner) or out.strip()
        if rc != 0:
            if not invert and rc >= 2:
                findings.append(Finding(
                    cid, FAIL, current,
                    "the check itself failed (rc=%d) — no baseline "
                    "comparison was possible" % rc))
                continue
            findings.append(Finding(cid, GAP if not invert else PASS,
                                    current, ""))
            continue
        findings.append(Finding(cid, GAP if invert else PASS,
                                current, ""))
    return findings


_NIST_MAP_PATH = pathlib.Path(__file__).resolve().parent.parent / "nist-map.json"
_NOTE_MAX = 3  # the card is a hint, not a CVE dump


_NIST_MAP_CACHE: dict | None = None


def _nist_controls() -> dict:
    global _NIST_MAP_CACHE
    if _NIST_MAP_CACHE is not None:
        return _NIST_MAP_CACHE
    try:
        _NIST_MAP_CACHE = json.loads(
            _NIST_MAP_PATH.read_text(encoding="utf-8")
        ).get("nist_defaults") or {}
    except (OSError, ValueError):
        _NIST_MAP_CACHE = {}
    return _NIST_MAP_CACHE


def cve_note(control_id: str, cache: dict) -> str:
    if not control_id or not isinstance(cache, dict):
        return ""
    entries = cache.get("entries")
    if not isinstance(entries, list):
        return ""
    nist_map = _nist_controls()
    hits = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("id"):
            continue
        controls = set(entry.get("nist") or [])
        for tool in entry.get("tools") or []:
            controls |= set((nist_map.get(tool) or {}).get("controls") or [])
        if control_id in controls:
            hits.append(entry)
    if not hits:
        return ""
    def _modified(entry):
        return str(entry.get("modified") or "")
    hits.sort(key=_modified, reverse=True)
    shown = ", ".join(
        f"{e['id']} ({_modified(e)[:10]})" if _modified(e) else str(e["id"])
        for e in hits[:_NOTE_MAX]
    )
    return f"Relevant CVEs on record: {shown}"
