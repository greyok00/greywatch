# hardening/detector.py — probe execution and PASS/GAP/FAIL/CANT-CHECK mapping.
# stdlib only. The runner is injected so tests never touch a real shell.
# Honesty rule: a probe that cannot run is CANT-CHECK, never a silent PASS.
from __future__ import annotations

import json
import pathlib
import shlex
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
    """Read a field from either a Control dataclass or a plain dict."""
    if isinstance(ctrl, dict):
        if key == "probe_invert":
            key = "invert"
        return ctrl.get(key, default)
    return getattr(ctrl, key, default)


def prod_runner(line: str) -> tuple[int, str]:
    """Run `line` as the calling (user-context) process — never sudo/root.

    Raises RuntimeError if an escalation is requested, which scan() maps to
    CANT-CHECK. A command that simply fails returns (rc, output) normally.
    """
    parts = shlex.split(line)
    if not parts:
        return 1, "empty probe command"
    if parts[0] in ("sudo", "su", "doas", "pkexec") or "sudo" in parts:
        raise RuntimeError(f"refusing privilege escalation: {parts[0]}")
    proc = subprocess.run(  # noqa: S603 - argv list, no shell
        parts, capture_output=True, text=True, shell=False, timeout=10,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def scan(controls, runner=prod_runner) -> list[Finding]:
    """Evaluate each control's probe via the injected runner.

    Mapping (the state machine's vocabulary):
    - rc==0 -> PASS (GAP when the probe is inverted: rc!=0 means fixed).
    - rc==1 -> GAP (PASS when inverted). rc==1 is the standard
      "condition false" outcome of the grep/test-style probes, i.e. a
      REAL baseline comparison succeeded and the baseline is not met,
      and a nonzero inverted probe is the compliant half of the same
      comparison — so FAIL is deliberately not entered for it.
    - rc>=2 on a non-inverted probe -> FAIL: the check itself misfired
      (probe crashed, syntax error, missing tool) and no sensible
      baseline comparison is possible this time.
    - rc!=0 on an INVERTED probe stays inside PASS/GAP whatever the
      magnitude: for an inverted probe nonzero IS the good outcome, so
      a high code is still a verdict, not a probe failure.
    - any runner exception -> CANT-CHECK with the error as note (a
      probe that could not run is never a silent PASS).
    """
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
        if rc != 0:
            if not invert and rc >= 2:
                findings.append(Finding(
                    cid, FAIL, out.strip(),
                    "the check itself failed (rc=%d) — no baseline "
                    "comparison was possible" % rc))
                continue
            # rc!=0 with a normal non-inverted probe: not at baseline.
            # rc!=0 with an inverted probe: compliant (see docstring).
            findings.append(Finding(cid, GAP if not invert else PASS,
                                    out.strip(), ""))
            continue
        findings.append(Finding(cid, GAP if invert else PASS,
                                out.strip(), ""))
    return findings


# ── display-only CVE context ────────────────────────────────────────────
# The daemon's weekly cache (data/cve-cache.json) is consulted for what is
# already on record; cve_note() NEVER invents fixes or dates. The NIST
# linkage comes from nist-map.json (tool -> controls), so a cache entry
# carrying `tools` resolves to the controls that tool is mapped to.
_NIST_MAP_PATH = pathlib.Path(__file__).resolve().parent.parent / "nist-map.json"
_NOTE_MAX = 3  # the card is a hint, not a CVE dump


_NIST_MAP_CACHE: dict | None = None


def _nist_controls() -> dict:
    """Tool -> {func, controls} from nist-map.json; {} when unreadable.

    Parsed once at module level and cached: the map is static for the
    process lifetime and every card render would otherwise re-read it.
    """
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
    """Return a short display-only note naming CVEs relevant to a control.

    An entry applies when it carries `nist` control ids matching the
    control, or tool names whose nist-map.json controls include it. The
    newest entries are kept (cap _NOTE_MAX). Returns "" when the cache is
    empty/malformed or nothing applies — and never suggests fixes.
    """
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
