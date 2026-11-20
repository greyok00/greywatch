"""The security posture score (owner 2026-11-15: one number, proven
with its own provenance).

Four inputs, each normalised to 0-100, combined by fixed weights into
one score, per the research pattern (guides/2026-11-15, the unified
aggregator): no input pretends, an unreadable input drops out and the
weights renormalise over the known ones, and the report names what fed
every number so any reader can check the maths.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re

WEIGHTS = {
    "lynis_hardening": 0.35,
    "baseline_pass": 0.30,
    "cve_exposure": 0.20,
    "apparmor_exposure": 0.15,
}

# one direction law (seen live 2026-11-15): the score reads
# higher-is-better, so an input that climbs as the machine gets WORSE
# must contribute inverted. cve_exposure measures open exposure - more
# unpatched rows, higher value, worse machine. Every other input climbs
# as the machine gets better.
DIRECTIONS = {
    "lynis_hardening": "higher-is-better",
    "baseline_pass": "higher-is-better",
    "cve_exposure": "lower-is-better",
    "apparmor_exposure": "higher-is-better",
}


def _lynis_index() -> tuple[int | None, str]:
    """The hardening index from the last audit run (0-100). Root-only
    file; the CLI reports it honestly when the user context can't read."""
    try:
        text = pathlib.Path("/var/log/lynis-report.dat").read_text(
            errors="replace")
        m = re.search(r"hardening_index=(\d{1,3})", text)
        if m:
            return int(m.group(1)), "/var/log/lynis-report.dat"
    except OSError:
        pass
    return None, "unreadable in this context (run as root for the number)"


def _apparmor_exposure() -> tuple[int | None, str]:
    """Enforced/total apparmor profile ratio x100; an unconfined box
    reads 0 and the report says why."""
    try:
        lines = pathlib.Path(
            "/sys/kernel/security/apparmor/profiles").read_text(
            errors="replace").splitlines()
    except OSError:
        return None, "unreadable in this context (run as root)"
    total = len([ln for ln in lines if ln.strip()])
    enforced = len([ln for ln in lines if ln.strip().endswith("(enforce)")])
    if not total:
        return 0, "no apparmor profiles loaded"
    return round(enforced * 100 / total), (
        f"{enforced}/{total} profiles enforced")


def _cve_exposure(data_dir) -> tuple[int | None, str]:
    """Open, applicable package rows from the Debian tracker cache.

    Announcement is not patching. A row leaves this count when its package
    is upgraded to the tracker's fixed version, either verified by the
    patch ledger or by the next tracker refresh."""
    data_dir = pathlib.Path(data_dir)
    cve = data_dir / "cve-cache.json"
    try:
        doc = json.loads(cve.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, "no CVE cache on file"
    entries = [e for e in (doc.get("entries") or [])
               if isinstance(e, dict) and e.get("package")]
    if not entries:
        return None, ("no package-aware CVE rows cached; run the Debian "
                      "tracker refresh")
    patched = {}
    try:
        for line in (data_dir / "cve-patched.jsonl").read_text(
                encoding="utf-8").splitlines():
            row = json.loads(line)
            package, to = row.get("package"), row.get("to")
            if package and to:
                patched[str(package)] = str(to)
    except (OSError, ValueError):
        pass
    try:
        import cve_data
    except Exception:                     # noqa: BLE001
        cve_data = None
    open_rows = []
    for entry in entries:
        package = str(entry.get("package") or "")
        fixed = str(entry.get("fixed") or "")
        if (package in patched and fixed and cve_data is not None
                and cve_data.version_ge(patched[package], fixed)):
            continue
        open_rows.append(entry)
    affected = {str(e.get("package")) for e in open_rows
                if e.get("package")}
    installed = int(doc.get("installed_count") or 0)
    if installed:
        # The share of installed packages with at least one open CVE.
        # Patching a package removes it from the numerator, so the input
        # moves; a raw count of thousands of rows only ever reads 100.
        value = max(0, min(100, round(100 * len(affected) / installed)))
        row_word = "row" if len(open_rows) == 1 else "rows"
        note = (f"{len(affected)} of {installed} installed packages have an "
                f"open CVE; {len(open_rows)} open {row_word}.")
    else:
        weight = {"HIGH": 2.0, "CRITICAL": 3.0, "MEDIUM": 1.0, "LOW": 0.4}
        raw = sum(weight.get(str(e.get("severity", "")).upper(), 1.0)
                  for e in open_rows)
        value = max(0, min(100, round(raw * 100 / 120)))
        pkg_word = "package" if len(affected) == 1 else "packages"
        note = f"{len(affected)} {pkg_word} with an open CVE"
    if patched:
        note += f"; {len(patched)} patched by this app"
    return value, note


def _baseline_pass(baseline_rows) -> tuple[int | None, str]:
    """The verifier's table: pass = 100, partial (armed/late) = 50,
    failure = 0."""
    rows = baseline_rows or []
    if not rows:
        return None, "no baseline table on file"
    def one(state):
        if state in ("ENABLED", "PRESENT", "ARMED", "FRESH",
                     "OFF-BY-DESIGN"):
            return 1.0
        if isinstance(state, str) and state.startswith("active="):
            return 0.5          # present but not fully armed
        return 0.0
    value = sum(one(s) for _n, _l, s, _f in rows) / len(rows)
    return round(value * 100), f"{len(rows)} checks in the baseline table"


def compute(baseline_rows=None, data_dir=None) -> dict:
    """The full report: the score, every input's raw value, its weight,
    and where each number came from."""
    try:
        import gwpaths
        data_dir = data_dir or gwpaths.data_dir()
    except Exception:                    # noqa: BLE001
        data_dir = pathlib.Path("/var/lib/greywatch")
    inputs = {}
    lynis, lynis_how = _lynis_index()
    inputs["lynis_hardening"] = {
        "value": lynis, "weight": WEIGHTS["lynis_hardening"],
        "direction": DIRECTIONS["lynis_hardening"], "how": lynis_how}
    base, base_how = _baseline_pass(baseline_rows)
    inputs["baseline_pass"] = {
        "value": base, "weight": WEIGHTS["baseline_pass"],
        "direction": DIRECTIONS["baseline_pass"], "how": base_how}
    cve, cve_how = _cve_exposure(data_dir)
    inputs["cve_exposure"] = {
        "value": cve, "weight": WEIGHTS["cve_exposure"],
        "direction": DIRECTIONS["cve_exposure"], "how": cve_how}
    aa, aa_how = _apparmor_exposure()
    inputs["apparmor_exposure"] = {
        "value": aa, "weight": WEIGHTS["apparmor_exposure"],
        "direction": DIRECTIONS["apparmor_exposure"], "how": aa_how}
    known = {k: v for k, v in inputs.items() if v["value"] is not None}
    wsum = sum(v["weight"] for v in known.values()) or 1.0

    def contribution(v: dict) -> float:
        # a lower-is-better input enters the higher-is-better score
        # inverted; its own value still reports the raw measure
        return (100 - v["value"] if v["direction"] == "lower-is-better"
                else v["value"])

    # one readable input is not a score: a single 100 rides the report
    # and calls a half-measured machine perfect (seen live 2026-11-15:
    # the user context reading only the CVE lane scored 100/100)
    score = (round(sum(v["weight"] * contribution(v)
                       for v in known.values())
                   / wsum) if len(known) >= 3 else None)
    unknown = [k for k, v in inputs.items() if v["value"] is None]
    report = {
        "version": 1,
        "built_at": _dt.datetime.now(_dt.timezone.utc).isoformat(
            timespec="seconds"),
        "score": score,
        "scale": "0-100, higher is better",
        "inputs": inputs,
        "renormalized_over": sorted(known),
        "unknown_inputs": unknown,
    }
    return report


def persist(report: dict, data_dir=None) -> pathlib.Path:
    try:
        import gwpaths
        data_dir = data_dir or gwpaths.data_dir()
    except Exception:                    # noqa: BLE001
        data_dir = pathlib.Path("/var/lib/greywatch")
    out = pathlib.Path(data_dir) / "posture.json"
    tmp = pathlib.Path(str(out) + ".tmp")
    tmp.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    try:
        os_replace(tmp, out)
    except NameError:                    # noqa: F821
        import os
        os.replace(tmp, out)
    return out


def should_replace(old, new) -> bool:
    """A narrower run never clobbers a wider report on file. The
    degraded context (seen live 2026-11-16: the desktop user's refresh)
    still answers honestly in its own output, but the file keeps the
    inputs only a root read could see, so an elevated re-write survives
    every later unprivileged refresh."""
    if not isinstance(old, dict):
        return True                       # nothing readable on file: write
    old_unknown = set(old.get("unknown_inputs") or [])
    new_unknown = set(new.get("unknown_inputs") or [])
    return new_unknown <= old_unknown


def os_replace(a, b):
    import os
    os.replace(a, b)


def human(report: dict) -> str:
    lines = []
    score = report.get("score")
    if score is not None:
        head = f"security posture: {score}/100"
    elif report["inputs"]:
        got = sum(1 for v in report["inputs"].values()
                  if v["value"] is not None)
        head = (f"security posture: withheld - only {got} of the four "
                "inputs are readable in this context (run as root for "
                "the full score)")
    else:
        head = "security posture: no inputs read"
    lines.append(head)
    for k, v in report["inputs"].items():
        got = v["value"] if v["value"] is not None else "unknown"
        low = " (lower is better)" if v.get("direction") == \
            "lower-is-better" else ""
        lines.append(f"  {k:<20} {str(got):>4}{low}  "
                     f"weight {v['weight']:.2f}  ({v['how']})")
    if report["unknown_inputs"]:
        lines.append("  inputs not readable here do not count; the score "
                     "renormalises over what it can read")
    return "\n".join(lines)
