from __future__ import annotations

from ui import cliapi


def open_rows():
    doc = cliapi.read_state("cve-cache.json") or {}
    entries = [e for e in (doc.get("entries") or [])
               if isinstance(e, dict) and e.get("package")]
    patched = {}
    for row in cliapi.read_jsonl("cve-patched.jsonl", last=5000):
        package, to = row.get("package"), row.get("to")
        if package and to:
            patched[str(package)] = str(to)
    try:
        from cve_data import version_ge
    except Exception:                      # noqa: BLE001
        version_ge = lambda _a, _b: False
    rows = []
    for entry in entries:
        package = str(entry.get("package") or "")
        fixed = str(entry.get("fixed") or "")
        if package in patched and fixed \
                and version_ge(patched[package], fixed):
            continue
        rows.append(entry)
    return rows, doc


def counts(rows, doc) -> dict:
    installed = int((doc or {}).get("installed_count") or 0)
    affected = len({str(r.get("package")) for r in rows if r.get("package")})
    shown = int((doc or {}).get("total_entries") or len(rows))
    return {"installed": installed, "affected": affected,
            "rows": len(rows), "total": shown,
            "capped": bool((doc or {}).get("capped"))}
