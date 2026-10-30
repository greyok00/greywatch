# assistant/events.py
"""Event grouping and noise classification.

The log records everything the protections see: every allow, every scan,
and the sample files the app's own test suite writes so the scanners have
something to catch. A raw row count therefore says nothing about risk —
21,000 rows on this machine were 7,700 distinct lines, and most of the
"High" ones were a harmless test file being quarantined over and over.

This module turns rows into the two things an answer can trust:

* a **group** — the same line repeated, once the volatile parts (paths,
  addresses, hashes, times) are blanked, with its count and first/last
  time;
* a **bucket** — NOISE (a known cause explains it away), EXPLAINED (real,
  but it has a standard reading), or REAL (nothing explains it).

Pure functions only: no GTK, no model, no file I/O.
"""
from __future__ import annotations

import re

NOISE = "noise"          # known benign: a test fixture, a system script
EXPLAINED = "explained"  # real line, standard cause, still worth a sentence
REAL = "real"            # nothing explains it

# Ordered rules; the first match wins, so specific before general.
# (tool or None, pattern, bucket, key, label, why)
_RULES = (
    (None, re.compile(r"/tmp/pytest-|/var/tmp/pytest-|pytest-of-"),
     NOISE, "test-fixture", "test fixture",
     "This is a sample file the app's own test suite writes into a "
     "temporary folder so the scanners have something to catch. The test "
     "run deletes it again; it is not malware."),
    (None, re.compile(r"eicar|eicar-test-signature", re.I),
     NOISE, "test-signature", "harmless test virus",
     "EICAR is the industry's standard harmless test virus — a short "
     "string that antivirus products are designed to catch. It cannot run."),
    (None, re.compile(r"\blwp-request\b"),
     NOISE, "perl-script", "Perl helper script",
     "lwp-request is a small Perl script that ships with the system's Perl "
     "tools. It is a script, not a hidden binary."),
    ("rkhunter", re.compile(r"shared\s+memory", re.I),
     EXPLAINED, "shared-memory", "shared memory block",
     "Large shared-memory blocks are normal for browsers, video drivers and "
     "virtual machines, and a firmware update can leave one behind. "
     "rkhunter lists them for review; a list is not a finding."),
    ("rkhunter", re.compile(r"properties|changed|modified|checksum", re.I),
     EXPLAINED, "rkhunter-baseline", "stale scanner baseline",
     "The rootkit scanner compares files against a baseline it saved "
     "earlier. A package update replaces those files, so the comparison "
     "flags them. It is a to-do, not a break-in: review the list, then "
     "refresh the baseline with 'sudo rkhunter --propupd'."),
    (None, re.compile(r"<unknown>|app_name[^a-z]{0,4}unknown|pid:\s*0\b",
                      re.I),
     EXPLAINED, "unattributed", "no program name on the line",
     "The log line has no program name because the connection was already "
     "open when the watcher looked. Missing attribution is not a hidden "
     "program; the address and the rule are still recorded."),
)


def tool_of(row: dict) -> str:
    return str(row.get("from_tool") or row.get("tool") or "")


def classify(row: dict) -> dict | None:
    """The bucket and reading for one row, or None when nothing explains it."""
    text = str(row.get("text") or "")
    tool = tool_of(row)
    for want_tool, pattern, bucket, key, label, why in _RULES:
        if want_tool and tool != want_tool:
            continue
        if pattern.search(text):
            return {"bucket": bucket, "key": key, "label": label, "why": why}
    return None


def bucket_of(row: dict) -> str:
    hit = classify(row)
    return hit["bucket"] if hit else REAL


def is_noise(row: dict) -> bool:
    hit = classify(row)
    return bool(hit and hit["bucket"] == NOISE)


def note(row: dict, prefix: str = "Note") -> str:
    """One short sentence for a chat answer, or '' when nothing applies."""
    hit = classify(row)
    if not hit:
        return ""
    return f"{prefix}: {hit['why']}"


def count_noise(rows, severity=("HIGH", "CRITICAL")) -> int:
    """How many of `rows` are known-benign, by default the serious ones
    (the count an answer uses when it says 'I left N lines out')."""
    out = 0
    for row in rows or []:
        if severity and str(row.get("severity") or "").upper() not in severity:
            continue
        if is_noise(row):
            out += 1
    return out


# ---- grouping -------------------------------------------------------------

_VOLATILE = (
    (re.compile(r"/tmp/pytest-of-[^/\s]+/pytest-\d+/\S+"), "<pytest-tmp>/…"),
    (re.compile(r"/var/tmp/pytest-of-[^/\s]+/pytest-\d+/\S+"), "<pytest-tmp>/…"),
    (re.compile(r"sha256:[0-9a-fA-F]+"), "sha256:<hash>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hash>"),
    (re.compile(r"\bpid[:= ]?\d+"), "pid=<n>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<address>"),
    (re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b"), "<time>"),
)


def signature(row: dict) -> tuple[str, str, str]:
    """Identity of a repeated line: tool, severity, wording with the
    volatile parts blanked. Two quarantine rows from two test runs share
    a signature; two different tools never do."""
    text = " ".join(str(row.get("text") or "").split())
    for pattern, sub in _VOLATILE:
        text = pattern.sub(sub, text)
    return (tool_of(row), str(row.get("severity") or "").upper(), text)


def group(rows) -> list[dict]:
    """Collapse repeated lines. Newest group first, each with its count,
    first/last timestamp, one example row and its noise reading."""
    out: dict[tuple, dict] = {}
    for row in rows or []:
        key = signature(row)
        ts = str(row.get("ts") or "")
        hit = out.get(key)
        if hit is None:
            out[key] = {"signature": key, "tool": key[0],
                        "severity": key[1], "count": 1, "first": ts,
                        "last": ts, "row": row,
                        "reading": classify(row)}
            continue
        hit["count"] += 1
        if ts and (not hit["first"] or ts < hit["first"]):
            hit["first"] = ts
        if ts and (not hit["last"] or ts >= hit["last"]):
            hit["last"] = ts
            hit["row"] = row
    groups = list(out.values())
    groups.sort(key=lambda g: (g["last"], g["first"]), reverse=True)
    return groups


def unique_rows(rows) -> list[dict]:
    """One row per repeated line, newest first — a listing that says how
    many times each line was recorded instead of printing it repeatedly."""
    return [g["row"] for g in group(rows)]


def count_real(rows) -> int:
    """Rows nothing explains — the honest count behind a severity badge."""
    return sum(1 for r in rows or [] if bucket_of(r) == REAL)
