"""CVE cache entries become ACTIVE rules (owner 2026-11-06, wave C).

The cache used to be inert metadata - ids parked next to events. Under
the two-system directive, "CVE data must become active rules": every
cached flaw that scores HIGH or above AND names a tool this machine can
check becomes one rule that
  1. the daemon announces once per flaw (the monitors' voice),
  2. the browser watch joins to events that mention the same CVE id,
  3. the assistant's playbook explains in plain words.
Nothing here patches anything: the keeper decides when packages move,
which is why each announcement says "verify the installed version".
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}(?!\d)")

ACTIVE_MIN_SCORE = 7.0           # below HIGH-weight: silence, no noise

TOOL_LABEL = {
    "appfw": "the app firewall's netfilter stack",
    "clamav": "the antivirus",
    "fail2ban": "the login blocker",
    "psad": "the scan watcher",
    "kernel": "the running Linux kernel",
}


def cache_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "cve-cache.json"


def announced_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "cve-announced.jsonl"


def load_cache(cache_path) -> list:
    try:
        data = json.loads(pathlib.Path(cache_path).read_text())
        return data.get("entries", []) if isinstance(data, dict) else []
    except (OSError, ValueError):
        return []


def active_rules(cache_path) -> list:
    """The cache's HIGH+ flaws for tools on this box, as rule dicts."""
    out = []
    for e in load_cache(cache_path):
        if not isinstance(e, dict):
            continue
        try:
            score = float(e.get("score", 0.0))
        except (TypeError, ValueError):
            continue
        if score < ACTIVE_MIN_SCORE or not e.get("tool"):
            continue
        out.append({"cve": e.get("id"), "tool": e.get("tool"),
                    "score": score, "severity": e.get("severity", ""),
                    "summary": e.get("summary", ""),
                    "modified": e.get("modified", "")})
    return out


def _announced(path: pathlib.Path) -> set:
    seen = set()
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if rec.get("cve"):
                    seen.add(rec["cve"])
    except OSError:
        return set()
    return seen


def _severity(score: float) -> str:
    return "CRITICAL" if score >= 9.0 else "HIGH"


def _text(rule: dict) -> str:
    who = TOOL_LABEL.get(rule["tool"], f"tool '{rule['tool']}'")
    sev = _severity(rule["score"])
    head = (f"{rule['cve']} (score {rule['score']} {sev}) affects {who}")
    if rule.get("summary"):
        return f"{head}: {rule['summary'][:160]} - installed versions need " \
               "checking against this flaw"
    return f"{head} - installed versions need checking against this flaw"


def evaluate(data_dir, cache_path=None) -> list:
    """Announce every ACTIVE flaw not yet announced. Returns the
    (severity, text, cve, tool) specs for the daemon to emit; writes one
    announce line per flaw so a restart never re-announces."""
    data_dir = pathlib.Path(data_dir)
    rules = active_rules(cache_path or (data_dir / "cve-cache.json"))
    path = announced_path(data_dir)
    seen = _announced(path)
    out, lines = [], []
    for rule in rules:
        cid = rule["cve"]
        if not cid or cid in seen:
            continue
        out.append((_severity(rule["score"]), _text(rule), cid,
                    rule["tool"]))
        lines.append(json.dumps(
            {"cve": cid, "tool": rule["tool"],
             "ts": _dt.datetime.now(_dt.timezone.utc)
             .isoformat(timespec="seconds")},
            separators=(",", ":")))
    if lines:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            out.clear()          # cannot persist seen-state: say nothing
    return out
