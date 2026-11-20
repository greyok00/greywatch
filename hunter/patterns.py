"""The delivery-pattern corpus — the hunter's web-trick rulebook.

The seed file ``patterns-rules.json`` carries a small, versioned set of
rules that read normalized ``docs``: one dict per HAR entry, history row,
or live-CDP summary. Matching is substring-shaped and case-folded; every
key in a rule's ``match`` dict must match, and lists inside a key means
any of them may match. Live-only rules say ``cdp_only`` and stay silent
unless the doc carries live evidence, because a plain capture cannot
honestly support them.

The corpus is stateless: repeats inside a suppression window collapse in
the engine's seen map, not here.
"""
from __future__ import annotations

import json
import pathlib

from hunter import web

RULES_NAME = "patterns-rules.json"
RULES_MAX = 200


def _rules_path() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent / RULES_NAME


def load_rules() -> tuple[int, list[dict]]:
    """(version, rules). A rule the schema cannot vouch for is dropped,
    not repaired — a half-defined rule would fire on nothing in
    particular."""
    version = 0
    kept: list[dict] = []
    try:
        doc = json.loads(_rules_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0, []
    if not isinstance(doc, dict):
        return 0, []
    version = int(doc.get("version") or 0)
    rules = doc.get("rules")
    if not isinstance(rules, list):
        return version, []
    for rule in rules[:RULES_MAX]:
        if not isinstance(rule, dict):
            continue
        if not _schema_ok(rule):
            continue
        kept.append(rule)
    return version, kept


_SCHEMA_REQUIRED = ("id", "title", "severity", "confidence", "what",
                    "next", "window_hours")
_MATCH_FIELDS = ("host", "url", "title", "mime")
# The corpus was built to grow: cloaking (UA-conditional content) and
# base64-page packing had rules but no evidence producer ever set those
# fields, so they were retired (round-2 audit, - a
# "what" that promised detection the software could not perform is
# worse than the absence of the rule. The same round killed
# pat-drive-by-kit (round-3 audit): its downloads counter rose only when
# an entry carried a content-disposition header, which the live watcher
# does not record, and imported captures are the wrong cdp flag - no
# producer could ever satisfy it. It returns when a producer records the
# header.
# (mime_flips/b64 fields had no producer; see the corpus note above)
_NEED_FIELDS = ("iframes_min", "downloads_min")


def _schema_ok(rule: dict) -> bool:
    if any(not rule.get(k) for k in _SCHEMA_REQUIRED[:4] + ("what", "next")):
        return False
    if rule.get("severity") not in ("HIGH", "MEDIUM", "LOW"):
        return False
    if not isinstance(rule.get("window_hours"), int):
        return False
    match = rule.get("match")
    if match is not None:
        groups = match if isinstance(match, list) else [match]
        if not groups or not all(isinstance(g, dict) and g for g in groups):
            return False
        for group in groups:
            if set(group) - set(_MATCH_FIELDS):
                return False
            if any(not isinstance(v, list) or not v for v in group.values()):
                return False
    needs = rule.get("needs")
    if needs is not None:
        if not isinstance(needs, dict) or not needs:
            return False
        if set(needs) - set(_NEED_FIELDS):
            return False
        if any(not isinstance(v, int) for v in needs.values()):
            return False
    return True


def window_hours() -> dict:
    """Rule id -> the quiet hours each rule declares for itself. The
    engine consults this first, so a rule author edits one place; the
    entry is validated against the same schema the rule passed."""
    try:
        _version, rules = load_rules()
    except (OSError, ValueError):
        return {}
    return {str(r["id"]): int(r["window_hours"]) for r in rules
            if isinstance(r, dict) and isinstance(r.get("id"), str)
            and isinstance(r.get("window_hours"), int)}


def apply_rules(docs, rules=None) -> list[dict]:
    """Findings for the seed rules that matched. The engine dedupes
    repeats; this stays a pure function of docs and rules."""
    version, seed_rules = load_rules()
    if rules is None:
        rules = seed_rules
    out: list[dict] = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        for rule in rules:
            if not isinstance(rule, dict) or not _schema_ok(rule):
                continue
            f = _apply_one(rule, d, version)
            if f is not None:
                out.append(f)
    return out


def _apply_one(rule, d, version) -> dict | None:
    """One rule against one doc. ``match`` is groups (a list of dicts, or
    a single dict): ANY one group matching fires the rule, and inside a
    group every named key must match. All ``needs`` floors must also be
    met, and live-only rules stay silent without live evidence."""
    facts: list[str] = []
    if rule.get("cdp_only") and not d.get("cdp"):
        return None
    needs = rule.get("needs") or {}
    for field, floor in needs.items():
        got = d.get(field.removesuffix("_min"), 0)
        try:
            if int(got or 0) < int(floor):
                return None
        except (TypeError, ValueError):
            return None
        facts.append(f"{field.removesuffix('_min')}={_clip(got, 40)}")
    groups = _match_groups(rule)
    hit = None
    for group in groups:
        if hit is None and group:
            hit = _group_hits(group, d)
    if groups and hit is None:
        return None             # a match clause is declared and unmet;
    if hit is not None:         # needs alone only fire a needs-only rule
        facts.extend(hit)
    if not facts:
        return None                        # nothing matched → no rule
    ev = [{"source": str(d.get("source") or "web-doc"),
           "url": _clip(d.get("url"), 200), "host": _clip(d.get("host"), 120),
           "ts": d.get("ts") or web._now_iso()}]
    return web.finding(
        rule["id"], rule["title"], _clip(rule["what"], 600),
        _clip(rule["next"], 400), rule["severity"], ev,
        confidence=rule.get("confidence", "medium"),
        facts=facts + [f"rules-version={version}"])


def _clip(value, n) -> str:
    return web._clip(value, n)


def _match_groups(rule) -> list[dict]:
    """``match`` as a flat dict is one group; a list is groups in order."""
    match = rule.get("match")
    if isinstance(match, dict):
        return [match]
    if isinstance(match, list):
        return [g for g in match if isinstance(g, dict) and g]
    return []


def _group_hits(group, d) -> list[str] | None:
    """The evidence strings the group matched, or None when any named key
    failed. A key hit names the phrase that made it hit, clipped."""
    facts = []
    for field, want in group.items():
        have = str(d.get(field) or "")
        probe = [str(w) for w in want if str(w).lower() in have.lower()]
        if not probe:
            return None                    # one failed key kills the group
        facts.append(f"{field}={_clip('/'.join(probe[:2]), 120)}")
    return facts