"""The blocked-address ledger.

Every block greywatch knows about psad's auto-block, fail2ban's bans,
or a keeper's own "block for good" lands here as one appended JSON line,
so after any restart the picture of who is locked out is intact and the
block reviewer can audit it. The file is append-only: a release is a new line,
never an edit, and a review verdict is tracked beside the block rather
than rewriting it.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import pathlib
import re

# fail2ban ban/unban lines carry one address and no field name. Match
# both families; the IPv6 alternative is deliberately colon-heavy so it
# cannot swallow ordinary words.
IP_RE = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)\b")
PSAD_BLOCK_RE = re.compile(
    r"(?:added)\s+(?:ip|ip6)tables auto-block against (\S+)", re.I)
PSAD_RENEW_RE = re.compile(
    r"renewed\s+(?:ip|ip6)tables auto-block against (\S+)", re.I)
PSAD_RELEASE_RE = re.compile(
    r"removed (?:ip|ip6)tables auto-block against (\S+)", re.I)


def _address(text: str) -> str | None:
    """The first valid IPv4/IPv6 token in an event line, or None."""
    for token in IP_RE.findall(text):
        token = token.strip("[]")
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        return token
    return None


def ledger_path(data_dir) -> pathlib.Path:
    d = pathlib.Path(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d / "blocked-ips.jsonl"


def _now():
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _append(path: pathlib.Path, record: dict) -> dict:
    record = {"ts": _now(), **record}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError:
        return record          # a closed ledger never blocks a decision card
    return record


def record_block(data_dir, ip: str, source: str, reason: str,
                 forever: bool = False, expires_at: str | None = None,
                 ttl_s: int | None = None) -> dict:
    rec = {"kind": "block", "ip": ip, "source": source,
           "reason": reason[:300], "forever": bool(forever)}
    if expires_at:
        rec["expires_at"] = str(expires_at)
    if ttl_s is not None:
        rec["ttl_s"] = int(ttl_s)
    return _append(ledger_path(data_dir), rec)


def record_release(data_dir, ip: str, source: str, reason: str) -> dict:
    return _append(ledger_path(data_dir),
                   {"kind": "release", "ip": ip, "source": source,
                    "reason": reason[:300]})


def record_review(data_dir, ip: str, verdict: str) -> dict:
    return _append(ledger_path(data_dir),
                   {"kind": "review", "ip": ip, "verdict": verdict})


def blocked(data_dir) -> dict:
    """ip -> the NEWEST block/release line (release overwrites and the
    entry's own kind says which state is current)."""
    path = ledger_path(data_dir)
    state: dict = {}
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if rec.get("kind") in ("block", "release") and rec.get("ip"):
                    state[rec["ip"]] = rec
    except OSError:
        return {}
    return state


def _expired(rec: dict, now=None) -> bool:
    """True when a temporary block's own deadline has passed.

    nftables removes the address on its timeout; the ledger must agree, or
    the Defense page would show a block that is no longer live."""
    value = rec.get("expires_at")
    if not value:
        return False
    try:
        when = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
    except (TypeError, ValueError):
        return False              # malformed deadline: keep the block visible
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return when <= now


def active_blocks(data_dir) -> dict:
    """ip -> newest entry whose kind is still 'block' and whose temporary
    deadline (when present) has not passed."""
    return {ip: rec for ip, rec in blocked(data_dir).items()
            if rec.get("kind") == "block" and not _expired(rec)}


def reviews(data_dir) -> dict:
    """ip -> newest verdict recorded (keep|lift)."""
    path = ledger_path(data_dir)
    state: dict = {}
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if rec.get("kind") == "review" and rec.get("ip"):
                    state[rec["ip"]] = rec.get("verdict")
    except OSError:
        return {}
    return state


def forever_blocks(data_dir) -> dict:
    """ip -> block record for entries the keeper asked to hold for good."""
    return {ip: rec for ip, rec in active_blocks(data_dir).items()
            if rec.get("forever")}


def classify_event(ev, data_dir) -> dict | None:
    """Turn one parsed event into a ledger line and write it.

    psad's three real auto-block syslog phrases (verified in the psad 2.4.6
    package source) and fail2ban's Ban/Unban lines are the sources the
    ledger can trust; anything else returns None untouched — and touches
    NO filesystem: the ledger_path mkdir+stat here cost two syscalls per
    consumed event, and under the boot flood that wedged the main loop
    past the pet gate (faulthandler dump 2026-11-11: 17/17 wedges inside
    this call). The state dir is made by _append, on a real write only.
    """
    tool = getattr(ev, "from_tool", "") or ""
    text = getattr(ev, "text", "") or ""
    if tool == "psad":
        m = PSAD_BLOCK_RE.search(text)
        if m:
            return record_block(data_dir, m.group(1), "psad",
                                "sustained attack: psad auto-block")
        m = PSAD_RENEW_RE.search(text)
        if m:
            return record_block(data_dir, m.group(1), "psad",
                                "attack resumed: psad renewed the block")
        m = PSAD_RELEASE_RE.search(text)
        if m:
            return record_release(data_dir, m.group(1), "psad",
                                  "auto-block expired or lifted")
        return None
    if tool == "fail2ban":
        t = text.lower()
        ip = _address(text)
        if not ip or not (t.startswith("ban") or t.startswith("unban")):
            return None
        if t.startswith("unban"):
            return record_release(data_dir, ip, "fail2ban",
                                  "ban released")
        return record_block(data_dir, ip, "fail2ban",
                            "repeated login failures")
    return None


def page_digest(evs, data_dir, answered=None) -> dict:
    """What the Defense page needs to draw, in one readable payload.

    Both the events store and this ledger are root-owned 0600, so the
    daemon publishes the same digest shape inside status.json that the
    recent-activity snapshot rides on; the desktop app reads status.json
    and never touches these files directly. Rows carry the block reviewer's
    plain-language class so the page explains WHY each address is held.
    """
    import blockreviewer

    verdicts = reviews(data_dir)
    rows = []
    for ip, rec in active_blocks(data_dir).items():
        verdict = blockreviewer.classify(ip)
        rows.append({
            "ip": ip, "source": str(rec.get("source", "")),
            "reason": str(rec.get("reason", "")),
            "forever": bool(rec.get("forever")),
            "expires_at": str(rec.get("expires_at", "")),
            "cls": verdict["cls"], "why": verdict["why"],
            "reviewed": verdicts.get(ip) or "",
            "ts": str(rec.get("ts", "")),
        })
    rows.sort(key=lambda r: (r["ts"],), reverse=True)
    asks, seen = [], set()
    for ev in reversed(list(evs or [])):
        if str(ev.get("from_tool", "")) != "block-reviewer":
            continue
        spec = ev.get("interaction")
        if not (isinstance(spec, dict) and spec.get("id")):
            continue
        sid = str(spec["id"])
        if sid in seen or sid in (answered or ()):
            continue
        seen.add(sid)
        asks.append({"id": sid, "ts": str(ev.get("ts", "")), "spec": spec})
        if len(asks) >= 50:
            break
    return {"blocked": rows[:200], "asks": asks}
