"""The blocked-address ledger.

Every block greywatch knows about psad's auto-block, fail2ban's bans,
or a keeper's own "block for good" lands here as one appended JSON line,
so after any restart the picture of who is locked out is intact and the
sidekick can audit it. The file is append-only: a release is a new line,
never an edit, and a review verdict is tracked beside the block rather
than rewriting it.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
PSAD_BLOCK_RE = re.compile(r"(?:added)\s+iptables auto-block against (\S+)",
                           re.I)
PSAD_RENEW_RE = re.compile(r"renewed\s+iptables auto-block against (\S+)",
                           re.I)
PSAD_RELEASE_RE = re.compile(r"removed iptables auto-block against (\S+)",
                             re.I)


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
                 forever: bool = False) -> dict:
    return _append(ledger_path(data_dir),
                   {"kind": "block", "ip": ip, "source": source,
                    "reason": reason[:300], "forever": bool(forever)})


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


def active_blocks(data_dir) -> dict:
    """ip -> newest entry whose kind is still 'block' (no release after)."""
    return {ip: rec for ip, rec in blocked(data_dir).items()
            if rec.get("kind") == "block"}


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
    ledger can trust; anything else returns None untouched.
    """
    tool = getattr(ev, "from_tool", "") or ""
    text = getattr(ev, "text", "") or ""
    path = ledger_path(data_dir)
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
        m = IP_RE.search(text)
        if not m or not (t.startswith("ban") or t.startswith("unban")):
            return None
        if t.startswith("unban"):
            return record_release(data_dir, m.group(0), "fail2ban",
                                  "ban released")
        return record_block(data_dir, m.group(0), "fail2ban",
                            "repeated login failures")
    return None
