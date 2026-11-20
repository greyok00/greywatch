"""appfw.asklifecycle — the ask queue's lifecycle (plan Task 6).

L1/L2 asks auto-resolve with a recorded reason; L3/L4 cards NEVER
auto-resolve (design §3, §6.1: the pending count can only shrink by an
owner's answer or an explicit sweep). Answered/stale files archive
after the TTL. The queue is always drainable; every decision row
carries level + reason + source.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib

ARCHIVE_TTL_S = 48 * 3600
DECISIONS_KEEP = 5000            # stated growth cap: newest rows survive


def _now() -> float:
    import time
    return time.time()


def sweep_asks(data_dir, now: float | None = None) -> dict:
    """One sweep pass over <data_dir>/appfw/asks/:
    - answered files archive immediately (the answer won);
    - pending L1/L2 (and legacy level-less files) auto-resolve deny with
      a recorded reason, then archive;
    - pending L3/L4 are NEVER swept; they stay pending forever;
    - archive itself GCs files older than the TTL.
    Returns counts: {resolved, kept, archived, gc}.
    """
    now = _now() if now is None else float(now)
    base = pathlib.Path(data_dir) / "appfw"
    asks = base / "asks"
    answers = base / "answers"
    archive = asks / "archive"
    decisions = base / "decisions.jsonl"
    counts = {"resolved": 0, "kept": 0, "archived": 0, "gc": 0}
    if asks.mkdir(parents=True, exist_ok=True) is None and not asks.is_dir():
        return counts
    try:
        archive.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    # (carried minor 5: the old 'seen' id map was built here and never
    # consulted — removed. 'never double records' is enforced by the
    # archive-move: an answered/resolved ask FILE leaves the directory,
    # so a second sweep cannot see its id again.)
    for path in sorted(asks.iterdir()):
        if not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            counts["gc"] += 1
            _archive(path, archive, now, counts)
            continue
        spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else doc
        key = str(doc.get("id") or spec.get("id") or path.stem)
        ans_path = answers / f"{path.stem}.json"
        answer = None
        if ans_path.exists():
            try:
                answer = json.loads(ans_path.read_text())
            except (OSError, ValueError):
                answer = None
        if answer is not None and isinstance(answer, dict) and \
                str(answer.get("action")) in ("allow", "deny"):
            _record(decisions, {"id": key,
                                "option": f"answer:{answer.get('action')}",
                                "level": str(spec.get("level") or ""),
                                "reason": "owner answered at the gate",
                                "ts": str(doc.get("ts") or "")})
            _archive(path, archive, now, counts)
            continue                     # the owner's answer wins; no sweep row
        level = str(spec.get("level") or "")
        if level in ("L3", "L4"):
            counts["kept"] += 1
            continue                     # a card never expires
        # Review M1: the answer may have landed while we worked — a
        # late-arriving owner answer is authoritative, re-check BEFORE
        # recording any auto-resolution.
        answer2 = None
        try:
            if ans_path.exists():
                answer2 = json.loads(ans_path.read_text())
        except (OSError, ValueError):
            answer2 = None
        if isinstance(answer2, dict) and \
                str(answer2.get("action")) in ("allow", "deny"):
            _record(decisions, {"id": key,
                                "option": f"answer:{answer2.get('action')}",
                                "level": str(spec.get("level") or ""),
                                "reason": "owner answered at the gate",
                                "ts": str(doc.get("ts") or "")})
            _archive(path, archive, now, counts)
            continue
        reason = (f"auto-resolved ({level or 'legacy'}: below card level; "
                  f"connection already timed out at the gate)")
        _record(decisions, {"id": key, "option": "deny",
                            "level": level or "legacy",
                            "reason": reason,
                            "ts": str(doc.get("ts") or "")})
        _archive(path, archive, now, counts)
        counts["resolved"] += 1
    # TTL for the archive itself
    for old in archive.iterdir():
        try:
            if now - old.stat().st_mtime > ARCHIVE_TTL_S:
                old.unlink()
                counts["gc"] += 1
        except OSError:
            continue
    return counts


def _record(decisions: pathlib.Path, row: dict) -> None:
    """Append a decisions row — planted-name refusal + stated cap
    (carried minor 4: the ledger meets the repo's repo-wide append
    standard; at DECISIONS_KEEP rows the oldest records are trimmed,
    newest kept)."""
    if "ts" not in row or not row["ts"]:
        row["ts"] = _dt.datetime.now(_dt.timezone.utc).isoformat(
            timespec="seconds")
    from status import append_checked
    append_checked(str(decisions), json.dumps(row) + "\n",
                   create_mode=0o600)
    _trim_decisions(decisions)


def _trim_decisions(decisions: pathlib.Path,
                    keep: int = DECISIONS_KEEP) -> None:
    try:
        window: list[str] = []
        with decisions.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                window.append(line.rstrip("\n"))
                if len(window) > keep:
                    window.pop(0)
        if len(window) < keep:
            return
        tail = window[-keep:]
        text = "\n".join(tail) + "\n"
        if decisions.read_text() == text:
            return
        # atomic_replace stages via the private root-owned staging file
        # (status._stage_for): the group-visible dir never sees a
        # plantable .tmp sidecar — the same standard the append carries.
        from status import atomic_replace
        atomic_replace(str(decisions), text)
    except OSError:
        pass


def _archive(path: pathlib.Path, archive: pathlib.Path, now: float,
             counts: dict) -> None:
    try:
        dest = archive / path.name
        if not dest.exists():
            path.rename(dest)
        else:
            path.unlink()
        counts["archived"] += 1
        try:
            ans = path.parent.parent / "answers" / f"{path.stem}.json"
            if ans.exists():
                ans.unlink()
        except OSError:
            pass
    except OSError:
        pass
