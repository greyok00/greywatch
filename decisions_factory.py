from __future__ import annotations
"""Records and inspects the decisions the suite offers for an event.

Each interaction spec carries a stable id derived from its event, so an
answer can be matched back to the ask that produced it."""


import datetime as _dt
import hashlib
import json
import pathlib
import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
FILE_RE = re.compile(r"/[\w./-]{1,200}")

HELPERS = frozenset({
    "drop-listener", "allow-listener",          # host listener decisions
    "restore-quarantine", "keep-quarantine",    # responderd quarantine
    "delete-quarantine", "file-action",         # purge (owner 2026-11-06)
    "unban-ip", "keep-scan-ban", "widen-scan-ban",  # scanner-ban / fail2ban
    "block-ip", "lift-block", "block-review",   # blocked-IP ledger (wave B)
    "none",                                     # investigate/no-op
})

DECISIONS_PATH = pathlib.Path(__file__).resolve().parent / "data" / "decisions.jsonl"


def _spec(ev, question, options) -> dict:
    digest = hashlib.md5(f"{ev.from_tool}|{ev.ts}|{ev.text}".encode()).hexdigest()[:6]
    return {"id": f"{ev.from_tool}:{digest}", "question": question,
            "options": options}


def interaction_for(ev) -> dict | None:
    """interaction_for."""
    if ev is None or ev.interaction:        # spec already attached (appfw)
        return ev.interaction if ev else None
    tool, text = ev.from_tool, ev.text.lower()
    ip = next(iter(IP_RE.findall(ev.text)), "")
    target = next(iter(FILE_RE.findall(ev.text)), "")

    # Only the primary "quarantine" line may raise a decision. The follow-up
    # "alert_local_only: quarantine: ..." line says the same thing and used to
    # open a second identical dialog for one file. One file → one prompt.
    # The id is keyed on the file path, so answering once covers every repeat.
    if tool == "responderd" and text.startswith("quarantine:"):
        target = next(iter(FILE_RE.findall(ev.text)), "")
        name = target.rsplit("/", 1)[-1] if target else "a file"
        m = re.search(r"\(sha256:[0-9a-f]+\)\s+(\S+)", ev.text)
        sig = m.group(1) if m else "a malware signature"
        digest = hashlib.md5((target or ev.text).encode()).hexdigest()[:6]
        return {"id": f"responderd:{digest}",
                "eyebrow": "Threat found",
                "subject": f"“{name}” was quarantined",
                "detail": f"{sig} · {target or 'location unknown'}",
                "question": "Keep it locked away, put it back, or "
                            "delete it for good?",
                "options": [
                    {"id": "keep", "label": "Keep quarantined",
                     "tone": "primary",
                     "helper": "keep-quarantine", "args": [target]},
                    {"id": "restore", "label": "Put it back",
                     "tone": "neutral",
                     "helper": "restore-quarantine", "args": [target]},
                    {"id": "delete", "label": "Delete permanently",
                     "tone": "danger",
                     "helper": "delete-quarantine", "args": [target]},
                ]}

    # psad's auto-block lines (wave A parser): the block already happened
    # at sustained-attack danger level 5, so the question is only whether
    # to convert it to a keeper-held "for good" block or release it early.
    if tool == "psad" and "auto-block" in text and ip:
        digest = hashlib.md5(ip.encode()).hexdigest()[:6]
        return {"id": f"psad:{digest}",
                "eyebrow": "Attack blocked",
                "subject": f"{ip} was locked out after a sustained attack",
                "detail": ev.text[:160],
                "question": "Hold this address out for good, or lift the "
                            "block now? Ignoring the card lets psad's "
                            "expiry timer release it.",
                "options": [
                    {"id": "forever", "label": "Block for good",
                     "tone": "danger", "helper": "block-ip",
                     "args": [ip]},
                    {"id": "lift", "label": "Lift the block",
                     "tone": "neutral", "helper": "lift-block",
                     "args": [ip]},
                ]}

    # Ban prompts get the same treatment: name the file or address, quote what
    # the scanner actually reported, and key the id to the subject so a repeat
    # detection cannot spawn a second identical box.
    if (tool == "yara-watch" and "quarantine" in text) or \
            (tool == "secops-mcp" and "ban" in text):
        subject = target or ip or ev.text[:60]
        digest = hashlib.md5(f"{tool}|{subject}".encode()).hexdigest()[:6]
        who = pathlib.Path(target).name if target else (ip or "an unknown target")
        return {"id": f"{tool}:{digest}",
                "eyebrow": tool,
                "subject": f"Block “{who}”?",
                "detail": ev.text[:220],
                "question": "Keep the block, lift it, or widen it?",
                "options": [
                    {"id": "keep", "label": "Keep block",
                     "tone": "primary",
                     "helper": "keep-scan-ban", "args": [target or ip]},
                    {"id": "unban", "label": f"Unblock {ip or 'it'}",
                     "tone": "danger",
                     "helper": "unban-ip", "args": [ip]},
                    {"id": "widen", "label": "Widen block",
                     "tone": "quiet",
                     "helper": "widen-scan-ban", "args": [ip]},
                ]}

    if tool == "fail2ban" and "near-ignoreip" in text:
        digest = hashlib.md5(f"fail2ban|{ip}".encode()).hexdigest()[:6]
        return {"id": f"fail2ban:{digest}",
                "eyebrow": "Fail2ban",
                "subject": f"Ban {ip or 'this address'}?",
                "detail": ev.text[:220],
                "question": "Keep the block, or lift it?",
                "options": [
                    {"id": "keep", "label": "Keep block",
                     "tone": "primary",
                     "helper": "keep-scan-ban", "args": [ip]},
                    {"id": "unban", "label": f"Unblock {ip or 'it'}",
                     "tone": "danger",
                     "helper": "unban-ip", "args": [ip]},
                ]}
    return None


def record_answer(decisions_path, spec_id: str, option_id: str) -> bool:
    """record_answer."""
    decisions_path = pathlib.Path(decisions_path)
    decisions_path.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    if decisions_path.exists():
        for line in decisions_path.read_text().splitlines():
            try:
                seen.add(json.loads(line)["id"])
            except (ValueError, KeyError):
                continue
    if spec_id in seen:
        return False
    with decisions_path.open("a") as f:
        f.write(json.dumps({"id": spec_id, "option": option_id,
                            "ts": _dt.datetime.now(_dt.timezone.utc)
                            .isoformat(timespec="seconds")}) + "\n")
    return True


def pending_ids(decisions_path) -> set:
    """pending_ids."""
    decisions_path = pathlib.Path(decisions_path)
    if not decisions_path.exists():
        return set()
    out = set()
    for line in decisions_path.read_text().splitlines():
        try:
            out.add(json.loads(line)["id"])
        except (ValueError, KeyError):
            continue
    return out


def sanitize(spec: dict) -> dict | None:
    """sanitize."""
    try:
        assert spec["id"] and spec["question"]
        options = spec["options"]
        for o in options:
            assert o["helper"] in HELPERS
            assert o["helper"] != "none" or o["label"].lower().startswith("investigate")
            assert isinstance(o.get("args", []), list)
        out = {"id": spec["id"], "question": spec["question"],
               "options": [{"id": o["id"], "label": o["label"],
                            "tone": o.get("tone", ""),
                            "helper": o["helper"], "args": o.get("args", [])}
                           for o in options]}
        for key in ("eyebrow", "subject", "detail"):
            if isinstance(spec.get(key), str):
                out[key] = spec[key]
        return out
    except (AssertionError, KeyError, TypeError):
        return None


# -- the ONE pending list (the 12-vs-0 fix, rebuild Phase 1) ------------------

_SOURCE_NAMES = {
    "hunter": "browser-watch",
    "blockreviewer": "block-reviewer",
}


def _source_for(spec_id: str) -> str:
    """The record source for a decision id: role names where the producer
    is one of the four intelligence roles, the tool name otherwise."""
    head = str(spec_id).split(":", 1)[0]
    return _SOURCE_NAMES.get(head, head)


def _kind_for(spec: dict) -> str:
    """question = the keeper must answer through a helper; advisory =
    carries context only. Derived from the options, never claimed."""
    if any(o.get("helper") for o in spec.get("options", [])
           if isinstance(o, dict)):
        return "question"
    return "advisory"


def enrich_decision(spec, ts: str = "") -> dict:
    """One item of the published pending list: the raw spec plus the flat
    fields status consumers sort and count on (source, kind, title)."""
    spec = spec if isinstance(spec, dict) else {}
    options = [o for o in spec.get("options", []) if isinstance(o, dict)]
    title = (spec.get("subject")
             or str(spec.get("question", "")).split("\n", 1)[0]) or "?"
    return {"id": str(spec.get("id") or ""),
            "source": _source_for(spec.get("id") or ""),
            "kind": _kind_for(spec),
            "title": title,
            "detail": spec.get("detail") or "",
            "ts": ts,
            "options": options,
            "spec": spec}


def iter_interaction_events(data_dir):
    """Events carrying a decision spec: whole file, the daemon's counting
    rule. Same fallback as the desktop list module: when events.jsonl is
    not readable, status.json's recent snapshot stands in so the list can
    never go blind while the daemon is still publishing."""
    data_dir = pathlib.Path(data_dir)
    try:
        raw = (data_dir / "events.jsonl").read_bytes().split(b"\n")
    except OSError:
        raw = []
    if not raw:
        try:
            snap = json.loads((data_dir / "status.json").read_text())
            events = snap.get("recent") or []
        except (OSError, ValueError):
            events = []
        raw = [json.dumps(ev).encode("utf-8", "replace") for ev in events]
    for line in raw:
        if b'"interaction"' not in line:
            continue
        try:
            ev = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(ev, dict):
            yield ev


def pending_spec_pairs(data_dir) -> list:
    """[(raw spec, ts)] of unanswered decisions, oldest asked first, one
    per id (newest occurrence wins for repeats). The same rule the GUI
    card list and the daemon's counter both follow."""
    answered = pending_ids(pathlib.Path(data_dir) / "decisions.jsonl")
    by_id, order = {}, []
    for ev in iter_interaction_events(data_dir):
        spec = ev.get("interaction")
        if not (isinstance(spec, dict) and spec.get("id")):
            continue
        sid = str(spec["id"])
        if sid not in by_id:
            order.append(sid)
        by_id[sid] = (spec, str(ev.get("ts", "")))
    return [(by_id[i][0], by_id[i][1]) for i in order
            if i not in answered]


def pending_decision_list(data_dir) -> list:
    """The full pending decision list for status.json: every source, each
    item carrying id, source, kind, title, detail, ts, options, and the
    raw spec. The header pill counts THIS list's length; the drawer, the
    pages and the popups render it, so no surface can disagree again."""
    return [enrich_decision(spec, ts)
            for spec, ts in pending_spec_pairs(data_dir)]


def enrich_pending(index, answered) -> list:
    """Daemon-side list build from the incremental interaction index (each
    value is a {"spec", "ts"} pair), oldest first, answered removed."""
    out = []
    for sid, val in index.items():
        if sid in answered:
            continue
        spec, ts = (val or (None, "")) if isinstance(val, dict) else (None, "")
        spec = spec if isinstance(spec, dict) else {"id": sid}
        out.append(enrich_decision(spec, ts or ""))
    return out
