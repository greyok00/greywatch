from __future__ import annotations

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
    "unban-ip", "keep-scan-ban", "widen-scan-ban",  # scanner-ban / fail2ban
    "none",                                     # investigate/no-op
})

DECISIONS_PATH = pathlib.Path(__file__).resolve().parent / "data" / "decisions.jsonl"


def _spec(ev, question, options) -> dict:
    digest = hashlib.md5(f"{ev.from_tool}|{ev.ts}|{ev.text}".encode()).hexdigest()[:6]
    return {"id": f"{ev.from_tool}:{digest}", "question": question,
            "options": options}


def interaction_for(ev) -> dict | None:
    if ev is None or ev.interaction:        # spec already attached (appfw)
        return ev.interaction if ev else None
    tool, text = ev.from_tool, ev.text.lower()
    ip = next(iter(IP_RE.findall(ev.text)), "")
    target = next(iter(FILE_RE.findall(ev.text)), "")

    if tool == "responderd" and "quarantine" in text:
        return _spec(ev, f"Responderd quarantined a file: {ev.text[:120]}. Keep or restore?", [
            {"id": "keep", "label": "Keep quarantined", "helper": "keep-quarantine", "args": [target]},
            {"id": "restore", "label": "Restore file", "helper": "restore-quarantine", "args": [target]},
        ])

    if (tool == "yara-watch" and "quarantine" in text) or \
            (tool == "secops-mcp" and "ban" in text):
        return _spec(ev, "Scanner wants a ban confirmed:", [
            {"id": "keep", "label": "Keep ban", "helper": "keep-scan-ban", "args": [target or ip]},
            {"id": "unban", "label": "Unban", "helper": "unban-ip", "args": [ip]},
            {"id": "widen", "label": "Widen ban scope", "helper": "widen-scan-ban", "args": [ip]},
        ])

    if tool == "fail2ban" and "near-ignoreip" in text:
        return _spec(ev, "Fail2ban flagged a near-ignoreip case:", [
            {"id": "keep", "label": "Keep ban", "helper": "keep-scan-ban", "args": [ip]},
            {"id": "unban", "label": "Unban IP", "helper": "unban-ip", "args": [ip]},
        ])
    return None


def record_answer(decisions_path, spec_id: str, option_id: str) -> bool:
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
    try:
        assert spec["id"] and spec["question"]
        options = spec["options"]
        for o in options:
            assert o["helper"] in HELPERS
            assert o["helper"] != "none" or o["label"].lower().startswith("investigate")
            assert isinstance(o.get("args", []), list)
        return {"id": spec["id"], "question": spec["question"],
                "options": [{"id": o["id"], "label": o["label"],
                             "helper": o["helper"], "args": o.get("args", [])}
                            for o in options]}
    except (AssertionError, KeyError, TypeError):
        return None
