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

    # Only the primary "quarantine" line may raise a decision. The follow-up
    # "alert_local_only: quarantine: ..." line says the same thing and used to
    # open a second identical dialog for one file (owner report 2026-10-27:
    # a wall of nameless allow/deny boxes). One file → one prompt.
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
                "question": "Keep it locked away, or put it back?",
                "options": [
                    {"id": "keep", "label": "Keep quarantined",
                     "tone": "primary",
                     "helper": "keep-quarantine", "args": [target]},
                    {"id": "restore", "label": "Put it back",
                     "tone": "danger",
                     "helper": "restore-quarantine", "args": [target]},
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
