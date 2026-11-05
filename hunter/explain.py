"""The bounded AI layer: explaining findings, never discovering them.

Rules own every fact. The cloud model gets one small job — reword an
already-proven finding in plainer language and suggest a next step — and
it does that under hard bounds: at most a few calls an hour, a
schema-validated JSON reply, a cooldown the moment it misbehaves, and a
deterministic fallback that is always there anyway. Nothing the model says
can create, change, or confirm a finding.

The endpoint is triage.py's existing local gateway (ollama on 127.0.0.1,
the configured cloud endpoint); the hunter never opens ports and never
sends anything but the finding's own summary fields — no events, no file
contents, no hostnames beyond what the finding already shows a user.
"""
from __future__ import annotations

import datetime as _dt
import json
import urllib.request

from hunter import store

PROMPT_VERSION = "hunter-explain-1"
DEFAULTS = {
    "endpoint": "http://127.0.0.1:11600/api/chat",
    "model": "glm-5.3-flash:cloud",
    "enabled": True,
    "per_hour": 3,
    "timeout": 60,
}
_COOLDOWN_MINUTES = 30
_FAILS_BEFORE_COOLDOWN = 2

SYSTEM = (
    "You are a security explainer inside GreyWatch. You are given ONE "
    "finding that a rule engine already proved, as JSON with its title, "
    "what it found, a suggested next step, severity, and named evidence. "
    "Reply with ONLY a JSON object: {\"summary\": ..., \"action\": ...}. "
    "summary: restate what was found in at most two short sentences for a "
    "non-expert. action: the single most useful next step, one short "
    "sentence. Use only the facts given; never add claims, never invent "
    "files, hosts, or CVEs. No markdown, no preamble."
)


def load_config(data_dir) -> dict:
    cfg = dict(DEFAULTS)
    path = store.config_path(data_dir)
    try:
        overrides = json.loads(path.read_text())
    except (OSError, ValueError):
        return cfg
    if isinstance(overrides, dict):
        for key in DEFAULTS:
            if key in overrides and isinstance(overrides[key],
                                               type(DEFAULTS[key])):
                cfg[key] = overrides[key]
    return cfg


def read_pointer(data_dir) -> str:
    """The user's defender-notes read pointer, straight from config.json.

    load_config only copies the AI tuning keys by design; the read pointer
    is a user-owned value and must not travel through it, or every tick
    would count the whole notes file as unread again."""
    try:
        cfg = json.loads(store.config_path(data_dir).read_text())
    except (OSError, ValueError):
        return ""
    return str(cfg.get("read_until") or "") if isinstance(cfg, dict) else ""


def budget_state(budget: dict) -> dict:
    """Budget bookkeeping with the hourly window and failure cooldown.

    Normalizes the caller's dict in place — used/fails/cooldown changes
    here are meant to be persisted by whoever passed the dict in."""
    b = budget if isinstance(budget, dict) else {}
    now = _now()
    window_start = _ts(b.get("window_start"))
    if not window_start or now - window_start >= 3600:
        b["window_start"] = _iso()
        b["used"] = 0
        b["fails"] = 0
    cooldown_until = _ts(b.get("cooldown_until"))
    b["cooling"] = bool(cooldown_until and now < cooldown_until)
    return b


def explain(finding: dict, cfg: dict, budget: dict) -> dict | None:
    """One bounded model call. Returns a defender note row or None.

    Every failure mode — offline, throttled, malformed reply — ends with
    None and the deterministic text stays authoritative.
    """
    if not cfg.get("enabled"):
        return None
    b = budget_state(budget)
    if b.get("cooling") or b.get("used", 0) >= int(b.get("per_hour",
                                                         cfg["per_hour"])):
        return None
    payload = {
        "model": cfg["model"],
        "stream": False,
        "think": False,
        "options": {"num_predict": 512, "temperature": 0.3},
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": _user_content(finding)},
        ],
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        cfg["endpoint"], data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=int(cfg["timeout"])) as r:
            doc = json.loads(r.read().decode("utf-8", "replace"))
    except (OSError, ValueError, KeyError):
        return _fail(b)
    if not isinstance(doc, dict):
        # A 2xx body of valid JSON that is not an object (a list, a bare
        # string, a number) is the endpoint speaking nonsense; treat it
        # like any other failed reply. Throwing here would abort the
        # caller's cycle - after the findings were appended and before
        # the events offset was persisted, so the next cycle re-hunted
        # the same events into a growing stack of duplicates.
        return _fail(b)
    text = str((doc.get("message") or {}).get("content")
               or doc.get("response") or "")
    parsed = _parse(text)
    if parsed is None:
        return _fail(b)
    b["used"] = int(b.get("used", 0)) + 1
    b["fails"] = 0
    return _note(finding, parsed, cfg["model"])


def _user_content(finding: dict) -> str:
    """Only the finding's own summary fields cross the boundary."""
    slim = {
        "title": finding.get("title", ""),
        "what": finding.get("what", ""),
        "next": finding.get("next", ""),
        "severity": finding.get("severity", ""),
        "facts": (finding.get("facts") or [])[:4],
        "evidence": [
            {"source": row.get("source", ""), "host": row.get("host", ""),
             "path": (row.get("path") or "")[:120],
             "url": (row.get("url") or "")[:160]}
            for row in (finding.get("evidence") or [])[:4]
        ],
    }
    return json.dumps({"finding": slim})


def _parse(text: str) -> dict | None:
    """Strip fences, take the first JSON object, enforce the schema."""
    if not text:
        return None
    body = text.strip()
    if body.startswith("```"):
        body = body.strip("`")
        body = body.split("\n", 1)[-1] if "\n" in body else body
    start = body.find("{")
    end = body.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        doc = json.loads(body[start:end + 1])
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    summary = str(doc.get("summary") or "").strip()
    action = str(doc.get("action") or "").strip()
    if not summary or summary.upper().startswith(("FINDING:", "JSON")):
        return None
    if len(summary) > 400 or len(action) > 300:
        summary, action = summary[:400], action[:300]
    return {"summary": summary, "action": action}


def _note(finding: dict, parsed: dict, model: str) -> dict:
    return {
        "ts": _iso(), "kind": "ai", "finding_id": finding.get("id", ""),
        "rule": finding.get("rule", ""), "severity":
            finding.get("severity", ""),
        "text": parsed["summary"], "hint": parsed["action"],
        "model": model, "prompt_version": PROMPT_VERSION,
    }


def rule_note(finding: dict) -> dict:
    """The deterministic note every finding gets, AI or no AI."""
    return {
        "ts": finding.get("ts") or _iso(), "kind": "rule",
        "finding_id": finding.get("id", ""),
        "rule": finding.get("rule", ""),
        "severity": finding.get("severity", ""),
        "text": finding.get("what", ""), "hint": finding.get("next", ""),
        "prompt_version": PROMPT_VERSION,
    }


def _fail(b: dict) -> None:
    b["used"] = int(b.get("used", 0)) + 1
    b["fails"] = int(b.get("fails", 0)) + 1
    if int(b["fails"]) >= _FAILS_BEFORE_COOLDOWN:
        until = _dt.datetime.now(_dt.timezone.utc) \
            + _dt.timedelta(minutes=_COOLDOWN_MINUTES)
        b["cooldown_until"] = until.isoformat(timespec="seconds")
        b["fails"] = 0


def _iso() -> str:
    # Microseconds: a note appended in the same wall second as the reader's
    # pointer must still compare later than the pointer, or it is born
    # read. Mixed precision with older state sorts correctly (a longer
    # string sorts after its own second-precision prefix).
    return _dt.datetime.now(_dt.timezone.utc).isoformat(
        timespec="microseconds")


def _now() -> float:
    return _dt.datetime.now(_dt.timezone.utc).timestamp()


def _ts(iso) -> float:
    try:
        return _dt.datetime.fromisoformat(str(iso)).timestamp()
    except (ValueError, TypeError):
        return 0.0


def note_is_unread(note: dict, since: str) -> bool:
    """A defender note is unread when it arrived after the user's pointer."""
    return str(note.get("ts") or "") > str(since or "")


def mark_read(data_dir, iso: str) -> None:
    """Persist the user's defender-notes read pointer into config.json.

    Only the pointer is merged in — unknown user keys survive untouched,
    and the write goes out by atomic replace like every other state file."""
    path = store.config_path(data_dir)
    try:
        cfg = json.loads(path.read_text())
    except (OSError, ValueError):
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    cfg["read_until"] = iso
    store.write_config(data_dir, cfg)