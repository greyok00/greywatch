"""Small-model triage for service failures.

The rules in selfheal.py cover the failures we have actually seen. This is
the fallback for the rest: hand the model a short, sanitised slice of the
service log and ask for one of a fixed set of answers. The model never gets
to choose a command — it picks an ACTION NAME from a whitelist, and a low
confidence or an unknown action is treated as "no idea".

Contract (JSON, one object):
    {"cause": "short-kebab-case", "action": "restart|start|reload|none",
     "confidence": 0.0-1.0, "explain": "one sentence"}

The endpoint is the house Ollama port (127.0.0.1:11600). A local 0.5-1B
model works with the same contract — set model= in the config file.
"""
from __future__ import annotations

import json
import pathlib
import re
import urllib.request

ENDPOINT = "http://127.0.0.1:11600/api/chat"
MODEL = "glm-5.3-flash:cloud"      # swap for a local 0.5-1B via config
TIMEOUT = 30
MAX_LINES = 40
MIN_CONFIDENCE = 0.55
ACTIONS = frozenset({"restart", "start", "reload", "none"})

_JSON_RE = re.compile(r"\{.*\}", re.S)

PROMPT = """You are the repair triage for a Linux security service.
Read the log excerpt and answer with ONE JSON object and nothing else:
{"cause": "<short-kebab-cause>", "action": "<restart|start|reload|none>",
 "confidence": <0..1>, "explain": "<one sentence>"}

Rules:
- Choose restart when the process crashed, hung, or exited with an error
  that a restart would clear.
- Choose start when the service is inactive/disabled rather than failing.
- Choose reload when the config is valid but the running process is stale.
- Choose none when the cause needs a human (disk full, permissions, port
  conflict, missing package, corrupt data).
- Never invent commands. Only the four action words are allowed.

Log excerpt:
---
%s
---"""


def config_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "ai-triage.json"


def load_config(data_dir) -> dict:
    """Off unless the owner turned it on.

    Keys: enabled, model, endpoint, min_confidence, timeout_sec.
    """
    try:
        doc = json.loads(config_path(data_dir).read_text())
        if isinstance(doc, dict):
            return doc
    except (OSError, ValueError):
        pass
    return {"enabled": False}


def parse_reply(text: str, min_conf: float = MIN_CONFIDENCE) -> dict | None:
    m = _JSON_RE.search(text or "")
    if not m:
        return None
    try:
        doc = json.loads(m.group(0))
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    action = str(doc.get("action") or "").strip().lower()
    try:
        conf = float(doc.get("confidence"))
    except (TypeError, ValueError):
        return None
    if action not in ACTIONS or not 0.0 <= conf <= 1.0:
        return None
    if conf < min_conf:
        return None
    return {"cause": str(doc.get("cause") or "unknown")[:60],
            "action": action, "confidence": conf,
            "explain": str(doc.get("explain") or "")[:200]}


def scrub(lines) -> str:
    """Keep the log tail short and drop obviously personal material: absolute
    home paths become ~ and long tokens are elided."""
    out = []
    for line in str(lines or "").splitlines()[-MAX_LINES:]:
        line = re.sub(r"/home/[^/\s]+", "~", line)
        line = re.sub(r"\b[0-9a-f]{32,}\b", "<hex>", line)
        out.append(line[:300])
    return "\n".join(out)


def triage(lines, model=MODEL, endpoint=ENDPOINT, timeout=TIMEOUT,
           min_conf=MIN_CONFIDENCE,
           opener=urllib.request.urlopen) -> dict | None:
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": PROMPT % scrub(lines)}],
        "stream": False, "think": False,
        "options": {"num_predict": 220, "temperature": 0.1},
    }).encode()
    req = urllib.request.Request(endpoint, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with opener(req, timeout=timeout) as resp:
            doc = json.loads(resp.read().decode("utf-8", "replace"))
        text = (doc.get("message") or {}).get("content") or ""
        return parse_reply(text, min_conf=min_conf)
    except Exception:
        return None


def make(data_dir):
    """Build the callable selfheal.py expects, or None when disabled."""
    cfg = load_config(data_dir)
    if not cfg.get("enabled"):
        return None
    model = str(cfg.get("model") or MODEL)
    endpoint = str(cfg.get("endpoint") or ENDPOINT)
    try:
        min_conf = float(cfg.get("min_confidence", MIN_CONFIDENCE))
    except (TypeError, ValueError):
        min_conf = MIN_CONFIDENCE
    try:
        timeout = int(cfg.get("timeout_sec", TIMEOUT))
    except (TypeError, ValueError):
        timeout = TIMEOUT
    return lambda lines: triage(lines, model=model, endpoint=endpoint,
                                timeout=timeout, min_conf=min_conf)
