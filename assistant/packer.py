"""Context packs: the only facts the assistant's answers are built from.

Pure reads: status snapshot, recent events, and BM25 hits over the
offline knowledge index. No network, no daemon calls.
"""
from __future__ import annotations

import json
import math
import pathlib

import gwpaths

CHAR_BUDGET = 8000
SNIPPET_CHARS = 300
RECENT_MAX = 8


def load_index(path: pathlib.Path | None = None) -> list[dict]:
    p = path or gwpaths.data_dir() / "knowledge-index.json"
    try:
        return json.loads(p.read_text())["chunks"]
    except (OSError, KeyError, ValueError):
        return []


def _tokens(text: str) -> list[str]:
    return text.lower().replace("\n", " ").split()


def bm25_top(chunks: list[dict], query: str, k: int = 4,
             min_score: float = 0.0) -> list[dict]:
    q = _tokens(query)
    if not q:
        return []
    docs, df = [], {}
    for c in chunks:
        seen = set(_tokens(c["text"]))
        docs.append(seen)
        for tok in seen:
            df[tok] = df.get(tok, 0) + 1
    n = len(docs)
    avg = (sum(len(d) for d in docs) / n) if n else 1.0
    scored = []
    for i, seen in enumerate(docs):
        s = 0.0
        for tok in set(q):
            tf = _tokens(chunks[i]["text"]).count(tok)
            if not tf:
                continue
            idf = math.log(1 + (n - df.get(tok, 0) + 0.5) / (df.get(tok, 0) + 0.5))
            s += idf * (tf * 2.2) / (tf + 1.5 * (0.75 + 0.25 * len(seen) / avg))
        if s >= min_score:
            scored.append((s, i))
    scored.sort(reverse=True)
    return [chunks[i] for _, i in scored[:k]]


def build_pack(status: dict, events: list[dict], question: str,
               registry: list[dict] | None = None) -> dict:
    tools = (status or {}).get("tools", {})
    green = sum(1 for t in tools.values() if t.get("state") == "GREEN")
    total = len(tools)
    warn = sum(1 for t in tools.values() if t.get("state") in ("YELLOW", "RED"))
    labels = {t["name"]: t.get("label", "") for t in (registry or [])}
    pack_tools = [{"name": n,
                   "state": t.get("state", "UNKNOWN"),
                   "label": labels.get(n) or t.get("label", "")}
                  for n, t in sorted(tools.items())]
    recent = [{"tool": e.get("from_tool", ""), "severity": e.get("severity", ""),
               "text": e.get("text", ""), "ts": e.get("ts", "")}
              for e in (events or [])[:RECENT_MAX]]
    snippets, used = [], 0
    for c in bm25_top(load_index(), question, k=4):
        s = {"title": c.get("title", ""), "source": c.get("source", ""),
             "text": c.get("text", "")[:SNIPPET_CHARS]}
        used += len(s["text"])
        if used > CHAR_BUDGET:
            break
        snippets.append(s)
    return {"status_line":
            f"{green} of {total} protections green, {warn} need attention",
            "tools": pack_tools, "snippets": snippets, "recent": recent}