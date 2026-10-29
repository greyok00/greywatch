"""Context packs: the only facts the assistant's answers are built from.

Pure reads: status snapshot, recent events, and BM25 hits over the
offline knowledge index. No network, no daemon calls.
"""
from __future__ import annotations

import json
import math
import pathlib

import gwpaths
from ui.models import recent_rows

CHAR_BUDGET = 8000
SNIPPET_CHARS = 300
RECENT_MAX = 8

_INDEX_CACHE: dict = {}          # one slot: (path, mtime, size) -> parsed chunks


def load_index(path: pathlib.Path | None = None) -> list[dict]:
    p = path or gwpaths.data_dir() / "knowledge-index.json"
    try:
        st = p.stat()
        key = (str(p), st.st_mtime_ns, st.st_size)
        cached = _INDEX_CACHE.get(key)
        if cached is not None:
            return cached
        chunks = json.loads(p.read_text())["chunks"]
        _INDEX_CACHE.clear()
        _INDEX_CACHE[key] = chunks
        return chunks
    except (OSError, KeyError, ValueError):
        return []


def _tokens(text: str) -> list[str]:
    return text.lower().replace("\n", " ").split()


_BM25_CACHE: dict | None = None   # one slot, private; see _bm25_corpus()


def _bm25_corpus(chunks: list[dict]) -> dict:
    """Tokenize a corpus once and reuse it while the chunks object is the
    same (keyed on identity AND size; the entry keeps a reference so id()
    cannot be recycled onto a fresh chunk list of the same length)."""
    global _BM25_CACHE
    entry = _BM25_CACHE
    key = (id(chunks), len(chunks))
    if entry is not None and entry["key"] == key and entry["ref"] is chunks:
        return entry
    toks = [_tokens(c["text"]) for c in chunks]
    sets = [set(t) for t in toks]
    df = {}
    for seen in sets:
        for tok in seen:
            df[tok] = df.get(tok, 0) + 1
    n = len(sets)
    avg = (sum(len(d) for d in sets) / n) if n else 1.0
    entry = {"key": key, "ref": chunks, "toks": toks, "sets": sets,
             "df": df, "avg": avg}
    _BM25_CACHE = entry
    return entry


def bm25_top(chunks: list[dict], query: str, k: int = 4,
             min_score: float = 0.0) -> list[dict]:
    q = _tokens(query)
    if not q:
        return []
    entry = _bm25_corpus(chunks)
    toks, sets, df = entry["toks"], entry["sets"], entry["df"]
    n = len(sets)
    avg = entry["avg"]
    scored = []
    for i, seen in enumerate(sets):
        s = 0.0
        for tok in set(q):
            tf = toks[i].count(tok)
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
                   "label": labels.get(n) or t.get("label", ""),
                   "installed": t.get("installed", True),
                   "paused": bool(t.get("paused", False))}
                  for n, t in sorted(tools.items())]
    recent = [{"tool": e.get("from_tool", ""), "severity": e.get("severity", ""),
               "text": e.get("text", ""), "ts": e.get("ts", "")}
              for e in recent_rows(events or [], RECENT_MAX)]
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