"""Headless knowledge base: retrieval the service, CLI and GUI all share.

The index is built by tools/build_knowledge_index.py at install time. This
module is the single reading surface: BM25 ranking lives in
assistant/packer.py (already written and tested), and this adds the parts
a command line needs — a stable answer object, source attribution, and no
dependency on GTK.

Owner 2026-11-13: "all docs ingested with the KB library ingestor ... all
of it available heuristically for the CLI to be able to control."
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def index_path(data_dir=None) -> pathlib.Path:
    if data_dir is not None:
        return pathlib.Path(data_dir) / "knowledge-index.json"
    from gwpaths import data_dir as _dd
    return _dd() / "knowledge-index.json"


def load(data_dir=None) -> list[dict]:
    """Every chunk, or [] when the index has not been built yet."""
    from assistant import packer
    p = index_path(data_dir)
    if not p.exists():
        return []
    try:
        return packer.load_index(p)
    except Exception:
        return []


def search(query: str, k: int = 5, data_dir=None) -> list[dict]:
    """Top-k chunks for a question, best first. Empty = honestly nothing."""
    chunks = load(data_dir)
    if not chunks:
        return []
    from assistant import packer
    try:
        return packer.bm25_top(chunks, query, k=k)
    except Exception:
        return []


def answer(query: str, k: int = 3, data_dir=None) -> dict:
    """One answer object: the question, the passages, and their sources.

    Deliberately dumb and honest: this is retrieval, not generation. Every
    passage carries the file it came from so a human (or the GUI) can check
    it. A caller that wants prose asks assistant/router.py; a caller that
    wants to know WHICH DOC SAYS SO uses this.
    """
    hits = search(query, k=k, data_dir=data_dir)
    return {
        "query": query,
        "found": bool(hits),
        "passages": [
            {"source": h.get("source", ""),
             "title": h.get("title", ""),
             "text": h.get("text", "")}
            for h in hits
        ],
    }


def stats(data_dir=None) -> dict:
    """What is actually ingested, by source file."""
    import collections
    chunks = load(data_dir)
    by_src = collections.Counter(c.get("source", "") for c in chunks)
    return {"chunks": len(chunks), "sources": dict(by_src)}
