# tools/build_knowledge_index.py
"""Build data/knowledge-index.json for the embedded assistant.

Chunk every readable fact source the app ships: HELP/ topic HTML and
markdown, runbooks, README.md, and one summary chunk per registry tool.
Not fact sources, and skipped deliberately: the blocklist blob
(data/blocklist.txt is a 2 MB filter list the app consumes, not a fact
the assistant can explain — it drowned 2860 of the 4088 chunks in the
2026-11-12 rebuild), hidden trees (.git, .pytest_cache, .superpowers:
60+ junk chunks shipped the same day), tests/ fixture prose, and
one-off plan/scratch files (SKIP_FILE_NAMES). Run at install time; the
assistant only reads the finished JSON.
"""
import json
import sys
import pathlib
from html.parser import HTMLParser

SKIP_PATH_PREFIXES = ("data/", "tests/", "dist/", "docs/superpowers/", "doc/shots/")
SKIP_FILE_NAMES = ("CHANGELOG.md", "REVERT-AND-FIX-PLAN.md",
                   "VISUAL-PLAN-UI.md", "TODO.md")
# 50 plan/brainstorm chunks rode the 2026-11-12 install build through
# docs/superpowers/ (the junk-scan law covered hidden trees but not this
# visible one) — plan docs are working notes, not app facts.

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHUNK_MAX = 800


class _Textify(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self._skip = [], 0

    def handle_starttag(self, tag, _a):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def _read_text(path: pathlib.Path) -> str:
    if path.suffix == ".html":
        p = _Textify()
        p.feed(path.read_text(errors="replace"))
        return "\n".join(p.parts)
    return path.read_text(errors="replace")


def _chunks(text: str):
    paras = []
    for para in text.split("\n\n"):
        para = para.strip()
        while len(para) > CHUNK_MAX:  # a single oversized paragraph has no
            cut = para.rfind("\n", 0, CHUNK_MAX)  # paragraph boundary left;
            if cut < CHUNK_MAX // 2:  # fall back to line, word, then a hard cut
                cut = para.rfind(" ", 0, CHUNK_MAX)
            if cut <= 0:
                cut = CHUNK_MAX
            paras.append(para[:cut])
            para = para[cut:].strip()
        if para:
            paras.append(para)
    buf, out = "", []
    for para in paras:
        if len(buf) + len(para) + 2 > CHUNK_MAX and buf:
            out.append(buf.strip())
            buf = ""
        buf += para + "\n\n"
    if buf.strip():
        out.append(buf.strip())
    return out


def build(corpus_root: pathlib.Path, out_path: pathlib.Path,
          registry_path: pathlib.Path | None = None) -> int:
    chunks = []
    for p in sorted(corpus_root.rglob("*")):
        # Skip VCS metadata, caches and anything hidden: a checkout's
        # .git hooks, .pytest_cache notes and .superpowers brainstorm
        # pages are not app facts, and the 2026-11-12 rebuild found 60+
        # such junk chunks shipped to the assistant's context pool.
        rel = p.relative_to(corpus_root)
        if any(part.startswith(".") for part in rel.parts):
            continue
        rp = rel.as_posix()
        if rp.startswith(SKIP_PATH_PREFIXES) or p.name in SKIP_FILE_NAMES:
            continue
        if not p.is_file() or p.suffix in (".py", ".so", ".jsonl", ".pyc", ".sh"):
            continue
        if p.suffix not in (".md", ".html", ".htm", ".txt"):
            continue
        try:
            text = _read_text(p)
        except OSError:
            continue
        for i, piece in enumerate(_chunks(text)):
            chunks.append({"id": f"{rel.as_posix()}#{i}", "source": rel.as_posix(),
                           "title": rel.as_posix(), "text": piece})
    if registry_path and registry_path.exists():
        entries = json.loads(registry_path.read_text())
        if isinstance(entries, dict):
            entries = entries.get("tools", [])
        for t in entries:
            body = f"{t.get('name')}: {t.get('label')} - unit {t.get('unit')}."
            chunks.append({"id": f"registry:{t['name']}",
                           "source": "registry.json",
                           "title": t.get("name", "tool"),
                           "text": body})
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Owner 2026-11-14: the knowledge library is bigger than the app's
    # own tree. State-dir knowledge/extra/** ingest as first-class
    # chunks (research guides, linux command notes, anything a future
    # ingester drops there), tagged with their own source path so the
    # pool grows in place without re-shipping the app.
    # the state dir is wherever the index is being written: the test
    # sandbox and the real machine behave identically
    extra_n, extra_sources = _extra_chunks(out_path.parent)
    chunks.extend(extra_n)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    meta = {"version": 2, "built_at": _utcnow(),
            "sources": {"shipped": str(corpus_root),
                        "extra": sorted(extra_sources)},
            "chunks": chunks}
    out_path.write_text(json.dumps(meta))
    return len(chunks)


def _utcnow():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _extra_root(data_dir=None) -> pathlib.Path:
    """Where in-process knowledge lands; the same root the sync and the
    install scripts copy ingested docs into."""
    if data_dir is None:
        try:
            import gwpaths
            data_dir = gwpaths.data_dir()
        except Exception:
            data_dir = ROOT / "data"
    return pathlib.Path(data_dir) / "knowledge" / "extra"


def _extra_chunks(data_dir=None, max_bytes: int = 0) -> tuple:
    """Chunks for every readable .md/.txt/.html under knowledge/extra/**.
    Tolerant of junk: unwreadable files are skipped, not fatal."""
    root = _extra_root(data_dir)
    chunks, sources = [], []
    if not root.is_dir():
        return chunks, sources
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part.startswith(".") for part in rel.parts):
            continue
        if not p.is_file() or p.suffix not in (".md", ".txt", ".html", ".htm"):
            continue
        try:
            text = _read_text(p)
        except OSError:
            continue
        sources.append(rel.as_posix())
        src = f"extra:{rel.as_posix()}"
        for i, piece in enumerate(_chunks(text)):
            chunks.append({"id": f"{src}#{i}", "source": src,
                           "title": rel.as_posix(), "text": piece})
    return chunks, sources


def main() -> int:
    sys.path.insert(0, str(ROOT))
    import gwpaths
    reg = ROOT / "registry.json"
    out = gwpaths.data_dir() / "knowledge-index.json"
    n = build(ROOT, out, registry_path=reg)
    print(f"knowledge index: {n} chunks -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
