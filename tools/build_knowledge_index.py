# tools/build_knowledge_index.py
"""Build data/knowledge-index.json for the embedded assistant.

Chunks every readable fact source the app ships: HELP/ topic HTML and
markdown, runbooks, README.md, and one summary chunk per registry tool.
Run at install time; the assistant only reads the finished JSON.
"""
import json
import sys
import pathlib
from html.parser import HTMLParser

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
        if not p.is_file() or p.suffix in (".py", ".so", ".jsonl", ".pyc", ".sh"):
            continue
        if p.suffix not in (".md", ".html", ".htm", ".txt"):
            continue
        try:
            text = _read_text(p)
        except OSError:
            continue
        for i, piece in enumerate(_chunks(text)):
            rel = p.relative_to(corpus_root).as_posix()
            chunks.append({"id": f"{rel}#{i}", "source": rel,
                           "title": rel, "text": piece})
    if registry_path and registry_path.exists():
        entries = json.loads(registry_path.read_text())
        if isinstance(entries, dict):
            entries = entries.get("tools", [])
        for t in entries:
            body = f"{t.get('name')}: {t.get('label')} — unit {t.get('unit')}."
            chunks.append({"id": f"registry:{t['name']}",
                           "source": "registry.json",
                           "title": t.get("name", "tool"),
                           "text": body})
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"version": 1, "chunks": chunks}))
    return len(chunks)


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