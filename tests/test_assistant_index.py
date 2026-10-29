# tests/test_assistant_index.py
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tools.build_knowledge_index import build


def test_build_chunks_md_html_and_registry(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "runbooks").mkdir(parents=True)
    (corpus / "HELP" / "systemd").mkdir(parents=True)
    (corpus / "README.md").write_text(
        "# greywatch\n\nIntro line.\n\nSecond paragraph with tool names.\n")
    (corpus / "runbooks" / "00-HOW-TO-RUN.md").write_text(
        "Run the daemon.\n\nIt tails journals.\n\nAnother paragraph.\n")
    (corpus / "HELP" / "systemd" / "systemd.exec.html").write_text(
        "<html><head><title>systemd.exec</title></head>"
        "<body><p>Environment options for services.</p></body></html>")
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps([
        {"name": "apparmor", "label": "AppArmor (MAC profile)",
         "unit": "apparmor.service"}]))
    out = tmp_path / "knowledge-index.json"
    n = build(corpus, out, registry_path=registry)
    data = json.loads(out.read_text())
    assert data["version"] == 1
    assert n >= 4 and len(data["chunks"]) == n
    texts = " ".join(c["text"] for c in data["chunks"])
    assert "systemd.exec" in texts          # html title textified
    assert "AppArmor (MAC profile)" in texts  # registry harvested
    for c in data["chunks"]:
        assert len(c["text"]) <= 800
        assert c["id"] and c["source"] and c["title"]


def test_build_splits_oversized_paragraph(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir(parents=True)
    long_para = " ".join(f"word{i}" for i in range(400))
    (corpus / "notes.md").write_text(long_para + "\n")
    out = tmp_path / "knowledge-index.json"
    n = build(corpus, out)
    data = json.loads(out.read_text())
    assert n == len(data["chunks"]) and n >= 3
    for c in data["chunks"]:
        assert len(c["text"]) <= 800
        assert c["source"] == "notes.md"
    orig = "".join((long_para + "\n").split())
    got = "".join("".join(c["text"].split()) for c in data["chunks"])
    assert got == orig  # no text lost or duplicated across splits