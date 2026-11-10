#!/usr/bin/env python3
"""build_digests.py - verify + index the assistant's tool digest corpus.

The committed digests in doc/tool-digests/*.md were distilled from the
gw-tools knowledge-ingestor db (the greysearch RAG lane, local, no
ollama/no network). This script is the honest checker: per tool it
confirms the digest exists, is complete, and either cites the db lane or
flags itself NOT COMPRESSED. `--index` rewrites doc/tool-digests/index.md.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIGESTS = ROOT / "doc" / "tool-digests"
DB = pathlib.Path("/home/grey/knowledge-ingestor/dbs/gw-tools")

DIGEST_TOOLS = (
    "psad", "rkhunter", "aide", "clamav", "arpwatch",
    "lynis", "nftables", "appfw", "greywatch",
)


def db_tools():
    """Tools with records in the gw-tools db (empty when db is absent)."""
    pack = DB / "pack.jsonl"
    tools = set()
    if pack.exists():
        for line in pack.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            title = (rec.get("t") or rec.get("title") or "")
            title = title.replace("MAN PAGE: ", "").replace(" - part", "|part")
            head = title.split("|")[0].strip().lower()
            # the man page and the digest name the virus tool differently
            head = "clamav" if head == "clamd" else head
            for tool in DIGEST_TOOLS:
                if head == tool or head.split(" - ")[0] == tool:
                    tools.add(tool)
    return tools


def check(digests_dir=DIGESTS, tools=DIGEST_TOOLS, out=sys.stdout):
    rows, bad = [], []
    for tool in tools:
        path = digests_dir / f"{tool}.md"
        if not path.exists():
            rows.append((tool, "MISSING")); bad.append(tool); continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if len(lines) < 20 or "HEURISTICS:" not in text:
            rows.append((tool, "THIN/NO-HEURISTICS")); bad.append(tool); continue
        if "ollama" in text.lower():
            rows.append((tool, "FORBIDDEN-LANE")); bad.append(tool); continue
        state = "COMPRESSED-DB" if tool in db_tools() else "NOT-COMPRESSED"
        rows.append((tool, state))
    for tool, state in rows:
        print(f"DIGEST {tool}: {state}", file=out)
    return rows, bad


def index(rows, digests_dir=DIGESTS):
    lines = ["# Tool digests (assistant corpus)", ""]
    for tool, state in rows:
        entry = f"- [{tool}](./{tool}.md)"
        if state != "COMPRESSED-DB":
            entry += f" - {state}"
        lines.append(entry)
    (digests_dir / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    argv = sys.argv[1:]
    rows, bad = check()
    if "--index" in argv:
        index(rows)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
