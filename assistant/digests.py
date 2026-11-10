# assistant/digests.py
"""The doc-digest lane of the heuristic tier (rebuild round 2, task 13).

Compressed tool notes ship with the app in doc/tool-digests/*.md (the
corpus tools/build_digests.py checks). This lane reads, on demand and only
when a question names a tool, the one digest that matches — no model load,
nothing sent anywhere. Every answer carries its basis on its face ("from
the psad digest"), and with no covering digest at all it returns None so
the ladder falls through instead of inventing.
"""
from __future__ import annotations

import pathlib
import re

# The corpus constants live HERE, in the shipped package - not in the
# treeside tools/ checker (the deb ships ui/ + assistant/, never tools/;
# an import of tools. from this module kept the app from ever mounting
# Overview on an installed copy). tools/build_digests.py imports these
# from here, the dependency direction the packaging law wants.
ROOT = pathlib.Path(__file__).resolve().parents[1]
DIGESTS = ROOT / "doc" / "tool-digests"
DIGEST_TOOLS = (
    "psad", "rkhunter", "aide", "clamav", "arpwatch",
    "lynis", "nftables", "appfw", "greywatch",
)

# Question shapes the digest lane answers. The status lane already runs on
# the pack ("is psad red?"), and plain "what is X?" asks keep their pinned
# status answer - the digest lane takes the how/why/meaning shapes it
# explains better than a status row can.
_CUE = re.compile(r"\b(how|why|explain|meaning|means)\b")

# Which digest a question's words name. The registry tool keys first, then
# the labels a person actually types ("antivirus", "app firewall").
# Longest needle wins: "app firewall" must beat the generic "firewall".
_NEEDLES = {
    "nftables": ("nftables", "nft", "packet firewall", "os firewall"),
    "appfw": ("appfw", "app firewall", "application firewall"),
    "psad": ("psad",),
    "rkhunter": ("rkhunter", "rootkit"),
    "aide": ("aide",),
    "clamav": ("clamav", "clamav", "antivirus", "anti-virus", "virus scanner",
               "virus scan"),
    "arpwatch": ("arpwatch",),
    "lynis": ("lynis",),
    "greywatch": ("greywatch",),
}

# Digest sections worth reading out. The command lines stay on disk.
_SECTIONS = ("WHAT IT IS", "WHAT ITS WARNINGS MEAN", "HEURISTICS")
_CAP = 1400


def tool_of(question: str, friendly: dict | None = None) -> str | None:
    """The one digest tool a question names, earliest mention first."""
    low = (question or "").lower()
    hits = []
    for tool, needles in _NEEDLES.items():
        for needle in sorted(set(needles), key=len, reverse=True):
            match = re.search(rf"\b{re.escape(needle)}\w*\b", low)
            if match:
                hits.append((match.start(), -len(needle), tool))
                break
    if not hits:
        return None
    hits.sort()
    earliest = hits[0]
    # "the app firewall" must pin appfw even when 'nft' style needles lose.
    pos, _n, tool = earliest
    return tool if pos >= 0 else None


def load(tool: str) -> str | None:
    """One digest from the checked corpus; None when it does not exist."""
    if tool not in DIGEST_TOOLS:
        return None
    path = DIGESTS / f"{tool}.md"
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def extract(text: str) -> str | None:
    """WHAT IT IS + a few heuristics, in the digest's own words."""
    sections: dict[str, list[str]] = {}
    current, buf = None, []
    for line in text.splitlines():
        stripped = line.strip()
        head = None
        for name in _SECTIONS:
            if stripped.upper().startswith(name + ":") \
                    or stripped.upper() == name:
                head = name
        if head is not None:
            if current is not None:
                sections[current] = buf
            current, buf = head, []
            rest = stripped[len(head):].lstrip(":").strip()
            if rest:
                buf.append(rest)
            continue
        if current is not None and stripped:
            buf.append(stripped)
    if current is not None:
        sections[current] = buf
    out = []
    what = " ".join(sections.get("WHAT IT IS", []))
    if what:
        out.append(what)
    rules = [line for line in sections.get("HEURISTICS", []) if line]
    if rules:
        out.append("Rules of thumb from the digest: "
                   + " ".join(rule.lstrip("- ") for rule in rules[:3]))
    body = " ".join(out).strip()
    if not body:
        return None
    return body[:_CAP]


def answer(question: str, friendly: dict | None = None) -> str | None:
    """The digest text for a question that names one tool and asks a
    what/why/how question; None keeps the ladder honest elsewhere."""
    tool = tool_of(question, friendly)
    if tool is None:
        return None
    if _CUE.search((question or "").lower()) is None:
        return None
    text = load(tool)
    if text is None:
        return None
    body = extract(text)
    if body is None:
        return None
    return (f"From the {tool} digest (compressed notes kept on this "
            f"machine): {body}")
