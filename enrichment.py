from __future__ import annotations

import json
import pathlib
import re
from typing import Optional

from events import Event

_MAP_PATH = pathlib.Path(__file__).resolve().parent / "nist-map.json"
CVE_RE = _cve_re = re.compile(r"CVE-\d{4}-\d{4,7}(?!\d)")
_FUNC_RE = _re2 = re.compile(r"^(IDENTIFY|PROTECT|DETECT|RESPOND|RECOVER)$")

_cache: dict = {}


def load_map(path=_MAP_PATH) -> dict:
    global _cache
    if not _cache:
        _cache = json.loads(pathlib.Path(path).read_text())["nist_defaults"]
    return _cache


def sync_map_names(registry: list) -> None:
    missing = [t["name"] for t in registry if t["name"] not in load_map()]
    assert not missing, f"nist-map missing tools: {missing}"


def extract_cves(text: str) -> list:
    seen, out = set(), []
    for m in CVE_RE.finditer(text):
        if m.group(0) not in seen:
            seen.add(m.group(0))
            out.append(m.group(0))
    return out[:10]                          # cap: events are not CVE dumps


def enrich(ev: Event) -> Event:
    defaults = load_map().get(ev.from_tool) or {"func": "DETECT", "controls": []}
    func = defaults["func"]
    assert _FUNC_RE.match(func)
    ev.nist_func = func
    ev.nist_control = list(dict.fromkeys(defaults["controls"]))[:6]
    ev.cves = extract_cves(ev.text)
    return ev
