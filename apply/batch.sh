#!/bin/bash
# : apply a batch of greywatch decision helpers under ONE polkit
# authentication. Input: a JSON file {"items": [{"helper": name,
# "args": [...]}]}. Only helper names that exist as scripts in apply/
# run; each item runs as its own subprocess, nothing is re-interpreted
# by a shell between items. Output: one JSON line {"rcs": [rc, ...]}
# in the input's item order, rc -1 where an item could not even start.
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
[ "${1:-}" ] || { echo "batch: no input file given" >&2; exit 2; }
[ -f "$1" ] || { echo "batch: input file missing: $1" >&2; exit 2; }
exec python3 - "$GW_DIR" "$1" "$GW_DIR/apply" <<'PY'
import json, pathlib, re, subprocess, sys

apply_dir = pathlib.Path(sys.argv[3])
try:
    doc = json.loads(pathlib.Path(sys.argv[2]).read_text())
except (OSError, ValueError):
    print("batch: unreadable input file", file=sys.stderr)
    sys.exit(2)
items = doc.get("items") if isinstance(doc, dict) else []
if not isinstance(items, list):
    print("batch: no items list in input", file=sys.stderr)
    sys.exit(2)
out = []
for it in items[:200]:
    name, args = None, []
    try:
        m = re.fullmatch(r"[a-z0-9-]+", str(it.get("helper") or ""))
        if m:
            name = m.group(0)
        args = [str(a) for a in (it.get("args") or [])]
    except Exception:
        out.append(-1)
        continue
    script = apply_dir / f"{name}.sh" if name else None
    if script is None or not script.is_file():
        out.append(-1)
        continue
    try:
        proc = subprocess.run([str(script)] + args, capture_output=True,
                              text=True, timeout=120)
        out.append(proc.returncode)
    except (OSError, subprocess.TimeoutExpired):
        out.append(-1)
print(json.dumps({"rcs": out}))
PY