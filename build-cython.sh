#!/bin/bash
# build-cython.sh — compile the importable modules to .so (Cython build
# path, commit #3). The .so files drop in next to the .py and the import
# machinery prefers them; the .c intermediates live ONLY in a scratch dir.
# Entrypoint scripts (systemd units, launch scripts and pkexec helpers run
# files BY PATH), package __init__.py files, tests, and gate children stay
# .py. The .so files are gitignored here — the source of truth is git.
set -euo pipefail
GW="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$GW"
PY=python3
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

"$PY" - "$SCRATCH" <<'PYEOF'
import pathlib
import sys

from Cython.Build import cythonize
from Cython.Compiler import Options as CythonOptions
from setuptools import Extension, setup

# ship no prose: docstrings are not embedded in the extension modules.
# Cython exposes this as a compile-time option, not a directive.
CythonOptions.docstrings = False

keep_py = {"greywatch_daemon.py", "cli.py", "setup.py", "doctor.py",
           "cve-refresh.py", "app.py", "tray_helper.py",
           "greywatch_watchdog.py"}
skip_top = {"tests", "gates", "doc", "docs", "tools", "packaging",
            "runbooks", ".venv", "venv"}
root = pathlib.Path(".").resolve()
exts = []
for f in sorted(root.rglob("*.py")):
    rel = f.relative_to(root)
    if rel.name in keep_py or rel.name == "__init__.py":
        continue
    if rel.parts[0] in skip_top or "__pycache__" in rel.parts:
        continue
    name = ".".join(rel.with_suffix("").parts)
    exts.append(Extension(name, sources=[str(f)]))
if not exts:
    sys.exit("no modules found")
setup(ext_modules=cythonize(exts, language_level=3,
                           build_dir=sys.argv[1],
                           c_line_in_traceback=False,
                           compiler_directives={
                               "annotation_typing": False,
                               "emit_code_comments": False}),
      script_args=["build_ext", "--inplace"])
PYEOF
echo "built: $(find "$GW" -name '*.so' -newer "$GW/README.md" | wc -l) extension modules in place (intermediates removed with $SCRATCH)"