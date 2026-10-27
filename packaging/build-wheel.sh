#!/bin/bash
# packaging/build-wheel.sh — build the pure-Python wheel (the artifact that
# GitHub Packages hosts; GitHub's registry has no Debian type).
#
#   ./packaging/build-wheel.sh [output-dir]       # default: dist
#
# The ENTIRE program tree ships verbatim as package data greywatch/_tree/
# (the same excludes as the .deb payload, minus the compiled .so files —
# the wheel stays py3-none-any), plus a greywatch package with a `gw`
# launcher that bootstraps the tree and runs cli.py — the same
# run-by-path semantics the .deb and the systemd unit already use. The
# source tree is untouched: this script writes its own stage pyproject,
# so the repo's pyproject stays what it is ("not a setuptools build
# project").
set -euo pipefail
GW="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
OUT="${1:-$GW/dist}"
VER="$(python3 -c "import tomllib;print(tomllib.load(open('$GW/pyproject.toml','rb'))['project']['version'])")"
STAGE="$(mktemp -d /tmp/greywatch-wheel.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT

PKG="$STAGE/greywatch"
TREE="$PKG/_tree"
mkdir -p "$PKG/_tree"

cat > "$PKG/__init__.py" <<'EOF'
"""greywatch — the pip wheel package.

The program tree rides verbatim in _tree (a package-data directory); the
`gw` launcher (greywatch._launch) bootstraps it and runs the real CLI.
Full-system integration (systemd units, polkit, icons) comes from the
Debian package or install.sh, not from pip.
"""
EOF

cat > "$PKG/_launch.py" <<'EOF'
"""Launch the real greywatch CLI from the tree pip installed."""
import pathlib
import sys


def main():
    tree = str(pathlib.Path(__file__).resolve().parent / "_tree")
    sys.path.insert(0, tree)
    sys.argv[0] = "gw"
    import cli
    raise SystemExit(cli.main())
EOF

# program tree as package data (source only; the wheel is py3-none-any)
tar -C "$GW" -cf - \
    --exclude='./.git' --exclude='./.github' --exclude='./tests' \
    --exclude='./doc/shots' --exclude='./*.md' --exclude='./runbooks' \
    --exclude='./tmp*' --exclude='./data' --exclude='./build' \
    --exclude='./*__pycache__*' --exclude='./dist' \
    --exclude='./.venv' --exclude='./venv' --exclude='./*.so' \
    --exclude='./.pytest_cache' --exclude='./.ruff_cache' \
    --exclude='./.claude' --exclude='./.mypy_cache' \
    --exclude='./.pre-commit*' --exclude='./.gitignore' \
    . | tar -C "$TREE" -xf -

# build metadata: the stage's own README and LICENSE, generated pyproject
cp "$GW/README.md" "$STAGE/README.md"
cp "$GW/LICENSE" "$STAGE/LICENSE"
cat > "$STAGE/pyproject.toml" <<EOF
[build-system]
requires = ["setuptools>=72"]
build-backend = "setuptools.build_meta"

[project]
name = "greywatch"
version = "$VER"
description = "One dashboard for every protection on a Linux machine"
readme = "README.md"
requires-python = ">=3.12"
authors = [{ name = "greywatch contributors" }]
license = "Apache-2.0"
license-files = ["LICENSE"]

[project.urls]
Homepage = "https://github.com/greyok00/greywatch"

[project.scripts]
gw = "greywatch._launch:main"

[tool.setuptools]
packages = ["greywatch"]

[tool.setuptools.package-data]
greywatch = ["_tree/**/*"]
EOF

python3 -m build --wheel "$STAGE" --outdir "$OUT"
echo "built: $(ls "$OUT"/greywatch-*.whl | head -1)"