#!/bin/bash
# packaging/build-tarball.sh — build the release tarball.
#
#   ./packaging/build-tarball.sh [output-dir]     # default: dist
#
# The tarball is what `sudo ./install.sh` runs from. It carries the program
# tree, the systemd/polkit templates install.sh fills in, and the compiled
# .so modules when they are present; tests, build tooling and screenshots
# stay out. Python files are stripped of comments and docstrings, matching
# the .deb, and every module that shipped .so drops its .py fallback —
# the wheel is the one release that still ships readable (stripped) source.
set -euo pipefail
GW="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
OUT="${1:-$GW/dist}"
VER="$(python3 -c "import tomllib;print(tomllib.load(open('$GW/pyproject.toml','rb'))['project']['version'])")"
NAME="greywatch-v$VER-linux-x86_64.tar.gz"
STAGE="$(mktemp -d /tmp/greywatch-tar.XXXXXX)"
TREE="$STAGE/greywatch-v$VER"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$TREE" "$OUT"

tar -C "$GW" -cf - \
    --exclude='./.git' --exclude='./.github' --exclude='./tests' \
    --exclude='./doc/shots' --exclude='./docs' --exclude='./packaging' \
    --exclude='./tools' --exclude='./gates' \
    --exclude='./runbooks' --exclude='./tmp*' --exclude='./data' \
    --exclude='./build' --exclude='./*__pycache__*' --exclude='./dist' \
    --exclude='./.venv' --exclude='./venv' --exclude='./.pytest_cache' \
    --exclude='./.ruff_cache' --exclude='./.claude' \
    --exclude='./.mypy_cache' --exclude='./.pre-commit*' \
    --exclude='./.gitignore' \
    . | tar -C "$TREE" -xf -

python3 "$GW/packaging/strip-source.py" "$TREE"
# the compiled release is the product: a module that shipped .so does
# not also ship readable source (owner 2026-10-30). A .py with a
# compiled sibling goes; everything run by path survives.
python3 "$GW/packaging/drop_fallbacks.py" "$TREE"

# Archive the VERSIONED directory, not its contents: extracting used to
# dump the whole program tree into the current directory.
tar czf "$OUT/$NAME" -C "$STAGE" "greywatch-v$VER"
( cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256" )
echo "built: $OUT/$NAME"
