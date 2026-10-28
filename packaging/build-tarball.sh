#!/bin/bash
# packaging/build-tarball.sh — build the release tarball.
#
#   ./packaging/build-tarball.sh [output-dir]     # default: dist
#
# The tarball is what `sudo ./install.sh` runs from. It carries the program
# tree, the systemd/polkit templates install.sh fills in, and the compiled
# .so modules when they are present; tests, build tooling and screenshots
# stay out. Python files are stripped of comments and docstrings, matching
# the .deb and the wheel.
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
    --exclude='./runbooks' --exclude='./tmp*' --exclude='./data' \
    --exclude='./build' --exclude='./*__pycache__*' --exclude='./dist' \
    --exclude='./.venv' --exclude='./venv' --exclude='./.pytest_cache' \
    --exclude='./.ruff_cache' --exclude='./.claude' \
    --exclude='./.mypy_cache' --exclude='./.pre-commit*' \
    --exclude='./.gitignore' \
    . | tar -C "$TREE" -xf -

python3 "$GW/packaging/strip-source.py" "$TREE"

tar czf "$OUT/$NAME" -C "$TREE" .
( cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256" )
echo "built: $OUT/$NAME"
