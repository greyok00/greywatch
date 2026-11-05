#!/usr/bin/env python3
"""Delete the .py fallback of every module that ships compiled.

The compiled release is the product: a module that ships as an
extension module (.so) should not also ship a readable source copy.
Anything the system runs by path — the daemon, the CLI, the GTK
entrypoint, the helpers — is never compiled, so it has no .so sibling
and survives untouched. The rule is purely mechanical: no policy list
to keep in sync with build-cython.sh.

    drop_fallbacks.py PATH [PATH ...]
"""
import pathlib
import sys


def main(paths):
    dropped = []
    for base in map(pathlib.Path, paths):
        for py in sorted(base.rglob("*.py")):
            if list(py.parent.glob(py.stem + ".cpython-*.so")):
                py.unlink()
                dropped.append(py)
    for p in dropped:
        print("dropped fallback:", p.relative_to(p.parents[2]))
    print(f"dropped {len(dropped)} fallback .py (compiled modules ship .so only)")
    return 0 if dropped is not None else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)