"""appfw.scope — per-app identity from cgroupv2 (plan Task 4, design §6.1 [1]).

The packet layer's subject changes from the website to the PROGRAM.
cgroup_scope() reads /proc/<pid>/cgroup; only the unified v2 hierarchy
(0::...) is honored — a v1/hybrid host is logged and treated as fully
unscoped (refuse to guess). Unidentified programs share one explicit
class token; nothing here can raise into the decision chain.
"""
from __future__ import annotations

import pathlib


_UNIFIED = "0::"
UNKNOWN_CLASS = "<unknown>"


class AppIdentity:
    __slots__ = ("scope", "basename", "level", "scoped", "class_token")

    def __init__(self, scope: str, basename: str, level: int, scoped: bool,
                 class_token: str = ""):
        self.scope = scope
        self.basename = basename
        self.level = level
        self.scoped = scoped
        self.class_token = class_token or basename or UNKNOWN_CLASS


def _read_cgroup(pid: int | None) -> str:
    """Read the cgroup line(s); OSError propagates only to cgroup_scope,
    which never lets it reach the chain. Returns '' when unreadable."""
    if pid is None or pid <= 0:
        return ""
    try:
        return pathlib.Path(f"/proc/{pid}/cgroup").read_text()
    except OSError:
        return ""


def cgroup_scope(pid: int | None) -> str:
    """The unified-hierarchy scope path for pid, or '' (never raises,
    even if the reader itself raises)."""
    try:
        text = _read_cgroup(pid)
    except OSError:
        return ""
    for line in text.splitlines():
        if line.startswith(_UNIFIED):
            # kernel-canonical ABSOLUTE path (leading '/') — the shape
            # every consumer (identity(), _depth_of, _scope_basename)
            # already tolerates; ONE tokenizer both readers share (M2:
            # appfw/enforce delegates here)
            return line[len(_UNIFIED):].strip()
    # No 0:: line at all: a cgroup-v1 (hybrid) host. Nothing here is a
    # v2 scope; treat every pid as unscoped rather than guess.
    if text.strip():
        print("appfw.scope: no unified 0:: entry — cgroup v1 host, "
              "treating as unscoped")
    return ""


def identity(scope_path: str, pid: int | None = None) -> AppIdentity:
    """Classify one scope path. '' ⇒ unscoped. level = path depth
    (1-based count of segments); 0 when unscoped."""
    scope_path = (scope_path or "").strip()
    if not scope_path or scope_path == "/":
        return AppIdentity("", "", 0, False, UNKNOWN_CLASS)
    parts = [p for p in scope_path.split("/") if p]
    level = len(parts)
    basename = parts[-1] if parts else ""
    return AppIdentity(scope_path, basename, level, True, basename)
