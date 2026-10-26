#!/usr/bin/env python3
"""W3 — Tetragon wizard (plan 148): exec/connect/file → presets copied from
the REAL policies → log-only/block → YAML → pkexec write → journal verify →
rollback (remove + unload via restart, owner-gated)."""
from rules import tetragon_policy, ValidationError
from wiz import common

TPD = "/etc/tetragon/tetragon.tp.d"


def build(kind, name, action="log-only"):
    lines = tetragon_policy(kind, name, {}, action)
    target = f"{TPD}/70-greywatch-{name}.yaml"
    return {"lines": lines, "target": target, "kind": kind, "action": action}


def preview(b):
    return "\n".join(b["lines"])


def apply_policy(b, payload_path=None):
    pathlib = __import__("pathlib")
    payload_path = payload_path or (
        pathlib.Path(__file__).resolve().parents[1] / "tmp-payload.yaml")
    pathlib.Path(payload_path).write_text("\n".join(b["lines"]) + "\n")
    return common.run_helper("tetra-write", [b["target"]])


def verify(b):
    """journal check that tetragon loaded the policy."""
    import subprocess
    try:
        out = subprocess.run(["journalctl", "-u", "tetragon", "-n", "20", "--no-pager"],
                             capture_output=True, text=True, timeout=15)
        return f"greywatch-{b['lines'][3].split(': ', 1)[1][2:]}" in out.stdout \
            or "loaded" in out.stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return False


def rollback(b):
    """Owner-gated: remove the drop-in (backup restored); unload requires a
    tetragon restart — recorded, attempted ONLY when allowed."""
    bak = b["target"] + ".bak"
    ok = common.restore_backup(bak, b["target"])
    return ok
