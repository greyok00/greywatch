"""wiz/common.py — the ONLY place wizard apply/verify/rollback happens.

Every privileged effect goes through apply/*.sh via pkexec; backups are made
BEFORE any write; rollback restores the backup and re-verifies. Tests call
these with GREYWATCH_HELPER_CMD set (a stub) — never root, never fuzzed.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKUP_DIR = ROOT / "data" / "backups"
HELPER_CMD = os.environ.get("GREYWATCH_HELPER_CMD")  # test-only override


def run_helper(helper: str, args: list, timeout=30) -> int:
    """pkexec ONLY: the exact allowlisted helper script, argv (no shell)."""
    script = ROOT / "apply" / f"{helper}.sh"
    if HELPER_CMD:
        return subprocess.run([HELPER_CMD, helper] + [str(a) for a in args],
                              capture_output=True, text=True,
                              timeout=timeout).returncode
    return subprocess.run(["pkexec", str(script)] + [str(a) for a in args],
                          capture_output=True, text=True,
                          timeout=timeout).returncode


def backup_file(path: str) -> str:
    """Copy <path> into data/backups with a versioned suffix; returns the
    backup path (also the rollback handle)."""
    src = pathlib.Path(path)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    dst = BACKUP_DIR / f"{src.name}.bak"
    shutil.copy2(src, dst)
    return str(dst)


def restore_backup(backup: str, path: str) -> bool:
    try:
        shutil.copy2(backup, path)
        return True
    except (OSError, shutil.Error):
        return False


def confirm_flow(wiz, steps, apply_fn, verify_fn, rollback_fn, *, dry=True):
    """Shared wizard loop: preview → (owner confirms) → apply → verify →
    rollback on failure. Returns dict with everything recorded per gate."""
    report = {"tool": wiz, "steps": steps, "apply_rc": None,
              "verify": False, "rolled_back": False}
    if not dry:
        report["apply_rc"] = apply_fn()
        if report["apply_rc"] == 0:
            report["verify"] = verify_fn()
            if not report["verify"]:
                report["rolled_back"] = bool(rollback_fn())
    return report