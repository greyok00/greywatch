"""The GUI is a skin over the CLI; the CLI is the product.

Every page drives the same named commands the CLI already has, through
this one seam: no page invents its own data path, no page writes a state
file. New verbs are added to the CLI first and the page uses them.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _cli_path() -> str:
    here = ROOT / "cli.py"
    if here.exists():
        return str(here)
    found = shutil.which("greywatch")
    return found or "greywatch"


def call(*args: str, timeout: float = 30.0) -> tuple[int, str, str]:
    """One CLI verb, blocking. (rc, stdout, stderr)."""
    try:
        r = subprocess.run(
            [sys.executable, _cli_path(), *args],
            capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        return 124, "", str(e)


def jcall(*args: str, timeout: float = 30.0):
    """One CLI verb asking for --json; returns the parsed doc or None."""
    rc, out, err = call(*args, "--json", timeout=timeout)
    if not out.strip():
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def spawn(*args: str) -> bool:
    """A long CLI verb, detached: the lane works on, the app reports it.
    Nothing waits on the result here."""
    try:
        subprocess.Popen(
            [sys.executable, _cli_path(), *args],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, cwd=str(ROOT),
            start_new_session=True)
        return True
    except OSError:
        return False


def read_state(name: str):
    """One app-owned state file from the data dir, read-only. Returns the
    parsed doc or None; the UI never writes state through a side door."""
    try:
        import gwpaths
        p = pathlib.Path(gwpaths.data_dir()) / name
    except Exception:                    # noqa: BLE001
        p = pathlib.Path("/var/lib/greywatch") / name
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def read_jsonl(name: str, last: int = 400):
    """One app-owned ledger from the data dir, newest-last as a list of
    rows, the file's newest `last` lines. Ledgers are JSON lines, not
    one document; read_state would refuse them by design."""
    try:
        p = pathlib.Path(state_path(name))
    except Exception:                    # noqa: BLE001
        return []
    try:
        lines = _tail_lines(p, last)
    except OSError:
        return []
    out = []
    for ln in lines[-last:]:
        if not ln.strip():
            continue
        try:
            out.append(json.loads(ln))
        except ValueError:
            out.append({"unparsed": ln[:120]})
    return out


def _tail_lines(path: pathlib.Path, last: int,
                block: int = 65536) -> list:
    """The file's newest `last` lines without reading the whole ledger.

    The Timeline and Tools windows read multi-megabyte ledgers on every
    repaint; reading from the end keeps that bounded.
    """
    if last <= 0:
        return []
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        pos = end
        data = b""
        while pos > 0 and data.count(b"\n") <= last:
            step = min(block, pos)
            pos -= step
            handle.seek(pos)
            data = handle.read(step) + data
    return data.decode("utf-8", "replace").splitlines()[-last:]


def state_path(name: str) -> str:
    try:
        import gwpaths
        return str(pathlib.Path(gwpaths.data_dir()) / name)
    except Exception:                    # noqa: BLE001
        return str(pathlib.Path("/var/lib/greywatch") / name)
