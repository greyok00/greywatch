#!/usr/bin/env python3
"""reconcile-privileged.py — the one privileged step of the 2026-11-12
"fix all" wave. Run as root on the live install:

    sudo python3 tools/reconcile-privileged.py

What it does (in order, each step idempotent, each step honest):

1. Trim the event ledger to its cap using the daemon's own trim logic
   (tail keep of MAX_EVENTS lines through atomic_replace) — the live
   service predates the cap and its hourly trim has been a no-op, so the
   ledger sits at ~225k lines. The doctor's ledger row flips READY the
   next time the running daemon publishes (or after a service refresh).
2. Deploy the rebuilt knowledge index (docs + digests + manual +
   runbooks, junk-free) to /var/lib/greywatch/knowledge-index.json via
   os.replace from a same-filesystem staging temp — the atomic swap the
   assistant's mtime cache expects. Regenerated fresh here from the
   DEPLOYED checkout so it matches what the assistant ships.
3. Chown/chmod the runtime files to the deployment convention
   (root:grey 0640 for the index) without touching anything else.

The script never starts or stops services, never calls out to the
network, and prints one line per action so the owner can audit it.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys

DATA = pathlib.Path("/var/lib/greywatch")
MAX_EVENTS = 20_000


def trim_ledger() -> None:
    """The daemon's own trim_events (tail-keep through atomic replace),
    run once outside the service because the running copy predates it."""
    events = DATA / "events.jsonl"
    if not events.exists():
        print(f"ledger: no events file at {events}")

        return
    from collections import deque
    with open(events, "r", encoding="utf-8", errors="replace") as fh:
        total = sum(1 for _ in fh)
    if total <= MAX_EVENTS:
        print(f"ledger: already within cap ({total} lines)")
        return
    with open(events, "r", encoding="utf-8", errors="replace") as fh:
        tail = deque(fh, maxlen=MAX_EVENTS)
    tmp = events.with_suffix(".jsonl.reconcile-tmp")
    with open(tmp, "w", encoding="utf-8") as out:
        out.writelines(tail)
        out.flush()
        os.fsync(out.fileno())
    tmp.chmod(0o640)
    shutil.chown(tmp, user="root", group="grey")
    os.replace(tmp, events)
    print(f"ledger: trimmed {total} -> {MAX_EVENTS} lines "
          "(atomic replace, cap policy honored)")


def deploy_index() -> None:
    """Rebuild the assistant knowledge index from the deployed tree and
    swap it in atomically."""
    lib = pathlib.Path("/usr/lib/greywatch")
    if not (lib / "tools" / "build_knowledge_index.py").exists():
        print("index: deployed tools/ missing; falling back to /opt copy")
        lib = pathlib.Path("/opt/greywatch")
    script = lib / "tools" / "build_knowledge_index.py"
    stage = DATA / "knowledge-index.json.reconcile-tmp"
    import subprocess
    # GREYWATCH_DATA_DIR points the builder's gwpaths at a staging dir;
    # the builder writes its output there, we move it into place after.
    staging_data = DATA / "reconcile-staging"
    staging_data.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GREYWATCH_DATA_DIR=str(staging_data),
               PYTHONPATH=str(lib))
    r = subprocess.run(["python3", str(script)], env=env,
                       capture_output=True, text=True)
    built = staging_data / "knowledge-index.json"
    if r.returncode != 0 or not built.exists():
        print(f"index: build FAILED rc={r.returncode}: "
              f"{(r.stderr or r.stdout or '')[-300:]}")
        return
    # 0640 root:grey — the deployment convention for root-written files
    # the desktop user reads.
    built.chmod(0o640)
    shutil.chown(built, user="root", group="grey")
    os.replace(built, DATA / "knowledge-index.json")
    print(f"index: deployed {r.stdout.strip() or 'rebuilt'} "
          f"-> {DATA / 'knowledge-index.json'}")
    shutil.rmtree(staging_data, ignore_errors=True)


def main() -> int:
    if os.geteuid() != 0:
        print("run as root: sudo python3 tools/reconcile-privileged.py")
        return 2
    trim_ledger()
    deploy_index()
    return 0


if __name__ == "__main__":
    sys.exit(main())
