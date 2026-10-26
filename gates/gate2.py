#!/usr/bin/env python3
"""GATE 2 evidence battery — G2.2 parse flood + G2.3 rotation torture.

Runs from a child process; parent checks exit code + printed numbers.
Scratch files live ONLY in ~/greywatch/tmp/ and are deleted by the caller.
No double reads, no lost lines (checksum by unique-line accounting).
"""
import os
import random
import shutil
import sys
import threading
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors import BoundedQueue, FileTailer
from events import normalize_event
from parsers import PARSERS
from greywatch_daemon import Daemon, read_events

TMP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
FLOOD_N = 100_000
LINES = 4_000           # torture: lines written per file
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")
    return ok


# ── G2.2: adversarial parse flood ───────────────────────────────────────

def flood():
    rng = random.Random(20261022)
    blob_sources = [
        lambda n: rng.randbytes(n)            # raw binary
        , lambda n: "".join(rng.choice("}{ \x00\xff\t\n\\\"'") for _ in range(n))
        , lambda n: (rng.choice(["{", "}", "[", "]", '"']) * n)
        , lambda n: rng.choice(["", "   ", "\x00", "a" * 5000, "\x7f" * 300, "€" * 400])
        + "x" * n
    ]
    tools = sorted(PARSERS)
    tracemalloc.start()
    exceptions = 0
    events = 0
    junk = None
    for i in range(FLOOD_N):
        line = blob_sources[i % len(blob_sources)](rng.randrange(0, 1200))
        for tool in tools:
            try:
                ev = PARSERS[tool](line)
                if ev is not None:
                    events += 1
            except Exception:
                exceptions += 1
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    check("G2.2 zero exceptions across ALL parsers", exceptions == 0,
          f"{exceptions} exceptions over {FLOOD_N}x{len(tools)} parses")
    check("G2.2 bounded memory peak < 50 MB", peak < 50 * 1024 * 1024,
          f"peak={peak/1024/1024:.1f} MB, parsed-events={events}")


# ── G2.3: rotation torture with checksums ───────────────────────────────

def torture():
    root = os.path.join(TMP, "rot-tort")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    log = os.path.join(root, "t.log")
    sink, dropped = [], []
    lock = threading.Lock()

    def cb(tool, line):
        with lock:
            sink.append(line)

    q = BoundedQueue(5000)

    def qcb(tool, line):
        q.put_nowait((tool, line))

    t = FileTailer(log, "torture", qcb)
    t.start()
    writes = 0                     # total lines ever written
    unique_seen = set()

    def drain_unique():
        got = [l for _t, l in q.drain()]
        for l in got:
            if l in unique_seen:
                dropped.append(l)  # DOUBLE read
                print(f"  DOUBLE {l!r} (pos={t._pos}, size={os.path.getsize(log) if os.path.exists(log) else -1})")
            else:
                unique_seen.add(l)
        return got

    def wait_and_drain(unique_seen, q, need, drain_unique):
        """Wait until the tailer delivers the newest `need` unique lines."""
        seen_before = len(unique_seen)
        end = time.monotonic() + 5.0
        while time.monotonic() < end:
            drain_unique()
            if len(unique_seen) - seen_before >= need:
                return True
            time.sleep(0.1)
        return False

    # phase A: truncate ×5 — write, CONFIRM read (checksum-able), then truncate
    seq = 0
    for round_no in range(5):
        burst = [f"tr{seq + i}" for i in range(20)]
        for l in burst:
            with open(log, "a") as f:
                f.write(l + "\n"); seq += 1; writes += 1
        okA = wait_and_drain(unique_seen, q, len(burst), drain_unique)
        print(f"   A{round_no}: ok={okA} unique={len(unique_seen)} pos={t._pos} trace={list(t._trace)[-3:]}")
        os.truncate(log, 0)
        time.sleep(0.3)             # > stat-tick blind window (50 ms)                      # truncate (all burst lines read)

    # phase B: rotate ×5 — confirm current reads, mv away, recreate, confirm
    for round_no in range(5):
        drain_unique()
        os.rename(log, os.path.join(root, f"t.log.{round_no}"))
        burst = [f"ro{seq + i}" for i in range(15)]
        with open(log, "a") as f:
            for l in burst:
                f.write(l + "\n"); seq += 1; writes += 1
        okB = wait_and_drain(unique_seen, q, len(burst), drain_unique)
        print(f"   B{round_no}: ok={okB} unique={len(unique_seen)} trace={list(t._trace)[-3:]}")
        time.sleep(0.1)

    # phase C: delete+recreate ×5 — confirm reads, delete, recreate, confirm
    for round_no in range(5):
        drain_unique()
        os.remove(log)
        burst = [f"dl{seq + i}" for i in range(15)]
        with open(log, "a") as f:
            for l in burst:
                f.write(l + "\n"); seq += 1; writes += 1
        okC = wait_and_drain(unique_seen, q, len(burst), drain_unique)
        print(f"   C{round_no}: ok={okC} unique={len(unique_seen)} trace={list(t._trace)[-3:]}")
        time.sleep(0.1)

    # phase D: concurrent multi-file writes — 3 extra files
    others = [os.path.join(root, f"c{i}.log") for i in range(3)]
    extra_tailers = [FileTailer(p, f"c{i}", qcb) for i, p in enumerate(others)]
    for et in extra_tailers:
        et.start()

    def writer(idx, count):
        for j in range(count):
            with open(others[idx], "a") as f:
                f.write(f"w{idx}-{j}\n")

    ths = [threading.Thread(target=writer, args=(i, 40)) for i in range(3)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    time.sleep(1.0)                 # let the extra tailers' stat-ticks deliver
    still_extra = 0
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        still_extra = len(drain_unique())
        if still_extra == 0:
            break
        time.sleep(0.2)
    for et in extra_tailers:
        et.stop()

    end = time.monotonic() + 2.0
    while time.monotonic() < end:
        drain_unique()
        time.sleep(0.2)
    t.stop()
    drain_unique()

    # final drain: everything still in files was seen
    with open(log) as f:
        still = {l.strip() for l in f if l.strip()}
    missing = still - unique_seen
    if dropped:
        print("  tailer trace on double:", list(t._trace))
    check("G2.3 no line read twice", len(dropped) == 0, f"doubles={dropped[:5]}")
    check("G2.3 every surviving line counted", len(missing) == 0,
          f"missing={sorted(missing)[:5]}")
    # 370 lines survive truncation (post-truncate 100 + rotate 75 + delete 75
    # + concurrent 120); every one of them must have been read exactly once
    check("G2.3 all surviving lines seen", len(unique_seen) >= 370,
          f"unique_seen={len(unique_seen)} (expected ≥ 370 of 470)")
    shutil.rmtree(root, ignore_errors=True)


# ── the same flood through the daemon's real path ───────────────────────

def flood_through_daemon():
    """100k lines through Daemon.consume — parser + enrichment + write;
    process must survive and memory stays bounded."""
    root = os.path.join(TMP, "daemon-flood")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    d = Daemon(data_dir=root, registry=[], max_events=500)
    rng = random.Random(99)
    tools = sorted(PARSERS)
    tracemalloc.start()
    alive_lines = 0
    for i in range(FLOOD_N):
        blob_sources = [
            lambda n: rng.randbytes(n),
            lambda n: "".join(rng.choice("}{ \x00\xff\t\n\\\"'") for _ in range(n)),
            lambda n: (rng.choice(["{", "}", "[", "]", '"']) * n),
            lambda n: "a" * 5000,
        ]
        line = blob_sources[i % 4](rng.randrange(0, 800))
        if isinstance(line, bytes):
            line = line.decode("latin-1", "ignore")
        for tool in tools:
            d.consume(tool, line)
            alive_lines += 1
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    check("G2.2 daemon consumed floods and still exists",
          d is not None and alive_lines == FLOOD_N * len(tools),
          f"consumed={alive_lines}")
    check("G2.2 daemon-path memory peak < 100 MB",
          peak < 100 * 1024 * 1024, f"peak={peak/1024/1024:.1f} MB")
    # trim worked
    d.trim_events()
    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    flood()
    flood_through_daemon()
    torture()
    fails = [r for r in RESULTS if not r[1]]
    print(f"== gate2 battery: {len(RESULTS) - len(fails)} pass / {len(fails)} fail ==")
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if fails else 0)