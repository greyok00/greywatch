"""ITER-0002: the pinned soak (REQ-030).

The daemon loop survives N cycles over an already-populated data dir:
ledgers present and over cap going in, a noisy collector feeding valid
events and malformed lines every pass, and afterwards the ledgers are
within their caps, status.json/doctor truth is restored, and no loop-
category failure was raised. The by-hand soak of 11-07 becomes
permanent evidence.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import greywatch_daemon as gd
from tests.test_daemon_loop import mk_daemon, _reg
from greywatch_daemon import read_events

CYCLES = 25
MAX_EVENTS = 30


def _prepopulate(d):
    """Ledgers arrive the way a long-lived machine's would: events over
    cap, a learning ledger, a malformed log with history."""
    with open(d.events_path, "w") as f:
        for i in range(MAX_EVENTS + 40):        # over cap on purpose
            f.write(json.dumps({"ts": f"2026-11-08T00:{i // 60:02d}",
                                "from_tool": "yara-watch",
                                "severity": "INFO",
                                "text": f"seed {i}"}) + "\n")
    import os
    # the daemon's own files are 0600; append_checked and the staged
    # trim refuse anything group/world-writable, so the seeds must
    # arrive the way root left them
    os.chmod(d.events_path, 0o600)
    (d.data_dir / "learning-seen.jsonl").write_text(
        "\n".join('{"ts":"2026-11-08T00:00:00+00:00","app":"/bin/s",'
                  '"host":"old.example","port":1,"proto":"tcp"}'
                  for _ in range(40)) + "\n")
    (d.data_dir / "malformed.log").write_text(
        "yara-watch\t{old-junk\n" * 1500)
    os.chmod(d.data_dir / "malformed.log", 0o600)   # daemon's own mode
    os.chmod(d.data_dir / "learning-seen.jsonl", 0o600)


def test_soak_n_cycles_over_a_populated_data_dir(tmp_path):
    from unittest.mock import patch
    d = mk_daemon(tmp_path, max_events=MAX_EVENTS)
    _prepopulate(d)

    # a mix every cycle: two honest events, one malformed line, one
    # tool state flip so write_status never sees a frozen snapshot
    def burst(tailers, settle):
        n = getattr(d, "_soak_i", 0)
        d._soak_i = n + 1
        return [
            ("yara-watch",
             f"eicar /tmp/x{n} (realtime sha256:{n:064x})"),
            ("fail2ban",
             f"2026-11-08 01:00:{n:02d},1 fail2ban.actions [1]: "
             f"NOTICE [sshd] Ban 203.0.113.{n % 250 + 1}"),
            ("responderd", "{definitely-not-json"),
        ]

    with patch.object(d, "collect_burst", side_effect=burst):
        for _ in range(CYCLES):
            snap = d.run_once(tailers=[], settle=0.01)
    # the loop's trim runs on its own clock (hourly), not per cycle:
    # give the soak its trim pass the way run_forever would
    d.trim_events()

    # no unhandled failure anywhere in the loop path (the soak would
    # have raised); nothing in the loop category on the board
    loop_fails = snap["failures"].get("loop")
    assert not loop_fails, loop_fails

    # ledgers inside their stated caps after N cycles
    assert len(read_events(d.events_path)) <= MAX_EVENTS
    seen_lines = (d.data_dir / "learning-seen.jsonl") \
        .read_text().splitlines()
    from appfw.policy import KEEP_LEDGER_LINES
    assert len(seen_lines) <= KEEP_LEDGER_LINES
    mal_lines = (d.data_dir / "malformed.log").read_text().splitlines()
    assert len(mal_lines) <= 2000, len(mal_lines)

    # the truth surfaces restored: status on disk, fresh, with the
    # doctor rows; doctor-last.json beside it
    status = json.loads(d.status_path.read_text())
    assert status.get("updated")
    assert "doctor" in status, list(status)[:20]
    doc_last = d.data_dir / "doctor-last.json"
    assert doc_last.exists()
    rows = json.loads(doc_last.read_text())
    assert isinstance(rows, (list, dict))

    # the newest events really are the newest (trim keeps the tail)
    evs = read_events(d.events_path)
    texts = [e.get("text", "") for e in evs[-2:]]
    assert f"x{CYCLES - 1}" in " ".join(texts)
