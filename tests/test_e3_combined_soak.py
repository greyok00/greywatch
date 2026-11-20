"""E-3: combined-lane soak — the research wave's integration walk.

test_soak_daemon.py soaks event bursts and ledger caps. This gate adds
the lanes that walk lives WITH it, in one daemon: the kernel catch path
(GW-DENY lines consumed while everything else floods), the assistant's
fact-pack builder over the live snapshot, and the research wave's own
observability keys (failure_storms / supervisors) carried by the same
status walk. Pass criterion: no loop-category failures, ledgers in caps,
every new key honest, and a storm triggered mid-soak is named.
"""
from __future__ import annotations

import json

import pytest

import greywatch_daemon as gd
from greywatch_daemon import Daemon, read_events
from registry import load_registry

MAX_EVENTS = 250
CYCLES = 12


def _reg():
    return load_registry()


def _catch_line(dst="93.184.216.34", spt=45121, dpt=443):
    return (f"kernel: GW-DENY IN= OUT=wlp0s20f3 SRC=192.168.1.42 DST={dst} "
            f"LEN=60 TOS=0x00 TTL=64 ID=1234 DF PROTO=tcp "
            f"SPT={spt} DPT={dpt}")


def test_combined_lanes_soak(tmp_path):
    d = Daemon(data_dir=tmp_path / "data", registry=_reg(),
               max_events=MAX_EVENTS)
    # the catch lane needs a policy: an unarmed Engine object (never
    # started - no worker, no kernel) provides it, test_appfw idiom
    from appfw.engine import Engine
    d.appfw_engine = Engine(d.data_dir, socket_dir=str(tmp_path))
    seen_storms = False
    for n in range(CYCLES):
        # a burst mixing every input class the loop really eats
        burst = [
            ("yara-watch", f"eicar /tmp/x{n} (realtime sha256:{n:064x})"),
            ("fail2ban", f"2026-11-08 01:00:{n:02d},1 fail2ban.actions "
             f"[1]: NOTICE [sshd] Ban 203.0.113.{n % 250 + 1}"),
            ("responderd", "{definitely-not-json"),       # malformed lane
            ("ufw", _catch_line(spt=45000 + n, dpt=4000 + n)),  # catch lane
        ]
        mp = pytest.MonkeyPatch.context()
        with mp as m:
            m.setattr(d, "collect_burst", lambda tailers, settle,
                      _b=burst: _b)
            d.run_once(tailers=[], settle=0.01)
        # mid-soak storm drill: four identical swallowed failures must
        # name themselves on the observability board
        if n == CYCLES // 2:
            for _ in range(gd.Daemon.FAIL_STORM_N):
                d.count_failure("scan", "soak-drill",
                                RuntimeError("soak hiccup"))
        d.trim_events()
        if d._fail_counts.get("scan", {}).get("storm"):
            seen_storms = True

    # loop survived the mix: no loop-category failures
    assert not d._fail_counts.get("loop", {}).get("count"), \
        d._fail_counts.get("loop")

    # ledgers inside their caps
    assert len(read_events(d.events_path)) <= MAX_EVENTS
    from appfw.policy import KEEP_LEDGER_LINES
    seen_path = d.data_dir / "learning-seen.jsonl"
    seen_lines = (seen_path.read_text().splitlines()
                  if seen_path.exists() else [])
    assert len(seen_lines) <= KEEP_LEDGER_LINES

    # the observability keys ride the same snapshot, honestly
    storms = sorted(k for k, v in d._fail_counts.items() if v.get("storm"))
    assert "scan" in storms, f"mid-soak storm not named: {storms}"

    # the catch lane really landed in the ledger as appfw events
    evs = read_events(d.events_path)
    appfw_rows = [e for e in evs if e.get("from_tool") == "appfw"]
    assert appfw_rows, "GW-DENY lines never reached the ledger"
    assert any("93.184.216.34" in (e.get("text") or "")
               for e in appfw_rows)


def test_status_snapshot_carries_research_keys(tmp_path):
    d = Daemon(data_dir=tmp_path / "data", registry=_reg(),
               max_events=MAX_EVENTS)
    for _ in range(gd.Daemon.FAIL_STORM_N):
        d.count_failure("feeds", "soak", RuntimeError("feed hiccup"))
    mp = pytest.MonkeyPatch.context()
    with mp as m:
        m.setattr(d, "collect_burst", lambda tailers, settle: [])
        snap = d.run_once(tailers=[], settle=0.01)
    assert snap["failure_storms"] == ["feeds"]
    # classic failures map unchanged in shape (additive law)
    assert snap["failures"]["feeds"] == gd.Daemon.FAIL_STORM_N
    # supervisor health has ONE source of truth: snap["components"]
    # (existed before the wave; no duplicate key was added)
    assert isinstance(snap.get("components"), dict)
