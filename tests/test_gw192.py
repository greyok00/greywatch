# GW-192: the healer treated healthy unit-less scanners as down.
# rkhunter and lynis have no systemd unit (their verdict lives in their
# logs), so snapshot()["tools"] never says unit_state == "active" for
# them, both tick() skip rules missed them, and every status pass ran
# repair attempts and one "down and could not be repaired automatically
# (unknown)" alarm per window on a scanner that was fine (owner live
# finding 2026-11-05: rkhunter flapped green -> HIGH -> green all day).
from __future__ import annotations

import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from selfheal import SelfHealer   # noqa: E402


def test_a_healthy_unitless_scanner_is_never_repaired():
    alerts: list = []
    logs: list = []
    healer = SelfHealer(
        "/tmp/nope",
        [{"name": "rkhunter", "label": "RKHunter (rootkit scan)",
          "unit": None, "scope": "root"}],
        log=lambda tool, text: logs.append((tool, text)),
        alert=lambda tool, text: alerts.append((tool, text)),
        clock=lambda: 0.0)
    snap = {"tools": {"rkhunter": {"state": "GREEN", "unit_state": "no-unit",
                                   "installed": True}}}
    for _ in range(20):
        assert healer.tick(snap) == []
    assert alerts == [] and logs == []
    assert healer.attempts == {}          # no attempt was ever budgeted


def test_a_unitless_scanner_is_not_spun_up_even_when_yellow():
    alerts: list = []
    healer = SelfHealer(
        "/tmp/nope",
        [{"name": "lynis", "label": "Lynis (audit)", "unit": None,
          "scope": "root"}],
        log=lambda tool, text: alerts.append(("log", text)),
        alert=lambda tool, text: alerts.append(tool),
        clock=lambda: 0.0)
    snap = {"tools": {"lynis": {"state": "YELLOW", "unit_state": "no-unit",
                                "installed": True}}}
    assert healer.tick(snap) == []
    assert alerts == []
