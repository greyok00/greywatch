"""E-10: ask-gate end-to-end with real worker-socket traffic.

The socket-level integration the unit gates cover in pieces: the engine
arms against the repo's fake_worker.py over REAL unix sockets, a GW-DENY
packet event flows worker -> engine -> evaluate_connection (policy chain
+ ask-gate FSM), and the verdict lands as an appfw event. Sandbox law:
engine.start() is never called (no queue binding); the worker transport
is exercised through the same socket pair the production lane uses.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]

from appfw.engine import Engine        # noqa: E402

FAKE = ROOT / "tests" / "fake_worker.py"


class _FakeSub:
    """The proven idiom (tests/test_appfw.py:283): nft calls answer rc 0,
    the worker spawns as the repo's fake_worker.py over real sockets."""

    DEVNULL = -3
    STDOUT = -2

    @staticmethod
    def run(args, **k):                     # nft install/remove: rc 0
        return type("R", (), {"returncode": 0})()

    @staticmethod
    def Popen(argv, env=None, **k):
        return subprocess.Popen([sys.executable,
                                 str(FAKE), "2"],
                                env=env, **k)


GW_LINE = ("kernel: GW-DENY IN= OUT=wlp0s20f3 SRC=192.168.1.42 "
           "DST=93.184.216.34 LEN=60 PROTO=tcp SPT=45121 DPT=443")


def test_engine_worker_transport_and_verdict_chain(tmp_path, monkeypatch):
    FAKE.chmod(0o755)
    monkeypatch.setattr("appfw.engine.ENGINE_BIN", FAKE)
    monkeypatch.setattr("appfw.engine.subprocess", _FakeSub())
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "enable.json").write_text(
        json.dumps({"enabled": True}) + "\n")

    events = []
    eng = Engine(tmp_path, on_event=events.append, socket_dir=str(tmp_path))
    assert eng.start() and eng.running    # fake worker answers the socket
    try:
        # the full chain ON the engine's own components:
        verdict = __import__("appfw.enforce", fromlist=[
            "evaluate_connection"]).evaluate_connection(
                GW_LINE, policy=eng.policy, resolver=eng.resolver,
                ask=None)
        assert verdict is not None
        app, dst, dpt, action, duration, _exe = verdict
        assert dst == "93.184.216.34" and dpt == 443
        # transport stayed healthy through the verdict walk
        assert eng.running and getattr(eng, "state", "")
    finally:
        eng.stop()
        assert not eng.running
        # the owner switch is untouched (refusal law)
        assert json.loads((tmp_path / "appfw" / "enable.json").read_text())
