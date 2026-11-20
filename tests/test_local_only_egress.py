"""E-8: the assistant lane is local-only — an egress-contract pin.

The local-model lane runs llama-cpp-python IN-PROCESS (assistant/llm.py
docstring: "No server, no port") against a local GGUF file; the heuristic
tier is pure Python. Neither layer may open a network connection. This
pin proves the negative statically (no network modules in the lane's
imports) and behaviorally (routing + advice work with every socket-using
module's connect blocked), so the local-only law cannot regress.
"""
from __future__ import annotations

import pathlib
import socket
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------- static
def test_assistant_lane_imports_no_network_stack():
    """assistant/*: the lane's own imports name no network client module
    (AST-checked, prose-safe: comments mentioning words like 'requests'
    do not count)."""
    import ast
    banned = {"socket", "ssl", "urllib", "http", "ftplib", "smtplib",
              "poplib", "imaplib", "telnetlib", "xmlrpc", "asyncio"
              }  # asyncio excluded nowhere in the lane; listed for churn safety
    banned.discard("asyncio")
    banned |= {"requests", "httpx", "aiohttp", "websockets"}
    for rel in ("assistant/llm.py", "assistant/model.py",
                "assistant/router.py", "assistant/advice.py",
                "assistant/intents.py", "assistant/tiers.py",
                "assistant/templates.py", "assistant/packer.py"):
        tree = ast.parse((ROOT / rel).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top not in banned, \
                        f"{rel} imports network module {top}"
            elif isinstance(node, ast.ImportFrom):
                top = (node.module or "").split(".")[0]
                assert top not in banned, \
                    f"{rel} imports from network module {top}"


# ------------------------------------------------------------ behavioral
def test_router_and_advice_run_with_sockets_blindfolded():
    """The deterministic lanes (route/parse, advice) complete with
    socket.socket.connect permanently refused: no code path dials out.
    """
    class _Refused:
        def __init__(self, *a, **k):
            pass

        def connect(self, address):
            raise OSError(111, "E-8 drill: network refused")

        def __getattr__(self, name):
            raise OSError(111, "E-8 drill: network refused")

    real_socket = socket.socket
    socket.socket = _Refused
    try:
        from assistant.router import _parse
        got = _parse('{"task": "tool_status", "tool": "clamav"}',
                     "clamav appfw")
        assert got is not None and got[0] == "tool_status"
        assert got[1] == "clamav"
        from assistant.router import route
        slot, _payload = route("hello", lambda prompt: "not json at all",
                               "clamav")
        assert slot == "summary"       # two-strike degrade, no dial-out
    finally:
        socket.socket = real_socket


def test_advice_lane_never_reaches_the_network(tmp_path, monkeypatch):
    """advice.advise_event (the assistant's per-event answer path) runs
    against a machine-facts row with the socket layer refused; the
    answer is the honest prose, never a connection attempt."""
    class _Refused:
        def __init__(self, *a, **k):
            pass

        def connect(self, address):
            raise OSError(111, "E-8 drill: network refused")

        def __getattr__(self, name):
            raise OSError(111, "E-8 drill: network refused")

    real_socket = socket.socket
    socket.socket = _Refused
    try:
        from assistant.advice import advise_event
        out = advise_event({"from_tool": "fail2ban",
                            "text": "Ban 203.0.113.9",
                            "severity": "MEDIUM",
                            "ts": "2026-11-12T06:00:00+00:00"})
        assert isinstance(out, str) and out.strip()
        assert "That line means" in out      # the real prose path
    finally:
        socket.socket = real_socket
