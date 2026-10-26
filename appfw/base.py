"""appfw.base — shared types for the app firewall.

Kept free of imports so every submodule can use them without a cycle.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DURATIONS = ("once", "until restart", "always")
ACTIONS = ("allow", "deny", "reject")

# Owner-permitted LOCAL services (2026-10-23, carried from the previous
# rule chain): SearXNG (8888) and the headless-browser control port (8899).
# Loopback only — a remote host can never match these, so permitting them
# cannot open anything to the network.
LOCAL_SERVICE_PORTS = frozenset({8888, 8899})


@dataclass
class Conn:
    """One intercepted outbound connection, resolved from /proc."""
    protocol: str = "tcp"
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    dst_host: str = ""
    pid: int = 0
    process_path: str = ""
    process_args: list = field(default_factory=list)

    @property
    def host(self) -> str:
        return str(self.dst_host or self.dst_ip or "")

    @property
    def app_name(self) -> str:
        import os
        return os.path.basename(str(self.process_path or "<unknown>"))


def is_local_service(conn: "Conn") -> bool:
    """True for the owner's permitted loopback services only."""
    ip = str(conn.dst_ip or "")
    local = (ip in ("127.0.0.1", "::1", "localhost")
             or ip.startswith("127.") or ip == "::1")
    port = int(conn.dst_port or 0)
    return local and port in LOCAL_SERVICE_PORTS