from __future__ import annotations

from dataclasses import dataclass, field

DURATIONS = ("once", "until restart", "always")
ACTIONS = ("allow", "deny", "reject")

LOCAL_SERVICE_PORTS = frozenset({8888, 8899})

# Port 43 is the WHOIS lookup protocol (RFC 3912): a one-line query to a
# public registry, nothing else speaks it. The dashboard's "who is this?"
# card depends on it, and a whois query lives for a fraction of a second —
# far shorter than process attribution takes — so asking the operator about
# every lookup produced an unanswerable "<unknown> wants access" box that
# auto-denied under the headless rule and made the identity card useless
# (owner install 2026-10-28).
REGISTRY_LOOKUP_PORT = 43


def is_registry_lookup(conn) -> bool:
    return int(conn.dst_port or 0) == REGISTRY_LOOKUP_PORT


@dataclass
class Conn:
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
    ip = str(conn.dst_ip or "")
    local = (ip in ("127.0.0.1", "::1", "localhost")
             or ip.startswith("127.") or ip == "::1")
    port = int(conn.dst_port or 0)
    return local and port in LOCAL_SERVICE_PORTS
