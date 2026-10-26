"""appfw.sd_notify — systemd-native service notification, stdlib-only.

Implements the sd_notify(3) protocol over the NOTIFY_SOCKET unix datagram
the manager injects (no python-systemd dependency — the owner rule is no
pip, ever). The daemon sends READY=1 on boot and WATCHDOG=1 every ~10 s;
with Type=notify + WatchdogSec=30, the manager considers the service dead
and restarts it if those pings stop (replacing the heartbeat-file + timer
pair, owner-approved 2026-10-25).
"""
from __future__ import annotations

import os
import socket


def notify(state: str) -> bool:
    """Send one sd_notify message. False = no socket (not under a notify
    unit / running unmanaged) — callers treat that as 'unmanaged, fine'."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):                    # abstract namespace socket
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(state.encode())
        return True
    except OSError:
        return False