"""appfw.resolve — /proc-based process resolution.

No kernel modules, no eBPF, and NO reverse DNS: parse /proc/net/{tcp,tcp6}
for the socket inode of the matching tuple, then scan /proc/<pid>/fd/* for
a socket:[inode] link and read that process's exe path and cmdline. This
is the classic fallback method — slower per burst than a kernel tracer but
dependency-free, and the result is cached by tuple.

INCIDENT NOTE (2026-10-24, owner's machine-wide outage): an earlier version
called reverse DNS inside the pump's hot path; one lookup stalled ~10 s per
connection, expired this cache's own TTL between calls, filled the queue,
and outbound traffic hung. Resolution is now /proc reads ONLY — a site-name
rule applies when the name is known from context; otherwise IP/path rules
decide. There is no query anywhere near the queue pump.
"""
from __future__ import annotations

import os
import pathlib
import struct
import time

CACHE_TTL = 5.0
CACHE_MAX = 5000

_FILES = {"tcp": "tcp", "tcp6": "tcp6", "udp": "udp", "udp6": "udp6"}


def _parse_net_file(path: pathlib.Path) -> list[tuple]:
    """Rows of (local_ip, local_port, remote_ip, remote_port, inode)."""
    out = []
    try:
        lines = path.read_text().splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            lip, lport = f[1].rsplit(":", 1)
            rip, rport = f[2].rsplit(":", 1)
            out.append((lip.strip(), int(lport, 16), rip.strip(),
                        int(rport, 16), int(f[9])))
        except (ValueError, IndexError):
            continue
    return out


def _hex_ip(hexstr: str) -> str:
    """Little-endian hex IPv4/IPv6 from /proc/net → dotted text."""
    try:
        if len(hexstr) == 8:
            import socket
            ip = socket.inet_ntoa(struct.pack("<I", int(hexstr, 16)))
            return "" if ip == "0.0.0.0" else ip
        if len(hexstr) == 32:
            import socket
            packed = struct.pack("<4I", *(int(hexstr[i:i + 8], 16)
                                          for i in (24, 16, 8, 0)))
            return "" if packed == b"\0" * 16 else socket.inet_ntop(
                socket.AF_INET6, packed)
    except (ValueError, OSError, OverflowError):
        pass
    return ""


def load_sockets(proc_root: str = "/proc") -> dict:
    """inode → (proto, local_ip, local_port, remote_ip, remote_port)."""
    root = pathlib.Path(proc_root)
    table = {}
    for proto, fname in _FILES.items():
        p = root / "net" / fname
        if not p.exists():
            continue
        for lip, lport, rip, rport, inode in _parse_net_file(p):
            table.setdefault(inode, (proto, _hex_ip(lip), lport,
                                     _hex_ip(rip), rport))
    return table


def fd_owners(proc_root: str = "/proc", inodes: set | None = None) -> dict:
    """inode → (pid, exe path, args). Only scans pids when asked."""
    root = pathlib.Path(proc_root)
    owners = {}
    want = set(inodes or ())
    if not want:
        return owners
    try:
        pids = [p for p in root.iterdir() if p.name.isdigit()]
    except OSError:
        return owners
    for pid in pids:
        try:
            cmd = (pid / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        try:
            exe = os.readlink(str(pid / "exe"))
        except OSError:
            exe = ""
        fds = pid / "fd"
        try:
            links = os.listdir(fds)
        except OSError:
            continue
        for fd in links:
            try:
                target = os.readlink(str(fds / fd))
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            try:
                inode = int(target[8:-1])
            except ValueError:
                continue
            if inode in want:
                path = exe or (cmd[0].decode("utf-8", "replace")
                               if cmd and cmd[0] else "")
                args = [a.decode("utf-8", "replace") for a in cmd
                        if a][:20]
                owners[inode] = (int(pid.name), path, args)
    return owners


class Resolver:
    """Cached resolver used by the engine. `resolve(conn)` fills in
    pid/process_path/process_args; failures leave them empty (fail-open;
    never block, never query).

    INCIDENT-GRADE PERFORMANCE (2026-10-25 outage #2): the queue pump is a
    single thread, so per-packet cost == the machine's ceiling. Now:
    - owners are cached PER INODE for their lifetime (a live fd never
      changes owner — one scan ever, per unseen socket);
    - the /proc/net parse is a shared ~250 ms snapshot (one parse per
      burst, never one per packet);
    - repeat connections hit the tuple cache within its TTL.
    Steady-state per-packet cost ≈ one dict lookup."""

    def __init__(self, proc_root: str = "/proc"):
        self.proc_root = proc_root
        self._by_inode: dict[int, tuple] = {}
        self._tuple: dict[tuple, tuple] = {}
        self._stamped: dict[tuple, float] = {}
        self._socks: dict = {}
        self._socks_at = 0.0
        self._socks_ttl = 0.25

    def _socket_table(self) -> dict:
        now = time.monotonic()
        if not self._socks or now - self._socks_at > self._socks_ttl:
            self._socks = load_sockets(self.proc_root)
            self._socks_at = now
        return self._socks

    def resolve(self, conn) -> None:
        key = (conn.protocol.lower(), conn.src_ip, int(conn.src_port),
               conn.dst_ip, int(conn.dst_port))
        now = time.monotonic()
        hit = self._tuple.get(key)
        if hit and now - self._stamped.get(key, 0) < CACHE_TTL * 12:
            conn.pid, conn.process_path, conn.process_args = hit
            return
        inode = None
        for ino, (proto, lip, lport, rip, rport) in \
                self._socket_table().items():
            if (key[0], key[1], key[2], key[3], key[4]) == (
                    proto, lip, lport, rip, rport):
                inode = ino
                break
        found = (0, "", [])
        if inode:
            found = self._by_inode.get(inode)
            if found is None:                  # first sighting: one scan
                owners = fd_owners(self.proc_root, {inode})
                found = owners.get(inode) or (0, "", [])
                self._by_inode[inode] = found
                if len(self._by_inode) > CACHE_MAX:
                    for old in sorted(self._by_inode)[:2500]:
                        self._by_inode.pop(old, None)
        pid, path, args = found
        conn.pid, conn.process_path, conn.process_args = pid, path, args
        self._tuple[key] = found
        self._stamped[key] = now
        if len(self._tuple) > CACHE_MAX:
            for old in sorted(self._stamped, key=self._stamped.get)[:2500]:
                self._tuple.pop(old, None)
                self._stamped.pop(old, None)
                self._stamped.pop(old, None)