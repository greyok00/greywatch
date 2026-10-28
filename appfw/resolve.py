from __future__ import annotations

import os
import pathlib
import struct
import time

CACHE_TTL = 5.0
CACHE_MAX = 5000
INODE_TTL = 60.0            # a socket inode is reused only after close
MISS_TTL = 2.0              # a miss is retried on the next packet
DST_TTL = 30.0              # remember app → destination for repeat sockets

# IPv6 lists are separate files but the same sockets; the NFQUEUE packet
# only carries "tcp"/"udp", so match on the family-less name or every
# IPv6 flow resolves to "<unknown>".
_FILES = {"tcp": "tcp", "tcp6": "tcp", "udp": "udp", "udp6": "udp"}


def _parse_net_file(path: pathlib.Path) -> list[tuple]:
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
            uid = int(f[7]) if f[7].isdigit() else -1
            out.append((lip.strip(), int(lport, 16), rip.strip(),
                        int(rport, 16), int(f[9]), uid))
        except (ValueError, IndexError):
            continue
    return out


def _hex_ip(hexstr: str) -> str:
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
    root = pathlib.Path(proc_root)
    table = {}
    for proto, fname in _FILES.items():
        p = root / "net" / fname
        if not p.exists():
            continue
        for lip, lport, rip, rport, inode, uid in _parse_net_file(p):
            table.setdefault(inode, (proto, _hex_ip(lip), lport,
                                     _hex_ip(rip), rport, uid))
    return table


def fd_owners(proc_root: str = "/proc", inodes: set | None = None,
              uid: int | None = None) -> dict:
    """Which process holds these socket inodes.

    Scanning every process costs ~380 ms on a desktop with a browser
    open; a burst of new connections then outruns attribution and every
    one of them shows up as "<unknown>" (owner report 2026-10-28). The
    socket table already names the owning uid, so only that user's
    processes are scanned — a tenfold cut — and the scan stops as soon
    as every wanted inode is found.
    """
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
        if uid is not None and uid >= 0:
            try:
                if os.stat(pid).st_uid != uid:
                    continue
            except OSError:
                continue
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
        if len(owners) >= len(want):
            break
    return owners


class Resolver:

    def __init__(self, proc_root: str = "/proc"):
        self.proc_root = proc_root
        self._by_inode: dict[int, tuple] = {}
        self._tuple: dict[tuple, tuple] = {}
        self._dst_recent: dict[tuple, tuple] = {}
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
        proto = conn.protocol.lower()
        if proto.endswith("6") and proto[:-1] in ("tcp", "udp"):
            proto = proto[:-1]                  # tcp6 → tcp (same flow)
        key = (proto, conn.src_ip, int(conn.src_port),
               conn.dst_ip, int(conn.dst_port))
        now = time.monotonic()
        hit = self._tuple.get(key)
        if hit is not None and now < hit[1]:
            conn.pid, conn.process_path, conn.process_args = hit[0]
            return
        inode, sock_uid = None, None
        for ino, (p, lip, lport, rip, rport, uid) in \
                self._socket_table().items():
            if (proto, conn.src_ip, int(conn.src_port),
                    conn.dst_ip, int(conn.dst_port)) == (
                    p, lip, lport, rip, rport):
                inode, sock_uid = ino, uid
                break
        found = None
        if inode:
            rec = self._by_inode.get(inode)
            if rec is not None and now - rec[1] < INODE_TTL:
                found = rec[0]
            else:                              # first sighting: one scan
                owners = fd_owners(self.proc_root, {inode}, uid=sock_uid)
                if not owners and sock_uid not in (None, -1):
                    # The socket uid and the process uid can differ (setuid
                    # helpers); a filtered miss gets one unfiltered retry.
                    owners = fd_owners(self.proc_root, {inode})
                found = owners.get(inode) or (0, "", [])
                self._by_inode[inode] = (found, now)
                if len(self._by_inode) > CACHE_MAX:
                    for old in list(self._by_inode)[:2500]:
                        self._by_inode.pop(old, None)
        if not found or not found[0]:
            # The app just opened another socket to the same place (CDNs do
            # this constantly); a closed first socket must not turn the
            # answer into "<unknown>" when we learned it seconds ago.
            snap = self._dst_recent.get((conn.dst_ip, int(conn.dst_port)))
            if snap is not None and now - snap[1] < DST_TTL:
                found = snap[0]
        if found and found[0]:
            self._dst_recent[(conn.dst_ip, int(conn.dst_port))] = (found, now)
            if len(self._dst_recent) > 512:
                for k in list(self._dst_recent)[:256]:
                    self._dst_recent.pop(k, None)
        found = found or (0, "", [])
        conn.pid, conn.process_path, conn.process_args = found
        self._tuple[key] = (found, now + (CACHE_TTL * 12 if found[0]
                                          else MISS_TTL))
        if len(self._tuple) > CACHE_MAX:
            for k in list(self._tuple)[:2500]:
                self._tuple.pop(k, None)
