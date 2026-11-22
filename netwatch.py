from __future__ import annotations
"""Light intrusion detection over connection events.

NetWatch watches a bounded window of recent connections and raises
events for port scans, connection bursts and repeated firewall denies."""


import collections
import dataclasses
import ipaddress
import re
import time

SCAN_WINDOW = 60.0
SCAN_PORTS = 8
SCAN_COOLDOWN = 300.0

# Inbound sensor thresholds. The sensor logs new and invalid TCP packets
# from the kernel (apply/netguard.sh); these windows decide when a handful
# of probes becomes a sweep. Slow scans get a longer window so a one-port-
# per-minute walk still crosses the line.
INBOUND_FAST_WINDOW = 60.0
INBOUND_FAST_PORTS = 8
INBOUND_SLOW_WINDOW = 600.0
INBOUND_SLOW_PORTS = 10
INBOUND_STEALTH_WINDOW = 60.0
INBOUND_STEALTH_BLOCK_PROBES = 2
INBOUND_ALERT_COOLDOWN = 300.0
INBOUND_BLOCK_COOLDOWN = 1800.0
INBOUND_DEDUPE_WINDOW = 2.0
INBOUND_MAX_SOURCES = 500
INBOUND_MAX_PORTS_PER_SOURCE = 4096

# Explicit private/infrastructure ranges. Do NOT use ipaddress.is_private
# here: Python also calls documentation ranges (203.0.113.0/24) private,
# which would make the tests and lab networks silently unblockable.
_LAN_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128",
))

_INBOUND_PREFIX = re.compile(r"\b(GW-SCAN|GW-STEALTH|PSAD-IN):")
_INBOUND_FIELD = re.compile(r"\b([A-Z][A-Z0-9_]*)=(\S+)")
_INBOUND_FLAG = re.compile(r"\b(SYN|FIN|RST|PSH|ACK|URG)\b")


@dataclasses.dataclass(frozen=True)
class InboundPacket:
    """One kernel-log observation from the host's inbound sensor."""
    src: str
    dst: str
    dpt: int | None
    proto: str
    flags: frozenset
    ttl: int | None
    iface: str
    shape: str
    raw: str = ""


def parse_inbound_line(line: str) -> InboundPacket | None:
    """Parse one GW-SCAN / GW-STEALTH / PSAD-IN kernel line.

    Kernel log formatting varies between journalctl transports and nft
    versions, so this reads fields by name instead of matching a fixed
    line shape. Anything unrecognised returns None; a detector must never
    raise on a hostile log line."""
    if not isinstance(line, str):
        return None
    m = _INBOUND_PREFIX.search(line)
    if not m:
        return None
    fields = {k: v for k, v in _INBOUND_FIELD.findall(line)}
    src = str(fields.get("SRC", "")).strip()
    try:
        ipaddress.ip_address(src)
    except (ValueError, TypeError):
        return None
    dst = str(fields.get("DST", "")).strip()
    proto = str(fields.get("PROTO", "")).strip().upper()
    try:
        dpt = int(fields.get("DPT", ""))
    except (TypeError, ValueError):
        dpt = None
    try:
        ttl = int(fields.get("TTL") or fields.get("HOPLIMIT") or "")
    except (TypeError, ValueError):
        ttl = None
    flags = frozenset(_INBOUND_FLAG.findall(line))
    return InboundPacket(
        src=src, dst=dst, dpt=dpt, proto=proto, flags=flags, ttl=ttl,
        iface=str(fields.get("IN", "")).strip(), shape=m.group(1), raw=line)


class InboundScanWatch:
    """Turn host-local inbound probes into scan/stealth findings.

    A finding is one dict (not an Event): the daemon needs the source and
    the block decision, not just display text. Private/LAN sources are
    always alert-only; external sources are eligible for a temporary block.
    """

    def __init__(self, emit, clock=time.monotonic, lan_nets=None):
        self._emit = emit
        self._clock = clock or time.monotonic
        self._lan_nets = tuple(lan_nets) if lan_nets is not None else _LAN_NETS
        self._ports: dict[str, collections.deque] = {}
        self._stealth: dict[str, collections.deque] = {}
        self._seen: dict[tuple, float] = {}
        self._last_alert: dict[tuple, float] = {}
        self._last_block: dict[str, float] = {}

    def ingest_raw(self, line: str, tool: str = "") -> list[dict]:
        try:
            pkt = parse_inbound_line(line)
            if pkt is None:
                return []
            return self.observe(pkt)
        except Exception:
            return []               # a detector must never break a tool

    def classify(self, ip: str) -> tuple[bool, str]:
        """(blockable, reason) for one source address."""
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False, "bad-address"
        if addr.is_loopback:
            return False, "loopback"
        if addr.is_link_local:
            return False, "link-local"
        if addr.is_multicast:
            return False, "multicast"
        if addr.is_unspecified:
            return False, "unspecified"
        for net in self._lan_nets:
            if addr.version == net.version and addr in net:
                return False, "lan"
        return True, "external"

    def observe(self, pkt: InboundPacket, now: float | None = None) -> list[dict]:
        if pkt.dpt is None or not pkt.src:
            return []
        now = self._clock() if now is None else now
        key = (pkt.src, pkt.dpt, pkt.proto)
        seen = self._seen.get(key)
        if seen is not None and now - seen < INBOUND_DEDUPE_WINDOW:
            return []
        self._seen[key] = now
        self._prune_seen(now)
        self._touch(pkt.src)

        ports = self._ports.setdefault(pkt.src, collections.deque())
        ports.append((now, pkt.dpt))
        while ports and (now - ports[0][0] > INBOUND_SLOW_WINDOW
                         or len(ports) > INBOUND_MAX_PORTS_PER_SOURCE):
            ports.popleft()

        # NULL/FIN/XMAS and invalid ACK probes do not carry a lone SYN.
        # SYN+FIN is also invalid TCP and is logged as a new connection by
        # nftables, so classify by the illegal flag combination too.
        stealth_flags = {"FIN", "PSH", "URG", "ACK", "RST"}
        is_stealth = (pkt.shape == "GW-STEALTH"
                      or bool(pkt.flags and pkt.flags & stealth_flags
                              and ("SYN" not in pkt.flags
                                   or "FIN" in pkt.flags
                                   or "RST" in pkt.flags)))
        if is_stealth:
            stealth = self._stealth.setdefault(pkt.src, collections.deque())
            stealth.append(now)
            while stealth and (now - stealth[0] > INBOUND_STEALTH_WINDOW
                               or len(stealth) > 4096):
                stealth.popleft()
            probes = len(stealth)
            can_block = probes >= INBOUND_STEALTH_BLOCK_PROBES
            return self._finding(
                pkt.src, "stealth", probes, INBOUND_STEALTH_WINDOW,
                now, can_block, pkt.flags)

        fast = len({p for (t, p) in ports
                    if now - t <= INBOUND_FAST_WINDOW})
        slow = len({p for (_t, p) in ports})
        if fast >= INBOUND_FAST_PORTS:
            return self._finding(pkt.src, "scan", fast,
                                 INBOUND_FAST_WINDOW, now, True, pkt.flags)
        if slow >= INBOUND_SLOW_PORTS:
            return self._finding(pkt.src, "scan", slow,
                                 INBOUND_SLOW_WINDOW, now, True, pkt.flags)
        return []

    def _finding(self, src, kind, count, window, now, can_block, flags):
        blockable, reason = self.classify(src)
        block = bool(can_block and blockable
                     and now - self._last_block.get(src, -1e12)
                     > INBOUND_BLOCK_COOLDOWN)
        # A block-worthy second stealth probe must not be swallowed by the
        # alert cooldown; ordinary repeat alerts still are.
        cooldown = now - self._last_alert.get((src, kind), -1e12)
        if cooldown <= INBOUND_ALERT_COOLDOWN and not block:
            return []
        self._last_alert[(src, kind)] = now
        if block:
            self._last_block[src] = now
        local = not blockable
        note = (f" ({reason} source; not auto-blocked)" if local else "")
        if kind == "stealth":
            flagtext = ",".join(sorted(flags)) or "invalid-TCP"
            text = (f"netwatch: stealth scan against this host from {src} "
                    f"({count} probe(s), TCP flags {flagtext}){note}")
        else:
            text = (f"netwatch: port scan against this host from {src} "
                    f"({count} distinct ports in {window:.0f} s){note}")
        meta = {"kind": kind, "source": src, "ports": count,
                "window": window, "flags": sorted(flags),
                "local": local, "block": block, "reason": reason}
        self._emit("HIGH", text, meta)
        return [meta]

    def _touch(self, src):
        if src in self._ports:
            return
        if len(self._ports) >= INBOUND_MAX_SOURCES:
            oldest = min(self._ports, key=lambda k: (
                self._ports[k][-1][0] if self._ports[k] else 0.0))
            self._ports.pop(oldest, None)
            self._stealth.pop(oldest, None)
            self._last_block.pop(oldest, None)
            for key in [k for k in self._last_alert if k[0] == oldest]:
                self._last_alert.pop(key, None)
        self._ports.setdefault(src, collections.deque())

    def _prune_seen(self, now):
        if len(self._seen) <= 4096:
            return
        for key, ts in list(self._seen.items()):
            if now - ts > INBOUND_SLOW_WINDOW:
                self._seen.pop(key, None)
        if len(self._seen) > 4096:
            self._seen = dict(list(self._seen.items())[-2048:])

BURST_WINDOW = 60.0
BURST_CONNS = 30
BURST_COOLDOWN = 300.0

CLUSTER_WINDOW = 300.0
CLUSTER_DENIES = 5
CLUSTER_COOLDOWN = 600.0

_UFW_SRC = re.compile(r"SRC=(\S+)")
_UFW_DPT = re.compile(r"DPT=(\d+)")
# appfw prints IPv6 destinations in brackets: [2606:4700::1]:443.
_APPFW_LINE = re.compile(
    r"appfw (\S+) → (\[[0-9A-Fa-f:]+\]|[^\s:]+):\d+ (allow|deny)\b")

MAX_KEYS = 500               # bounded: newest keys win, evicted beyond


class NetWatch:
    """NetWatch."""
    def __init__(self, emit):
        self._emit = emit
        self._scans: dict[str, tuple[set, float]] = {}
        self._bursts: dict[str, tuple[set, float]] = {}
        self._deny_hits: dict[str, collections.deque] = collections.defaultdict(
            collections.deque)
        self._last_scan: dict[str, float] = {}
        self._last_burst: dict[str, float] = {}
        self._last_cluster: dict[str, float] = {}

    def ingest(self, ev) -> None:
        self.ingest_line(getattr(ev, "from_tool", None),
                         getattr(ev, "text", None))

    def ingest_line(self, tool, text) -> None:
        """Analyze one raw tool line. The daemon calls this before parsing,
        because parse_ufw's display text no longer carries SRC=/DPT=."""
        try:
            if not isinstance(text, str):
                return
            if tool == "ufw" and "BLOCK" in text:
                self._ufw_block(text)
            elif tool == "appfw":
                self._appfw(text)
        except Exception:
            pass                    # an analyzer must never break a tool

    def _bound(self, table, now) -> None:
        if len(table) > MAX_KEYS:
            oldest = sorted(table, key=lambda k: table[k][1] if
                            isinstance(table[k], tuple) else 0)[:100]
            for k in oldest:
                table.pop(k, None)

    def _ufw_block(self, text: str) -> None:
        s = _UFW_SRC.search(text)
        d = _UFW_DPT.search(text)
        if not s or not d:
            return
        src, dpt = s.group(1), d.group(1)
        now = time.monotonic()
        entry = self._scans.get(src)
        if entry is None or now - entry[1] > SCAN_WINDOW:
            entry = (set(), now)
            self._scans[src] = entry
        entry[0].add(dpt)
        self._bound(self._scans, now)
        if len(entry[0]) >= SCAN_PORTS:
            if now - self._last_scan.get(src, -1e12) > SCAN_COOLDOWN:
                self._last_scan[src] = now
                self._emit("HIGH", f"netwatch: port scan from {src} "
                           f"({len(entry[0])} distinct ports in "
                           f"{SCAN_WINDOW:.0f} s)")

    def _appfw(self, text: str) -> None:
        m = _APPFW_LINE.search(text)
        now = time.monotonic()
        if m:
            app, dst = m.group(1), m.group(2)
            entry = self._bursts.get(app)
            if entry is None or now - entry[1] > BURST_WINDOW:
                entry = ({dst}, now)
                self._bursts[app] = entry
            entry[0].add(dst)
            self._bound(self._bursts, now)
            if len(entry[0]) >= BURST_CONNS:
                if now - self._last_burst.get(app, -1e12) > BURST_COOLDOWN:
                    self._last_burst[app] = now
                    self._emit("MEDIUM", f"netwatch: connection burst by "
                               f"{app} ({len(entry[0])} distinct "
                               f"destinations in {BURST_WINDOW:.0f} s)")
        m2 = re.search(r"deny \[.*?blocked by the downloaded list: (\S+)\]",
                       text)
        if not m2:
            m2 = re.search(r"deny \[.*?: (\S+)\]", text)
        if not m2:
            return
        host = m2.group(1)
        hits = self._deny_hits[host]
        hits.append(now)
        while hits and now - hits[0] > CLUSTER_WINDOW:
            hits.popleft()
        if len(hits) >= CLUSTER_DENIES:
            if now - self._last_cluster.get(host, -1e12) > CLUSTER_COOLDOWN:
                self._last_cluster[host] = now
                self._emit("MEDIUM", f"netwatch: {len(hits)} denied attempts "
                           f"against {host} in {CLUSTER_WINDOW:.0f} s")
        # The deques trim their own timestamps, but the host key sets
        # grow with every distinct denied host a firewall ever names:
        # bound them like _scans/_bursts so uptime cannot inflate them.
        self._bound(self._deny_hits, now)
        self._bound(self._last_cluster, now)
