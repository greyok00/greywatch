"""The live CDP watcher — a read-only guest over a browser's debug port.

When a browser is running with a remote-debugging port (the app never
starts one itself, and never pins a port: the config names it),
this module opens a websocket, asks for ``Network`` events, and keeps
only their metadata — URLs, statuses, MIME types. No bodies, no
evaluation, no input events, no navigation: a browser is never mutated
from here.

Buffered events rotate out as HAR-shaped documents written into the
hunter inbox, where the ordinary inbox lane parses them by the same
``parse_har`` caps every other capture goes through. Everything is
localhost only; there is no TLS and nothing is sent anywhere.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request


DISCOVER_TIMEOUT_S = 3.0
SOCKET_IDLE_S = 0.25
MAX_EVENTS = 1000          # one rotating document carries at most these
MAX_QUEUE = 4000           # never buffer more than this many raw events
BUFFER_KEEP = 8 * 1024 * 1024 + 4096     # holds one max-size frame whole
ROTATE_AGAIN_S = 60.0
DRAIN_PER_POLL = 200       # frames read from the wire per poll, at most

_HANDSHAKE = (
    "GET {path} HTTP/1.1\r\n"
    "Host: 127.0.0.1:{port}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "User-Agent: greywatch-hunter-reader\r\n\r\n")


# ------------------------------------------------------------- discovery

def discover(port) -> dict | None:
    """The browser's version document, or None. Strictly a localhost
    read; a port that answers no JSON answers nothing."""
    try:
        url = f"http://127.0.0.1:{int(port)}/json/version"
        with urllib.request.urlopen(url, timeout=DISCOVER_TIMEOUT_S) as r:
            body = r.read(65536)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        if isinstance(exc, urllib.error.HTTPError):
            exc.close()
        return None
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None
    return doc if isinstance(doc, dict) and doc.get("webSocketDebuggerUrl") \
        else None


# ------------------------------------------------- minimal RFC6455 pieces

def _masking_key() -> bytes:
    return os.urandom(4)


def encode_client_text(payload) -> bytes:
    """A single unfragmented text frame, masked (clients must mask)."""
    data = payload.encode() if isinstance(payload, str) else bytes(payload)
    length = len(data)
    if length < 126:
        head = struct.pack("!BB", 0x81, 0x80 | length)
    elif length < (1 << 16):
        head = struct.pack("!BBH", 0x81, 0x80 | 126, length)
    else:
        head = struct.pack("!BBQ", 0x81, 0x80 | 127, length)
    key = _masking_key()
    masked = bytes(b ^ key[i % 4] for i, b in enumerate(data))
    return head + key + masked


def encode_client_close() -> bytes:
    return struct.pack("!BB", 0x88, 0x80) + os.urandom(4)


def parse_frame(buf: bytes, client: bool) -> tuple[int, bytes, int]:
    """(opcode, payload, bytes-consumed) from the front of ``buf``.
    ``client`` marks the READER side reading plain server frames; raise
    ValueError when the buffer holds too little to parse a whole frame."""
    if len(buf) < 2:
        raise ValueError("short")
    opcode = buf[0] & 0x0F
    masked = bool(buf[1] & 0x80)
    length = buf[1] & 0x7F
    pos = 2
    if length == 126:
        if len(buf) < pos + 2:
            raise ValueError("short")
        length = struct.unpack("!H", buf[pos:pos + 2])[0]
        pos += 2
    elif length == 127:
        if len(buf) < pos + 8:
            raise ValueError("short")
        length = struct.unpack("!Q", buf[pos:pos + 8])[0]
        pos += 8
    if length > 8 * 1024 * 1024:
        raise ValueError("oversize")
    key = b""
    if masked:
        if len(buf) < pos + 4:
            raise ValueError("short")
        key = buf[pos:pos + 4]
        pos += 4
    if len(buf) < pos + length:
        raise ValueError("short")
    data = buf[pos:pos + length]
    if masked:
        data = bytes(b ^ key[i % 4] for i, b in enumerate(data))
    return opcode, data, pos + length


def read_ws_response(buf: bytes) -> bool:
    """True when the head of ``buf`` says the upgrade was accepted."""
    head = buf.split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    if not lines or b"101" not in lines[0]:
        return False
    return any(line.lower().startswith(b"upgrade:") for line in lines[1:])


# -------------------------------------------------------- HAR-shaped docs

def har_doc_from(events) -> dict:
    """One HAR document in the exact shape ``web.parse_har`` consumes:
    ``log.entries`` with request/response pairs merged on requestId."""
    entries: dict[str, dict] = {}
    order: list[str] = []
    for ev in events[:MAX_EVENTS]:
        if not isinstance(ev, dict):
            continue
        method = str(ev.get("method") or "")
        params = ev.get("params") or {}
        if not isinstance(params, dict):
            continue
        rid = str(params.get("requestId") or "")
        if not rid:
            continue
        if method == "Network.requestWillBeSent":
            req = params.get("request") or {}
            if not isinstance(req, dict) or rid in entries:
                continue
            entries[rid] = {
                "request": {"url": str(req.get("url") or ""),
                            "method": str(req.get("method") or "")},
                "response": {},
                # These two keys are how the corpus's live-only rules
                # tell a page's subframe activity from its main doc.
                "_resourceType": str(params.get("type") or ""),
                "pageref": str(params.get("frameId") or ""),
            }
            order.append(rid)
        elif method == "Network.responseReceived":
            entry = entries.get(rid)
            if entry is None:
                continue
            resp = params.get("response") or {}
            if isinstance(resp, dict):
                ctype = str((resp.get("headers") or {}).get(
                    "content-type", "") or resp.get("mimeType") or "")
                entry["response"] = {
                    "status": resp.get("status"),
                    "headers": ([{"name": "content-type", "value": ctype}]
                                if ctype else []),
                    "content": {"mimeType": str(resp.get("mimeType") or "")},
                }
    raw_entries = [entries[rid] for rid in order if entries.get(rid)]
    return {"log": {"version": "1.2",
                    "creator": {"name": "greywatch-hunter",
                                "version": "live"},
                    "pages": [], "entries": raw_entries}}


def _events_from_buffer(buf: bytes) -> tuple[list[dict], bytes]:
    """Every complete JSON event in ``buf``; the tail that never parsed
    stays for the next poll."""
    events: list[dict] = []
    pos = 0
    tail_start = 0
    while pos < len(buf):
        try:
            opcode, payload, used = parse_frame(buf[pos:], client=True)
        except ValueError:
            break               # a partial frame waits for the next chunk
        if opcode == 8:                     # close: the peer ended cleanly
            return events, b""
        if opcode == 1:
            try:
                ev = json.loads(payload.decode("utf-8", "replace"))
            except ValueError:
                ev = None
            if isinstance(ev, dict) and str(ev.get("method") or "") \
                    .startswith("Network."):
                events.append(ev)
        # The tail is everything after the LAST COMPLETE frame - any
        # whole frame, not just text ones - so a chunk boundary that
        # lands inside a frame keeps its header for the next read.
        tail_start = pos + used
        pos += used
    return events, buf[tail_start:]


# ---------------------------------------------------------------- state

class Watcher:
    """One browser endpoint, polled non-blocking between hunt cycles.

    ``poll`` finds the endpoint, opens the socket once, drains what has
    arrived, and rotates a document out when one is due. ``status``
    reports the words the UI chip shows: off, watching, idle, or down."""

    def __init__(self, inbox, rotate_s: float = ROTATE_AGAIN_S) -> None:
        self.inbox = pathlib.Path(inbox)
        self.rotate_s = max(5.0, float(rotate_s))
        self.sock: socket.socket | None = None
        self.port = 0
        self.buffer = b""
        self.queue: list[dict] = []
        self.events = 0
        self.docs = 0
        self.seq = 0
        self.tmp_n = 0
        self.enabled = False
        self.state = "off"
        self.last_rotate = time.monotonic()

    def status(self) -> dict:
        return {"state": self.state, "port": self.port,
                "events": self.events, "docs": self.docs,
                "queued": len(self.queue)}

    def poll(self, port, drain_budget: float = SOCKET_IDLE_S) -> dict:
        now = time.monotonic()
        try:
            port = int(port or 0)
        except (TypeError, ValueError):
            port = 0
        # Every path that leaves the watcher without a live socket first
        # rotates what it harvested: the end of a browsing session is
        # exactly when the tail must land in the inbox, not sit in RAM
        # waiting for a reconnect that may never come.
        if not port:
            self.close()
            self._rotate_due(now)
            self.state = "off"
            return self.status()
        if self.port != port:
            self.close()
            self.port = port
        if self.sock is None and not self._connect(port, now):
            # one reconnect attempt per poll: the interval between hunt
            # cycles is already the throttle
            self.state = "down"
            self._rotate_due(now)
            return self.status()
        if self.sock is not None and not self.enabled:
            self._enable_network()
        if self.sock is not None:
            self._drain(drain_budget)
            if self.sock is None:
                self._rotate_due(now)
                self.state = "idle" if self.queue else "down"
                return self.status()
        self._rotate_due(now)
        if self.sock is not None:
            self.state = "watching"
        elif self.queue:
            self.state = "idle"
        else:
            self.state = "down"
        return self.status()

    def _rotate_due(self, now) -> None:
        if len(self.queue) >= MAX_EVENTS or (
                self.queue and now - self.last_rotate >= self.rotate_s):
            self.flush()

    def _connect(self, port, now) -> bool:
        found = discover(port)
        if not found:
            return False
        parsed = urllib.parse.urlparse(
            str(found.get("webSocketDebuggerUrl") or ""))
        path = parsed.path or "/devtools/browser"
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
            sock.settimeout(SOCKET_IDLE_S)
            key = base64.b64encode(os.urandom(16)).decode()
            sock.sendall(_HANDSHAKE.format(path=path, port=port,
                                           key=key).encode())
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                head += chunk
            if not read_ws_response(head):
                sock.close()
                return False
            # Bytes past the blank line in this same packet are the
            # first events; dropping them was a real race (the stub's
            # 101 and its frames often arrive together).
            i = head.find(b"\r\n\r\n")
            self.buffer = head[i + 4:]
        except (OSError, ValueError):
            return False
        self.sock = sock
        self.enabled = False
        return self._enable_network()

    def _enable_network(self) -> bool:
        try:
            self.sock.sendall(encode_client_text(json.dumps({
                "id": 1, "method": "Network.enable",
                "params": {"maxResourceBufferSize": 0,
                           "maxPostDataSize": 0}})))
            self.enabled = True
            return True
        except (OSError, AttributeError):
            self.close()
            return False

    def _drain(self, budget: float) -> None:
        # Bytes that arrived with the 101 are already in the buffer; parse
        # them before waiting on the socket at all, or a timeout would
        # starve them out of the drain window.
        self._absorb()
        deadline = time.monotonic() + max(0.0, budget)
        for _ in range(DRAIN_PER_POLL):
            if self.sock is None or time.monotonic() > deadline:
                break
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                self.close()
                return
            if not chunk:
                self.close()          # the browser closed its debug port
                return
            self.buffer = (self.buffer + chunk)[-BUFFER_KEEP:]
            self._absorb()

    def _absorb(self) -> None:
        """Parse complete events out of the buffer and queue them."""
        try:
            events, self.buffer = _events_from_buffer(self.buffer)
        except ValueError:
            self.buffer = b""
            return
        if events:
            self.queue.extend(events)
            if len(self.queue) > MAX_QUEUE:
                self.queue = self.queue[-MAX_QUEUE:]
            self.events += len(events)

    def flush(self) -> pathlib.Path | None:
        """Rotate the buffered events out as one HAR-shaped doc; the
        batch leaves the queue only when its document is on the disk,
        so a failed write is retried on the next poll, not lost."""
        if not self.queue:
            return None
        batch = self.queue[:MAX_EVENTS]
        doc = har_doc_from(batch)
        if not doc.get("log", {}).get("entries"):
            self.queue = self.queue[len(batch):]      # consumed, nothing
            return None                               # a reader could use
        self.seq += 1
        out = None
        try:
            # A restart re-counts from zero, so the name may already exist;
            # walk forward instead of overwriting an unprocessed document,
            # and land the write atomically (temp + exclusive rename), so a
            # sibling hunter process or the tick's reader never sees a
            # truncated document and a racing writer never truncates one.
            self.inbox.mkdir(parents=True, exist_ok=True)
            for _ in range(999):
                candidate = self.inbox / f"cdp-live-{self.seq:05d}.har"
                if not candidate.exists():
                    out = candidate
                    break
                self.seq += 1
            if out is None:
                # Every name is taken: the inbox is stalled for reasons
                # beyond this socket - keep the batch queued rather than
                # overwrite or discard an unprocessed document.
                return None
            tmp = self.inbox / f".cdp-{os.getpid()}-{self.tmp_n}.tmp"
            while True:
                try:
                    fh = open(tmp, "x")
                    break
                except FileExistsError:
                    self.tmp_n += 1
                    tmp = self.inbox / f".cdp-{os.getpid()}-{self.tmp_n}.tmp"
            with fh:
                fh.write(json.dumps(doc))
            os.replace(tmp, out)
        except OSError:
            self.tmp_n += 1
            return None
        self.queue = self.queue[len(batch):]
        self.docs += 1
        self.last_rotate = time.monotonic()
        return out

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.sendall(encode_client_close())
            except (OSError, AttributeError):
                pass
            try:
                self.sock.close()
            except (OSError, AttributeError):
                pass
        self.sock = None
        self.enabled = False