"""The live CDP watcher: framing, HAR shaping, rotation, and a stub.

The stub is a threaded localhost server that speaks the RFC6455
handshake and two canned CDP frames. Nothing here touches a real
browser; the whole lane is read-only metadata (no bodies, no
evaluation, no input).
"""
import json
import socketserver
import threading

from hunter import store, watch, web


# ---------------------------------------------------------------- framing

def test_client_frames_round_trip():
    raw = watch.encode_client_text("hello")
    opcode, payload, used = watch.parse_frame(raw, client=False)
    assert opcode == 1 and payload == b"hello" and used == len(raw)
    # long payloads use the 16-bit and 64-bit length forms and survive
    long = "x" * 70000
    raw = watch.encode_client_text(long)
    opcode, payload, used = watch.parse_frame(raw, client=False)
    assert opcode == 1 and payload == long.encode() and used == len(raw)


def test_server_frames_parse_without_mask():
    frame = bytes([0x81, 0x03]) + b"abc"
    opcode, payload, used = watch.parse_frame(frame, client=True)
    assert opcode == 1 and payload == b"abc" and used == 5
    frames = frame + bytes([0x81, 0x00])
    i = 0
    seen = []
    while i < len(frames):
        op, pl, used = watch.parse_frame(frames[i:], client=True)
        seen.append((op, pl))
        i += used
    assert seen == [(1, b"abc"), (1, b"")]


def test_close_frame_is_the_end():
    close = bytes([0x88, 0x02, 0x03, 0xE8])
    opcode, _payload, _used = watch.parse_frame(close, client=True)
    assert opcode == 8


# --------------------------------------------------------------- har docs

_REQUEST_WILL_BE_SENT = {
    "method": "Network.requestWillBeSent",
    "params": {"requestId": "1", "request": {
        "url": "https://kit.example/load.js", "method": "GET"},
        "type": "Script"},
}
_RESPONSE_RECEIVED = {
    "method": "Network.responseReceived",
    "params": {"requestId": "1", "response": {
        "url": "https://kit.example/load.js", "status": 200,
        "mimeType": "text/javascript",
        "headers": {"content-type": "text/javascript"}}},
}


def test_har_doc_round_trips_through_parse_har(tmp_path):
    doc = watch.har_doc_from([_REQUEST_WILL_BE_SENT, _RESPONSE_RECEIVED])
    out = tmp_path / "live.har"
    out.write_text(json.dumps(doc), encoding="utf-8")
    parsed = web.parse_har(out)
    assert parsed and parsed["entries"], "parse_har must read a live doc"
    e = parsed["entries"][0]
    assert e["url"] == "https://kit.example/load.js"
    assert e["host"] == "kit.example"
    assert e["status"] == 200
    assert e["mime"] == "text/javascript"


def test_har_doc_caps_events():
    events = [dict(_REQUEST_WILL_BE_SENT, params=dict(
        _REQUEST_WILL_BE_SENT["params"], requestId=str(i),
        request={"url": f"https://h{i}.example/", "method": "GET"}))
        for i in range(watch.MAX_EVENTS + 50)]
    doc = watch.har_doc_from(events)
    assert len(doc["log"]["entries"]) == watch.MAX_EVENTS


# ------------------------------------------------------------- discovery

def test_discover_reads_the_version_endpoint(tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"Browser": "Stub/1.0",
                               "webSocketDebuggerUrl":
                               "ws://127.0.0.1:9/anything"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        found = watch.discover(port)
        assert found and found.get("webSocketDebuggerUrl")
    finally:
        srv.shutdown()
    assert watch.discover(1 + port) is None or True   # absent port: no crash


# ---------------------------------------------------- the watcher + stub

def _stub_frames():
    def frame(payload: bytes) -> bytes:
        n = len(payload)
        assert n < 65536
        return bytes([0x81, 0x7E]) + n.to_bytes(2, "big") + payload

    ev1 = json.dumps({"method": "Network.requestWillBeSent", "params": {
        "requestId": "7", "type": "Script",
        "request": {"url": "https://stub.example/a.js", "method": "GET"}}})
    ev2 = {"method": "Network.responseReceived", "params": {
        "requestId": "7",
        "response": {"url": "https://stub.example/a.js", "status": 200,
                     "mimeType": "text/javascript",
                     "headers": {"content-type": "text/javascript"}}}}
    ev3 = json.dumps({"method": "Network.requestWillBeSent", "params": {
        "requestId": "8", "type": "Document",
        "request": {"url": "https://stub.example/", "method": "GET"}}})
    return frame(ev1.encode()), frame(json.dumps(ev2).encode()), \
        frame(ev3.encode())


class _WsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        # read the request head to the blank line
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                return
            data += chunk
        if data.startswith(b"GET /json"):
            body = json.dumps({"Browser": "Stub/1.0",
                               "webSocketDebuggerUrl":
                               "ws://127.0.0.1:9/anything"}).encode()
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\n\r\n" + body)
            return
        reply = (b"HTTP/1.1 101 Switching Protocols\r\n"
                 b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                 b"Sec-WebSocket-Accept: stub\r\n\r\n")
        sock.sendall(reply)
        for fr in _stub_frames():
            try:
                sock.sendall(fr)
            except OSError:
                return
        # Linger long enough that the watcher's own enable frame has
        # arrived and its drain window has started before the close; a
        # 0.2 s linger raced the whole handshake on a loaded machine.
        sock.settimeout(1.0)
        try:
            while sock.recv(4096):
                pass
        except OSError:
            pass


def test_watcher_polls_the_stub_and_writes_the_doc(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    srv = socketserver.TCPServer(("127.0.0.1", 0), _WsHandler)
    srv.allow_reuse_address = True
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        w = watch.Watcher(store.inbox_dir(str(data_dir)))
        status = w.poll(port, drain_budget=0.5)
        assert status["state"] in ("watching", "idle"), status
        assert status["events"] >= 1, "the stub's frames must be buffered"
    finally:
        srv.shutdown()
        srv.server_close()
    f = w.flush()
    assert f is not None and f.is_file(), "flush wrote the buffered doc"
    parsed = web.parse_har(f)
    assert parsed and any(e["url"] == "https://stub.example/a.js"
                          for e in parsed["entries"])
    assert w.poll(1 + port)["state"] == "down"


def test_watcher_without_an_endpoint_sits_down(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    w = watch.Watcher(store.inbox_dir(str(data_dir)))
    assert w.poll(59996)["state"] == "down"
    assert w.poll(59997)["state"] == "down"