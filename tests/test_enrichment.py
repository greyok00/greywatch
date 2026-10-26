import http.server
import importlib.util
import json
import pathlib
import socketserver
import threading

import pytest

from enrichment import enrich, extract_cves, load_map, sync_map_names
from events import Event
from registry import load_registry

_spec = importlib.util.spec_from_file_location(
    "cve_refresh", pathlib.Path(__file__).resolve().parents[1] / "cve-refresh.py")
cve_refresh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cve_refresh)
cve_refresh.REQ_GAP_S = 0.01               # tests: no 6 s throttle between stubs

REGISTRY = load_registry()
DEAD_URL = "http://127.0.0.1:1/x"          # nothing listens: offline proxy


def test_map_covers_every_registered_tool():
    sync_map_names(REGISTRY)               # raises if not


def test_enrich_all_severities_and_tools():
    for name in load_map():
        e = Event(from_tool=name, severity="HIGH", text="text CVE-2026-1234",
                  ts="2026-10-22T00:00:00+00:00")
        enrich(e)
        assert e.nist_func in ("IDENTIFY", "PROTECT", "DETECT", "RESPOND")
        assert e.nist_control and all(
            c.startswith(("AC-", "SI-", "AU-", "CM-", "SC-7", "CA-", "RA-"))
            for c in e.nist_control)
        assert e.cves == ["CVE-2026-1234"]


def test_enrich_defaults_per_tool():
    e = Event(from_tool="ufw", severity="MEDIUM", text="BLOCK 1.2.3.4",
              ts="2026-10-22T00:00:00+00:00")
    enrich(e)
    assert e.nist_func == "PROTECT" and "AC-4" in e.nist_control
    r = Event(from_tool="fail2ban", severity="HIGH", text="Ban 1.2.3.4",
              ts="2026-10-22T00:00:00+00:00")
    enrich(r)
    assert r.nist_func == "RESPOND" and "AC-7" in r.nist_control


def test_enrich_never_raises_on_unknown_tool():
    e = Event(from_tool="ghost-tool", severity="INFO", text="x", ts="t")
    enrich(e)
    assert e.nist_func == "DETECT"


def test_cve_regex_validated():
    assert extract_cves("hits CVE-2026-1234 and cve-nope and CVE-26-001 and CVE-2026-22222222") \
        == ["CVE-2026-1234"]
    assert extract_cves("CVE-2026-2222222 stays") == ["CVE-2026-2222222"]
    assert extract_cves("none here") == []



def _serve(body: bytes):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_cve_refresh_offline_writes_reason(tmp_path):
    cache = tmp_path / "cve-cache.json"
    cve_refresh.refresh(base_url=DEAD_URL, cache_path=cache, queries=["a"])
    data = json.loads(cache.read_text())
    assert data["reason"].startswith("offline")
    assert data["fetched_utc"]
    assert cve_refresh.main() == 0          # module contract: offline exits 0


def test_cve_refresh_stubbed_online_parses_entries(tmp_path):
    good = json.dumps({"vulnerabilities": [
        {"cve": {"id": "CVE-2026-0001", "lastModified": "2026-10-22"}},
        {"cve": {"id": "garbage"}, "broken": True},
    ]}).encode()
    srv, url = _serve(good)
    try:
        c = tmp_path / "online.json"
        cve_refresh.refresh(base_url=url, cache_path=c, queries=["appfw"],
                            )
        d = json.loads(c.read_text())
        assert d["reason"] is None
        assert d["entries"] == [{"id": "CVE-2026-0001", "modified": "2026-10-22"}]
    finally:
        srv.shutdown()


def test_cve_refresh_malformed_body_never_raises(tmp_path):
    srv, url = _serve(b"not-json at all")
    srv2, url2 = _serve(json.dumps({"vulnerabilities": "notalist"}).encode())
    try:
        c = tmp_path / "malformed-cache.json"
        cve_refresh.refresh(base_url=url, cache_path=c, queries=["clamav"])
        d = json.loads(c.read_text())
        assert d["reason"].startswith("offline")   # bad JSON → treated as failed fetch
        c2 = tmp_path / "malformed2.json"
        cve_refresh.refresh(base_url=url2, cache_path=c2, queries=["clamav"])
        d2 = json.loads(c2.read_text())
        assert d2["reason"] is None and d2["entries"] == []
    finally:
        srv.shutdown()
        srv2.shutdown()


def test_cve_cache_caps(tmp_path):
    many = json.dumps({"vulnerabilities": [
        {"cve": {"id": f"CVE-2026-{i:04d}", "lastModified": "x"}}
        for i in range(1, 901)]}).encode()
    srv, url = _serve(many)
    try:
        c = tmp_path / "c.json"
        cve_refresh.refresh(base_url=url, cache_path=c, queries=["yara"])
        d = json.loads(c.read_text())
        assert len(d["entries"]) <= cve_refresh.MAX_ENTRIES_QUERIES
    finally:
        srv.shutdown()


def test_cve_refresh_preserves_previous_entries_offline(tmp_path):
    c = tmp_path / "cache.json"
    c.write_text(json.dumps({"fetched_utc": "old",
                             "entries": [{"id": "CVE-2025-9999", "modified": ""}],
                             "reason": None}))
    cve_refresh.refresh(base_url=DEAD_URL, cache_path=c, queries=["a"])
    d = json.loads(c.read_text())
    assert any(e["id"] == "CVE-2025-9999" for e in d["entries"])
    assert d["reason"]
