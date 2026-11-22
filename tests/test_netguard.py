import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netwatch import InboundScanWatch, NetWatch, parse_inbound_line


def _line(src="203.0.113.7", dpt=22, proto="TCP", shape="GW-SCAN",
          flags="SYN"):
    return (f"kernel: {shape}: IN=wlan0 OUT= SRC={src} "
            f"DST=192.168.0.203 PROTO={proto} SPT=4000 DPT={dpt} {flags}")


def test_parse_inbound_line_tolerates_kernel_shapes():
    pkt = parse_inbound_line(_line())
    assert pkt and pkt.src == "203.0.113.7" and pkt.dpt == 22
    assert pkt.proto == "TCP" and pkt.shape == "GW-SCAN"
    assert parse_inbound_line("garbage") is None
    assert parse_inbound_line("GW-SCAN: SRC=not-an-ip DPT=22") is None


def test_fast_scan_alerts_once_and_marks_external_block():
    seen = []
    g = InboundScanWatch(lambda s, t, m: seen.append((s, t, m)),
                         clock=lambda: 0.0)
    for port in range(4000, 4008):
        g.ingest_raw(_line(dpt=port))
    assert len(seen) == 1
    severity, text, meta = seen[0]
    assert severity == "HIGH" and "against this host" in text
    assert meta["source"] == "203.0.113.7"
    assert meta["block"] is True and meta["local"] is False
    for port in range(5000, 5008):
        g.ingest_raw(_line(dpt=port))
    assert len(seen) == 1              # cooldown


def test_slow_scan_crosses_the_long_window():
    seen = []
    now = [0.0]
    g = InboundScanWatch(lambda s, t, m: seen.append(m),
                         clock=lambda: now[0])
    for i in range(10):
        now[0] = i * 60.0
        g.ingest_raw(_line(dpt=1000 + i))
    assert len(seen) == 1
    assert seen[0]["block"] is True
    assert seen[0]["window"] == 600.0


def test_syn_fin_is_stealth_even_when_logged_as_new():
    seen = []
    g = InboundScanWatch(lambda s, t, m: seen.append(m), clock=lambda: 0.0)
    g.ingest_raw(_line(shape="GW-SCAN", flags="SYN FIN"))
    assert len(seen) == 1 and seen[0]["kind"] == "stealth"


def test_stealth_alerts_first_then_blocks_on_second():
    seen = []
    now = [0.0]
    g = InboundScanWatch(lambda s, t, m: seen.append(m),
                         clock=lambda: now[0])
    g.ingest_raw(_line(shape="GW-STEALTH", flags="FIN"))
    assert len(seen) == 1 and seen[0]["kind"] == "stealth"
    assert seen[0]["block"] is False
    now[0] = 5.0
    g.ingest_raw(_line(dpt=23, shape="GW-STEALTH", flags="FIN"))
    assert len(seen) == 2 and seen[-1]["block"] is True


def test_private_and_loopback_sources_are_never_autoblocked():
    for src in ("192.168.0.32", "10.1.2.3", "172.16.0.5", "127.0.0.1",
                "169.254.1.1"):
        seen = []
        g = InboundScanWatch(lambda s, t, m: seen.append(m),
                             clock=lambda: 0.0)
        for port in range(1, 9):
            g.ingest_raw(_line(src=src, dpt=port))
        assert seen, src
        assert seen[0]["block"] is False and seen[0]["local"] is True
        assert seen[0]["reason"] in ("lan", "loopback", "link-local")


def test_global_ipv6_sweep_is_blockable_like_ipv4():
    seen = []
    g = InboundScanWatch(lambda s, t, m: seen.append(m), clock=lambda: 0.0)
    for port in range(1, 9):
        g.ingest_raw(_line(src="2001:db8::9", dpt=port))
    assert seen and seen[0]["local"] is False
    assert seen[0]["block"] is True
    assert seen[0]["reason"] == "external"


def test_duplicate_log_line_does_not_inflate_the_port_count():
    seen = []
    g = InboundScanWatch(lambda s, t, m: seen.append(m), clock=lambda: 0.0)
    for port in range(1, 8):
        g.ingest_raw(_line(dpt=port))
    g.ingest_raw(_line(dpt=7))        # duplicate, same source/port/time
    assert seen == []


def test_netwatch_raw_ufw_line_is_analyzed():
    """Regression: parse_ufw's display text lost SRC=/DPT=, so the old
    daemon path could never feed NetWatch from a real UFW line."""
    seen = []
    nw = NetWatch(lambda s, t: seen.append((s, t)))
    for port in range(4000, 4008):
        nw.ingest_line(
            "ufw", f"[ 1.0] [UFW BLOCK] IN=wlan0 SRC=203.0.113.7 "
                   f"DST=192.168.0.203 PROTO=TCP DPT={port}")
    assert len(seen) == 1 and "port scan" in seen[0][1]


def test_temporary_ledger_block_expires(tmp_path):
    import datetime as dt
    import blockledger
    past = (dt.datetime.now(dt.timezone.utc)
            - dt.timedelta(minutes=1)).isoformat(timespec="seconds")
    future = (dt.datetime.now(dt.timezone.utc)
              + dt.timedelta(minutes=30)).isoformat(timespec="seconds")
    blockledger.record_block(tmp_path, "203.0.113.9", "net-watch",
                             "scan", expires_at=past, ttl_s=60)
    assert blockledger.active_blocks(tmp_path) == {}
    blockledger.record_block(tmp_path, "203.0.113.10", "net-watch",
                             "scan", expires_at=future, ttl_s=1800)
    active = blockledger.active_blocks(tmp_path)
    assert "203.0.113.10" in active
    assert active["203.0.113.10"]["ttl_s"] == 1800
