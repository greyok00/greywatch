import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netwatch import NetWatch


class E:
    def __init__(self, from_tool, text):
        self.from_tool, self.text = from_tool, text


def test_port_scan_detected_and_cooldown():
    seen = []
    nw = NetWatch(lambda sev, text: seen.append((sev, text)))
    src = "203.0.113.7"
    lines = [E("ufw", f"[UFW BLOCK] IN=wlan0 SRC={src} "
                       f"DST=192.168.77.50 PROTO=TCP DPT={p}")
             for p in range(4000, 4012)]          # 12 distinct ports > 8
    for line in lines:
        nw.ingest(line)
    scans = [s for s in seen if "port scan" in s[1]]
    assert len(scans) == 1 and scans[0][0] == "HIGH"
    assert src in scans[0][1]
    for p in range(5000, 5015):
        nw.ingest(E("ufw", f"[UFW BLOCK] SRC={src} DST=192.168.77.50 "
                            f"PROTO=TCP DPT={p}"))
    assert len([s for s in seen if "port scan" in s[1]]) == 1


def test_scattered_traffic_is_not_a_scan():
    seen = []
    nw = NetWatch(lambda sev, text: seen.append((sev, text)))
    for i in range(10):
        nw.ingest(E("ufw", f"[UFW BLOCK] SRC=198.51.100.{i} "
                           f"DST=192.168.77.50 PROTO=TCP DPT=443"))
    assert seen == []                           # ten sources, one port each


def test_connection_burst_by_one_program():
    seen = []
    nw = NetWatch(lambda sev, text: seen.append((sev, text)))
    for i in range(35):
        nw.ingest(E("appfw", f"appfw python3 → host{i}.example:443 allow "
                             f"[note]"))
    bursts = [b for b in seen if "connection burst" in b[1]]
    assert len(bursts) == 1 and bursts[0][0] == "MEDIUM"


def test_denial_cluster_vs_one_host():
    seen = []
    nw = NetWatch(lambda sev, text: seen.append((sev, text)))
    text = ("appfw curl → ads.example:443 deny "
            "[blocked by the downloaded list: ads.example]")
    for _ in range(5):
        nw.ingest(E("appfw", text))
    clusters = [c for c in seen if "denied attempts" in c[1]]
    assert len(clusters) == 1 and clusters[0][0] == "MEDIUM"


def test_analyzer_never_raises_on_garbage():
    seen = []
    nw = NetWatch(lambda sev, text: seen.append((sev, text)))
    for line in ("", "garbage", "SRC= DPT=", "appfw", None):
        if line is None:
            try:
                nw.ingest(E("appfw", None))
            except Exception as e:              # pragma: no cover
                raise AssertionError(f"analyzer raised: {e}")
        else:
            nw.ingest(E("ufw", line))
            nw.ingest(E("appfw", line))
    assert isinstance(seen, list)               # anything, raised nothing
