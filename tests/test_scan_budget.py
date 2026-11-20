"""Scan throttling: every on-demand scanner runs capped by default, and
ClamAV runs barely at all until asked for speed.

Owner directive 2026-11-03: boots were slammed by uncapped scanners,
ClamAV loudest of all. The fix lives in scan_session.py: THROTTLE caps per
tool (systemd unit properties, with a nice/ionice fallback), breadth caps
in the ClamAV argv, a 45s-deffered updates thread, and two customer keys —
``full`` (throttled) and ``max-speed`` (the one uncapped run, UI confirms
first). The legacy ``scan-all`` key keeps working for upgrades."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_throttle_table_caps_every_serial_scanner():
    from scan_session import SCAN_ALL, THROTTLE
    for tool in SCAN_ALL:
        caps = THROTTLE[tool]
        assert caps["io_class"] == "idle", tool
        assert caps["weight"] <= 50, tool
        assert caps["cpu_quota"] != "", tool
    # ClamAV is the heaviest, so it keeps the broadest allowance — on a
    # 20-core box three cores, never the old quarter of one (owner
    # 2026-11-19: "it should have never been capped to a single core").
    clamav = THROTTLE["clamav"]
    assert clamav["cpu_quota"] == "300%"
    assert clamav["nice"] == 10
    assert clamav["mem"] != ""


def test_unit_properties_are_correctly_spelled_and_throttle_only():
    from scan_session import unit_properties_for
    props = unit_properties_for("clamav", True)
    text = " ".join(props)
    assert "--property=CPUQuota=300%" in text
    assert "--property=Nice=10" in text
    assert "--property=MemoryMax=1536M" in text
    assert "--property=IOSchedulingClass=idle" in text
    assert "--property=CPUWeight=" in text
    # An uncapped run never carries caps — that is the whole product point.
    assert unit_properties_for("clamav", False) == []


def test_unknown_tool_gets_no_caps():
    from scan_session import unit_properties_for
    assert unit_properties_for("yara-anything-else", True) == []


def test_clamav_argv_breadth_caps_land_when_throttled():
    # Superseded (owner 2026-11-17): the resident engine is retired and
    # nothing consults its socket; the throttled standalone scanner IS
    # the antivirus. Every mode runs throttled - no run drops the caps.
    from scan_session import commands_for, MODES
    home, ui_user = "/home/alice", "grey"
    throttled = commands_for("clamav", home, ui_user)[0]
    joined = " ".join(throttled)
    assert "--max-filesize=512M" in joined
    assert "--max-scansize=2G" in joined
    assert "--cross-fs=no" in joined
    assert throttled[0] == "/usr/bin/clamscan"
    assert "clamdscan" not in joined
    # The uncapped variant is retired: one shape for every run, the
    # machine always keeps the desktop.
    for key, (_order, throttled_mode) in MODES.items():
        assert throttled_mode is True, (
            f"mode {key} runs uncapped - the banned shape")
    for mode_key in ("full", "max-speed"):
        argv = commands_for(mode_key, home, ui_user)[0]
        if argv[0].endswith("clamscan"):
            assert "--max-filesize=512M" in " ".join(argv)
    # The live engine path is retired (owner 2026-11-17): no socket is
    # consulted, no clamdscan ever leaves this module.


def test_full_max_speed_and_legacy_scan_all_run_the_same_five():
    from scan_session import commands_for
    home, ui_user = "/home/alice", "grey"
    for key in ("full", "max-speed", "scan-all"):
        tools = [c[0] for c in commands_for(key, home, ui_user)]
        assert len(tools) == 5, (key, tools)
    a = commands_for("full", home, ui_user)
    b = commands_for("scan-all", home, ui_user)
    assert a == b


def test_the_launch_path_carries_the_throttle_decision():
    """Max speed is uncapped end to end: _launch passes the session's
    throttle decision into commands_for, or the breadth caps would linger
    while the unit caps drop — a max-speed run that still refuses files."""
    src = (ROOT / "scan_session.py").read_text(encoding="utf-8")
    body = src[src.index("def _launch"):]
    assert "throttle=bool((self.session or {}).get(\"throttle\", True))" \
        in body[:3000]


def test_clamav_scan_key_maps_to_deep_scan():
    # one scanner for the key; the engine picks the binary by the live
    # socket (D1-a): clamdscan when the daemon serves, clamscan fallback
    from scan_session import commands_for
    tools = [c[0] for c in commands_for("clamav", "/home/alice", "grey")]
    assert len(tools) == 1
    assert tools[0] in ("/usr/bin/clamdscan", "/usr/bin/clamscan")


def test_updates_thread_is_deferred_not_absent():
    """Boot is a ramp (owner, 2026-11-03): protections start immediately,
    the CVE refresh waits behind a 45s delay instead of sprinting at boot."""
    src = (ROOT / "greywatch_daemon.py").read_text(encoding="utf-8")
    assert "UPDATES_DELAY_S" in src
    assert "_updates_later" in src
    assert "sleep(" in src
    assert "ensure_updates" in src
    for needle in ("45", "gw-updates-later"):
        assert needle in src, needle




def test_detached_handle_accepts_unit_properties():
    """Caps must survive the spawner boundary: DetachedHandle takes the
    properties list and _start_unit appends it after RuntimeMaxSec."""
    src = (ROOT / "scan_session.py").read_text(encoding="utf-8")
    assert "properties=None" in src or "properties: " in src
    assert "self.properties" in src
    assert "RuntimeMaxSec" in src

def test_scan_commands_carry_the_scratch_exclusions():
    """The app's own scratch trees are never findings (owner confirmed
    the flagged paths were test dummies + the pentest payload):
    the clamscan argv excludes them, and the sync teaches tetragon the
    same list (2026-11-14; the socket pick retired 2026-11-17)."""
    import scan_session as ss
    argv = " ".join(ss.commands_for("clamav", "/home/alice", "grey")[0])
    assert "--exclude-dir=pytest-of-grey" in argv
    assert "--exclude=gw-eicar" in argv
    sync = (ss.__file__ and pathlib.Path(
        __file__).resolve().parents[1] / "sync-to-system.sh").read_text()
    assert "ExcludePath /etc/unicornscan" in sync
    assert "GW-POLICY-EXCLUDES" in sync
