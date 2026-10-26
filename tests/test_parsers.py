import pathlib

import pytest

from events import normalize_event
from registry import load_registry
from parsers import PARSERS

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
REGISTRY = load_registry()


def _lines(tool):
    f = FIXTURES / f"{tool}.txt"
    if not f.exists():
        return []
    return [raw for raw in f.read_text().splitlines()
            if raw.strip() and not raw.lstrip().startswith(("#", "!SKIP "))]


def _ev(tool, line):
    return normalize_event(tool, line)


def test_every_tool_has_a_parser():
    names = {t["name"] for t in REGISTRY}
    assert set(PARSERS) == names



JUNK = ["", "   ", "\x00", "}{{{{", "a" * 5000, "\x00\x01\x02binary\x7f",
        '{"partial":', "not json but has braces }{{", "\n", "\t", "€©üñî",
        '{"ts": "nope", "action": 42}']


@pytest.mark.parametrize("tool", sorted(PARSERS))
@pytest.mark.parametrize("junk", JUNK)
def test_all_parsers_never_raise_on_junk(tool, junk):
    assert PARSERS[tool](junk) is None


@pytest.mark.parametrize("tool", sorted(PARSERS))
def test_every_fixture_line_parses(tool):
    for line in _lines(tool):
        ev = normalize_event(tool, line)
        assert ev is not None, f"{tool} failed on: {line[:80]}"


@pytest.mark.parametrize("tool", sorted(PARSERS))
def test_skip_lines_stay_none(tool):
    f = FIXTURES / f"{tool}.txt"
    if not f.exists():
        return
    for raw in f.read_text().splitlines():
        if raw.lstrip().startswith("!SKIP "):
            line = raw.lstrip().removeprefix("!SKIP ")
            assert normalize_event(tool, line) is None, \
                f"{tool}: noise line produced an event: {line[:80]}"



def test_responderd_severities():
    assert _ev("responderd", '{"ts": "2026-10-22 18:40:11", "action": "quarantine", "detail": "x"}').severity == "HIGH"
    assert _ev("responderd", '{"ts": "2026-10-22 18:40:11", "action": "kill", "detail": "x"}').severity == "HIGH"
    assert _ev("responderd", '{"ts": "2026-10-22 18:46:52", "action": "tetragon_watch", "detail": "x"}').severity == "INFO"
    assert _ev("responderd", '{"ts": "2026-10-22 18:40:13", "action": "alert_local_only", "detail": "tick"}').severity == "INFO"


def test_yara_found_is_high():
    e = _ev("yara-watch", "eicar /tmp/eicar-rt2.txt (realtime sha256:275a021bbfb6489e)")
    assert e.severity == "HIGH" and "eicar" in e.text


def test_clamav_infected_files():
    assert _ev("clamav", "Infected files: 0").severity == "INFO"
    assert _ev("clamav", "Infected files: 2").severity == "HIGH"
    assert _ev("clamav", "/usr/tmp/eicar.txt FOUND").severity == "HIGH"


def test_fail2ban_ban_unban():
    ban = _ev("fail2ban", "2026-10-22 18:00:32,110 fail2ban.actions [4247]: NOTICE [sshd] Ban 203.0.113.9")
    assert ban.severity == "HIGH" and "sshd" in ban.text and "203.0.113.9" in ban.text
    unb = _ev("fail2ban", "2026-10-22 19:00:33,110 fail2ban.actions [4247]: NOTICE [sshd] Unban 203.0.113.9")
    assert unb.severity == "INFO"


def test_ufw_block_levels():
    e = _ev("ufw", "[ 81234.567891] [UFW BLOCK] IN=wlan0 OUT= SRC=203.0.113.9 DST=192.168.77.50 PROTO=TCP DPT=23")
    assert e.severity == "MEDIUM" and "203.0.113.9" in e.text
    u = _ev("ufw", "[ 81300.111222] [UFW BLOCK_UNKNOWN] IN=wlan0 OUT= SRC=203.0.113.99 DST=192.168.77.50 PROTO=UDP")
    assert u.severity == "HIGH"




def test_appfw_allow_deny():
    a = normalize_event("appfw",
                        "appfw python3 → example.com:443 allow "
                        "[permitted local service]")
    assert a and a.severity == "INFO" and "allow" in a.text.lower()
    d = normalize_event("appfw",
                        "appfw curl → bad.example:80 deny "
                        "[blocked by the downloaded list: bad.example]")
    assert d and d.severity == "MEDIUM"


def test_arpwatch_message_kinds():
    new = normalize_event("arpwatch", "Oct 22 18:00:01 host arpwatch[247]: new station 192.168.77.77 (0:11:22:33:44:55)")
    assert new and new.severity == "INFO"
    flip = normalize_event("arpwatch", "Oct 22 18:05:09 host arpwatch[247]: flipped bits or wifi wlan0")
    assert flip and flip.severity == "MEDIUM"
    chg = normalize_event("arpwatch", "Oct 22 18:06:00 host arpwatch[247]: changed ethernet address 192.168.77.77")
    assert chg and chg.severity == "MEDIUM"
    assert _ev("arpwatch", "Oct 22 18:06:30 host arpwatch[247]: arp cache maintained") is None


def test_aide_differences():
    assert _ev("aide", "aide-run --check: differences found!").severity == "HIGH"
    assert _ev("aide", "aide-run --check: no differences found!").severity == "INFO"


def test_apparmor_denied_only():
    e = _ev("apparmor", 'type=AVC msg=audit(1758533000.100:223): apparmor="DENIED" operation="open" profile="/usr/bin/lynis" comm="lynis" pid=910')
    assert e.severity == "MEDIUM" and "DENIED" in e.text


def test_lynis_warnings_only():
    w = _ev("lynis", "2026-10-22 06:00:00 Warning: Found weak SSH MAC algorithm in sshd_config")
    assert w.severity == "MEDIUM"
    assert _ev("lynis", "2026-10-22 06:00:00 Lynis version: 3.1.4") is None


def test_rkhunter_levels():
    w = _ev("rkhunter", "[18:01:00]     Warning: Suspicious file type found in file: /etc/passwd.check")
    assert w.severity == "HIGH"
    c = _ev("rkhunter", "[18:02:00]   No warnings were found while checking the system.")
    assert c.severity == "INFO"


def test_auditd_types():
    e = _ev("auditd", 'type=SYSCALL msg=audit(1758532800.001:221): arch=c000003e syscall=59 success=yes')
    assert e.severity == "INFO" and e.from_tool == "auditd"
    a = _ev("auditd", "type=ANOM_ABEND msg=audit(1758532900.500:222): auid=0 ses=1")
    assert a.severity == "MEDIUM"


def test_tetragon_exec_event():
    e = _ev("tetragon", '{"ts": "2026-10-22 18:46:52", "raw_time": "2026-10-23T01:46:51.914676024Z", "binary": "/bin/bash", "pid": 869948, "uid": null, "parent": "claude", "args": "-c echo hi"}')
    assert e and "/bin/bash" in e.text and "pid=869948" in e.text
    assert e.severity == "INFO"
