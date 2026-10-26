"""The wizard's real-information layer (owner 2026-10-23: "it should not
require me typing anything"). Parsers are pure so they can be tested with
real command output captured once, headless."""
import pathlib

import ui.discover as d


def test_interfaces_hide_virtual_plumbing_and_wifi_first(monkeypatch,
                                                         tmp_path):
    fake = tmp_path / "sys" / "class" / "net"
    for name in ("wlan0", "eth1"):          # machine-independent: no /sys
        (fake / name / "wireless").parent.mkdir(parents=True, exist_ok=True)
    (fake / "wlan0" / "wireless").touch()
    monkeypatch.setattr(d, "SYS_NET", str(fake))
    got = d.parse_interfaces(["lo", "docker0", "veth1a2b", "br-123",
                              "eth1", "wlan0"])
    assert [i["name"] for i in got] == ["wlan0", "eth1"]
    assert got[0]["wireless"] is True
    assert got[1]["wireless"] is False


def test_neighbours_skip_failed_and_docker():
    text = """192.168.77.1 dev wlan0 lladdr 02:4e:71:2a:21:a6 REACHABLE
192.168.77.233 dev wlan0 FAILED
172.17.0.4 dev docker0 lladdr 02:42:ac:11:00:04 STALE
192.168.77.32 dev wlan0 lladdr 02:4d:12:98:12:76 STALE
192.168.77.1 dev wlan0 lladdr 02:4e:71:2a:21:a6 REACHABLE"""
    got = d.parse_neighbors(text)
    assert [h["ip"] for h in got] == ["192.168.77.1", "192.168.77.32"]
    assert got[0]["reachable"] is True and got[0]["mac"].startswith("02:")


def test_listening_ports_only_outside_facing():
    text = """LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:11600 0.0.0.0:*
LISTEN 0 4096 [::]:443 [::]:*"""
    ports = d.parse_listening(text)
    assert [p["port"] for p in ports] == [22, 443]
    assert ports[0]["label"].startswith("22 · SSH")


def test_established_peers_are_web_connections_only():
    text = """ESTAB 0 0 192.168.77.5:53122 142.250.185.78:443
ESTAB 0 0 192.168.77.5:53123 10.0.0.2:8080
ESTAB 0 0 192.168.77.5:53124 151.101.1.1:80"""
    assert d.parse_established(text) == ["142.250.185.78", "151.101.1.1"]


def test_desktop_entries_resolve_real_program_paths(tmp_path):
    f1 = tmp_path / "good.desktop"
    f1.write_text("[Desktop Entry]\nName=Tested App\nExec=/bin/sh -c true %u\n")
    f2 = tmp_path / "hidden.desktop"
    f2.write_text("[Desktop Entry]\nName=Hidden\nExec=/bin/sh\nNoDisplay=true\n")
    f3 = tmp_path / "missing.desktop"
    f3.write_text("[Desktop Entry]\nName=Gone\nExec=/no/such/program\n")
    got = d.parse_desktop([(f1, f1.read_text()), (f2, f2.read_text()),
                           (f3, f3.read_text())])
    assert got == [("Tested App", "/bin/sh")]


def test_malware_catalogue_names_are_generated_and_valid():
    assert d.yara_name("eicar").startswith("gw_eicar")
    src = d.yara_source("webshell", "gw_webshell")
    assert "rule gw_webshell" in src and "2 of ($a, $b, $c)" in src


def test_fail2ban_names_come_from_what_is_watched():
    assert d.f2b_name("journal:ssh.service") == "ssh-guard"
    assert d.f2b_name("/var/log/nginx/access.log") == "access-guard"
    assert d.f2b_name("") == "log-guard"


def test_pattern_catalogue_regexes_use_the_host_token():
    for p in d.F2B_PATTERNS:
        assert "<HOST>" in p["regex"], p["key"]
        assert p["title"] and p["about"]


def test_enabled_jails_reads_the_real_config_shape(tmp_path):
    # the parser runs on the real directory; this asserts the real machine
    # has the shipped sshd jail and the result is plain names.
    jails = d.enabled_jails()
    assert all(isinstance(j, str) and j and not j.startswith("[") for j in jails)


def test_blocklist_parser_accepts_real_hosts_lines(tmp_path):
    from ui import blocklist
    text = ("# header\n0.0.0.0 ads.example\n127.0.0.1 tracker.example\n"
            "0.0.0.0 localhost\n::1 ip6-localhost\n0.0.0.0 bad_host\n"
            "0.0.0.0 0.0.0.0\n")
    assert blocklist.parse_hosts(text) == {"ads.example", "tracker.example"}
    path = tmp_path / "bl.txt"
    path.write_text(text)
    bl = blocklist.BlockList(path)
    assert bl.match("ads.example") and bl.match("x.ads.example")
    assert not bl.match("notads.example")
