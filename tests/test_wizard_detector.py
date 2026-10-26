from __future__ import annotations

import pathlib
import re
import tempfile

import pytest

from wizard.detector import (
    ProbeResult,  # noqa: F401 - re-exported surface check
    desktop_env,
    disk_encrypted,
    disk_space,
    firewall_state,
    form_factor,
    listeners,
    pkg_has,
    prod_runner,
    services_running,
    sysctl_get,
)

PASS, CANT = "PASS", "CANT-CHECK"

_ID_PATTERNS = [
    re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"),      # MAC
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
               r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),          # UUID
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),                    # serial-like hex
]


def assert_no_identifiers(value):
    text = str(value)
    for pat in _ID_PATTERNS:
        assert not pat.search(text), f"identifier leaked: {text!r}"


class FakeRunner:

    def __init__(self, table):
        self.table = table

    def __call__(self, line):
        if line.startswith(("sudo", "pkexec", "doas", "su ")):
            raise RuntimeError(f"refusing escalation: {line}")
        for key, resp in self.table.items():
            if line.startswith(key):
                return resp
        raise RuntimeError(f"unexpected probe: {line}")


def ok(rc, out):
    return (rc, out)


PKG_CASES = [
    ({"dpkg --version": ok(0, ""),
      "dpkg -s nginx": ok(0, "Package: nginx\nStatus: install ok installed")},
     "nginx", PASS, True, "dpkg says installed"),
    ({"dpkg --version": ok(0, ""),
      "dpkg -s nginx": ok(1, "not installed")},
     "nginx", PASS, False, "dpkg says absent"),
    ({"dpkg --version": ok(0, ""),
      "dpkg -s nginx": ok(3, "dpkg: error")},
     "nginx", "FAIL", None, "manager misfire is FAIL, not CANT"),
    ({"dpkg --version": ok(127, "not found"),
      "rpm --version": ok(0, ""),
      "rpm -q nginx": ok(0, "nginx-1.2.3")},
     "nginx", PASS, True, "rpm fallback"),
    ({"dpkg --version": ok(127, ""),
      "rpm --version": ok(127, ""),
      "pacman --version": ok(0, ""),
      "pacman -Q nginx": ok(1, "not found")},
     "nginx", PASS, False, "pacman fallback absent"),
    ({}, "nginx", CANT, None, "no manager at all"),
]


@pytest.mark.parametrize("table,name,state,value,label", PKG_CASES)
def test_pkg_has(table, name, state, value, label):
    res = pkg_has(name, runner=FakeRunner(table))
    assert (res.state, res.value) == (state, value), label
    assert_no_identifiers(res.value)


@pytest.mark.parametrize("name", ["", "nginx;rm -rf /", "nginx\netc",
                                  "nginx/", "nginx,deb", "nginx%sudo"])
def test_pkg_has_rejects_malformed_names(name):
    assert pkg_has(name, runner=FakeRunner({})).state == "FAIL"


def test_pkg_has_chain_continues_after_exception():
    class Picky(FakeRunner):
        def __call__(self, line):
            if line.startswith("dpkg -s"):
                raise RuntimeError("dpkg crashed")
            return super().__call__(line)

    res = pkg_has("nginx", runner=Picky({
        "dpkg --version": ok(0, ""),
        "pacman --version": ok(0, ""),
        "pacman -Q nginx": ok(0, ""),
    }))
    assert res.state == PASS and res.value is True

    res2 = pkg_has("nginx", runner=Picky({
        "dpkg --version": ok(0, ""),
    }))
    assert res2.state == CANT and "dpkg" in res2.note


def test_services_running_parses_unit_names_only():
    table = {"systemctl": ok(0, (
        "  UNIT                 LOAD   ACTIVE SUB     DESCRIPTION\n"
        "  ssh.service           loaded active running OpenSSH daemon\n"
        "  chronyd.service       loaded active running NTP client\n"))}
    res = services_running(runner=FakeRunner(table))
    assert res.state == PASS
    assert res.value == ["chronyd.service", "ssh.service"]
    assert_no_identifiers(res.value)


def test_services_running_systemctl_fails():
    res = services_running(runner=FakeRunner({"systemctl": ok(1, "oops")}))
    assert res.state == CANT and res.value is None


LISTENER_CASES = [
    ({"ss -tuln": ok(0, (
        "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        "tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*\n"
        "udp   UNCONN 0      0      [::]:53            [::]:*\n"))},
     [22, 53]),
    ({"ss -tuln": ok(0, "")}, []),
    ({"ss -tuln": ok(1, "ss: failed")}, CANT),
]


@pytest.mark.parametrize("table,expected", LISTENER_CASES)
def test_listeners(table, expected):
    res = listeners(runner=FakeRunner(table))
    if expected == CANT:
        assert res.state == CANT and res.value is None
    else:
        assert res.value == expected
    assert_no_identifiers(res.value)


def test_listeners_never_keeps_process_names():
    table = {"ss -tuln": ok(0, (
        "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(\"sshd\",pid=999)\n"))}
    res = listeners(runner=FakeRunner(table))
    assert res.value == [22]
    assert_no_identifiers(res.value)


def test_firewall_state_tables_and_ufw():
    table = {"nft list tables": ok(0, "table inet filter\ntable ip nat\n"),
             "ufw status": ok(0, "Status: active\n")}
    res = firewall_state(runner=FakeRunner(table))
    assert res.state == PASS
    assert res.value == ["nft:table inet filter", "nft:table ip nat", "ufw:active"]
    assert_no_identifiers(res.value)


def test_firewall_state_no_ufw_binary():
    table = {"nft list tables": ok(0, "table inet filter\n"),
             "ufw status": ok(127, "command not found")}
    res = firewall_state(runner=FakeRunner(table))
    assert res.value == ["nft:table inet filter"]


def test_firewall_state_keeps_nft_when_ufw_raises():
    class UfwBoom(FakeRunner):
        def __call__(self, line):
            if line.startswith("ufw"):
                raise RuntimeError("ufw exploded")
            return super().__call__(line)

    res = firewall_state(runner=UfwBoom({
        "nft list tables": ok(0, "table inet filter\n")}))
    assert res.state == CANT
    assert res.value == ["nft:table inet filter"]
    assert "ufw" in res.note
    assert_no_identifiers(res.value)


def test_firewall_state_ufw_unparsable_is_cant_not_silence():
    res = firewall_state(runner=FakeRunner({
        "nft list tables": ok(0, "table inet filter\n"),
        "ufw status": ok(0, "some garbage output\n")}))
    assert res.state == CANT
    assert res.value == ["nft:table inet filter"]
    assert "unparsable" in res.note


def test_firewall_state_no_tools_at_all_is_cant():
    table = {"nft list tables": ok(127, "not found"),
             "ufw status": ok(127, "not found")}
    res = firewall_state(runner=FakeRunner(table))
    assert res.state == CANT and res.value is None


def test_sysctl_get_scalar():
    res = sysctl_get("net.ipv4.ip_forward", runner=FakeRunner({
        "sysctl -n ": ok(0, "0\n")}))
    assert res.state == PASS and res.value == "0"
    assert_no_identifiers(res.value)


def test_sysctl_get_rejects_malformed_key():
    assert sysctl_get("bad key!", runner=FakeRunner({})).state == "FAIL"


def test_sysctl_get_cant():
    res = sysctl_get("kernel.hidden", runner=FakeRunner({
        "sysctl -n ": ok(1, "permission denied")}))
    assert res.state == CANT


def test_disk_encrypted_true_from_crypttab(tmp_path):
    tab = tmp_path / "crypttab"
    tab.write_text("sda3_crypt /dev/disk/by-uuid/xyz none luks\n")
    res = disk_encrypted(runner=FakeRunner({"lsblk -o TYPE": ok(0, " TYPE\n disk\n")}),
                         crypttab_path=tab)
    assert res.state == PASS and res.value is True


def test_disk_encrypted_true_from_lsblk(tmp_path):
    res = disk_encrypted(runner=FakeRunner({
        "lsblk -o TYPE": ok(0, "TYPE\npart\n crypt\npart\n")}),
        crypttab_path=tmp_path / "absent")
    assert res.state == PASS and res.value is True


def test_disk_encrypted_crypt_word_elsewhere_is_not_a_hit(tmp_path):
    res = disk_encrypted(runner=FakeRunner({
        "lsblk -o TYPE": ok(0, "TYPE\ndisk\npart\npart\n")}),
        crypttab_path=tmp_path / "absent")
    assert res.state == PASS and res.value is False


def test_disk_encrypted_false_when_lsblk_clean(tmp_path):
    res = disk_encrypted(runner=FakeRunner({"lsblk -o TYPE": ok(0, "TYPE\ndisk part\npart\n")}),
                         crypttab_path=tmp_path / "absent")
    assert res.state == PASS and res.value is False


def test_disk_encrypted_cant_when_all_sources_unreadable(tmp_path):
    res = disk_encrypted(runner=FakeRunner({"lsblk -o TYPE": ok(1, "failed")}),
                         crypttab_path=tmp_path / "absent")
    assert res.state == CANT


def test_disk_encrypted_never_returns_device_names(tmp_path):
    res = disk_encrypted(runner=FakeRunner({
        "lsblk -o TYPE": ok(0, "crypt\n0f1e2d3c4b5a6f7e8d9c0b1a\n")}),
        crypttab_path=tmp_path / "absent")
    assert res.value is True and assert_no_identifiers(res.value) is None


def test_desktop_env():
    assert desktop_env({"XDG_CURRENT_DESKTOP": "GNOME"}).value == "GNOME"
    assert_no_identifiers(desktop_env({"XDG_CURRENT_DESKTOP": "KDE"}).value)


def test_desktop_env_unset_is_cant_check():
    res = desktop_env({})  # unset (not merely empty) -> honesty, not ""
    assert res.state == CANT and res.value is None
    assert "XDG_CURRENT_DESKTOP" in res.note
    assert desktop_env({"XDG_CURRENT_DESKTOP": ""}).value == ""


def test_form_factor_laptop():
    with tempfile.TemporaryDirectory() as td:
        for n in ("BAT0", "AC"):
            pathlib.Path(td, n).touch()
        res = form_factor(runner=FakeRunner({}), power_supply_dir=pathlib.Path(td))
    assert res.state == PASS and res.value is True
    assert_no_identifiers(res.value)


def test_form_factor_desktop():
    with tempfile.TemporaryDirectory() as td:
        pathlib.Path(td, "AC").touch()
        res = form_factor(runner=FakeRunner({}), power_supply_dir=pathlib.Path(td))
    assert res.state == PASS and res.value is False


def test_form_factor_cant_when_dir_missing(tmp_path):
    res = form_factor(runner=FakeRunner({}), power_supply_dir=tmp_path / "nope")
    assert res.state == CANT


def test_form_factor_never_returns_dir_names():
    class FakeDir:
        def iterdir(self):
            return [pathlib.PurePath("BAT1_serialSN1234567890abc"),  # hostile
                    pathlib.PurePath("AC")]

    res = form_factor(runner=FakeRunner({}), power_supply_dir=FakeDir())
    assert res.value is True and assert_no_identifiers(res.value) is None


class _Usage:
    def __init__(self, total, free):
        self.total, self.free = total, free


def test_disk_space_gb():
    res = disk_space("/backup", usage_fn=lambda p: _Usage(512 * 1024 ** 3,
                                                          128 * 1024 ** 3))
    assert res.state == PASS and res.value == [512.0, 128.0]
    assert isinstance(res.value, list)


def test_disk_space_cant_on_error():
    def boom(_):
        raise OSError("gone")
    assert disk_space("/nope", usage_fn=boom).state == CANT


def test_all_probe_values_safe_and_shaped():
    runner = FakeRunner({
        "dpkg --version": ok(0, ""), "dpkg -s ssh": ok(0, ""),
        "systemctl": ok(0, "  ssh.service loaded active running d\n"),
        "ss -tuln": ok(0, "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"),
        "nft list tables": ok(0, "table inet filter\n"),
        "ufw status": ok(0, "Status: inactive\n"),
        "sysctl -n ": ok(0, "1\n"),
        "lsblk": ok(0, "disk part\n"),
    })
    vals = [
        pkg_has("ssh", runner=runner).value,
        services_running(runner=runner).value,
        listeners(runner=runner).value,
        firewall_state(runner=runner).value,
        sysctl_get("vm.swappiness", runner=runner).value,
        disk_encrypted(runner=runner,
                       crypttab_path=pathlib.Path("/nonexistent-crypttab")).value,
        desktop_env({"XDG_CURRENT_DESKTOP": "GNOME"}).value,
        form_factor(runner=runner).value,
        disk_space("/", usage_fn=lambda p: _Usage(1, 1)).value,
    ]
    assert any(v is not None for v in vals)
    assert_no_identifiers(vals)
    for v in vals:  # boolean / list / scalar-string outputs only
        assert isinstance(v, (bool, list, str)), v


def test_prod_runner_reused_and_user_context():
    assert prod_runner is __import__("hardening.detector",
                                     fromlist=["prod_runner"]).prod_runner
    with pytest.raises(RuntimeError):
        prod_runner("pkexec ls")


def test_prod_runner_real_call_runs():
    rc, out = prod_runner("echo wizard-ok")
    assert rc == 0 and out.strip() == "wizard-ok"
