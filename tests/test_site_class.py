import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ui.site_class import classify


def test_name_families_win_over_ports():
    assert classify("ec2-1-2-3.us-west-2.compute.amazonaws.com", 443) == \
        "Amazon cloud"
    assert classify("d1234.cloudfront.net", 443) == "content delivery"
    assert classify("www.googleapis.com", 443) == "Google service"
    assert classify("windowsupdate.microsoft.com", 443) == \
        "Microsoft service"
    assert classify("updates.ubuntu.com", 443) == "software updates"
    assert classify("github.com", 443) == "code hosting"
    assert classify("steamcommunity.com", 443) == "game platform"
    assert classify("i.nflxvideo.net", 443) == "video streaming"


def test_ports_describe_bare_addresses():
    assert classify("", 443) == "secure web"
    assert classify("", 80) == "web"
    assert classify("", 53) == "name lookup (DNS)"
    assert classify("", 22) == "remote login (SSH)"
    assert classify("", 5432) == "database"
    assert classify("", 51820) == "VPN"


def test_unknown_service_says_so():
    assert classify("104.18.37.251", 9999) == \
        "unrecognized service — treat with care"
    assert classify("") == "unrecognized service — treat with care"
