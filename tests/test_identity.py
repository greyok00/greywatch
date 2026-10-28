"""Who is on the other end? — the identity layer that feeds the popup.

Offline only: whois/PTR results are parsed from captured text and the
network calls are stubbed. The GUI test is display-guarded like the rest
of the smoke suite.
"""

import sys
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui import identity  # noqa: E402


ARIN_THEN_RIPE = """\
NetRange:       57.128.0.0 - 57.255.255.255
CIDR:           57.128.0.0/9
NetName:        RIPE-ERX-57
Organization:   RIPE Network Coordination Centre (RIPE)
Country:        NL
ReferralServer:  whois.ripe.net
inetnum:        57.141.0.0 - 57.149.255.255
netname:        FB-BLOCK
descr:          Facebook, Inc.
country:        IE
org-name:       Meta Platforms Ireland Limited
origin:         AS32934
"""

GOOGLE = """\
NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOGL
OriginAS:
Organization:   Google LLC (GOGL)
OrgName:        Google LLC
Country:        US
"""


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return tmp_path


def test_parse_prefers_the_delegated_answer():
    got = identity.parse_whois(ARIN_THEN_RIPE)
    # ARIN's block names the registry; the delegated RIPE block names the
    # holder. The parser must take the later, more specific record.
    assert got["org"] == "Meta Platforms Ireland Limited"
    assert got["netname"] == "FB-BLOCK"
    assert got["country"] == "IE"
    assert got["asn"] == "AS32934"
    assert got["range"] == "57.141.0.0 - 57.149.255.255"
    assert got["registry_is_owner"] is False


def test_registry_only_answer_is_not_treated_as_the_owner():
    got = identity.parse_whois("NetName: RIPE-ERX-57\n"
                               "Organization: RIPE Network Coordination Centre\n"
                               "Country: NL\n")
    assert got["registry_is_owner"] is True
    assert got["netname"] == "RIPE-ERX-57"


def test_registrable_domain_keeps_two_label_suffixes():
    assert identity.registrable("edge-dgw-shv-01-phx1.facebook.com") == \
        "facebook.com"
    assert identity.registrable("www.bbc.co.uk") == "bbc.co.uk"
    assert identity.brand_for("facebook.com") == "Facebook"
    assert identity.brand_for("some-random-vendor.example") == \
        "Some-random-vendor"


def test_short_org_drops_the_legal_tail():
    assert identity.short_org("Meta Platforms Ireland Limited") == "Meta"
    assert identity.short_org("Google LLC") == "Google"
    assert identity.short_org("Amazon.com, Inc.") == "Amazon"


def test_host_card_speaks_plainly():
    ident = identity.parse_whois(ARIN_THEN_RIPE)
    ident = {"ip": "57.144.134.145",
             "ptr": "edge-dgw-shv-01-phx1.facebook.com",
             "domain": "facebook.com", "brand": "Facebook",
             "org": "Meta Platforms Ireland Limited", "country": "IE",
             "country_name": "Ireland", "asn": "", "netname": "FB-BLOCK",
             "range": "57.141.0.0 - 57.149.255.255"}
    card = identity.host_card(ident)
    assert card["title"] == "Facebook"
    assert card["sentence"] == ("This is Facebook — a network registered to "
                                "Meta in Ireland.")
    assert ("Country", "Ireland (IE)") in card["rows"]
    assert card["warning"] == ""


def test_unknown_address_is_described_without_alarming():
    card = identity.host_card({"ip": "203.0.113.9"})
    assert "private server" in card["sentence"]
    assert card["warning"]          # a second look is still suggested


def test_country_phrases_take_the_article_when_english_needs_one():
    assert identity.country_phrase("United States") == "the United States"
    assert identity.country_phrase("Ireland") == "Ireland"
    assert identity.country_phrase("") == ""


def test_program_card_separates_packages_from_loose_files():
    packaged = identity.program_card(
        {"title": "Brave", "binary": "brave", "path": "/opt/brave.com/brave/brave",
         "package": "brave-browser", "owner": "root", "kind": "package"})
    assert "came with your system" in packaged["sentence"]
    assert packaged["warning"] == ""

    loose = identity.program_card(
        {"title": "Chromium", "binary": "chrome",
         "path": "/home/x/.cache/ms-playwright/chrome", "package": "",
         "owner": "x", "kind": "loose"})
    assert "not installed from a package" in loose["sentence"]
    assert loose["warning"]


def test_lookup_host_uses_the_cache(monkeypatch):
    calls = {"n": 0}

    def fake_ptr(host):
        calls["n"] += 1
        return "edge-1.facebook.com"

    monkeypatch.setattr(identity, "reverse_name", fake_ptr)
    monkeypatch.setattr(identity, "run_whois",
                        lambda h, timeout=6.0: ARIN_THEN_RIPE)
    monkeypatch.setattr(identity, "geoip_country", lambda h: ("", ""))
    first = identity.lookup_host("57.144.134.145", use_cache=True)
    again = identity.lookup_host("57.144.134.145", use_cache=True)
    assert first == again and calls["n"] == 1
    assert first["brand"] == "Facebook"
    assert first["country_name"] == "Ireland"


def test_lookup_program_reads_the_desktop_entry(monkeypatch):
    monkeypatch.setattr(identity, "_app_index",
                        {"brave": {"name": "Brave Web Browser",
                                   "icon": "brave-browser"}})
    monkeypatch.setattr(identity, "owning_package",
                        lambda p, timeout=3.0: "brave-browser")
    monkeypatch.setattr(identity, "file_owner", lambda p: "root")
    got = identity.lookup_program("/opt/brave.com/brave/brave",
                                  use_cache=False)
    assert got["title"] == "Brave Web Browser"
    assert got["kind"] == "package" and got["package"] == "brave-browser"


def test_spec_facts_understands_an_old_detail_string():
    from ui.decisions import _spec_facts
    old = {"id": "appfw:brave:10:1",
           "detail": "/opt/brave.com/brave/brave\n→ 3.233.158.24:443 (tcp)"
                     " · pid 10",
           "host": "3.233.158.24"}
    facts = _spec_facts(old)
    assert facts["path"] == "/opt/brave.com/brave/brave"
    assert facts["app_name"] == "brave"
    assert facts["port"] == 443 and facts["proto"] == "tcp"


def test_daemon_accepts_every_persistent_answer(monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(ROOT / "data"))
    import greywatch_daemon as dm
    for value in ("trust", "trust-block", "host", "block-host",
                  "57.144.134.145", "57.144.134.*"):
        assert dm.Daemon._host_op(value) == value
    assert dm.Daemon._host_op("not a host; rm -rf /") is None
    assert dm.Daemon._host_op(None) is None
