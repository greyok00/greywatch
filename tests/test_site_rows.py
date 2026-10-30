import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ui.site_names import NameResolver
from ui.site_rows import (SiteRow, build_rows, display_line, filter_rows,
                          parse_appfw)


class Trust:
    def __init__(self):
        self.allow = {"trusted.example"}
        self.block = {"104.18.37.251"}
        self.apps_allow = set()


def test_union_dedupes_and_maps_verdicts():
    events = [
        {"ts": "2026-10-30T07:00:00+00:00",
         "text": "allow firefox → 142.250.72.14:443 (known)"},
        {"ts": "2026-10-30T07:05:00+00:00",
         "text": "deny curl → bad.example:80 (unknown)"},
    ]
    rows = build_rows(Trust(), events, connected=["updates.ubuntu.com"],
                       history=["news.example"])
    by = {r.entry: r for r in rows}
    assert "142.250.72.14" in by and by["142.250.72.14"].program == "firefox"
    assert by["142.250.72.14"].port == 443
    assert by["142.250.72.14"].description == "secure web"
    assert by["trusted.example"].verdict == "allow"
    assert by["104.18.37.251"].verdict == "block"
    assert by["updates.ubuntu.com"].description == "software updates"
    assert by["bad.example"].count == 1


def test_recent_sightings_come_first_then_alphabetical():
    class Empty:
        allow, block, apps_allow = set(), set(), set()

    events = [{"ts": "2026-10-30T07:00:00+00:00",
               "text": "allow p → b.example:443 (x)"}]
    rows = build_rows(Empty(), events, history=["z.example", "a.example"])
    assert rows[0].entry == "b.example"
    assert [r.entry for r in rows[1:]] == ["a.example", "z.example"]


def test_filter_matches_name_address_description_and_program():
    events = [{"ts": "2026-10-30T07:00:00+00:00",
               "text": "allow firefox → 142.250.72.14:443 (x)"}]
    rows = build_rows(Trust(), events)
    assert [r.entry for r in filter_rows(rows, "firefox")] == ["142.250.72.14"]
    assert [r.entry for r in filter_rows(rows, "secure web")] == \
        ["142.250.72.14"]
    assert filter_rows(rows, "142.250")[0].name == "142.250.72.14"


def test_display_line_is_one_readable_sentence():
    row = SiteRow(entry="142.250.72.14", name="google.com",
                  address="142.250.72.14", description="Google service",
                  program="firefox", port=443, last_seen="", count=3,
                  verdict="")
    assert display_line(row) == \
        "google.com (142.250.72.14) — Google service"
    bare = SiteRow(entry="104.18.37.251", name="104.18.37.251",
                   address="", description="content delivery", program="",
                   port=443, last_seen="", count=0, verdict="")
    assert display_line(bare) == "104.18.37.251 — content delivery"


def test_appfw_parser_ignores_non_appfw_text():
    assert parse_appfw({"text": "allow firefox → x.example:443 (y)"}) == \
        ("x.example", 443, "firefox")
    assert parse_appfw({"text": "something else"}) is None


def test_name_resolver_caches_and_expires(tmp_path):
    path = tmp_path / "site-names.json"
    calls = []

    def lookup(address):
        calls.append(address)
        return {"1.2.3.4": "one.example"}.get(address, "")

    r = NameResolver(path, lookup=lookup)
    assert r.name_for("1.2.3.4") == "one.example"
    assert r.name_for("1.2.3.4") == "one.example"
    assert calls == ["1.2.3.4"]
    assert json.loads(path.read_text())["1.2.3.4"]["name"] == "one.example"

    old = NameResolver(path, lookup=lookup)
    old.cache["1.2.3.4"]["at"] = "2020-01-01T00:00:00+00:00"
    old.save()
    fresh = NameResolver(path, lookup=lookup)
    assert fresh.name_for("1.2.3.4") == "one.example"
    assert calls == ["1.2.3.4", "1.2.3.4"]
    assert fresh.name_for("9.9.9.9") == "9.9.9.9"
