# Tests for hardening.detector.cve_note — display-only CVE context.
# Synthetic CVE ids only (CVE-2999-xxxx): no live cache, no fields the
# real fixture layout is depended on, and no machine-specific values.
from hardening.detector import cve_note

CACHE = {
    "fetched_utc": "2026-01-02T00:00:00Z",
    "queries": ["fail2ban", "clamav"],
    "entries": [
        {"id": "CVE-2999-0001", "modified": "2026-01-02T00:00:00.000",
         "nist": ["AC-7"]},
        {"id": "CVE-2999-0002", "modified": "2026-01-01T00:00:00.000",
         "tools": ["fail2ban"]},
        {"id": "CVE-2999-0003", "modified": "2026-01-03T00:00:00.000",
         "nist": ["SI-3"]},
    ],
}


def test_control_matches_direct_and_via_tool_map():
    note = cve_note("AC-7", CACHE)
    assert "CVE-2999-0001" in note          # direct nist linkage
    assert "CVE-2999-0002" in note          # fail2ban -> AC-7 via nist-map
    assert "CVE-2999-0003" not in note      # mismatched control


def test_newest_first_and_cap():
    cache = dict(CACHE, entries=[
        {"id": f"CVE-2999-{i:04d}", "modified": f"2026-01-{i:02d}T00:00:00",
         "nist": ["AC-7"]} for i in range(9, 0, -1)
    ])
    note = cve_note("AC-7", cache)
    assert "CVE-2999-0009" in note and "CVE-2999-0001" not in note
    assert note.count("CVE-2999-") == 3     # _NOTE_MAX


def test_nothing_applies_returns_empty():
    assert cve_note("AU-42", CACHE) == ""


def test_empty_or_malformed_cache_returns_empty():
    assert cve_note("AC-7", {}) == ""
    assert cve_note("AC-7", {"entries": None}) == ""
    assert cve_note("AC-7", {"entries": ["junk", {"nist": ["AC-7"]},
                                          {"id": "CVE-2999-0004",
                                           "nist": ["AC-7"]}]}) \
        == "Relevant CVEs on record: CVE-2999-0004"


def test_never_invents_fixes():
    note = cve_note("AC-7", CACHE)
    for banned in ("fix", "apt ", "install", "upgrade"):  # hint words only
        assert banned not in note.lower()
