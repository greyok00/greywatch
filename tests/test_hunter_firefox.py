"""The Firefox lanes: download-history findings and pref hijack checks.

Everything reads copies of the profile's own files, built as fixtures with
sqlite3 or plain text, so no test ever touches a real browser.
"""
import json
import sqlite3

from hunter import firefox
from hunter.web import DOUBLE_EXT_RE, DOWNLOADS_WINDOW_DAYS


def _places(tmp_path, rows):
    """A minimal places.sqlite: moz_places + the downloads annos."""
    prof = tmp_path / ".mozilla" / "firefox" / "profile.default"
    prof.mkdir(parents=True)
    db = prof / "places.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY,
                                          name TEXT);
        CREATE TABLE moz_annos (place_id INTEGER, anno_attribute_id INTEGER,
                                content TEXT, dateAdded INTEGER);
    """)
    for url, name, content, added in rows:
        cur = conn.execute("INSERT INTO moz_places (url) VALUES (?)", (url,))
        pid = cur.lastrowid
        aid = conn.execute(
            "SELECT id FROM moz_anno_attributes WHERE name=?",
            (name,)).fetchone()
        if aid is None:
            aid = conn.execute(
                "INSERT INTO moz_anno_attributes (name) VALUES (?)",
                (name,)).lastrowid
        else:
            aid = aid[0]
        conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content,"
            " dateAdded) VALUES (?,?,?,?)", (pid, aid, json.dumps(content),
                                             added))
    conn.commit()
    conn.close()
    return prof


def _url(target_name, scheme="https"):
    return f"{scheme}://download.example.com/files/{target_name}"


def test_history_findings_catch_the_double_extension(tmp_path):
    now_us = int(DOUBLE_EXT_RE and firefox._now_us())
    _places(tmp_path, [(
        _url("invoice.pdf.exe"), "downloads/finished",
        {"state": 1, "endTime": now_us, "targetPath": "/x/invoice.pdf.exe"},
        now_us - 3 * 24 * 3600 * 1_000_000)])
    found = firefox.history_findings(str(tmp_path))
    assert len(found) == 1
    f = found[0]
    assert f["rule"] == "ff-history-double-extension"
    assert f["severity"] == "HIGH"
    assert f["status"] == "confirmed"
    assert any("invoice.pdf.exe" in fact for fact in f["facts"])


def test_history_findings_flag_a_program_name_as_a_lead(tmp_path):
    now_us = firefox._now_us()
    _places(tmp_path, [(
        _url("setup-tool.exe"), "downloads/finished", {"state": 1},
        now_us - 2 * 24 * 3600 * 1_000_000)])
    found = firefox.history_findings(str(tmp_path))
    assert len(found) == 1
    f = found[0]
    assert f["rule"] == "ff-history-executable"
    assert f["severity"] == "MEDIUM"
    assert f["status"] == "lead"


def test_history_findings_respect_the_window(tmp_path):
    now_us = firefox._now_us()
    _places(tmp_path, [(
        _url("old-invoice.pdf.exe"), "downloads/finished", {"state": 1},
        now_us - (DOWNLOADS_WINDOW_DAYS + 6) * 24 * 3600 * 1_000_000)])
    assert firefox.history_findings(str(tmp_path)) == []


def test_history_findings_ignore_ordinary_and_broken_rows(tmp_path):
    now_us = firefox._now_us()
    _places(tmp_path, [
        (_url("readme.txt"), "downloads/finished", {"state": 1}, now_us),
        (_url("whatever.pdf"), "downloads/metaBugID", {"state": 1}, now_us),
        ("https://example.com/", "downloads/finished", {1: "broken"}, now_us),
    ])
    assert firefox.history_findings(str(tmp_path)) == []


def test_history_findings_dedupe_the_same_download(tmp_path):
    _places(tmp_path, [(
        _url("invoice.pdf.exe"), "downloads/finished", {"state": 1},
        (firefox._now_us()),
        ), (
        _url("invoice.pdf.exe"), "downloads/finished", {"state": 1},
        firefox._now_us())])
    found = firefox.history_findings(str(tmp_path))
    assert len(found) == 1


# ------------------------------------------------------------ hijack lane

def _prefs(tmp_path, body):
    prof = tmp_path / ".mozilla" / "firefox" / "profile.default"
    prof.mkdir(parents=True)
    (prof / "prefs.js").write_text(body, encoding="utf-8")
    return prof


_HOMEPAGE_HIJACK = (
    'user_pref("browser.startup.homepage", "https://search-portal-4x.net");')

_SEARCH_HIJACK = (
    'user_pref("browser.search.defaultenginename", "QuickSearch Now");')

_SAFE_DEFAULTS = (
    'user_pref("browser.startup.homepage", "https://www.startpage.com");\n'
    'user_pref("browser.search.defaultenginename", "DuckDuckGo");')


def test_hijack_findings_flag_an_unknown_homepage(tmp_path):
    _prefs(tmp_path, _HOMEPAGE_HIJACK)
    found = firefox.hijack_findings(str(tmp_path))
    assert len(found) == 1
    f = found[0]
    assert f["rule"] == "ff-hijack"
    assert "search-portal-4x.net" in " ".join(f["facts"])


def test_hijack_findings_flag_an_unknown_engine(tmp_path):
    _prefs(tmp_path, _SEARCH_HIJACK)
    found = firefox.hijack_findings(str(tmp_path))
    assert found and found[0]["facts"]
    assert any("QuickSearch Now" in fact for fact in found[0]["facts"])


def test_hijack_findings_stay_quiet_on_the_safe_defaults(tmp_path):
    _prefs(tmp_path, _SAFE_DEFAULTS)
    hijacks = firefox.hijack_findings(str(tmp_path))
    assert hijacks == []


def test_hijack_findings_absent_profile_is_empty(tmp_path):
    assert firefox.hijack_findings(str(tmp_path)) == []