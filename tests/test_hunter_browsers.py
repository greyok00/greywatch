"""The browser-config checks: Chromium preferences and Firefox permissions.

Fixtures are profile folders built by hand: Preferences JSON, Secure
Preferences JSON, an Extensions dir, and Firefox's permissions.sqlite.
No test touches a real browser or the network.
"""
import json
import sqlite3

from hunter import browsers


def _chromium_profile(tmp_path, name="Default", browser="google-chrome"):
    prof = tmp_path / ".config" / browser / name
    prof.mkdir(parents=True)
    return prof


def _prefs(prof, body):
    (prof / "Preferences").write_text(json.dumps(body), encoding="utf-8")
    return prof


def _search_pref(name):
    return {"default_search_provider_data": {"template_url_data":
                                             {"short_name": name}}}


def test_unknown_default_search_engine_is_a_hijack_lead(tmp_path):
    prof = _chromium_profile(tmp_path)
    _prefs(prof, _search_pref("WebQuery Turbo"))
    hits = [f for f in browsers.config_findings(str(tmp_path))
            if f["rule"] == "cfg-search-hijack"]
    assert hits and "WebQuery Turbo" in hits[0]["what"]
    assert hits[0]["severity"] == "HIGH"


def test_known_engines_stay_quiet(tmp_path):
    prof = _chromium_profile(tmp_path)
    _prefs(prof, _search_pref("Google"))
    assert [f for f in browsers.config_findings(str(tmp_path))
            if f["rule"] == "cfg-search-hijack"] == []


def test_startup_urls_off_the_beaten_track_are_leads(tmp_path):
    prof = _chromium_profile(tmp_path)
    _prefs(prof, {"session": {"restore_on_startup": 4,
                              "startup_urls": ["https://portal-redirect.io"]}})
    found = [f for f in browsers.config_findings(str(tmp_path))
             if f["rule"] == "cfg-search-hijack"]
    assert found and "portal-redirect.io" in found[0]["what"]


def test_fresh_notification_grants_are_suspect(tmp_path):
    prof = _chromium_profile(tmp_path)
    _prefs(prof, {"profile": {"content_settings": {"exceptions":
        {"notifications": {
            "https://notify-spam.example,https://*": {
                "setting": 1, "last_modified": str(
                browsers._now_us() + browsers._CHROMIUM_EPOCH_OFFSET_US - 3600 * 1_000_000),
                "expiration": "0"}}}}}})
    found = [f for f in browsers.config_findings(str(tmp_path))
             if f["rule"] == "cfg-notification-grant"]
    assert found and "notify-spam.example" in found[0]["what"]


def test_old_notification_grants_stay_quiet(tmp_path):
    prof = _chromium_profile(tmp_path)
    old = (browsers._now_us() + browsers._CHROMIUM_EPOCH_OFFSET_US - 60 * 24 * 3600 * 1_000_000)
    _prefs(prof, {"profile": {"content_settings": {"exceptions":
        {"notifications": {"https://old-site.example,https://*": {
            "setting": 1, "last_modified": str(old)}}}}}})
    assert [f for f in browsers.config_findings(str(tmp_path))
            if f["rule"] == "cfg-notification-grant"] == []


def test_extensions_are_reported_for_first_seen(tmp_path):
    prof = _chromium_profile(tmp_path)
    ext = prof / "Extensions" / "abcdefghij123456"
    ver = ext / "1.2_0"
    ver.mkdir(parents=True)
    (ver / "manifest.json").write_text(json.dumps(
        {"name": "Tab Sorter Now", "version": "1.2"}), encoding="utf-8")
    found = [f for f in browsers.config_findings(str(tmp_path))
             if f["rule"] == "cfg-new-extension"]
    assert len(found) == 1
    assert "Tab Sorter Now" in found[0]["what"]
    assert "abcdefghij123456" in " ".join(found[0]["facts"])


def test_firefox_notification_permissions_are_checked(tmp_path):
    prof = tmp_path / ".mozilla" / "firefox" / "profile.default"
    prof.mkdir(parents=True)
    db = prof / "permissions.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(
        "CREATE TABLE moz_perms (id INTEGER PRIMARY KEY, origin TEXT,"
        " type TEXT, permission INTEGER, expireType INTEGER,"
        " expireTime INTEGER, modificationTime INTEGER);")
    conn.execute(
        "INSERT INTO moz_perms (origin, type, permission, expireType,"
        " expireTime, modificationTime) VALUES (?,?,?,?,?,?)",
        ("https://popup-prank.example", "desktop-notification", 1, 0, 0,
         browsers._now_us() - 1200 * 1_000_000))
    conn.commit()
    conn.close()
    found = [f for f in browsers.config_findings(str(tmp_path))
             if f["rule"] == "cfg-notification-grant"]
    assert found and "popup-prank.example" in found[0]["what"]


def test_missing_profiles_are_quiet(tmp_path):
    assert browsers.config_findings(str(tmp_path)) == []