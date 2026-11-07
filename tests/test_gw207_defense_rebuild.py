"""Rebuild Phase 2: the Firewall page acts, does not just report.

Three pins: an armor row that reads open or cannot read carries its own
arming button (and a good row carries none), an unreadable probe never
renders as safe, and the page stays a threat-lane desk - no tool
lifecycle controls ever appear on it.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui import defense  # noqa: E402


def _count_buttons(host):
    from gi.repository import Gtk
    out = []

    def walk(w):
        for k in list(w) if hasattr(w, "__iter__") else []:
            if isinstance(k, Gtk.Button):
                out.append(k)
            walk(k)
    if hasattr(host, "__iter__"):
        walk(host)
    return out


def _labels(host):
    return [b.get_label() for b in _count_buttons(host)]


def _walk(host):
    out = []
    try:
        kids = list(host)
    except TypeError:
        return out
    for k in kids:
        out.append(k)
        out.extend(_walk(k))
    return out


# ---- armor control rows -------------------------------------------------
@pytest.fixture
def stub_armor(monkeypatch):
    def set(psad=None, arp=None):
        monkeypatch.setattr(defense, "psad_status", lambda: psad or {})
        monkeypatch.setattr(defense, "arp_status", lambda: arp or {})
    return set


def _build_view(monkeypatch):
    import gi
    gi.require_version("Gtk", "4.0")
    v = defense.DefenseView()
    monkeypatch.setattr(defense, "cve_rows", lambda _dd: None)
    return v


def test_good_armor_rows_carry_no_button(monkeypatch, stub_armor):
    v = _build_view(monkeypatch)
    stub_armor({"fed": True, "table": True, "armed": True,
                "service": True},
               {"pinned": True, "sysctls": True})
    v.refresh({"defense": {}})
    labels = _labels(v._armor)
    # good probes carry nothing; the watchlist head's refresh and explain
    # buttons are the only other controls the armor section ever holds
    assert labels == [f"{label}: good" for label, _k, _h
                      in v._ARMOR_PROBES] + ["Refresh map", "Explain"]
    v.unparent()


def test_open_and_unreadable_rows_carry_their_arming_helper(
        monkeypatch, stub_armor):
    v = _build_view(monkeypatch)
    stub_armor({"fed": False, "table": None, "armed": True,
                "service": False},
               {"pinned": None, "sysctls": True})
    v.refresh({"defense": {}})
    buttons = _count_buttons(v._armor)
    armed = [b for b in buttons if b.get_sensitive()]
    pairs = {b.get_label(): b for b in armed}
    # every open or unreadable probe carries its own Arm button; the two
    # good rows (armed, sysctls) sit out. The watchlist refresh is the
    # one remaining sensitive button and it arms nothing.
    assert set(pairs) - {"Refresh map", "Explain"} == {
        "Arm: Sweep watcher feed", "Arm: Inbound log chain",
        "Arm: psad service", "Arm: Router address pinned"}
    assert set(pairs) | {"Refresh map", "Explain"} == {
        b.get_label() for b in armed}
    v.unparent()


def test_arm_buttons_route_through_the_confirm_pipeline(monkeypatch,
                                                        stub_armor):
    v = _build_view(monkeypatch)
    stub_armor({"fed": False, "table": False, "armed": False,
                "service": False},
               {"pinned": False, "sysctls": False})
    routed = []
    v._win = type("W", (), {"_run_log_option": (lambda self, btn, opt:
                                                routed.append(dict(opt)))})()
    v.refresh({"defense": {}})
    # the click-through covers the arming rows only: the watchlist
    # refresh is a separate channel and must never be driven here
    buttons = [b for b in _count_buttons(v._armor) if b.get_sensitive()
               and str(b.get_label() or "").startswith("Arm:")]
    for b in buttons:
        b.emit("clicked")
    psad_labels = ("Sweep watcher feed", "Inbound log chain",
                   "Auto-block armed", "psad service")
    arp_labels = ("Router address pinned", "ARP replies closed")
    assert all(r["helper"] == "psad-tune" for r in routed
               if r["label"] in psad_labels)
    assert all(r["helper"] == "hardening-arp" for r in routed
               if r["label"] in arp_labels)
    assert all(r["args"] == [] and r["tone"] == "primary" for r in routed)
    assert len(buttons) == len(routed) == len(v._ARMOR_PROBES)
    v.unparent()


# ---- unreadable never reads as safe --------------------------------------
def test_unreadable_armor_never_renders_good(monkeypatch, stub_armor):
    v = _build_view(monkeypatch)
    stub_armor({"fed": None, "table": None, "armed": None,
                "service": None},
               {"pinned": None, "sysctls": None})
    v.refresh({"defense": {}})
    labels = [str(b.get_label()) for b in _walk(v._armor)
              if hasattr(b, "get_label") and b.get_label()]
    assert any("cannot read" in t for t in labels)
    assert not any(": good" in t for t in labels)
    v.unparent()


# ---- the browser watch panel ---------------------------------------------
def _finding(fid="f1", title="Hijacked rule", how="HIGH"):
    return {"id": fid, "rule": "persistence-scratch-path", "title": title,
            "what": "user crontab points at /tmp", "severity": how,
            "asset": "firefox:default", "status": "open",
            "ts": "2026-11-06T07:00:00+00:00"}


def test_watch_panel_renders_published_digest(monkeypatch, stub_armor):
    v = _build_view(monkeypatch)
    stub_armor({"fed": True}, {"pinned": True})
    v.refresh({"defense": {}, "browser_watch": [_finding()]})
    host = v._watch
    assert _count_cards(host) == 1
    text = " ".join(str(getattr(k, "get_label", lambda: None)()) or ""
                    for k in _walk(host))
    assert "Hijacked rule" in text and "user crontab" in text
    v.unparent()


def test_watch_panel_honest_when_not_published(monkeypatch, stub_armor):
    v = _build_view(monkeypatch)
    stub_armor({"fed": True}, {"pinned": True})
    v.refresh({"defense": {}})                 # no browser_watch key at all
    text = " ".join(str(getattr(k, "get_label", lambda: None)()) or ""
                    for k in _walk(v._watch))
    assert "has not published" in text
    v.unparent()


def test_watch_panel_no_findings_state(monkeypatch, stub_armor):
    v = _build_view(monkeypatch)
    stub_armor({"fed": True}, {"pinned": True})
    v.refresh({"defense": {}, "browser_watch": []})
    text = " ".join(str(getattr(k, "get_label", lambda: None)()) or ""
                    for k in _walk(v._watch))
    assert "No browser findings to review." in text
    v.unparent()


def _count_cards(host):
    n = 0
    for k in _walk(host):
        if "gw-card" in k.get_css_classes():
            n += 1
    return n


# ---- the firewall page stays threat lane ----------------------------------
def test_no_tool_lifecycle_controls_on_the_firewall_page(monkeypatch,
                                                         stub_armor):
    from gi.repository import Gtk
    v = _build_view(monkeypatch)
    stub_armor({"fed": False}, {"pinned": None})
    v.refresh({"defense": {"blocked": [{"ip": "192.168.0.44",
                                        "ts": "", "reason": "auto"}]},
               "browser_watch": [_finding()]})
    banned_words = ("start", "stop", "pause", "resume", "restart",
                    "restart now")

    def walk(w):
        if isinstance(w, Gtk.Button):
            yield w
        kids: list = []
        try:
            c = w.get_first_child()
        except Exception:
            c = None
        while c is not None:
            kids.append(c)
            c = c.get_next_sibling()
        for k in kids:
            yield from walk(k)
    for b in walk(v):
        label = (b.get_label() or "").lower()
        assert not any(word in label.split() for word in banned_words), \
            f"tool-lifecycle control on the firewall page: {label}"
    v.unparent()


# ---- the daemon publishes it ----------------------------------------------
def test_daemon_publishes_browser_watch_digest(tmp_path, monkeypatch):
    import greywatch_daemon as gd
    monkeypatch.setenv("GREYWATCH_HELPER_CMD", str(tmp_path / "none.sh"))
    d = gd.Daemon(data_dir=tmp_path / "data", registry=gd.load_registry())
    (d.data_dir / "hunter").mkdir(parents=True, exist_ok=True)
    (d.data_dir / "hunter" / "findings.jsonl").write_text(
        json.dumps(_finding()) + "\n" + json.dumps(_finding("f2")) + "\n")
    (d.data_dir / "hunter" / "config.json").write_text(
        json.dumps({"quieted_findings": [{"id": "f2"}]}))
    d.write_status()
    snap = json.loads((d.data_dir / "status.json").read_text())
    ids = [f.get("id") for f in snap.get("browser_watch") or []]
    assert ids == ["f1"]
