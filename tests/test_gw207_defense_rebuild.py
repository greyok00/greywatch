"""Rebuild round 2, task 7: the Firewall page is fw-A.

A verdict strip that answers "is the wall up" (glyph, headline, counts
and the psad age line), one decisions card that glows while asks wait
(the one published pending list, the existing answer machinery), a
blocked-addresses table with Unblock on the row through the lift-block
lane, and the armor chain as ONE chip line. Two hard laws pinned here:

- the psad/arp probes never run on the UI thread: show returns before
  the probe lands, the page paints from the last cached digest (an
  honest "probing" state first), and a read inside the TTL never re-runs
  the subprocesses;
- the CVE rows are gone from this page (they move to Protections in
  task 10): the flaw-list reader is never called here and no flaw text
  renders.
"""
import datetime as dt
import json
import pathlib
import sys
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ui import defense, guided, protectdesk  # noqa: E402

GOOD_PSAD = {"fed": True, "table": True, "armed": True, "service": True}
GOOD_ARP = {"pinned": True, "sysctls": True}


# --------------------------------------------------------------- helpers
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


def _labels(host):
    return [b.get_label() for b in _walk(host)
            if hasattr(b, "get_label") and b.get_label()]


def _texts(host):
    out = []
    for w in _walk(host):
        if hasattr(w, "get_label") and w.get_label():
            out.append(str(w.get_label()))
        elif hasattr(w, "get_text"):
            out.append(str(w.get_text() or ""))
    return out


def _count_cards(host):
    return sum(1 for k in _walk(host)
               if hasattr(k, "get_css_classes")
               and "gw-card" in k.get_css_classes())


def _buttons(host):
    return [b for b in _walk(host) if isinstance(b, Gtk.Button)]


def _iso(hours_ago):
    when = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours_ago)
    return when.isoformat()


class _FakeWin:
    """The window seams the page routes through: the confirm pipeline,
    the handoff router, the data dir, the decisions window."""

    def __init__(self, tmp_path):
        self.data_dir = tmp_path
        self.routed = []
        self.handoffs = []
        self.shows = []
        self._decisions = 0

    def _run_log_option(self, _btn, opt):
        self.routed.append(dict(opt))

    def handoff(self, page_key, dock_group=None, row=None):
        self.handoffs.append((page_key, dock_group, row))
        return True

    def _show(self, key):
        self.shows.append(key)

    def _open_decisions(self, *_a):
        self._decisions += 1

    def _ask_assistant(self, *_a):
        pass


def _stub_probes(monkeypatch, psad=None, arp=None, gate=None):
    """Hermetic probes. Returns the calls record - (kind, thread id)
    pairs, so a test reads ONLY its own thread's probes: a probe worker
    another test left behind can still land one late call into whatever
    stub stands at that moment, and that call is not this test's."""
    psad = psad if psad is not None else dict(GOOD_PSAD)
    arp = arp if arp is not None else dict(GOOD_ARP)
    calls = []

    def slow_or_fast(kind, payload):
        def probe():
            if gate is not None:
                gate.wait(5)
            # the caller's Thread OBJECT, not its ident: idents recycle,
            # a Thread instance does not, so rounds are attributable
            calls.append((kind, threading.current_thread()))
            return dict(payload)
        return probe

    monkeypatch.setattr(defense, "psad_status", slow_or_fast("psad", psad))
    monkeypatch.setattr(defense, "arp_status", slow_or_fast("arp", arp))
    return calls


def _of_thread(calls, worker):
    """The probe calls one worker thread made, in order."""
    return [k for k, tok in calls if tok is worker]


def _ui(calls):
    """The probe calls the MAIN thread (the UI thread) made - the law
    says this list stays empty, whatever other suites' workers do."""
    return _of_thread(calls, threading.main_thread())


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    """One clean probe cache per test, with the original restored back."""
    monkeypatch.setattr(defense, "_PROBE_CACHE",
                        {"when": 0.0, "psad": None, "arp": None})
    yield


def _build(win=None):
    win = win or _FakeWin(pathlib.Path("/tmp/gw207-nondata"))
    v = defense.DefenseView(win=win)
    return v, win


def _drain(v):
    """Wait out the worker thread and let its idle callback land."""
    t = getattr(v, "_probe_thread", None)
    if t is not None and t.is_alive():
        t.join(timeout=5)
    assert t is None or not t.is_alive(), "probe thread never finished"
    ctx = GLib.main_context_default()
    for _ in range(20):
        ctx.iteration(False)


def _reset_cache():
    """A spent probe cache, set as close to the refresh as the language
    allows: a straggler worker from a neighbour suite may still write
    the shared read mid-test, and these pins drive the TTL logic, not
    a borrowed freshness."""
    defense._PROBE_CACHE.update(when=0.0, psad=None, arp=None)


# ---------------------------------------------------- threaded armor paint
def test_defense_show_runs_no_subprocess(monkeypatch):
    """THE timing pin: the page paints and returns before either probe
    has run; the probes land in the worker, off the UI thread."""
    gate = threading.Event()
    calls = _stub_probes(monkeypatch, gate=gate)
    v, _w = _build()
    _reset_cache()
    v.refresh({"defense": {}})
    assert _ui(calls) == []                  # returned before any probe
    assert any("probing" in t.lower() for t in _texts(v._armor))
    gate.set()
    _drain(v)
    worker = getattr(v, "_probe_thread", None)
    assert _of_thread(calls, worker) == ["psad", "arp"]
    assert _ui(calls) == []                  # the UI thread never probed
    v.unparent()


def test_probe_results_land_and_cache_holds_within_ttl(monkeypatch):
    """The finished read paints the chips; a re-show inside the TTL
    paints from the cache and never re-runs the subprocesses."""
    calls = _stub_probes(monkeypatch)
    v, _w = _build()
    _reset_cache()
    v.refresh({"defense": {}})
    _drain(v)
    first = getattr(v, "_probe_thread", None)
    assert "psad: good" in _texts(v._armor)
    v.refresh({"defense": {}})
    assert _of_thread(calls, first).count("psad") == 1
    _reset_cache()                           # TTL spent: a probe may run
    _drain(v)
    v.refresh({"defense": {}})
    _drain(v)
    second = getattr(v, "_probe_thread", None)
    assert _of_thread(calls, second) == ["psad", "arp"]
    assert _ui(calls) == []                  # the UI thread never probed
    v.unparent()


def test_probe_paint_says_probing_only_until_read_lands(monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build()
    v.refresh({"defense": {}})
    _drain(v)
    words = _texts(v._armor)
    assert not any("probing" in t.lower() for t in words)
    assert "nftables: good" in words and "arpwatch: good" in words
    v.unparent()


# -------------------------------------------------------- the armor chips
def test_chip_line_names_open_and_unreadable_never_good(monkeypatch):
    _stub_probes(
        monkeypatch,
        psad={"fed": False, "table": None, "armed": True, "service": False},
        arp={"pinned": None, "sysctls": True})
    v, _w = _build()
    v.refresh({"defense": {}})
    _drain(v)
    words = _texts(v._armor)
    assert "psad: open" in words
    assert "nftables: cannot read" in words
    assert "arpwatch: cannot read" in words
    assert not any(": good" in t for t in words)
    v.unparent()


def test_all_green_line_when_every_probe_is_good(monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build()
    v.refresh({"defense": {}})
    _drain(v)
    words = _texts(v._armor)
    assert "psad: good" in words
    assert "all green" in " ".join(words)
    # a fully standing chain carries nothing to arm
    assert not [b for b in _labels(v._armor)
                if str(b).startswith("Arm ")]
    v.unparent()


def test_open_chains_carry_their_arming_lane(monkeypatch):
    _stub_probes(monkeypatch,
                 psad={"fed": False, "table": False, "armed": False,
                       "service": False},
                 arp={"pinned": False, "sysctls": False})
    v, w = _build()
    v.refresh({"defense": {}})
    _drain(v)
    arm = [b for b in _buttons(v._armor)
           if str(b.get_label() or "").startswith("Arm ")]
    routed = []
    w.routed = routed
    for b in arm:
        b.emit("clicked")
    helpers = sorted(r["helper"] for r in routed)
    assert helpers == ["hardening-arp", "psad-tune"]
    assert arm and v._ARMOR_CLASSES
    v.unparent()


# ------------------------------------------------------------ verdict strip
def test_verdict_strip_says_wall_up_with_counts(monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build()
    snap = {"defense": {"blocked": [{"ip": "203.0.113.9", "ts": _iso(1)},
                                    {"ip": "198.51.100.4", "ts": _iso(2)}]},
            "pending_list": [{"spec": {"id": "responderd:q1",
                                       "options": [{"id": "keep",
                                                    "helper":
                                                    "keep-quarantine"}]},
                              "ts": _iso(1)}]}
    v.refresh(snap)
    words = _texts(v._strip)
    assert "Wall up" in words
    assert "2 blocked - 1 needs you" in words
    glyph = str(getattr(v._strip_glyph, "get_text", lambda: "")())
    assert glyph                                        # a glyph rides
    assert "warn" in v._strip_glyph.get_css_classes()
    v.unparent()


def test_verdict_strip_plural_needs_you(monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build()
    snap = {"defense": {"blocked": []}, "pending_list": []}
    v.refresh(snap)
    words = _texts(v._strip)
    assert "0 blocked - 0 need you" in words
    assert "ok" in v._strip_glyph.get_css_classes()
    v.unparent()


def test_psad_age_line_off_the_published_feed(monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build()
    snap = {"recent": [{"ts": _iso(1), "from_tool": "psad",
                        "text": "block 192.0.2.7"}]}
    v.refresh(snap)
    assert any("psad spoke 1 h ago" in t for t in _texts(v._strip))
    v.unparent()
    v2, _w2 = _build()
    v2.refresh({"recent": []})
    assert any("psad has not spoken in this window" in t
               for t in _texts(v2._strip))
    v2.unparent()


# --------------------------------------------------------- decisions card
def _pending_spec(sid="responderd:q1"):
    return {"spec": {"id": sid, "eyebrow": "quarantine",
                     "subject": "scratch-bin touched",
                     "question": "keep it out?",
                     "options": [
                         {"id": "keep", "label": "Keep quarantined",
                          "helper": "keep-quarantine", "tone": "primary"},
                         {"id": "delete", "label": "Delete now",
                          "helper": "delete-quarantine", "tone": "danger"},
                         {"id": "restore", "label": "Put it back",
                          "helper": "restore-quarantine", "tone": "primary"}]},
            "ts": _iso(1)}


def test_decisions_card_lists_the_published_pending_list(monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build()
    v.refresh({"defense": {}, "pending_list": [_pending_spec()]})
    assert _count_cards(v._asks) == 1
    labels = _labels(v._asks)
    for want in ("Keep quarantined", "Delete now", "Put it back"):
        assert want in labels
    card = next(k for k in _walk(v._asks)
                if "gw-card" in k.get_css_classes())
    assert "gw-guided-pulse" in card.get_css_classes()   # attention target
    assert card._spec_id == "responderd:q1"              # stable handoff key
    v.unparent()


def test_decisions_card_quiet_and_unglowing_when_nothing_waits(monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build()
    v.refresh({"defense": {}})
    assert "Nothing is waiting for your answer." in _texts(v._asks)
    assert not any("gw-guided-pulse" in k.get_css_classes()
                   for k in _walk(v._asks))
    v.unparent()


def test_decisions_answers_record_through_the_one_pipeline(
        tmp_path, monkeypatch):
    ctx = GLib.main_context_default()
    _stub_probes(monkeypatch)
    v, w = _build(_FakeWin(tmp_path))
    v.refresh({"defense": {}, "pending_list": [_pending_spec()]})
    btn = next(b for b in _buttons(v._asks)
               if b.get_label() == "Keep quarantined")
    runs = []
    monkeypatch.setattr(
        "ui.decisionlist._helper_exec",
        lambda helper, args: (runs.append(helper) or 0, ""))
    recorded = []
    monkeypatch.setattr("ui.decisionlist.answer_record",
                        lambda *a, **_k: recorded.append(a) or True)
    btn.emit("clicked")
    for _ in range(40):
        ctx.iteration(False)
    assert runs == ["keep-quarantine"]
    assert recorded[-1][1] == "responderd:q1"
    v.unparent()


# -------------------------------------------------------- blocked addresses
def _blocked_snap(rows=None):
    return {"defense": {"blocked": rows if rows is not None else
                        [{"ip": "203.0.113.9", "ts": _iso(2),
                          "reason": "auto", "reason_words": "",
                          "why": "outside the house", "cls": "foreign",
                          "reviewed": ""},
                         {"ip": "wrong", "ts": "", "reason": "",
                          "why": "", "cls": "", "reviewed": ""}]}}


def test_blocked_table_carries_unblock_per_row(monkeypatch, tmp_path):
    _stub_probes(monkeypatch)
    v, w = _build(_FakeWin(tmp_path))
    v.refresh(_blocked_snap())
    assert _count_cards(v._blocked) == 2
    buttons = _buttons(v._blocked)
    # one Unblock per real address; the junk row carries no button
    assert [b.get_label() for b in buttons] == ["Unblock"]
    w.routed.clear()
    buttons[0].emit("clicked")
    assert w.routed == [{"id": "unblock", "label": "Unblock",
                         "tone": "danger", "helper": "lift-block",
                         "args": ["203.0.113.9"]}]
    v.unparent()


def test_blocked_row_says_the_cause_not_just_the_ip(monkeypatch, tmp_path):
    _stub_probes(monkeypatch)
    v, _w = _build(_FakeWin(tmp_path))
    v.refresh(_blocked_snap())
    words = _texts(v._blocked)
    assert any("203.0.113.9" in t for t in words)
    assert any("outside the house" in t for t in words)
    v.unparent()


def test_blocked_and_asked_empty_states_stay_honest(monkeypatch, tmp_path):
    _stub_probes(monkeypatch)
    v, _w = _build(_FakeWin(tmp_path))
    v.refresh({"defense": {}})
    assert "Nothing is blocked right now." in _texts(v._blocked)
    v.unparent()


# ------------------------------------------------------- CVE rows are gone
def test_cve_rows_are_gone_from_the_firewall_page(monkeypatch, tmp_path):
    _stub_probes(monkeypatch)
    called = []

    def fake_cve_rows(_dd):
        called.append(_dd)
        return [{"cve": "CVE-2026-0001", "score": 9.8, "severity":
                 "CRITICAL", "tool": "nginx", "summary": "boom"}]
    monkeypatch.setattr(protectdesk, "cve_rows", fake_cve_rows)
    v, _w = _build(_FakeWin(tmp_path))
    v.refresh({"defense": {}})
    assert called == []                  # the reader is never called here
    words = " ".join(_texts(v))
    assert "CVE-2026-0001" not in words
    v.unparent()


# ---------------------------------------------------- browser watch stays
def _finding(fid="f1", title="Hijacked rule", how="HIGH"):
    return {"id": fid, "rule": "persistence-scratch-path", "title": title,
            "what": "user crontab points at /tmp", "severity": how,
            "asset": "firefox:default", "status": "open",
            "ts": "2026-11-06T07:00:00+00:00"}


def test_watch_panel_renders_published_digest(tmp_path, monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build(_FakeWin(tmp_path))
    v.refresh({"defense": {}, "browser_watch": [_finding()]})
    text = " ".join(_texts(v._watch))
    assert "Hijacked rule" in text and "user crontab" in text
    v.unparent()


def test_watch_panel_honest_when_not_published(tmp_path, monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build(_FakeWin(tmp_path))
    v.refresh({"defense": {}})
    assert any("has not published" in t for t in _texts(v._watch))
    v.unparent()


# ------------------------------------------------ the threat-lane law holds
def test_no_tool_lifecycle_controls_on_the_firewall_page(monkeypatch,
                                                        tmp_path):
    _stub_probes(monkeypatch)
    v, _w = _build(_FakeWin(tmp_path))
    v.refresh({"defense": {"blocked": [{"ip": "192.168.0.44", "ts": "",
                                        "reason": "auto"}]},
               "browser_watch": [_finding()]})
    banned = ("start", "stop", "pause", "resume", "restart")
    for b in _buttons(v):
        label = (b.get_label() or "").lower()
        assert not any(word in label.split() for word in banned), \
            f"tool-lifecycle control on the firewall page: {label}"
    v.unparent()


# ------------------------------------------------------------- dock groups
def test_dock_groups_rules_psad_open_config(tmp_path, monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build(_FakeWin(tmp_path))
    groups = v.dock_groups()
    assert [t for t, _ws in groups] == ["Rules", "psad", "Open config"]
    by_title = dict(groups)
    rules = [w for w in by_title["Rules"]]
    assert any(isinstance(w, Gtk.Entry) for w in rules)
    labels = [w.get_label() for w in rules if isinstance(w, Gtk.Button)]
    assert "Block address" in labels and "Allow address" in labels
    psad_row = [w for w in by_title["psad"]]
    plabels = [w.get_label() for w in psad_row if isinstance(w, Gtk.Button)]
    assert "Arm auto-block" in plabels and "Disarm auto-block" in plabels
    conf = [w for w in by_title["Open config"]]
    clabels = [w.get_label() for w in conf if isinstance(w, Gtk.Button)]
    assert clabels == ["nftables rules", "psad.conf"]
    v.unparent()


def test_rules_block_add_runs_the_block_lane(tmp_path, monkeypatch):
    _stub_probes(monkeypatch)
    v, w = _build(_FakeWin(tmp_path))
    v._rules_entry.set_text("198.51.100.77")
    v._rules_add.emit("clicked")
    assert w.routed == [{"id": "block", "label": "Block 198.51.100.77",
                         "tone": "danger", "helper": "block-ip",
                         "args": ["198.51.100.77"]}]
    v._rules_entry.set_text("not-an-address")
    w.routed.clear()
    v._rules_add.emit("clicked")
    assert w.routed == []                    # nothing fires on junk
    assert "IPv4" in (v._rules_status.get_text() or "")
    v.unparent()


def test_rules_allow_and_psad_knobs_are_disabled_honestly(tmp_path,
                                                         monkeypatch):
    _stub_probes(monkeypatch)
    v, _w = _build(_FakeWin(tmp_path))
    v.dock_groups()
    for btn, tip in ((v._rules_allow, "no lane"),
                     (v._disarm, "no helper"),
                     (v._alert, "no lane")):
        assert not btn.get_sensitive()
        assert tip in (btn.get_tooltip_text() or "")
    v.unparent()


def test_open_config_buttons_hand_off_to_the_tools_page(tmp_path,
                                                        monkeypatch):
    """Re-rooted for task 9: the in-card config editor now exists on the
    Tools page, so the Open-config handoff goes there (the psad card
    carries the raw psad.conf editor)."""
    _stub_probes(monkeypatch)
    v, w = _build(_FakeWin(tmp_path))
    v.dock_groups()
    v._conf_nft.emit("clicked")
    v._conf_psad.emit("clicked")
    assert w.handoffs == [("tools", None, None),
                          ("tools", None, None)]
    v.unparent()


# ------------------------------------------------------------- entry + pin
def test_page_entry_is_rules():
    assert guided.PAGE_ENTRY.get("defense") == "Rules"


# ------------------------------------------------------- the daemon side
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
