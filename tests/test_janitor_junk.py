"""The janitor is disabled by owner law (2026-11-14).

The daemon never answers a decision. Every quarantine ask stays pending
until the owner answers it through the CLI. These tests pin that law and
the scratch-path classifier the CLI sweep still uses.
"""
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from decisions_factory import pending_spec_pairs  # noqa: E402
from greywatch_daemon import Daemon, load_registry  # noqa: E402
from status import append_checked  # noqa: E402


def _ask(rid, path, subject=True, options=True):
    spec = {"id": rid}
    if subject:
        spec["subject"] = f'"{pathlib.Path(path).name}" was quarantined'
        spec["question"] = "Keep it locked away?"
    if options:
        spec["options"] = [
            {"id": "keep", "helper": "keep-quarantine", "args": [path]},
            {"id": "restore", "helper": "restore-quarantine", "args": [path]},
            {"id": "delete", "helper": "delete-quarantine", "args": [path]},
        ]
    return spec


def _seed(tmp, asks):
    lines = []
    for rid, path, extra in asks:
        body = {"ts": "2026-11-10T00:00:00+00:00", "text": "quarantine: x",
                "interaction": _ask(rid, path, **extra)}
        lines.append(json_line(body))
    (tmp / "events.jsonl").write_text("\n".join(lines))


def json_line(body):
    import json
    return json.dumps(body, ensure_ascii=False)


def _daemon(tmp):
    return Daemon(data_dir=tmp, registry=load_registry())


def test_temp_junk_ask_auto_kept_never_pending(tmp_path):
    tmp = tmp_path / "data"
    (tmp / "appfw").mkdir(parents=True)
    junk_path = tmp_path / "pytest-of-grey" / "run" / "Sample.docx"
    junk_path.parent.mkdir(parents=True)
    junk_path.write_text("junk copy")          # the "quarantined" copy
    _seed(tmp, [("responderd:junk1", str(junk_path), {})])
    d = _daemon(tmp)
    assert d._janitor_quarantine_junk() == 0
    # the daemon records no answer at all
    answers = (d.decisions_path.read_text()
               if d.decisions_path.exists() else "")
    assert "responderd:junk1" not in answers
    pairs = [p[0]["id"] for p in pending_spec_pairs(tmp)]
    assert "responderd:junk1" in pairs       # the owner answers it


def test_real_malware_ask_still_asks(tmp_path):
    tmp = tmp_path / "data"
    (tmp / "appfw").mkdir(parents=True)
    real = tmp / "quarantine-real" / "invoice.docx"
    real.parent.mkdir(parents=True)
    real.write_text("quarantine copy")
    _seed(tmp, [("responderd:real1", str(real), {})])
    d = _daemon(tmp)
    assert d._janitor_quarantine_junk() == 0
    pairs = [p[0]["id"] for p in pending_spec_pairs(tmp)]
    assert pairs == ["responderd:real1"]       # the owner still decides


def test_janitor_runs_in_the_boot_pass(tmp_path):
    tmp = tmp_path / "data"
    (tmp / "appfw").mkdir(parents=True)
    junk = tmp_path / "pytest-x" / "a.bin"
    junk.parent.mkdir(parents=True)
    junk.write_text("junk")
    _seed(tmp, [("responderd:bj", str(junk), {})])
    d = _daemon(tmp)
    d.run_once(tailers=[])
    # the boot pass records no answer; the ask reaches the owner
    answers = (d.decisions_path.read_text()
               if d.decisions_path.exists() else "")
    assert "responderd:bj" not in answers
    pairs = [p[0]["id"] for p in pending_spec_pairs(tmp)]
    assert "responderd:bj" in pairs, _boot_state(tmp, d)


def test_append_never_glues_onto_a_torn_last_line(tmp_path):
    """A torn last write leaves the ledger without its trailing newline;
    the next append must SEPARATE, never weld the two lines into one
    record no reader can parse (the pending-ask-loses-its-id class the
    0.4.5.6 CI battery caught: the boot pass's first appended event
    welded itself onto the seeded ask)."""
    ledger = tmp_path / "events.jsonl"
    ledger.write_text(json.dumps(
        {"ts": "t0", "interaction": {"id": "responderd:torn"}}))
    ledger.chmod(0o644)     # a private root-owned ledger; a 0664 umask
    # artifact would trip append_checked's group-writable refusal first
    append_checked(str(ledger), json.dumps({"ts": "t1"}) + "\n")
    append_checked(str(ledger), json.dumps({"ts": "t2"}) + "\n")
    rows = [ln for ln in ledger.read_text().splitlines() if ln.strip()]
    assert len(rows) == 3
    assert json.loads(rows[0])["interaction"]["id"] == "responderd:torn"
    assert json.loads(rows[1])["ts"] == "t1"
    assert json.loads(rows[2])["ts"] == "t2"
    pairs = [p[0]["id"] for p in pending_spec_pairs(tmp_path)]
    assert pairs == ["responderd:torn"]


def test_append_leaves_a_healthy_ledger_untouched(tmp_path):
    """The separator must fire ONLY on a torn tail: on a ledger whose
    records already end with a newline, appends add nothing extra —
    no blank line, no doubled separator (a pread fallback that fired
    on every append littered learning-seen.jsonl with blank lines and
    broke a raw line-count assertion)."""
    ledger = tmp_path / "events.jsonl"
    ledger.write_text(json.dumps(
        {"ts": "t0", "interaction": {"id": "responderd:ok"}}) + "\n")
    ledger.chmod(0o644)
    append_checked(str(ledger), json.dumps({"ts": "t1"}) + "\n")
    append_checked(str(ledger), json.dumps({"ts": "t2"}) + "\n")
    lines = ledger.read_text().splitlines()
    assert len(lines) == 3
    assert all(ln.strip() for ln in lines)
    assert json.loads(lines[0])["interaction"]["id"] == "responderd:ok"


def _boot_state(data_dir, d):
    """Evidence at the boundary the boot pass owns: what the ledger and
    the published snapshot carried when the read-back went empty. A CI
    failure used to die on a bare `in []` with nothing to diagnose."""
    facts = []
    events = data_dir / "events.jsonl"
    try:
        raw = events.read_bytes()
        lines = [ln for ln in raw.split(b"\n") if ln.strip()]
        hits = [ln for ln in lines if b'"interaction"' in ln]
        facts.append(f"events: exists, {len(lines)} lines, "
                     f"{len(hits)} interaction lines")
        if hits:
            facts.append(f"first hit: {hits[0][:200]!r}")
    except OSError as e:
        facts.append(f"events: unreadable ({e})")
    try:
        snap = json.loads((data_dir / "status.json").read_text())
        recent = snap.get("recent") or []
        facts.append(f"status: recent={len(recent)}, "
                     f"pending_decisions={snap.get('pending_decisions')}")
        rec_ids = [(r.get("interaction") or {}).get("id")
                   for r in recent if isinstance(r, dict)]
        facts.append(f"status recent ids: {[i for i in rec_ids if i]}")
    except (OSError, ValueError) as e:
        facts.append(f"status: unreadable ({e})")
    facts.append(f"failures: {d._fail_counts}")
    facts.append(f"uid={os.geteuid()} outbox={len(d._outbox)}")
    return "; ".join(facts)
