"""The janitor is disabled by owner law (2026-11-14).

The daemon never answers a decision. Every quarantine ask stays pending
until the owner answers it through the CLI. These tests pin that law and
the scratch-path classifier the CLI sweep still uses.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from decisions_factory import pending_spec_pairs  # noqa: E402
from greywatch_daemon import Daemon, load_registry  # noqa: E402


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
    assert "responderd:bj" in pairs
