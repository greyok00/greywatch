"""The bulk quarantine purge's containment law.

A real purge (2026-11-12) proved the old fallback dangerous: a manifest
pointed anywhere else still swept $HOME's quarantine dir. The helper now
globs ONLY the manifest's own sibling directory — a fixture manifest in
/tmp can never touch files outside its own recorded paths.
"""
import json
import subprocess
import os
import pathlib


def _run(tmp_path, manifest, args=()):
    env = dict(os.environ, GW_QUAR_MANIFEST=str(manifest))
    return subprocess.run(
        ["bash", "apply/purge-quarantine.sh", *args],
        capture_output=True, text=True, env=env, timeout=30)


def test_purge_sweeps_only_the_manifest_sibling(tmp_path):
    qdir = tmp_path / "quarantine"
    qdir.mkdir()
    (qdir / "Docs.zip.20261103-050403.quar").write_text("x")
    manifest = tmp_path / "quarantine.jsonl"
    manifest.write_text(json.dumps({
        "ts": "t0", "orig": "/tmp/dead/dir/Docs.zip",
        "file": str(qdir / "Docs.zip.20261103-050403.quar")}) + "\n")
    r = _run(tmp_path, manifest)
    assert r.returncode == 0
    assert "purged 1" in r.stdout
    assert not list(qdir.iterdir())          # every recorded copy gone
    rows = [json.loads(l) for l in manifest.read_text().splitlines()
            if l.strip()]
    assert rows[-1]["action"] == "deleted"
    # idempotent: a second purge is a clean zero
    r2 = _run(tmp_path, manifest)
    assert "purged 0" in r2.stdout and "already gone" in r2.stdout


def test_purge_never_touches_a_foreign_quarantine_dir(tmp_path, monkeypatch):
    """The containment pin: a fixture manifest + a fake $HOME quarantine
    dir. The old code swept it; the fix must leave it untouched."""
    fake_home = tmp_path / "home"
    foreign = fake_home / "security-hardening" / "quarantine"
    foreign.mkdir(parents=True)
    (foreign / "REAL.USER.FILE.20261101-000000.quar").write_text("keep")
    manifest = tmp_path / "q.jsonl"
    manifest.write_text(json.dumps({
        "ts": "t0", "orig": "/tmp/dead/x/D.txt",
        "file": str(tmp_path / "nowhere" / "D.txt.20261101.quar")}) + "\n")
    monkeypatch.setenv("HOME", str(fake_home))
    r = _run(tmp_path, manifest)
    assert r.returncode == 0
    assert (foreign / "REAL.USER.FILE.20261101-000000.quar").exists()


def test_purge_single_path_leaves_others(tmp_path):
    qdir = tmp_path / "quarantine"
    qdir.mkdir()
    (qdir / "A.20261103-050403.quar").write_text("x")
    (qdir / "B.20261103-050403.quar").write_text("x")
    manifest = tmp_path / "quarantine.jsonl"
    manifest.write_text("\n".join([
        json.dumps({"ts": "t0", "orig": "/tmp/d/A.txt",
                    "file": str(qdir / "A.20261103-050403.quar")}),
        json.dumps({"ts": "t1", "orig": "/tmp/d/B.txt",
                    "file": str(qdir / "B.20261103-050403.quar")}),
    ]) + "\n")
    r = _run(tmp_path, manifest, args=["/tmp/d/A.txt"])
    assert r.returncode == 0 and "purged 1" in r.stdout
    assert [p.name for p in sorted(qdir.iterdir())] == \
        ["B.20261103-050403.quar"]
