"""GW-195 (owner live finding, 2026-11-05): the app firewall refused to
arm its packet worker for a pointless reason. The deb ships the worker's
C source but not the bin/ directory it compiles into, so gcc failed with
"cannot create output file" and the engine logged, five minutes at a
time: "nfq worker binary missing and gcc build failed (engine refuses to
arm half-broken)". The fix is at the source: make the bin directory
before building."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from appfw import config
from appfw.engine import Engine


def test_worker_build_makes_its_bin_directory(tmp_path, monkeypatch):
    calls = []

    def fake_gcc(cmd, capture_output=True, text=True, timeout=60):
        calls.append(list(cmd))
        # gcc only succeeds when the parent directory exists - the real
        # failure on this machine was exactly that
        out = pathlib.Path(cmd[4])           # gcc -O2 -Wall -o <bin> <src>
        assert out.parent.is_dir(), "gcc output dir missing"
        out.write_bytes(b"\x7fELF")
        out.chmod(0o755)
        return type("R", (), {"returncode": 0, "stdout": "",
                              "stderr": ""})()

    monkeypatch.setattr("appfw.engine.subprocess.run", fake_gcc)
    engine = Engine(data_dir=tmp_path,
                    worker_bin=tmp_path / "bin" / "nfq_worker",
                    worker_src=str(ROOT / "appfw" / "nfq_worker.c"))
    # mirror the deb's shape: src ships, bin/ does not
    assert not engine._worker_bin.parent.exists()
    assert engine._ensure_worker_binary() is True
    assert engine._worker_bin.parent.is_dir()
    assert engine._worker_bin.read_bytes() == b"\x7fELF"


def test_worker_build_refuses_when_bin_cannot_exist(tmp_path):
    engine = Engine(data_dir=tmp_path,
                    worker_bin=tmp_path / "file-not-dir" / "nfq_worker",
                    worker_src=str(ROOT / "appfw" / "nfq_worker.c"))
    (tmp_path / "file-not-dir").write_text("occupied")
    assert engine._ensure_worker_binary() is False
