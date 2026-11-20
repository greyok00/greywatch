"""The daemon's posture publish lane (owner 2026-11-16): the root store
the Security Center never needs a password for. Headless-safe — the
baseline verifier's unit checks are stubbed, a tmp dir stands in for
/var/lib/greywatch, and the GUI share is a no-op when not root (the
guard that lives inside that helper)."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


class _BeatHost:
    """Only what the beat binds: the data dir and the GUI share."""

    def __init__(self, data_dir):
        self.data_dir = pathlib.Path(data_dir)
        self.shared = []

        from greywatch_daemon import Daemon
        self._posture_beat = Daemon._posture_beat

    def _share_with_ui(self, path):
        self.shared.append(path)

    def beat(self):
        self._posture_beat(self)


def test_posture_beat_persists_a_full_report(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    import greywatch_daemon as daemon            # noqa: F401 (the beat's home)

    fake_rows = [("ufw", "ufw.service active+enabled", "ENABLED", ""),
                 ("yara-rules", "config file", "PRESENT", "")]
    called = {}

    def fake_verifier(data_dir=None):
        called["data_dir"] = str(data_dir)
        return fake_rows

    monkeypatch.setattr("baseline.baseline_verifier", fake_verifier)

    host = _BeatHost(tmp_path)
    host.beat()

    doc = json.loads((tmp_path / "posture.json").read_text())
    assert called["data_dir"] is not None          # the verifier got the dir
    assert doc["inputs"]["baseline_pass"]["value"] is not None
    assert set(doc["inputs"]) == {"lynis_hardening", "baseline_pass",
                                  "cve_exposure", "apparmor_exposure"}
    assert all("how" in v for v in doc["inputs"].values())
    assert host.shared == [tmp_path / "posture.json"]
