import json
import pathlib
import subprocess
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from appfw import config as acfg
from appfw.engine import Engine


class _FakeSub:
    DEVNULL = -3
    STDOUT = -2
    @staticmethod
    def run(args, **k):                    # nft install/remove: rc 0
        return type("R", (), {"returncode": 0})()

    @staticmethod
    def Popen(argv, env=None, **k):        # the fake worker in-place
        return _fake_popen(argv, env=env)


def _engine(tmp_path, monkeypatch, workers=3):
    fake = ROOT / "tests" / "fake_worker.py"
    fake.chmod(0o755)
    monkeypatch.setattr("appfw.engine.ENGINE_BIN", fake)
    monkeypatch.setattr("appfw.engine.subprocess", _FakeSub())
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "enable.json").write_text(
        json.dumps({"enabled": True}) + "\n")
    events = []
    eng = Engine(tmp_path, on_event=events.append,
                 socket_dir=str(tmp_path))
    return eng, events


def _fake_popen(argv, env=None, **k):
    return subprocess.Popen([sys.executable, str(ROOT / "tests" /
                                                    "fake_worker.py"), "3"],
                            env=env)


def test_pkts_get_verdicts_through_real_sockets(tmp_path, monkeypatch):
    eng, events = _engine(tmp_path, monkeypatch)
    acfg.save(tmp_path, {**acfg.DEFAULTS, "ipv6_enabled": False})
    assert eng.start()
    time.sleep(1.5)
    verdicts = [e for e in events if "answered: allow" in e
                or "ALLOW" in e or "allow" in e]
    assert verdicts, events
    eng.stop()


def test_ruleset_ipv6_toggle(tmp_path):
    off = acfg.build_ruleset({**acfg.DEFAULTS, "ipv6_enabled": False})
    on = acfg.build_ruleset({**acfg.DEFAULTS, "ipv6_enabled": True})
    assert "ip6 daddr ::1" in off and "ip6 daddr ::1" in on   # exempt always
    assert "ip6 protocol tcp" not in off
    assert "ip6 protocol tcp" in on                            # queue when on
    assert "udp dport 53" in off and "udp dport 53" in on      # DNS exempt
    assert "queue num 111 bypass" in off and "queue num 111 bypass" in on


def test_config_defaults_survive_corruption(tmp_path):
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    (tmp_path / "appfw" / "config.json").write_text("{busted")
    cfg = acfg.load(tmp_path)
    assert cfg["ipv6_enabled"] is True and cfg["nfqueue_num"] == 111


def test_engine_refuses_to_arm_with_switch_off(tmp_path):
    eng = Engine(tmp_path, socket_dir=str(tmp_path))
    assert not eng.start()


def test_worker_missing_binary_refuses_to_arm(tmp_path, monkeypatch):
    (tmp_path / "appfw").mkdir(parents=True, exist_ok=True)
    eng = Engine(tmp_path, socket_dir=str(tmp_path),
                 worker_bin=tmp_path / "missing-worker",
                 worker_src=tmp_path / "no-such-source.c")
    events = []
    eng.on_event = events.append
    wrote = tmp_path / "appfw" / "enable.json"
    wrote.write_text(json.dumps({"enabled": True}) + "\n")
    assert not eng.start()
    assert any("worker" in e or "failed" in e for e in events)
