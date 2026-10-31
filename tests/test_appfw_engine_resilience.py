import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from appfw import history                      # noqa: E402
from appfw.engine import Engine               # noqa: E402


def test_history_is_group_readable_and_newest_last(tmp_path):
    for i in range(12):
        history.record(tmp_path, "arm", reason=f"r{i}", detail="x" * 100)
    path = tmp_path / "appfw" / "engine-history.jsonl"
    lines = path.read_text().splitlines()
    assert json.loads(lines[-1])["reason"] == "r11"
    assert (path.stat().st_mode & 0o777) == 0o640


def test_history_recent_returns_newest_first(tmp_path):
    history.record(tmp_path, "start")
    history.record(tmp_path, "stop", reason="switch")
    got = history.recent(tmp_path, limit=3)
    assert [e["event"] for e in got] == ["stop", "start"]


def test_missing_table_is_reinstalled_not_ignored(tmp_path, monkeypatch):
    eng = Engine(tmp_path)
    calls = []
    monkeypatch.setattr(eng, "_install_nft",
                        lambda: calls.append("arm") or True)
    monkeypatch.setattr(eng, "_worker_healthy", lambda: True)
    monkeypatch.setattr(eng, "table_present", lambda: False)
    eng.running = True
    assert eng._watchdog_step() is True
    assert calls == ["arm"]
    assert history.recent(tmp_path)[0]["event"] == "reinstall"


def test_dead_worker_is_respawned_without_deleting_the_table(tmp_path,
                                                            monkeypatch):
    eng = Engine(tmp_path)
    respawned, removed = [], []
    monkeypatch.setattr(eng, "_worker_healthy", lambda: False)
    monkeypatch.setattr(eng, "table_present", lambda: True)
    monkeypatch.setattr(eng, "_bind_worker",
                        lambda: respawned.append(1))
    monkeypatch.setattr(eng, "_remove_nft", lambda: removed.append(1))
    eng.running = True
    eng._watchdog_step()
    assert respawned == [1]
    assert removed == []
    assert history.recent(tmp_path)[0]["event"] == "respawn"


def test_stall_restarts_worker_and_keeps_the_table(tmp_path, monkeypatch):
    eng = Engine(tmp_path)
    respawned, removed = [], []
    monkeypatch.setattr(eng, "_worker_healthy", lambda: True)
    monkeypatch.setattr(eng, "table_present", lambda: True)
    monkeypatch.setattr(eng, "_query_backlog", lambda: 70000)
    monkeypatch.setattr(eng, "_bind_worker",
                        lambda: respawned.append(1))
    monkeypatch.setattr(eng, "_remove_nft", lambda: removed.append(1))
    eng.running = True
    eng._stall_since = 0.0
    import appfw.engine as mod
    clock = [100.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    eng._watchdog_step()               # starts the stall clock
    clock[0] += 3.0
    eng._watchdog_step()               # crosses the 2 s threshold
    assert respawned == [1]
    assert removed == []
    assert {e["event"] for e in history.recent(tmp_path)} >= {"stall"}
