import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from appfw import history                          # noqa: E402
from appfw.askgate import AskGate                  # noqa: E402
from appfw.config import DEFAULTS, mode_of         # noqa: E402
from appfw.engine import Engine                    # noqa: E402


def test_unanswered_prompt_takes_the_headless_verdict():
    gate = AskGate("deny-once", timeout=30, window=300,
                   ask=lambda spec: None, clock=lambda: 0.0)
    assert gate.ask({"dst_ip": "203.0.113.9"}) == ("deny", "once", None)
    allow = AskGate("allow-once", timeout=30, window=300, ask=lambda s: None)
    assert allow.ask({"dst_ip": "203.0.113.10"}) == ("allow", "once", None)


def test_repeat_destination_is_suppressed_for_the_window():
    clock = [0.0]
    seen = []

    def ask(spec):
        seen.append(spec["dst_ip"])
        return ("allow", "once", None)

    gate = AskGate("deny-once", timeout=30, window=300, ask=ask,
                   clock=lambda: clock[0])
    assert gate.ask({"dst_ip": "203.0.113.9", "dst_port": 443})[0] == "allow"
    clock[0] = 100
    assert gate.ask({"dst_ip": "203.0.113.9", "dst_port": 8080})[0] == "allow"
    assert seen == ["203.0.113.9"]            # asked once, ports differ
    clock[0] = 400
    gate.ask({"dst_ip": "203.0.113.9", "dst_port": 443})
    assert len(seen) == 2                     # window expired


def test_modes_map_from_config():
    assert mode_of({"learning_mode": True}) == "learning"
    cfg = dict(DEFAULTS, learning_mode=False, strict_mode=True, fail_open=False)
    assert mode_of(cfg) == "whitelist"
    cfg = dict(DEFAULTS, learning_mode=False, strict_mode=False, fail_open=True)
    assert mode_of(cfg) == "standard"
    assert DEFAULTS["ask_timeout_sec"] == 30
    assert DEFAULTS["ask_repeat_window_sec"] == 300


def test_whitelist_valve_suspends_after_five_seconds_down(tmp_path,
                                                         monkeypatch):
    import appfw.engine as mod
    cfg_path = tmp_path / "appfw" / "config.json"
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text('{"learning_mode": false, "strict_mode": true, '
                        '"fail_open": false}')
    eng = Engine(tmp_path)
    scripts = []
    monkeypatch.setattr(eng, "_worker_healthy", lambda: False)
    monkeypatch.setattr(eng, "table_present", lambda: True)
    monkeypatch.setattr(eng, "_bind_worker", lambda: None)
    monkeypatch.setattr(eng, "_query_backlog", lambda: 0)
    monkeypatch.setattr(eng, "_remove_nft", lambda: None)
    monkeypatch.setattr(mod.subprocess, "run",
                        lambda *a, **k: scripts.append(k.get("input"))
                        or type("R", (), {"returncode": 0, "stdout": "",
                                          "stderr": ""})())
    clock = [200.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    eng.running = True
    eng._watchdog_step()                 # clock starts
    clock[0] += 6.0
    eng._watchdog_step()                 # valve trips
    assert eng._whitelist_suspended
    assert "flags bypass" in scripts[-1]     # traffic restored fail-open
    assert "suspend" in {e["event"] for e in history.recent(tmp_path)}


def test_valve_never_rewrites_the_owner_config(tmp_path, monkeypatch):
    import appfw.engine as mod
    cfg_path = tmp_path / "appfw" / "config.json"
    cfg_path.parent.mkdir(parents=True)
    original = '{"strict_mode": true, "fail_open": false}'
    cfg_path.write_text(original)
    eng = Engine(tmp_path)
    monkeypatch.setattr(eng, "_worker_healthy", lambda: False)
    monkeypatch.setattr(eng, "table_present", lambda: True)
    monkeypatch.setattr(eng, "_bind_worker", lambda: None)
    monkeypatch.setattr(eng, "_query_backlog", lambda: 0)
    monkeypatch.setattr(eng, "_remove_nft", lambda: None)
    monkeypatch.setattr(mod.subprocess, "run",
                        lambda *a, **k: type("R", (), {"returncode": 0,
                                                       "stdout": "",
                                                       "stderr": ""})())
    clock = [300.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    eng.running = True
    eng._watchdog_step()
    clock[0] += 6.0
    eng._watchdog_step()
    eng._suspend_whitelist()             # idempotent: no second rewrite
    assert cfg_path.read_text() == original
