import importlib.util
import json
import pathlib
import sys
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from appfw.atomicio import write_json_atomic
from appfw import rules as R
from appfw.rules import RuleStore
from supervisor import Supervisor, Supervised
from schemas import validate as V


def test_atomic_write_survives_interrupt(tmp_path, monkeypatch):
    p = tmp_path / "f.json"
    write_json_atomic(p, {"a": 1})
    monkeypatch.setattr("appfw.atomicio.os.replace",
                        lambda *a, **k: (_ for _ in ()).throw(
                            OSError("killed mid-write")))
    with pytest.raises(OSError):
        write_json_atomic(p, {"a": 2})
    monkeypatch.undo()
    assert json.loads(p.read_text()) == {"a": 1}   # prior state intact
    assert list(tmp_path.glob("*.tmp")) == []      # torn tmp cleaned up
    write_json_atomic(p, {"a": 2})
    assert json.loads(p.read_text()) == {"a": 2}


def test_store_tolerates_a_corrupt_file(tmp_path):
    d = tmp_path
    (d / "allow-always.json").write_text("{TOTALLY CORRUPT")
    st = RuleStore(d)
    st.add(R.validate("curl", "allow", "always", "process.path",
                      "/usr/bin/curl"))
    assert [r.name for r in st.all_rules()] == ["curl"]
    assert any("unreadable" in e for e in st.load_errors)


def test_store_skips_bad_entries_and_loads_the_rest(tmp_path):
    (tmp_path / "allow-always.json").write_text(json.dumps({
        "kind": "allow-always",
        "rules": [
            {"name": "good", "action": "allow", "duration": "always",
             "op_kind": "process.path", "op_value": "/bin/ok"},
            {"name": "empty-operator", "action": "allow",
             "duration": "always", "op_kind": "process.path", "op_value": ""},
        ]}))
    st = RuleStore(tmp_path)
    assert [r.name for r in st.all_rules()] == ["good"]
    assert any("[1]" in e for e in st.load_errors)   # entry 1 skipped+logged


def test_schema_validator_basics():
    schema = {"type": "object", "required": ["a"],
              "properties": {"a": {"type": "integer", "min": 0}}}
    assert V.validate({"a": 1}, schema) == []
    errs = V.validate({"a": -1}, schema)
    assert errs and "below min" in errs[0]
    assert V.validate({}, schema) and "missing required" in V.validate(
        {}, schema)[0]
    doc = {"kind": "x", "rules": [{"name": "r", "action": "allow",
            "duration": "always", "op_kind": "dst.host",
            "op_value": "example.com", "created": 1}]}
    assert V.validate_rules(doc) == []
    assert V.validate_rules({"kind": "x", "rules": [{"op_value": ""}]})


def test_legacy_migration(tmp_path):
    legacy = tmp_path / "appfw-app-x-process-path.json"
    legacy.write_text(json.dumps(
        {"name": "appfw-app-x", "action": "deny", "duration": "always",
         "op_kind": "process.path", "op_value": "/bin/x", "created": 5}))
    st = RuleStore(tmp_path)
    assert (tmp_path / "deny-always.json").exists()
    assert "appfw-app-x" in [r.name for r in st.all_rules()]
    assert (tmp_path / "legacy-backup" /
            "appfw-app-x-process-path.json").exists()
    assert not legacy.exists()
    st2 = RuleStore(tmp_path)
    assert "appfw-app-x" in [r.name for r in st2.all_rules()]


def test_pending_never_auto_promotes(tmp_path):
    st = RuleStore(tmp_path)
    rule = R.validate("p-endpoint", "allow", "always", "dst.host",
                      "learned.example")
    st.add_pending(rule)
    assert st.decide(_conn("learned.example")) is None   # never enforced
    assert st.approve_pending("ghost") is False
    assert st.approve_pending("p-endpoint") is True      # explicit approval IS
    assert st.decide(_conn("learned.example")).action == "allow"  # the only path


def _conn(host):
    from appfw.base import Conn
    return Conn(dst_host=host)


def test_session_rules_die_at_start(tmp_path):
    st = RuleStore(tmp_path)
    st.add(R.validate("tmp", "deny", "until restart", "process.path",
                      "/bin/x"))
    assert st.decide(_conn_path("/bin/x")) is not None
    assert st.session_reset() == 1
    assert st.decide(_conn_path("/bin/x")) is None


def _conn_path(path):
    from appfw.base import Conn
    return Conn(process_path=path)


def test_supervisor_restarts_a_dead_thread():
    s = Supervisor()

    def worker():
        while True:
            time.sleep(0.05)

    u = s.register("worker", worker)
    u.start()
    time.sleep(0.2)
    assert u.supervise() == "running"
    u.thread = threading.Thread(target=lambda: None)
    u.thread.start()
    u.thread.join()
    u.last_start = time.monotonic() - 3.0
    assert u.supervise() == "restarted"
    assert u.thread.is_alive() and u.restarts == 1


def test_breaker_trips_and_resets_after_quiet():
    def dying():
        raise RuntimeError("broken")

    u = Supervised("boom", dying)
    u.last_start = 0.0
    for _ in range(3):
        u._mark_failure()
    assert u.tripped
    assert u.supervise() == "tripped"          # parked, surfaced honestly
    u.failures[-1] -= u.quiet_reset + 1.0      # quiet long enough
    assert u.supervise() != "tripped"          # quiet ⇒ the retry attempt happens
    u._mark_failure(); u._mark_failure(); u._mark_failure()
    assert u.tripped                           # 3 fresh failures park it again


def test_delegated_launcher_restarts_a_dead_tailer():
    started = []

    class FakeTailer:
        tool = "x"
        def __init__(self):
            self._thread = None
        def start(self):
            started.append(1)
            self._thread = threading.Thread(target=lambda: None)
            self._thread.start()

    t = FakeTailer()
    s = Supervisor()
    s.register("tail:x", target=t.start,
               health=lambda: t._thread is not None and t._thread.is_alive(),
               latched_target=False)
    t.start()                                   # manual launch: started==1
    t._thread.join()
    s.units["tail:x"].last_start = time.monotonic() - 3.0
    state = s.check_all()["tail:x"]
    assert state == "restarted" and len(started) == 2


def _watchdog():
    spec = importlib.util.spec_from_file_location(
        "gw_watchdog", ROOT / "doc" / "greywatch_watchdog.py")
    return importlib.util.module_from_spec(spec), spec


def test_watchdog_restarts_on_stale_or_missing_heartbeat(tmp_path,
                                                         monkeypatch):
    mod, spec = _watchdog()
    spec.loader.exec_module(mod)
    hb = tmp_path / "heartbeat"
    calls = []
    monkeypatch.setattr(mod, "HEARTBEAT", hb)

    def fake_run(argv, **k):
        if "is-active" in argv:
            return type("R", (), {"returncode": 0})()   # unit alive
        calls.append(list(argv))
        return type("R", (), {"returncode": 0})()
    monkeypatch.setattr(mod.subprocess, "run", fake_run)

    hb.touch()                                  # fresh → no restart
    assert mod.main() == 0 and calls == []
    past = time.time() - 90
    import os
    os.utime(str(hb), (past, past))             # stale → restart
    assert mod.main() == 0 and len(calls) == 1 and "restart" in calls[0]
    hb.unlink()                                 # missing → restart (fail-closed)
    assert mod.main() == 0 and len(calls) == 2

    def dead_unit(argv, **k):
        if "is-active" in argv:
            return type("R", (), {"returncode": 1})()
        calls.append(list(argv))
        return type("R", (), {"returncode": 0})()
    hb.touch()
    monkeypatch.setattr(mod.subprocess, "run", dead_unit)
    assert mod.main() == 0 and len(calls) == 3
