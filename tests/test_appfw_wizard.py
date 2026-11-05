import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wiz import appfw_wizard as aw
from ui import notify_alert as na


@pytest.fixture
def wiz_env(tmp_path, monkeypatch):
    monkeypatch.setattr(aw, "DATA", tmp_path)
    monkeypatch.setattr(aw, "LEDGER", tmp_path / "learning-seen.jsonl")
    return tmp_path


def test_build_and_preview_program_and_site(wiz_env):
    built = aw.appfw_build({"kind": "program", "action": "deny",
                            "value": "/usr/bin/curl"})
    assert built["rule"]["op_kind"] == "process.path"
    assert built["rule"]["action"] == "deny"
    assert "DENY" in built["preview"] and "curl" in built["preview"]
    built2 = aw.appfw_build({"kind": "site", "action": "allow",
                             "value": "*.trusted.example"})
    assert built2["rule"]["op_kind"] == "dst.host"
    with pytest.raises(aw.R.ValidationError):
        aw.appfw_build({"kind": "program", "action": "explode",
                        "value": "/usr/bin/curl"})
    with pytest.raises(aw.R.ValidationError):
        aw.appfw_build({"kind": "nonsense", "action": "allow", "value": "x"})


def test_apply_spec_persists_and_dedupes(wiz_env):
    aw.apply_spec({"kind": "program", "action": "allow",
                   "value": "/usr/bin/ollama"})
    aw.apply_spec({"kind": "program", "action": "allow",
                   "value": "/usr/bin/ollama"})
    files = list((wiz_env / "appfw" / "rules").glob("*.json"))
    assert [p.name for p in files] == ["allow-always.json"]
    rules = json.loads(files[0].read_text())["rules"]
    assert len(rules) == 1
    assert rules[0]["action"] == "allow"
    assert rules[0]["op_value"] == "/usr/bin/ollama"


def test_learning_ledger_and_approve_flow(wiz_env):
    aw.LEDGER.write_text(
        json.dumps({"ts": "t1", "app": "/usr/bin/python3.13",
                    "host": "api.example", "port": 443, "proto": "tcp"}) + "\n" +
        json.dumps({"ts": "t2", "app": "/usr/bin/node",
                    "host": "ws.example", "port": 443, "proto": "tcp"}) + "\n")
    pairs = aw.learned_pairs()
    assert [p["app"] for p in pairs][:2] == ["/usr/bin/node",
                                             "/usr/bin/python3.13"]
    aw.appfw_main(["approve"])
    allow = json.loads(
        (wiz_env / "appfw" / "rules" / "allow-always.json").read_text())
    assert len(allow["rules"]) == 2


def test_cli_list_and_remove(wiz_env):
    aw.appfw_main(["allow", "/usr/bin/curl"])
    out = aw.appfw_main(["list"])
    assert out == 0                          # prints; no crash
    assert aw.appfw_main(["remove", "appfw-app-curl"]) == 0
    for fname in ("allow-always.json", "deny-always.json"):
        p = wiz_env / "appfw" / "rules" / fname
        if p.exists():
            assert json.loads(p.read_text())["rules"] == []
    assert aw.appfw_main(["deny", ""]) != 0  # empty value refused


def test_parse_deny_engine_lines():
    assert na.parse_deny(
        "appfw curl → bad.example:80 deny [note]") == \
        {"app": "curl", "host": "bad.example:80", "action": "deny"}
    assert na.parse_deny("appfw engine: running (queue 111)") is None
    assert na.parse_deny("") is None


def test_one_square_replaces_itself_and_never_stacks(tmp_path, monkeypatch):
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)

    class FakeNotification:
        instances = []
        def __init__(self, summary=None, body=None):
            self.summary, self.body = summary, body
            self.updates = []
            self.shown = 0
            self.actions = []
        @classmethod
        def new(cls, summary, body):
            inst = cls(summary, body)
            cls.instances.append(inst)
            return inst
        def set_timeout(self, t):
            pass
        def update(self, s, b):
            self.updates.append((s, b))
        def add_action(self, *a):
            self.actions.append(a)
        def show(self):
            self.shown += 1

    class FakeNotify:
        Notification = FakeNotification

    q = na.BlockedQueue(pathlib.Path("/tmp"))
    alert = na.NotifyAlert(q, notifier=FakeNotify)
    t1 = alert.handle_deny("/usr/bin/curl", "bad.example")
    assert "Blocked" in t1 and "curl" in t1
    t2 = alert.handle_deny("/usr/bin/python3", "tracker.example")
    assert "2" in t2 and "python3" in t2
    assert len(FakeNotification.instances) == 1   # ONE square, replaced
    first = FakeNotification.instances[0]
    assert first.shown >= 2 and first.updates     # updated in place
    assert [a[0] for a in first.actions[:2]] == ["unblock-all", "review"]


def test_unblock_all_writes_allow_rules_and_clears_burst(tmp_path):
    q = na.BlockedQueue(tmp_path)
    q.add_deny("/usr/bin/curl", "bad.example")
    q.add_deny("/usr/bin/curl", "again.example")     # same app → one rule
    q.add_deny("<unknown>", "opaque.example")        # unresolvable → skipped
    done = q.unblock_all()
    assert done == ["/usr/bin/curl"]
    allow = json.loads(
        (tmp_path / "appfw" / "rules" / "allow-always.json").read_text())
    values = [r["op_value"] for r in allow["rules"]]
    assert values == ["/usr/bin/curl"]
    assert q.pending() == 0
