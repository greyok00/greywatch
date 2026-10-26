import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wiz import appfw_wizard as aw
from appfw import rules as R
from appfw.rules import RuleStore


@pytest.fixture
def wiz_env(tmp_path, monkeypatch):
    monkeypatch.setattr(aw, "DATA", tmp_path)
    monkeypatch.setattr(aw, "LEDGER", tmp_path / "learning-seen.jsonl")
    return tmp_path


def test_pending_lifecycle(wiz_env):
    st = RuleStore(wiz_env / "appfw" / "rules")
    rule = R.validate("p-api", "allow", "always", "dst.host", "api.example")
    st.add_pending(rule)
    assert aw.appfw_main(["pending"]) == 0
    assert st.decide(_conn("api.example")) is None
    assert aw.appfw_main(["promote", "p-api"]) == 0
    st.reload()
    assert st.decide(_conn("api.example")).action == "allow"
    assert aw.appfw_main(["promote", "ghost"]) != 0


def test_revoke_declines_without_promoting(wiz_env):
    st = RuleStore(wiz_env / "appfw" / "rules")
    rule = R.validate("p-tracker", "allow", "always", "dst.host",
                      "tracker.example")
    st.add_pending(rule)
    assert aw.appfw_main(["revoke", "p-tracker"]) == 0
    st.reload()
    assert st.pending_rules() == []
    assert st.decide(_conn("tracker.example")) is None
    allow_path = wiz_env / "appfw" / "rules" / "allow-always.json"
    if allow_path.exists():                 # containers are optional
        assert json.loads(allow_path.read_text())["rules"] == []
    assert aw.appfw_main(["revoke", "ghost"]) != 0


def test_engine_learned_pair_can_flow_to_pending(wiz_env):
    st = RuleStore(wiz_env / "appfw" / "rules")
    learned = R.validate(f"appfw-app-{pathlib.Path('/usr/bin/curl').name}",
                         "allow", "always", "process.path", "/usr/bin/curl")
    st.add_pending(learned)
    assert st.approve_pending(learned.name)
    allow = json.loads(
        (wiz_env / "appfw" / "rules" / "allow-always.json").read_text())
    assert [r["op_value"] for r in allow["rules"]] == ["/usr/bin/curl"]


def _conn(host):
    from appfw.base import Conn
    return Conn(dst_host=host)


def _conn_path():
    from appfw.base import Conn
    return Conn(process_path="/usr/bin/curl")
