"""The daemon must be able to ask the GUI about a connection.

Before this bridge the popup code existed but nothing called it: every
unknown connection got the fixed headless verdict, so the dashboard could
say "deny-once (headless fallback)" while the owner was never asked.
"""
import json
import threading

import greywatch_daemon as dm

SPEC = {
    "id": "appfw:brave:4242:55555",
    "eyebrow": "App firewall",
    "subject": "brave wants internet access",
    "detail": "/usr/bin/brave → example.com:443 (TCP) · pid 4242",
    "host": "example.com",
    "options": [
        {"id": "deny-once", "label": "Block", "args": ["deny", "once"]},
        {"id": "allow-once", "label": "Allow", "args": ["allow", "once"]},
    ],
}


def _now():
    """Asks older than the poller's freshness window are ignored — the
    daemon has already timed out on them. Tests must use the real time."""
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _daemon(tmp_path, policy="deny-once"):
    # registry=[] is how the other daemon tests keep systemd out of the way
    d = dm.Daemon(data_dir=tmp_path, registry=[])
    d._ask_policy = policy
    return d


def test_ask_writes_request_and_reads_answer(tmp_path):
    d = _daemon(tmp_path)
    d.ASK_TIMEOUT_S = 5
    req, ans = d._ask_paths(SPEC)

    def answer():
        # the GUI writes the answer file the moment it exists
        for _ in range(100):
            if req.exists():
                break
            threading.Event().wait(0.02)
        doc = json.loads(req.read_text())
        assert doc["id"] == SPEC["id"]
        assert doc["spec"]["host"] == "example.com"
        ans.parent.mkdir(parents=True, exist_ok=True)
        ans.write_text(json.dumps({"action": "allow", "duration": "once",
                                   "host_op": None}))

    t = threading.Thread(target=answer)
    t.start()
    got = d._appfw_ask_user(SPEC)
    t.join(timeout=3)
    assert got == ("allow", "once", None)
    assert not req.exists() and not ans.exists()


def test_no_gui_falls_back_to_headless_deny(tmp_path):
    d = _daemon(tmp_path, policy="deny-once")
    d.ASK_TIMEOUT_S = 0.3
    assert d._appfw_ask_user(SPEC) == ("deny", "once")


def test_no_gui_falls_back_to_headless_allow(tmp_path):
    d = _daemon(tmp_path, policy="allow-once")
    d.ASK_TIMEOUT_S = 0.3
    assert d._appfw_ask_user(SPEC) == ("allow", "once")


def test_malformed_answer_is_not_trusted(tmp_path):
    d = _daemon(tmp_path)
    d.ASK_TIMEOUT_S = 2
    req, ans = d._ask_paths(SPEC)

    def answer():
        for _ in range(100):
            if req.exists():
                break
            threading.Event().wait(0.02)
        ans.parent.mkdir(parents=True, exist_ok=True)
        ans.write_text(json.dumps({"action": "maybe"}))

    t = threading.Thread(target=answer)
    t.start()
    assert d._appfw_ask_user(SPEC) == ("deny", "once")
    t.join(timeout=3)


def test_ask_dirs_are_shared_with_the_gui_user(tmp_path):
    d = _daemon(tmp_path)
    d.ASK_TIMEOUT_S = 0.01
    base = tmp_path / "appfw"
    # Start restrictive: an inherited 0755 would hide the bug this guards
    # against — a GUI that cannot write its answer.
    (base / "asks").mkdir(parents=True)
    (base / "answers").mkdir(parents=True)
    for p in (base / "asks", base / "answers"):
        p.chmod(0o700)
    d._appfw_ask_user(SPEC)
    for p in (base / "asks", base / "answers"):
        assert p.is_dir()
        assert p.stat().st_mode & 0o020, f"{p} must be group-writable"


def test_gui_polls_ask_and_writes_answer(tmp_path, monkeypatch):
    """The popup path: a request file becomes one dialog, and its answer
    is written where the daemon is waiting."""
    from ui.decisions import DecisionBroker

    asks = tmp_path / "appfw" / "asks"
    answers = tmp_path / "appfw" / "answers"
    asks.mkdir(parents=True)
    (asks / "abc123.json").write_text(json.dumps({
        "id": SPEC["id"], "ts": _now(), "spec": SPEC}))

    b = DecisionBroker()
    b._asks_dir, b._answers_dir = asks, answers
    b._asked_files = set()
    seen = []

    def fake_show(spec, eyebrow="Protection", resolve=None):
        seen.append(spec["id"])
        resolve(1)          # options[1] == allow-once

    monkeypatch.setattr(b, "_show_dialog", fake_show)
    assert b._poll_appfw_asks() is True
    assert seen == [SPEC["id"]]
    doc = json.loads((answers / "abc123.json").read_text())
    assert doc["action"] == "allow" and doc["duration"] == "once"
    # a second poll must not queue the same ask twice
    assert b._poll_appfw_asks() is True
    assert seen == [SPEC["id"]]


def test_gui_dismiss_answers_deny(tmp_path, monkeypatch):
    from ui.decisions import DecisionBroker

    asks = tmp_path / "appfw" / "asks"
    answers = tmp_path / "appfw" / "answers"
    asks.mkdir(parents=True)
    (asks / "def456.json").write_text(json.dumps({
        "id": SPEC["id"], "ts": _now(), "spec": SPEC}))

    b = DecisionBroker()
    b._asks_dir, b._answers_dir = asks, answers
    b._asked_files = set()
    monkeypatch.setattr(b, "_show_dialog",
                        lambda spec, eyebrow="Protection", resolve=None:
                        resolve(None))
    b._poll_appfw_asks()
    doc = json.loads((answers / "def456.json").read_text())
    assert doc["action"] == "deny"
