"""The bounded AI layer: budget, cooldown, schema, and the hard line that
the model rewords findings — it never creates them.

The endpoint/model values are owner-pinned (the local ollama gateway on
:11600, cloud model, think=false), so they are pinned here too. Every
failure mode — offline, malformed, over budget, disabled — answers None
and leaves the deterministic rule text authoritative."""
import json
import pathlib
import sys
import urllib.request as _ur

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hunter import explain, store  # noqa: E402


def _finding():
    return {"id": "abc", "rule": "har-double-extension",
            "title": "A download tried to look like a document",
            "what": "“invoice.pdf.exe” was offered as a download.",
            "next": "Delete the file.", "severity": "HIGH",
            "facts": ["path=/home/u/Downloads/invoice.pdf.exe"],
            "evidence": [{"source": "har", "host": "evil.example",
                          "path": "", "url": "https://evil.example/invoice"}]}


def _fresh_budget():
    return {"window_start": explain._iso(), "used": 0, "fails": 0}


class _Reply:
    def __init__(self, doc=None):
        self._doc = doc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self._doc).encode()


def _install_reply(monkeypatch, calls, content, *, raise_error=None):
    """The gateway reply format: {'message': {'content': '<text>'}}."""
    def fake(req, timeout=None):
        calls.append((req.get_full_url(), json.loads(req.data.decode())))
        if raise_error is not None:
            raise raise_error
        return _Reply({"message": {"content": content}})
    monkeypatch.setattr(_ur, "urlopen", fake)


def _gateway_content() -> str:
    return json.dumps({"summary": "A file pretended to be a PDF.",
                       "action": "Delete it from Downloads."})


# ------------------------------------------------------------- hard pins

def test_defaults_pin_the_owner_gateway():
    assert explain.DEFAULTS["endpoint"] == "http://127.0.0.1:11600/api/chat"
    assert explain.DEFAULTS["model"] == "glm-5.3-flash:cloud"
    assert explain.DEFAULTS["enabled"] is True
    assert explain.DEFAULTS["per_hour"] == 3


def test_payload_is_small_local_and_think_false(monkeypatch):
    calls = []
    _install_reply(monkeypatch, calls, _gateway_content())
    note = explain.explain(_finding(), dict(explain.DEFAULTS),
                           _fresh_budget())
    url, payload = calls[0]
    assert url == explain.DEFAULTS["endpoint"]
    assert payload["model"] == "glm-5.3-flash:cloud"
    assert payload["stream"] is False and payload["think"] is False
    assert payload["options"]["num_predict"] == 512
    assert payload["options"]["temperature"] == 0.3
    assert payload["messages"][0]["role"] == "system"
    assert note["kind"] == "ai" and note["model"] == explain.DEFAULTS["model"]
    assert note["text"] == "A file pretended to be a PDF."


def test_only_finding_summary_fields_cross_the_boundary(monkeypatch):
    calls = []
    _install_reply(monkeypatch, calls, _gateway_content())
    sneaky = _finding()
    sneaky["evidence"] = [{"source": "events", "tool": "auditd",
                           "text": "RAW-EVENT-BODY should never travel",
                           "path": "/x" * 100, "url": "https://e/x"}]
    explain.explain(sneaky, dict(explain.DEFAULTS), _fresh_budget())
    _, payload = calls[0]
    user = payload["messages"][1]["content"]
    assert "RAW-EVENT-BODY" not in user and "auditd" not in user


# ------------------------------------------------------------- budget/cooldown

def test_disabled_or_over_budget_answers_without_calling(monkeypatch):
    calls = []
    _install_reply(monkeypatch, calls, _gateway_content())
    cfg = dict(explain.DEFAULTS)
    assert explain.explain(_finding(), {**cfg, "enabled": False},
                           _fresh_budget()) is None
    spent = {"window_start": explain._iso(), "used": 3, "fails": 0}
    assert explain.explain(_finding(), cfg, spent) is None
    assert calls == []  # never reached the gateway either time


def test_two_failures_arm_a_cooldown(monkeypatch):
    calls = []
    _install_reply(monkeypatch, calls, "{}",
                   raise_error=OSError("gateway down"))
    cfg = dict(explain.DEFAULTS)
    budget = _fresh_budget()
    assert explain.explain(_finding(), cfg, budget) is None
    assert budget["used"] == 1 and budget["fails"] == 1
    assert not budget.get("cooldown_until")
    assert explain.explain(_finding(), cfg, budget) is None
    assert budget.get("cooldown_until")
    # While cooling, no call is even attempted — the recompute happens
    # on the next call, so the flag flips exactly there.
    assert explain.explain(_finding(), cfg, budget) is None
    assert budget["cooling"] is True
    assert len(calls) == 2


def test_success_counts_and_resets_the_failure_streak(monkeypatch):
    calls = []
    cfg = dict(explain.DEFAULTS)
    budget = _fresh_budget()
    _install_reply(monkeypatch, calls, "not even json",
                   raise_error=None)
    # A malformed reply is a failure: used, but no cooldown yet.
    assert explain.explain(_finding(), cfg, budget) is None
    assert budget["fails"] == 1
    _install_reply(monkeypatch, calls, _gateway_content())
    note = explain.explain(_finding(), cfg, budget)
    assert note and note["kind"] == "ai"
    assert budget["used"] == 2 and budget["fails"] == 0
    assert not budget.get("cooling")


def test_budget_window_resets_after_an_hour():
    budget = {"window_start": "2020-01-01T00:00:00+00:00", "used": 3,
              "fails": 1}
    explain.budget_state(budget)
    assert budget["used"] == 0 and budget["fails"] == 0
    assert not budget["cooling"]


# ----------------------------------------------------------------- parse

def test_parse_handles_fences_prose_and_rejects_junk():
    good = '{"summary": "s", "action": "a"}'
    assert explain._parse("```json\n" + good + "\n```") == \
        {"summary": "s", "action": "a"}
    assert explain._parse("Sure: " + good + " hope it helps") == \
        {"summary": "s", "action": "a"}
    assert explain._parse("") is None
    assert explain._parse("no braces here") is None
    assert explain._parse("[1,2]") is None
    assert explain._parse('{"summary": "FINDING: echo", "action": "a"}') \
        is None
    assert explain._parse('{"summary": "   ", "action": "a"}') is None


def test_parse_caps_length_instead_of_rejecting():
    doc = {"summary": "s" * 500, "action": "a" * 400}
    parsed = explain._parse(json.dumps(doc))
    assert len(parsed["summary"]) == 400 and len(parsed["action"]) == 300


# ------------------------------------------------------------ notes/pointers

def test_rule_note_carries_the_deterministic_text():
    f = _finding()
    note = explain.rule_note(f)
    assert note["kind"] == "rule"
    assert note["text"] == f["what"] and note["hint"] == f["next"]
    assert note["finding_id"] == f["id"] and note["severity"] == "HIGH"
    # Unread semantics: string compare on ISO timestamps.
    assert explain.note_is_unread({"ts": "2026-01-02T00:00:00+00:00"}, "")
    assert explain.note_is_unread({"ts": "2026-01-02T00:00:00+00:00"},
                                  "2026-01-01T00:00:00+00:00")
    assert not explain.note_is_unread({"ts": "2026-01-01T00:00:00+00:00"},
                                      "2026-01-02T00:00:00+00:00")


def test_mark_read_preserves_unknown_keys(tmp_path):
    cfg_path = store.config_path(tmp_path)
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text(json.dumps({"read_until": "old", "custom": 5}))
    explain.mark_read(tmp_path, "2026-02-02T00:00:00+00:00")
    doc = json.loads(cfg_path.read_text())
    assert doc["read_until"] == "2026-02-02T00:00:00+00:00"
    assert doc["custom"] == 5
    # A missing config gains just the pointer.
    other = tmp_path / "fresh"
    other.mkdir()
    explain.mark_read(other, "2026-02-03T00:00:00+00:00")
    assert explain.read_pointer(other) == "2026-02-03T00:00:00+00:00"


def test_load_config_copies_only_typed_known_keys(tmp_path):
    cfg_path = store.config_path(tmp_path)
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text(json.dumps({
        "per_hour": 5, "enabled": False, "endpoint": "http://127.0.0.1:9/x",
        "model": "glm-5.2:cloud",
        "timeout": "120", "read_until": "z", "custom": {"a": 1}}))
    cfg = explain.load_config(tmp_path)
    assert cfg["per_hour"] == 5 and cfg["enabled"] is False
    assert cfg["endpoint"] == "http://127.0.0.1:9/x"
    assert cfg["model"] == "glm-5.2:cloud"
    # A wrong-typed override falls back to the default rather than through.
    assert cfg["timeout"] == explain.DEFAULTS["timeout"]
    # Unknown keys and the user's read pointer never ride along in the
    # AI config — the pointer has its own reader.
    assert "custom" not in cfg and "read_until" not in cfg