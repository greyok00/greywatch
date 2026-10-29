# tests/test_assistant_llm.py
import pathlib
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from assistant.llm import ANSWER_SYSTEM, Llm


class FakeModel:
    def __init__(self, replies):
        self.replies = list(replies)

    def create_chat_completion(self, messages, max_tokens=None, stream=False):
        text = self.replies.pop(0) if self.replies else "ok"
        if not stream:
            return {"choices": [{"message": {"content": text}}]}
        return [{"choices": [{"delta": {"content": c}}]}
                for c in text] + [{"choices": [{"delta": {}}]}]


def _wait_ready(llm, want_ok=True, timeout=5.0):
    """start() runs on a worker thread — wait for the callback."""
    got, done = {}, threading.Event()

    def cb(ok, err):
        got["ok"], got["err"] = ok, err or ""
        done.set()
    llm.start(cb)
    assert done.wait(timeout), "loader thread never called back"
    assert got["ok"] is want_ok, got["err"]
    return got


def test_ready_with_injected_binding(tmp_path):
    model = FakeModel(["hello world", "hello world"])
    llm = Llm(model_path=str(tmp_path / "x.gguf"),
              binding=lambda *a, **k: model)
    _wait_ready(llm)
    assert llm.is_ready()
    assert llm.ask_sync("route this") == "hello world"

    tokens, done, hit = [], {}, threading.Event()
    llm.ask_stream("summarize", on_token=tokens.append,
                   on_done=lambda full: (done.__setitem__("done", full),
                                         hit.set()),
                   on_error=lambda e: hit.set())
    assert hit.wait(5.0)
    assert "".join(tokens) == "hello world"
    assert done["done"] == "hello world"


def test_missing_binding_and_file_is_docs_only(tmp_path):
    llm = Llm(model_path=str(tmp_path / "absent.gguf"))
    got = _wait_ready(llm, want_ok=False)
    assert not llm.is_ready()
    assert "docs-only" in got["err"]


def test_answer_system_carries_the_three_hard_rules():
    low = ANSWER_SYSTEM.lower()
    assert "pack" in low and "json intent" in low


def test_error_path_reaches_on_error(tmp_path):
    class Boom(FakeModel):
        def create_chat_completion(self, *a, **k):
            raise RuntimeError("kaboom")
    llm = Llm(model_path="x", binding=lambda *a, **k: Boom([]))
    _wait_ready(llm)
    errors, hit = [], threading.Event()
    llm.ask_stream("x", on_token=lambda t: None, on_done=lambda f: None,
                   on_error=lambda e: (errors.append(e), hit.set()))
    assert hit.wait(5.0)
    assert "kaboom" in str(errors[0])


def test_ask_sync_before_start_raises_runtimeerror():
    llm = Llm(model_path="x", binding=lambda *a, **k: FakeModel([]))
    with pytest.raises(RuntimeError, match="not ready"):
        llm.ask_sync("hi")


def test_stop_makes_ask_sync_raise_runtimeerror(tmp_path):
    model = FakeModel(["hello world", "hello world"])
    llm = Llm(model_path=str(tmp_path / "x.gguf"),
              binding=lambda *a, **k: model)
    _wait_ready(llm)
    llm.stop()
    with pytest.raises(RuntimeError, match="not ready"):
        llm.ask_sync("hi")


def test_start_twice_fires_on_ready_once(tmp_path):
    model = FakeModel(["hello world", "hello world"])
    llm = Llm(model_path=str(tmp_path / "x.gguf"),
              binding=lambda *a, **k: model)
    calls, done = [], threading.Event()

    def cb(ok, err):
        calls.append((ok, err or ""))
        done.set()
    llm.start(cb)
    assert done.wait(5.0), "loader thread never called back"
    llm.start(cb)                       # second start spawns nothing
    assert llm.is_ready()
    assert calls == [(True, "")]
    assert len(calls) == 1

def test_prompts_carry_the_action_key_contract():
    from assistant.llm import ROUTER_SYSTEM
    assert '"action"' in ROUTER_SYSTEM and '"action"' in ANSWER_SYSTEM
