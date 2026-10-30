# tests/test_assistant_llm.py
import pathlib
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from assistant.llm import ANSWER_SYSTEM, THINK_CLOSE, THINK_OPEN, Llm


class FakeModel:
    def __init__(self, replies):
        self.replies = list(replies)

    def create_chat_completion(self, messages, max_tokens=None, stream=False,
                               **_ignored):
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


def test_live_generation_is_tamed(tmp_path):
    """The 360M model looped stock phrases at default sampling (0.8, no
    repeat penalty — 'the answer is:' dead ends). Router and answers run
    cool and penalised now."""
    class Cap:
        def __init__(self):
            self.kw = {}

        def create_chat_completion(self, **kw):
            self.kw = dict(kw)
            if kw.get("stream"):
                return ([{"choices": [{"delta": {"content": "a"}}]},
                         {"choices": [{"delta": {}}]}])
            return {"choices": [{"message": {"content": "{}"}}]}

    cap = Cap()
    llm = Llm(model_path=str(tmp_path / "x.gguf"),
              binding=lambda *a, **k: cap)
    _wait_ready(llm)
    llm.ask_sync("route me")
    assert cap.kw["temperature"] == 0.2
    assert cap.kw["repeat_penalty"] == 1.05
    got, done = [], threading.Event()
    llm.ask_stream("summarize", lambda t: got.append(t),
                   lambda full: done.set(), lambda e: done.set())
    assert done.wait(5.0)
    assert "".join(got) == "a"
    assert cap.kw["stream"] is True
    assert cap.kw["temperature"] == 0.2
    assert cap.kw["repeat_penalty"] == 1.15
    assert cap.kw["max_tokens"] == 160   # 1.7B needs room for a real sentence


# ---- Qwen3: CPU threads, thinking off, stream-side think filter -----------

def test_default_threads_leaves_headroom_on_a_shared_box():
    from assistant.llm import default_threads
    n = default_threads()
    assert 2 <= n <= 8


def test_both_prompts_carry_no_think(tmp_path):
    seen = []

    class Rec(FakeModel):
        def create_chat_completion(self, messages, **kw):
            seen.append(messages)
            return super().create_chat_completion(messages, **kw)
    llm = Llm(model_path="x", binding=lambda *a, **k: Rec(["ok", "ok"]))
    _wait_ready(llm)
    llm.ask_sync("route")
    hit = threading.Event()
    llm.ask_stream("answer", on_token=lambda t: None,
                   on_done=lambda f: hit.set(),
                   on_error=lambda e: hit.set())
    assert hit.wait(5.0)
    assert all(m[-1]["content"].endswith("/no_think") for m in seen)


def test_sync_strips_a_thinking_block():
    llm = Llm(model_path="x", binding=lambda *a, **k: FakeModel([
        "<thi" + "nk>step by step</thi" + "nk>The firewall is running."]))
    _wait_ready(llm)
    assert llm.ask_sync("q") == "The firewall is running."


def test_stream_never_emits_thinking_tokens():
    text = "<thi" + "nk>hidden reasoning</thi" + "nk>Visible answer."
    llm = Llm(model_path="x", binding=lambda *a, **k: FakeModel([text]))
    _wait_ready(llm)
    tokens, hit, full = [], threading.Event(), {}
    llm.ask_stream("q", on_token=tokens.append,
                   on_done=lambda f: (full.__setitem__("done", f), hit.set()),
                   on_error=lambda e: hit.set())
    assert hit.wait(5.0)
    out = "".join(tokens)
    assert out == "Visible answer."
    assert full["done"] == "Visible answer."


def test_stream_think_filter_holds_partial_tags_across_tokens():
    from assistant.llm import ThinkFilter
    f = ThinkFilter()
    out = "".join(f.feed(t) for t in ["<th", "ink>", "secret", "</thi",
                                      "nk>", "H", "i"])
    assert out == "Hi"


def test_stream_drops_leading_blank_lines():
    from assistant.llm import ThinkFilter
    f = ThinkFilter()
    out = "".join(f.feed(t) for t in ["\n", "\n", "First line.\n", "Second."])
    assert out == "First line.\nSecond."


def test_stream_drops_blank_lines_after_a_think_block():
    from assistant.llm import ThinkFilter
    f = ThinkFilter()
    out = "".join(f.feed(t) for t in [THINK_OPEN, "why", THINK_CLOSE,
                                      "\n", "\n", "Answer."])
    assert out == "Answer."


def test_stream_keeps_blank_lines_inside_the_answer():
    from assistant.llm import ThinkFilter
    f = ThinkFilter()
    assert "".join(f.feed(t) for t in ["Hi.\n", "\nNext."]) == "Hi.\n\nNext."


def test_stream_of_only_whitespace_flushes_to_nothing():
    from assistant.llm import ThinkFilter
    f = ThinkFilter()
    assert "".join(f.feed(t) for t in ["\n", "  "]) == ""
    assert f.flush() == ""


def test_n_threads_can_be_pinned_for_tests():
    llm = Llm(model_path="x", n_threads=3)
    assert llm._n_threads == 3


def test_model_constant_is_the_qwen3_file():
    from assistant.model import MODEL_FILENAME, MODEL_URL, MODEL_MIN_BYTES
    assert MODEL_FILENAME == "Qwen3-1.7B-Q4_K_M.gguf"
    assert MODEL_URL.endswith("/" + MODEL_FILENAME)
    assert MODEL_MIN_BYTES < 1_107_409_472
