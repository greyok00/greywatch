# tests/test_assistant_live_model.py
"""Live GGUF smoke test — skipped unless a real model is present.

Loading a 1.7B on CPU costs seconds and RAM, so the suite only runs this
when asked: point it at any GGUF and set GW_LIVE_MODEL=1, e.g.

    GW_LIVE_MODEL=1 GREYWATCH_ASSISTANT_MODEL=/path/to/model.gguf \
        python3 -m pytest tests/test_assistant_live_model.py -q

Without the env var (or with no model) it skips, so CI and a docs-only
checkout stay fast.
"""
import os
import pathlib
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

pytestmark = pytest.mark.skipif(
    os.environ.get("GW_LIVE_MODEL") != "1",
    reason="live model check: set GW_LIVE_MODEL=1 to run")


def _model_path():
    env = os.environ.get("GREYWATCH_ASSISTANT_MODEL")
    if env:
        return pathlib.Path(env)
    from assistant.model import MODEL_FILENAME
    import gwpaths
    return gwpaths.data_dir() / "models" / MODEL_FILENAME


def test_live_model_answers_a_router_question_and_an_advice_question():
    path = _model_path()
    if not path.exists():
        pytest.skip(f"no GGUF at {path}")
    try:
        import llama_cpp  # noqa: F401
    except ImportError:
        pytest.skip("llama-cpp-python binding not installed")

    from assistant.llm import Llm
    llm = Llm(model_path=str(path))
    ready, done = {}, threading.Event()

    def cb(ok, err):
        ready["ok"], ready["err"] = ok, err or ""
        done.set()
    llm.start(cb)
    assert done.wait(120), "model never finished loading"
    assert ready["ok"], ready["err"]

    # Router: a small JSON slot, no thinking, no prose.
    routed = llm.ask_sync(
        "Question: what is the state of the firewall?\n"
        "Slots: overview, explain_event, tool_status, intent, summary.")
    assert routed.strip(), "empty router reply"
    assert "<thi" + "nk>" not in routed

    # Answer: grounded in the supplied pack, not invented.
    pack = ("Context: the firewall (ufw) is RED, not running.\n"
            "Recent events: none.\n"
            "Summarize in 2-3 plain sentences. If the pack lacks the "
            "answer, say so.\nquestion: is the firewall ok?")
    acc, hit = [], threading.Event()
    llm.ask_stream(pack, acc.append,
                   lambda full: hit.set(), lambda e: hit.set())
    assert hit.wait(120)
    text = "".join(acc).strip()
    assert text, "empty answer stream"
    assert "<thi" + "nk>" not in text
    low = text.lower()
    assert "firewall" in low or "ufw" in low
