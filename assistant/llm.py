# assistant/llm.py
"""The assistant's brain, loaded inside this process.

No server, no port: llama-cpp-python runs the 360M model on CPU threads
in a worker thread. The binding import is optional by repo rule —
without it the chat still answers from templates (docs-only mode).
"""
from __future__ import annotations

import pathlib
import threading

try:
    from llama_cpp import Llama
except ImportError:
    Llama = None

ROUTER_SYSTEM = (
    "You route questions for a local security app. Reply with ONLY a JSON "
    'object, nothing else: {"task": "<slot>", "tool": "<tool or empty>"}. '
    "Slots: overview (state of all protections) | explain_event (explain a "
    "recent alert) | tool_status (about one named tool) | intent (the user "
    "asks to change or act: pause, resume, show) | summary (anything else). "
    "tool must be one of the listed tool names or empty.")

ANSWER_SYSTEM = (
    "You are the greywatch assistant. Obey three rules: (1) answer only "
    "from the supplied context pack and say when it lacks the answer; "
    "(2) propose state changes only as a JSON intent like "
    '{"task":"intent","tool":"<name>"} — never as shell or instructions; '
    "(3) be brief and plain.")


class Llm:
    def __init__(self, model_path: str, binding=None,
                 n_ctx: int = 4096, n_threads: int = 3):
        self.model_path = model_path
        self._binding = binding          # tests inject fakes here
        self._n_ctx, self._n_threads = n_ctx, n_threads
        self._model = None
        self._err = "not started"
        self._started = False
        self._lock = threading.Lock()

    def start(self, on_ready) -> None:
        if self._started:
            return
        self._started = True

        def work():
            try:
                if self._binding is not None:
                    self._model = self._binding()
                    self._err = ""
                    on_ready(True, "")
                    return
                if Llama is None:
                    self._err = ("llama-cpp-python not installed — "
                                 "chat runs in docs-only mode")
                elif not pathlib.Path(self.model_path).exists():
                    self._err = ("model file missing, run the installer — "
                                 "chat runs in docs-only mode")
                else:
                    self._model = Llama(model_path=self.model_path,
                                        n_ctx=self._n_ctx,
                                        n_threads=self._n_threads,
                                        verbose=False)
                    self._err = ""
                on_ready(self._model is not None, self._err)
            except Exception as e:                     # noqa: BLE001
                self._err = str(e)
                on_ready(False, self._err)
        threading.Thread(target=work, daemon=True).start()

    def is_ready(self) -> bool:
        return self._model is not None

    def _messages(self, prompt: str) -> list[dict]:
        return [{"role": "system", "content": ROUTER_SYSTEM},
                {"role": "user", "content": prompt}]

    def _answer_messages(self, prompt: str) -> list[dict]:
        return [{"role": "system", "content": ANSWER_SYSTEM},
                {"role": "user", "content": prompt}]

    def ask_sync(self, prompt: str, max_tokens: int = 48) -> str:
        with self._lock:
            if self._model is None:
                raise RuntimeError("assistant model not ready")
            out = self._model.create_chat_completion(
                messages=self._messages(prompt), max_tokens=max_tokens)
        return out["choices"][0]["message"]["content"].strip()

    def ask_stream(self, prompt: str, on_token, on_done, on_error,
                   max_tokens: int = 220) -> None:
        if self._model is None:
            on_error(RuntimeError("assistant model not ready"))
            return

        def work():
            try:
                acc = []
                with self._lock:
                    stream = self._model.create_chat_completion(
                        messages=self._answer_messages(prompt),
                        max_tokens=max_tokens, stream=True)
                    for part in stream:
                        tok = (part["choices"][0]["delta"].get("content")
                               or "")
                        if tok:
                            acc.append(tok)
                            on_token(tok)
                on_done("".join(acc))
            except Exception as e:                     # noqa: BLE001
                on_error(e)
        threading.Thread(target=work, daemon=True).start()

    def stop(self) -> None:
        with self._lock:
            self._model = None