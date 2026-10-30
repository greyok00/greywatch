# assistant/llm.py
"""The assistant's brain, loaded inside this process.

No server, no port: llama-cpp-python runs the model on CPU threads in a
worker thread. The binding import is optional by repo rule — without it
the chat still answers from templates (docs-only mode).

The model is a Qwen3-1.7B instruct GGUF (assistant/model.py). Qwen3 is a
hybrid-reasoning model, so every request disables thinking two ways: the
prompt carries "/no_think" and the stream drops any `` thinking...</think>``
block that still appears — otherwise a short answer budget is spent
reasoning instead of replying.
"""
from __future__ import annotations

import os
import pathlib
import threading

from assistant.model import NO_THINK

try:
    from llama_cpp import Llama
except ImportError:
    Llama = None

ROUTER_SYSTEM = (
    "You route questions for a local security app. Reply with ONLY a JSON "
    'object, nothing else: {"task": "<slot>", "tool": "<tool or empty>"}. '
    "Slots: overview (state of all protections) | explain_event (explain a "
    "recent alert) | tool_status (about one named tool) | "
    "intent (the user asks to change or act) — for the intent slot the "
    'JSON must include "action":"pause|resume|show|status|scan" | summary '
    "(anything else). "
    "For pause, resume and show, tool must be one of the listed tool "
    "names. For a scan, reply with "
    '{"task":"intent","action":"scan","tool":"<scan name>"}; tool must be '
    'one of the listed scan names, and "scan-all" when none is named.')

ANSWER_SYSTEM = (
    "You are the greywatch assistant. Obey three rules: (1) answer only "
    "from the supplied context pack and say when it lacks the answer; "
    "(2) propose state changes or scans only as a JSON intent like "
    '{"task":"intent","action":"<pause|resume|show|status|scan>",'
    '"tool":"<name>"}'
    " — never as shell or instructions; "
    "(3) be brief and plain.")


def default_threads() -> int:
    """CPU-only inference on a shared box: leave the other work breathing."""
    cores = os.cpu_count() or 4
    return max(2, min(8, cores - 2))


THINK_OPEN = "<" + "think" + ">"
THINK_CLOSE = "<" + "/think" + ">"


def strip_think(text: str) -> str:
    """Remove a complete or unterminated thinking block."""
    out, i = [], 0
    while True:
        start = text.find(THINK_OPEN, i)
        if start < 0:
            out.append(text[i:])
            break
        out.append(text[i:start])
        end = text.find(THINK_CLOSE, start)
        if end < 0:
            break                      # never closed: drop the rest
        i = end + len(THINK_CLOSE)
    return "".join(out)


class ThinkFilter:
    """Stream-side equivalent of strip_think.

    Tokens arrive in pieces, so the filter holds text only while it could
    still be the start of (or inside) a thinking block and passes
    everything else straight through.
    """

    def __init__(self):
        self._state = "start"          # start | inside | pass
        self._buf = ""
        self._started = False          # first visible character seen

    def _lead(self, text: str) -> str:
        """Drop blank lines before the answer starts.

        Qwen opens with whitespace — both before and after a thinking
        block — and those blank lines read as a gap at the top of the
        bubble.
        """
        if self._started:
            return text
        text = text.lstrip()
        if text:
            self._started = True
        return text

    def feed(self, tok: str) -> str:
        if self._state == "pass":
            return self._lead(tok)
        self._buf += tok
        if self._state == "start":
            lead = self._buf.lstrip()
            if THINK_OPEN.startswith(lead):
                return ""              # could still become the open tag
            if lead.startswith(THINK_OPEN):
                self._state = "inside"
                self._buf = lead[len(THINK_OPEN):]
                return self.feed("")
            self._state, out = "pass", self._buf
            self._buf = ""
            return self._lead(out)
        # inside
        end = self._buf.find(THINK_CLOSE)
        if end < 0:
            return ""
        rest = self._buf[end + len(THINK_CLOSE):]
        self._state, self._buf = "pass", ""
        return self._lead(rest)

    def flush(self) -> str:
        """End of stream: a bare '<think' prefix that never resolved is
        model noise, not an answer."""
        if self._state == "start":
            out, self._buf = self._buf.lstrip(), ""
            return "" if not out or out.startswith("<") else out
        self._buf = ""
        return ""


class Llm:
    def __init__(self, model_path: str, binding=None,
                 n_ctx: int = 4096, n_threads: int | None = None):
        self.model_path = model_path
        self._binding = binding          # tests inject fakes here
        self._n_ctx = n_ctx
        self._n_threads = default_threads() if n_threads is None else n_threads
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
                {"role": "user", "content": f"{prompt}\n\n{NO_THINK}"}]

    def _answer_messages(self, prompt: str) -> list[dict]:
        return [{"role": "system", "content": ANSWER_SYSTEM},
                {"role": "user", "content": f"{prompt}\n\n{NO_THINK}"}]

    def ask_sync(self, prompt: str, max_tokens: int = 48) -> str:
        with self._lock:
            if self._model is None:
                raise RuntimeError("assistant model not ready")
            out = self._model.create_chat_completion(
                messages=self._messages(prompt), max_tokens=max_tokens,
                temperature=0.2, repeat_penalty=1.05)
        return strip_think(
            out["choices"][0]["message"]["content"]).strip()

    def ask_stream(self, prompt: str, on_token, on_done, on_error,
                   max_tokens: int = 160) -> None:
        if self._model is None:
            on_error(RuntimeError("assistant model not ready"))
            return

        def work():
            try:
                acc, think = [], ThinkFilter()
                with self._lock:
                    stream = self._model.create_chat_completion(
                        messages=self._answer_messages(prompt),
                        max_tokens=max_tokens, stream=True,
                        temperature=0.2, repeat_penalty=1.15)
                    for part in stream:
                        tok = (part["choices"][0]["delta"].get("content")
                               or "")
                        if not tok:
                            continue
                        tok = think.feed(tok)
                        if tok:
                            acc.append(tok)
                            on_token(tok)
                tail = think.flush()
                if tail:
                    acc.append(tail)
                    on_token(tail)
                on_done("".join(acc))
            except Exception as e:                     # noqa: BLE001
                on_error(e)
        threading.Thread(target=work, daemon=True).start()

    def stop(self) -> None:
        with self._lock:
            self._model = None
