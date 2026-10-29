# assistant/model.py
"""Which GGUF the assistant loads — one definition, two readers.

The installer fetches this file; the window loads it. They used to spell
the filename out separately, so changing the model meant editing two
places and a stale copy surfaced as a silent docs-only chat.

The owner's verdict on the 360M was "it needs more power to it"; this is
a 1.7B instruct model, CPU-only (the GPU belongs to cortexagent), quantised
to Q4_K_M so it fits in ~1.1 GB of file and ~1.3 GB of RAM.
"""
from __future__ import annotations

MODEL_FILENAME = "Qwen3-1.7B-Q4_K_M.gguf"
MODEL_URL = ("https://huggingface.co/unsloth/Qwen3-1.7B-GGUF/resolve/main/"
             "Qwen3-1.7B-Q4_K_M.gguf")
# The real artifact is 1,107,409,472 bytes. The floor only has to reject a
# truncated download, so it sits well below that.
MODEL_MIN_BYTES = 900 * 1024 * 1024
# Qwen3 is a hybrid-reasoning model: without this it "thinks" first and
# burns the whole token budget before answering.
NO_THINK = "/no_think"
