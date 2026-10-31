from __future__ import annotations

import time


class AskGate:
    """One prompt per destination per window; unanswered prompts take the
    configured headless verdict rather than hanging the serial engine."""

    def __init__(self, headless: str, timeout: float = 30.0,
                 window: float = 300.0, ask=None, clock=time.monotonic):
        self.headless = ("allow-once" if headless == "allow-once"
                         else "deny-once")
        self.timeout = max(5.0, float(timeout))
        self.window = max(0.0, float(window))
        self._ask = ask
        self.clock = clock
        self._seen: dict[str, tuple[float, tuple]] = {}

    def _fallback(self):
        return (("allow" if self.headless == "allow-once" else "deny"),
                "once", None)

    def ask(self, spec: dict):
        """Verdict for one connection: rules have already been evaluated.

        Repeat questions about the same destination IP (ports vary per
        connection) reuse the previous answer inside the window, so a
        random address cannot bombard the owner with prompts.
        """
        dst = str(spec.get("dst_ip") or "")
        now = self.clock()
        if dst and dst in self._seen:
            at, verdict = self._seen[dst]
            if now - at <= self.window:
                return verdict
        verdict = None
        if self._ask is not None:
            try:
                verdict = self._ask(spec)
            except Exception:          # noqa: BLE001 - fall back, never hang
                verdict = None
        if not verdict:
            verdict = self._fallback()
        if dst:
            self._seen[dst] = (now, verdict)
        return verdict
