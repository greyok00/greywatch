from __future__ import annotations

import time


class AskGate:
    """One prompt per destination per window; unanswered prompts take the
    configured headless verdict rather than hanging the serial engine."""

    SEEN_CAP = 512

    def __init__(self, headless: str, window: float = 300.0,
                 ask=None, clock=time.monotonic):
        self.headless = ("allow-once" if headless == "allow-once"
                         else "deny-once")
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
        random address cannot bombard the desktop user with prompts.
        """
        dst = str(spec.get("dst_ip") or "")
        # A prompt whose 5-tuple carries no address (a connection the
        # engine could not attribute) still deserves the one-per-window
        # discipline: key that shape on the attributes it has, or every
        # such ask re-waits the full dialog timeout with no memory
        # (round-3 symbolic audit R13).
        key = dst or "|".join(str(spec.get(k) or "") for k in
                              ("app_name", "pid", "dst_port", "protocol"))
        now = self.clock()
        if key and key in self._seen:
            at, verdict = self._seen[key]
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
        if key:
            if len(self._seen) >= self.SEEN_CAP:
                # dict insertion order: the first key is the oldest
                # decision; dropping it keeps the map bounded for a scan
                # that walks thousands of distinct destinations.
                self._seen.pop(next(iter(self._seen)), None)
            self._seen[key] = (now, verdict)
        return verdict
