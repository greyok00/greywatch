"""Shutdown must be bounded and must not leave tailer children behind.

Root cause (measured 2026-11-13): JournalTailer.stop() joined the reader
thread BEFORE killing its journalctl child. The thread is blocked inside
`for line in proc.stdout`, so every tailer burned the full 2 s join
timeout and only then terminated the child: four tailers put an 8 s
floor under any stop. Separately, run_forever() exited without stopping
its live tailers at all, orphaning four journalctl processes.
"""
import threading
import time

from collectors import JournalTailer


class _BlockingProc:
    """A child that only unblocks when terminated, like journalctl -f.

    Iterating the process blocks (that is what the tailer thread does);
    terminate() releases it, exactly as SIGTERM does to journalctl.
    """

    def __init__(self):
        self._terminated = threading.Event()
        self._dead = threading.Event()
        self.stdout = self          # `for line in proc.stdout` iterates this

    def __iter__(self):
        self._terminated.wait()
        self._dead.set()
        return iter(())

    def terminate(self):
        self._terminated.set()

    def kill(self):
        self._terminated.set()

    def wait(self, timeout=None):
        return 0 if self._dead.wait(timeout) else 0

    def poll(self):
        return 0 if self._dead.is_set() else None


def test_journal_tailer_stop_is_bounded_and_kills_the_child():
    proc = _BlockingProc()
    t = JournalTailer("ufw", "-k -f", lambda *a: None)
    t._proc = proc
    t._thread = threading.Thread(target=lambda: list(proc.stdout), daemon=True)
    t._thread.start()
    time.sleep(0.05)                # let the reader block on the child
    t0 = time.monotonic()
    t.stop()
    elapsed = time.monotonic() - t0
    assert elapsed < 0.6, f"stop took {elapsed:.2f}s; child was not killed first"
    assert t._proc is None


def _fake_tailer():
    stopped = threading.Event()

    class T:
        tool = "fake"

        def start(self):
            pass

        def stop(self):
            stopped.set()
    return T(), stopped


def test_run_forever_stops_its_live_tailers(tmp_path):
    import greywatch_daemon as G

    d = G.Daemon(str(tmp_path))
    d.write_status = lambda *a, **k: {}
    d._build_baseline_async = lambda: None
    d.stop_appfw = lambda: None
    tailers = [_fake_tailer() for _ in range(4)]
    stop = threading.Event()
    stop.set()                      # leave the loop on the first check
    d.run_forever(tailers=[t for t, _ in tailers], stop=stop)
    for _t, stopped in tailers:
        assert stopped.is_set(), "run_forever exited without stopping a tailer"
    assert d._closing is True
