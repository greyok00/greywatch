"""T3: collectors — tailing, rotation, truncation, rediscovery, stubs, queue."""
import os
import time
import threading

import pytest

from collectors import BoundedQueue, FileTailer, JournalTailer

POLL = 0.05          # tailer tick
WAIT = 1.2           # generous wall for kernel events to land


class Sink:
    def __init__(self):
        self.lines = []
        self.lock = threading.Lock()

    def callback(self, tool, line):
        with self.lock:
            self.lines.append((tool, line.rstrip("\n")))

    def tools(self):
        with self.lock:
            return sorted({t for t, _ in self.lines})


def wait_for(fn, timeout=WAIT):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return True
        time.sleep(POLL)
    return False


def make_tailer(tmp_path, name, sink):
    path = tmp_path / name
    t = FileTailer(str(path), name, sink.callback, on_error=lambda _m: None)
    t.start()
    return t, path


def test_bounded_queue_newest_wins_with_counter():
    q = BoundedQueue(max_items=3)
    for i in range(5):
        q.put_nowait(i)
    assert q.drain() == [2, 3, 4]          # oldest two dropped
    assert q.dropped == 2


def test_file_tailer_sees_appends(tmp_path):
    sink = Sink()
    t, path = make_tailer(tmp_path, "app.log", sink)
    try:
        with open(path, "a") as f:
            f.write("l1\nl2\nl3\n")
        assert wait_for(lambda: len(sink.lines) >= 3)
        assert [l for _t, l in sink.lines] == ["l1", "l2", "l3"]
    finally:
        t.stop()


def test_file_tailer_absent_then_created(tmp_path):
    sink = Sink()
    t, path = make_tailer(tmp_path, "late.log", sink)
    try:
        assert wait_for(lambda: True)      # let first read cycle pass
        with open(path, "a") as f:
            f.write("born\n")
        assert wait_for(lambda: sink.lines)
    finally:
        t.stop()


def test_file_tailer_truncate_resume_no_loss(tmp_path):
    sink = Sink()
    t, path = make_tailer(tmp_path, "trunc.log", sink)
    try:
        with open(path, "a") as f:
            f.write("a\nb\n")
        assert wait_for(lambda: len(sink.lines) == 2)
        os.truncate(path, 0)               # truncate → re-read from 0
        assert wait_for(lambda: True)
        with open(path, "a") as f:
            f.write("c\n")
        assert wait_for(lambda: [l for _t, l in sink.lines].count("c") >= 1)
        # checksum: every non-empty read line count matches 2 + re-read + c
        body = [l for _t, l in sink.lines]
        assert body.count("a") == 1 and body.count("b") == 1 and body.count("c") == 1
    finally:
        t.stop()


def test_file_tailer_truncate_same_length_rewrite(tmp_path):
    """Regression: truncate + immediate SAME-LENGTH rewrite must not stall
    the tailer (G2.3 race — pos==size with stale bytes)."""
    sink = Sink()
    t, path = make_tailer(tmp_path, "same.log", sink)
    try:
        with open(path, "a") as f:
            f.write("aaaa\nbbbb\n")     # two 5-byte lines
        assert wait_for(lambda: len(sink.lines) == 2)
        os.truncate(path, 0)
        with open(path, "a") as f:      # same length, new content
            f.write("cccc\ndddd\n")
        assert wait_for(lambda: [l for _t, l in sink.lines].count("cccc") >= 1)
        body = [l for _t, l in sink.lines]
        assert body.count("cccc") == 1 and body.count("dddd") == 1
    finally:
        t.stop()


def test_file_tailer_rotation_follows(tmp_path):
    sink = Sink()
    t, path = make_tailer(tmp_path, "rot.log", sink)
    try:
        with open(path, "a") as f:
            f.write("old-1\n")
        assert wait_for(lambda: sink.lines)
        os.rename(path, tmp_path / "rot.log.1")   # rotate away → not followed
        with open(path, "a") as f:
            f.write("new-1\n")                    # recreate same basename
        assert wait_for(lambda: any(l == "new-1" for _t, l in sink.lines))
        body = [l for _t, l in sink.lines]
        assert body.count("old-1") == 1 and body.count("new-1") == 1
    finally:
        t.stop()


def test_file_tailer_delete_and_recreate(tmp_path):
    sink = Sink()
    t, path = make_tailer(tmp_path, "gone.log", sink)
    try:
        with open(path, "a") as f:
            f.write("v1\n")
        assert wait_for(lambda: sink.lines)
        os.remove(path)
        assert wait_for(lambda: True)
        with open(path, "a") as f:
            f.write("v2\n")
        assert wait_for(lambda: any(l == "v2" for _t, l in sink.lines))
    finally:
        t.stop()


def test_journal_tailer_stub(tmp_path):
    """Parameterized journal follower with an injected fake reader."""
    sink = Sink()
    lines = ["journal-line-1", "journal-line-2"]

    class FakeProc:
        stdout = iter(lines)

        def close(self):    # matches JournalTailer cleanup, not required
            pass

    t = JournalTailer("ufw", "-k -f -o cat", sink.callback, fake_cmd=FakeProc)
    t.start()
    t.stop()
    assert [l for _t, l in sink.lines] == ["journal-line-1", "journal-line-2"]
    assert sink.tools() == ["ufw"]


def test_tailer_survives_callback_exception(tmp_path):
    """A throw inside the callback must not kill the tailer (never-raise L1)."""
    sink = Sink()

    def bad_callback(tool, line):
        sink.lines.append((tool, line))
        raise RuntimeError("boom")

    t, path = make_tailer(tmp_path, "boom.log", __import__("types").SimpleNamespace(
        callback=bad_callback, lines=sink.lines, lock=sink.lock))
    try:
        with open(path, "a") as f:
            f.write("x1\nx2\n")
        assert wait_for(lambda: len(sink.lines) >= 2)
    finally:
        t.stop()