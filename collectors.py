from __future__ import annotations

import ctypes
import datetime as _dt
import errno
import hashlib
import os
import queue
import select
import subprocess
import threading

def _monotonic():
    import time
    return time.monotonic()

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200

_MASK = (IN_MODIFY | IN_ATTRIB | IN_MOVED_TO | IN_CREATE | IN_DELETE)

_libc = ctypes.CDLL(None, use_errno=True)

IN_NONBLOCK = os.O_NONBLOCK
_ANCHOR_KB = 4096            # tail-anchor window for truncate+rewrite races
TICK_S = 0.05                # event-poll tick (latency of inotify reads)
SYNC_S = 0.5                 # stat-sync interval (truncate blind window)
_event_fmt = "iIII"          # wd, mask, cookie, len
_event_size = ctypes.sizeof(ctypes.c_int32) * 3 + ctypes.sizeof(ctypes.c_uint32)


class Inotify:

    def __init__(self):
        self.fd = _libc.inotify_init1(IN_NONBLOCK)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")

    def add_watch(self, path):
        wd = _libc.inotify_add_watch(self.fd, path.encode(), _MASK)
        if wd < 0:
            return None
        return wd

    def rm_watch(self, wd):
        if wd is not None and wd >= 0:
            _libc.inotify_rm_watch(self.fd, wd)

    def events(self):
        try:
            ready, _, _ = select.select([self.fd], [], [], 0)
        except (OSError, ValueError):
            return
        if not ready:
            return
        try:
            data = os.read(self.fd, 65536)
        except OSError as e:
            if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise
            return
        i = 0
        while i + _event_size <= len(data):
            wd, mask, _cookie, name_len = struct_unpack_from(data, i)
            name = data[i + _event_size:i + _event_size + name_len]
            name = name.split(b"\x00")[0].decode("utf-8", "replace")
            yield wd, mask, name
            i += _event_size + name_len

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


def struct_unpack_from(data, offset):
    import struct
    return struct.unpack_from(_event_fmt, data, offset)


class BoundedQueue:

    def __init__(self, max_items: int = 5000):
        self.max_items = max_items
        self._q = queue.Queue(maxsize=max_items)
        self.dropped = 0
        self._lock = threading.Lock()

    def put_nowait(self, item, line=None):
        if line is not None:
            item = (item, line)
        with self._lock:
            while True:
                try:
                    self._q.put_nowait(item)
                    return
                except queue.Full:
                    try:
                        self._q.get_nowait()   # drop oldest
                        self.dropped += 1
                    except queue.Empty:
                        self.dropped += 1
                        return

    def drain(self, limit: int = 2000):
        out = []
        try:
            while len(out) < limit:
                out.append(self._q.get_nowait())
        except queue.Empty:
            pass
        return out

    def clear(self):
        self.drain()

    def depth(self):
        return self._q.qsize()


class FileTailer:

    def __init__(self, path, tool, callback, on_error=None, chunk=65536,
                 start_at_end=False):
        self.path = str(path)
        self.tool = tool
        self.callback = callback
        self.on_error = on_error or (lambda msg: None)
        self.chunk = chunk
        self.start_at_end = start_at_end   # prod daemon: skip history at start
        self._ino = None
        self._wd_file = None
        self._wd_parent = None
        self._fh = None
        self._pos = 0
        self._buffer = b""
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._trace = []        # bounded diagnostic ring (last 60 ops)
        self._trace_lock = threading.Lock()

    def _note(self, what):
        with self._trace_lock:
            self._trace.append(f"{_dt.time()} {what} pos={self._pos}")
            if len(self._trace) > 60:
                del self._trace[:len(self._trace) - 60]

    def start(self):
        self._ino = Inotify()
        parent = os.path.dirname(self.path) or "/"
        if os.path.isdir(parent):
            self._wd_parent = self._ino.add_watch(parent)
        self._open()
        self._thread = threading.Thread(target=self._run, name=f"tail:{self.tool}",
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._ino:
            self._ino.rm_watch(self._wd_file)
            self._ino.rm_watch(self._wd_parent)
            self._ino.close()
        try:
            if self._fh:
                self._fh.close()
        except OSError:
            pass

    def _open(self):
        try:
            self._fh = open(self.path, "rb")
            self._wd_file = self._ino.add_watch(self.path)
            self._last_stat = os.stat(self.path)
            self._digest = hashlib.sha256()    # content anchor: bytes read so far
            self._tail_bytes = b""             # last bytes read (for tail anchor)
            if self.start_at_end and self._pos == 0:
                self._pos = self._fh.seek(0, 2)
                self._seed_anchors()
            elif self._pos:                    # reopened after rotation → new file
                self._pos = 0
                self._fh.seek(0)
            else:
                self._fh.seek(0)
        except (OSError, FileNotFoundError):
            self._fh = None
            self._wd_file = None

    def _seed_anchors(self):
        try:
            self._digest = hashlib.sha256()
            pos = self._pos
            if pos <= _ANCHOR_KB:
                h = hashlib.sha256()
                with open(self.path, "rb") as probe:
                    h.update(probe.read(pos))
                self._digest = h
            with open(self.path, "rb") as probe:
                probe.seek(max(0, pos - _ANCHOR_KB))
                self._tail_bytes = probe.read(_ANCHOR_KB)
        except OSError:
            pass

    def _run(self):
        self._read_available()
        last_sync = 0.0
        while not self._stop.is_set():
            for wd, mask, name in self._ino.events():
                try:
                    self._handle(wd, mask, name)
                except OSError as e:
                    self.on_error(f"{self.tool}: {e}")
            now = _monotonic()
            if now - last_sync >= SYNC_S:
                self._read_available()
                last_sync = now
            self._stop.wait(TICK_S)

    def _handle(self, wd, mask, name):
        base = os.path.basename(self.path)
        if wd == self._wd_file and (mask & IN_MODIFY):
            self._read_available()
        elif wd == self._wd_file and (mask & IN_ATTRIB):
            self._check_truncate()
        elif (wd == self._wd_parent and (mask & (IN_MOVED_TO | IN_CREATE))
              and name == base):
            try:
                st_new = os.stat(self.path)
                same = (self._fh is not None and
                        os.fstat(self._fh.fileno()).st_ino == st_new.st_ino and
                        st_new.st_size >= self._pos)
            except OSError:
                same = False
            if not same:
                self._reopen_rotated()
        elif wd == self._wd_parent and (mask & IN_DELETE):
            self._fh = None

    def _read_available(self):
        if self._fh is None:
            try:
                self._open()
            except OSError:
                return
            if self._fh is None:
                return
        self._check_truncate()
        if self._fh is None:
            # _check_truncate may have torn the handle down (a rotate can
            # land between our open and its stat); the next event or the
            # periodic sync reopens — do not read from the dead handle
            return
        try:
            while True:
                data = self._fh.read(self.chunk)
                if data:
                    self._buffer += data
                    self._pos += len(data)
                    self._digest.update(data)
                    self._tail_bytes = (self._tail_bytes + data)[-_ANCHOR_KB:]
                if len(data) == self.chunk:
                    continue
                break
        except OSError as e:
            self.on_error(f"{self.tool}: read error {e}")
            self._fh = None
            return
        self._emit_buffer()

    def _check_truncate(self):
        if self._fh is None:
            return
        try:
            fst = os.fstat(self._fh.fileno())
            pst = os.stat(self.path)
        except OSError:
            self._fh = None
            return
        if (pst.st_dev, pst.st_ino) != (fst.st_dev, fst.st_ino):
            self._reopen_rotated()      # path now = different file
            return
        st = fst
        changed = self._last_stat is not None and \
            st.st_ctime_ns != self._last_stat.st_ctime_ns
        if st.st_size < self._pos:
            self._note(f"TRUNC-det size={st.st_size}")
            self._reset_for_truncate()
            self._last_stat = st
            return
        if st.st_size == self._pos and changed and self._pos > 0:
            pos = self._pos
            if pos <= _ANCHOR_KB:
                fresh = self._hash_first_bytes(pos)
                if fresh is not None and fresh != self._digest.hexdigest():
                    self._note("TRUNC-det window")
                    self._reset_for_truncate()
            else:
                try:
                    with open(self.path, "rb") as probe:
                        probe.seek(pos - _ANCHOR_KB)
                        actual = probe.read(_ANCHOR_KB)
                    if len(actual) == _ANCHOR_KB and \
                            self._tail_bytes is not None and \
                            actual != self._digest_tail():
                        self._note("TRUNC-det tail")
                        self._reset_for_truncate()
                except OSError:
                    pass
        self._last_stat = st

    def _digest_tail(self):
        h = hashlib.sha256()
        h.update(self._tail_bytes)
        return h.hexdigest()

    def _hash_first_bytes(self, upto):
        try:
            h = hashlib.sha256()
            with open(self.path, "rb") as probe:
                remaining = upto
                while remaining > 0:
                    b = probe.read(min(1 << 16, remaining))
                    if not b:
                        break
                    h.update(b)
                    remaining -= len(b)
            return h.hexdigest()
        except OSError:
            return None

    def _reset_for_truncate(self):
        self._note("RESET")
        self._pos = 0
        self._buffer = b""
        self._digest = hashlib.sha256()
        self._tail_bytes = b""
        try:
            self._fh.seek(0)
        except (OSError, ValueError):
            self._fh = None
            self._open()
    def _reopen_rotated(self):
        self._note("REOPEN")
        if self._wd_file is not None:
            self._ino.rm_watch(self._wd_file)
            self._wd_file = None
        try:
            if self._fh:
                self._fh.close()
        except OSError:
            pass
        self._fh = None
        self._pos = 0
        self._buffer = b""
        self._digest = hashlib.sha256()
        self._open()
        self._read_available()  # a recreate may already hold unread bytes

    def _emit_buffer(self):
        while True:
            nl = self._buffer.find(b"\n")
            if nl < 0:
                break
            line = self._buffer[:nl]
            self._buffer = self._buffer[nl + 1:]
            try:
                text = line.decode("utf-8", "replace")
            except UnicodeDecodeError:
                text = str(line)
            try:
                self.callback(self.tool, text)
            except Exception:          # callback must not kill the tailer
                pass


class JournalTailer:

    def __init__(self, tool, argline, callback, fake_cmd=None, line_filter=None):
        self.tool = tool
        self.argline = argline          # e.g. "-k -f -o cat" for ufw
        self.callback = callback
        self.fake_cmd = fake_cmd
        self.line_filter = tuple(line_filter or [])
        self._proc = None
        self._stop = threading.Event()
        self._thread = None

    def _passes(self, line: str) -> bool:
        if not self.line_filter:
            return True
        return any(k in line for k in self.line_filter)

    def start(self):
        self._thread = threading.Thread(target=self._run, name=f"journal:{self.tool}",
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _spawn(self):
        if self.fake_cmd is not None:
            return self.fake_cmd()
        return subprocess.Popen(
            ["journalctl"] + self.argline.split(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=1,
            universal_newlines=True)

    def _run(self):
        failures = 0
        while not self._stop.is_set():
            self._proc = self._spawn()
            if self._proc is None or not getattr(self._proc, "stdout", None):
                failures += 1
                self._stop.wait(min(30.0, 1.0 * 2 ** min(failures, 5)))
                continue
            got_line = False
            try:
                for line in self._proc.stdout:
                    got_line = True
                    if self._stop.is_set():
                        break
                    if not self._passes(line):
                        continue
                    try:
                        self.callback(self.tool, line.rstrip("\n"))
                    except Exception:
                        pass
            except (OSError, ValueError):
                pass
            finally:
                try:
                    self._proc.stdout.close()
                except (OSError, AttributeError):
                    pass
            if not got_line:
                failures += 1
            else:
                failures = 0
            if not self._stop.is_set():
                self._stop.wait(min(30.0, 1.0 * 2 ** min(failures, 5)))
