"""appfw.engine — the interception engine (native transport, task #13).

The queue-111 transport is the COMPILED C worker (`appfw/bin/nfq_worker`,
source appfw/nfq_worker.c): the python3-netfilterqueue binding could not
land verdicts for TCP new-connection traffic on this stack (queue_total
built while "allow" decisions streamed — HELP/nftables/nfqueue.md). The
engine keeps rules, policy, resolve and UI; ONLY the netlink transport
moved to C:

  worker → engine : dgram /run/greywatch/nfq_events.sock   ("PKT id proto src sport dst dport")
  engine → worker : dgram /run/greywatch/nfq_worker.sock   ("ALLOW id" / "DROP id")

Worker contract (in C, unforgeable from Python): hold each packet ≤250 ms,
fail-open ACCEPT on timeout or overflow; signals accept everything.

Invariants (owner, unchanged): every queue rule carries `bypass`; arming is
the owner switch (data/appfw/enable.json, atomic, corrupt ⇒ OFF); DNS and
loopback are kernel-exempted before the queue (the two outage lessons);
fail-open on every error path.
"""
from __future__ import annotations

import json
import os
import time
import pathlib
import socket
import subprocess
import threading

from . import config
from .base import Conn
from .policy import Policy, decide
from .resolve import Resolver
from .rules import RuleStore, rule_from_decision

QUEUE_NUM = 111
NFT_TABLE = "greywatch_appfw"
ENGINE_BIN = pathlib.Path(__file__).resolve().parent / "bin" / "nfq_worker"
WORKER_SRC = pathlib.Path(__file__).resolve().parent / "nfq_worker.c"


def enable_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "appfw" / "enable.json"


def read_enabled(data_dir) -> bool:
    """Owner switch: OFF by default. Anything unreadable counts as OFF."""
    try:
        doc = json.loads(enable_path(data_dir).read_text())
        return bool(doc.get("enabled"))
    except (OSError, ValueError, AttributeError):
        return False


def write_enabled(data_dir, enabled: bool) -> None:
    """Atomic + fsync (P0-a): a mid-write kill leaves the prior state."""
    from .atomicio import write_json_atomic
    path = enable_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(path, {"enabled": bool(enabled)})


class Engine:
    """Owns the transport + enforcement. One instance per suite — the root
    daemon runs it; nothing else may install the table."""

    def __init__(self, data_dir, on_event=None, trust_list=None,
                 blocklist=None, ask=None, worker_bin=None,
                 worker_src=None, socket_dir=None,
                 proc_root: str = "/proc"):
        self.data_dir = pathlib.Path(data_dir)
        self.store = RuleStore(self.data_dir / "appfw" / "rules")
        self.store.reload()
        self.policy = Policy(self.data_dir, trust_list=trust_list,
                             blocklist=blocklist)
        self.resolver = Resolver(proc_root)
        self.on_event = on_event or (lambda text: None)
        self.ask = ask
        self._worker_bin = pathlib.Path(worker_bin or ENGINE_BIN)
        self._worker_src = pathlib.Path(worker_src or WORKER_SRC)
        self._socket_dir = str(socket_dir or "/run/greywatch")
        self._events_path = os.path.join(self._socket_dir, "nfq_events.sock")
        self._control_path = os.path.join(self._socket_dir, "nfq_worker.sock")
        self._events_sock = None
        self._proc = None
        self._reader = None
        self._cfg_mtime = 0.0
        self.running = False
        self._stop = threading.Event()
        # fail-open watchdog (2026-10-25 lockup): if the worker stops reading
        # our verdicts, the send queue grows; we tear the queue down rather
        # than black-hole traffic. Never trust a single health signal.
        self._ctl_sock = None
        self._stall_since = 0.0
        self._watchdog_thread = None
        # event-log throttle: a connection storm must not fill the daemon's
        # 200 MB cap with one event per SYN (797k dropped in this outage).
        self._log_last = 0.0
        self._log_suppressed = 0

    # ── lifecycle ────────────────────────────────────────────────────────
    def start(self) -> bool:
        if self.running:
            return True
        if not read_enabled(self.data_dir):
            return False
        try:
            self.store.reload()
            self.store.session_reset()   # 'until restart' dies at boot, by design
        except Exception:
            pass
        self._cfg_mtime = config.mtime(self.data_dir)
        if self._install_nft():
            try:
                self._bind_worker()
            except Exception as e:
                self._remove_nft()
                self.on_event(f"appfw engine failed to start worker: {e}")
                return False
        else:
            self.on_event("appfw engine: nftables install failed — OFF")
            return False
        self.running = True
        self._stop.clear()
        self._stall_since = 0.0
        self._watchdog_thread = threading.Thread(
            target=self._watchdog, daemon=True, name="appfw-failopen-watchdog")
        self._watchdog_thread.start()
        self.on_event("appfw engine: running "
                      f"(queue {config.load(self.data_dir).get('nfqueue_num')}, "
                      f"worker {self._worker_bin.name})")
        return True

    def stop(self) -> None:
        self._stop.set()
        self.running = False
        try:
            if self._proc is not None and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
        except Exception:
            pass
        self._proc = None
        try:
            if self._events_sock is not None:
                self._events_sock.close()
        except Exception:
            pass
        self._events_sock = None
        reader = getattr(self, "_reader", None)
        if reader is not None and reader.is_alive():
            reader.join(timeout=0.5)   # drained, not abandoned mid-recvfrom
        self._reader = None
        for path in (self._events_path, self._control_path):
            try:
                pathlib.Path(path).unlink(missing_ok=True)
            except OSError:
                pass
        self._remove_nft()
        self.on_event("appfw engine: stopped")

    # ── transport: nft + worker ──────────────────────────────────────────
    def _install_nft(self) -> bool:
        script = config.build_ruleset(config.load(self.data_dir))
        run = subprocess.run(["nft", "-f", "-"], input=script,
                             capture_output=True, text=True, timeout=10)
        if run.returncode == 0:
            return True
        subprocess.run(["nft", "-f", "-"],
                       input=f"delete table inet {NFT_TABLE}\n",
                       capture_output=True, text=True, timeout=10)
        second = subprocess.run(["nft", "-f", "-"], input=script,
                                capture_output=True, text=True, timeout=10)
        return second.returncode == 0

    def _remove_nft(self) -> None:
        subprocess.run(["nft", "-f", "-"],
                       input=f"delete table inet {NFT_TABLE}\n",
                       capture_output=True, text=True, timeout=10)

    def _ensure_worker_binary(self) -> bool:
        if os.access(self._worker_bin, os.X_OK):
            return True
        try:
            gcc = subprocess.run(
                ["gcc", "-O2", "-Wall", "-o", str(self._worker_bin),
                 str(self._worker_src), "-lnetfilter_queue"],
                capture_output=True, text=True, timeout=60)
        except Exception:
            gcc = None
        return bool(gcc and gcc.returncode == 0
                    and os.access(self._worker_bin, os.X_OK))

    def _bind_worker(self) -> None:
        if not self._ensure_worker_binary():
            raise RuntimeError("nfq worker binary missing and gcc build "
                               "failed (engine refuses to arm half-broken)")
        # audit #3: a prior SIGKILLed daemon leaves an ORPHAN worker bound to
        # queue 111; a second worker can then never create_queue. Reap any
        # worker bound to OUR binary before spawning the replacement.
        try:
            subprocess.run(["pkill", "-f", str(self._worker_bin)],
                           capture_output=True, timeout=5)
            time.sleep(0.5)
        except Exception:
            pass
        for path in (self._events_path, self._control_path):
            pathlib.Path(path).unlink(missing_ok=True)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if self._events_path.startswith("/run/"):
            os.makedirs(self._socket_dir, exist_ok=True)
        sock.bind(self._events_path)
        self._events_sock = sock
        env = dict(os.environ,
                   NFQ_CONTROL_PATH=self._control_path,
                   NFQ_EVENTS_PATH=self._events_path)
        try:
            self._proc = subprocess.Popen(
            [str(self._worker_bin)], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise RuntimeError(f'worker spawn failed: {e!r}')
        if self._proc.poll() is not None:
            raise RuntimeError("worker exited immediately")
        self._reader = threading.Thread(target=self._recv_loop, daemon=True,
                                        name="appfw-worker-reader")
        self._reader.start()

        # audit #7: worker death must flip running=False (it never did — the
        # engine reported "running" while enforcement was already gone).
        def _monitor(worker_spawn=self._proc):
            try:
                worker_spawn.wait(timeout=86400)
            except Exception:
                pass
            else:
                self.on_event("appfw worker exited — enforcement OFF")
                self.running = False
        threading.Thread(target=_monitor, daemon=True,
                         name="appfw-worker-monitor").start()

    # ── the decision half (Python stays the policy brain) ────────────────
    def _recv_loop(self) -> None:
        """PKT line → resolve → decide → persist `always` rules → verdict
        back to the worker. Never raises; the worker's own 250 ms sweep is
        the fail-open if this thread dies."""
        ctl = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        # Non-blocking verdict lane (2026-10-25 deadlock): if the worker is
        # briefly behind, the send must fail fast, not freeze this thread.
        # The worker's 250 ms sweep ACCEPTs the packet — fail-open.
        ctl.setblocking(False)
        self._ctl_sock = ctl
        while not self._stop.is_set():
            try:
                data, _ = self._events_sock.recvfrom(512)
            except OSError:
                break
            line = data.decode("utf-8", "replace").strip()
            if not line.startswith("PKT "):
                continue
            try:
                self._decide_line(line, ctl)
            except Exception as e:            # fail-open per packet
                try:
                    ctl.sendto(f"ALLOW {line.split()[1]}".encode(),
                               self._control_path)
                except Exception:
                    pass
                self.on_event(f"appfw packet error — {e}")

    def _watchdog(self) -> None:
        """Hard fail-open: a stalled worker must never black-hole traffic.

        SIOCOUTQ on the verdict socket is bytes the peer has not read. A
        healthy worker drains it every loop; >64 KB for 2 s means it is
        wedged or gone. Tear the nft table down (no queue ⇒ traffic flows)
        rather than waiting for recovery or trusting one health signal."""
        q_ioctl = getattr(socket, "SIOCOUTQ", 0x5411)
        while not self._stop.wait(2.0):
            if not self.running:
                return
            try:
                if self._proc is None or self._proc.poll() is not None:
                    self.on_event("appfw watchdog: worker gone — FAIL-OPEN")
                    self.stop()
                    return
                q = 0
                if self._ctl_sock is not None:
                    q = self._ctl_sock.getsockopt(socket.SOL_SOCKET, q_ioctl)
            except OSError:
                q = 0
            if q > 65536:
                if self._stall_since == 0.0:
                    self._stall_since = time.monotonic()
                elif time.monotonic() - self._stall_since >= 2.0:
                    self.on_event(
                        f"appfw watchdog: verdict backlog {q} B — FAIL-OPEN")
                    self.stop()          # kills worker, deletes nft table
                    return
            else:
                self._stall_since = 0.0

    def _decide_line(self, line: str, ctl: socket.socket) -> None:
        parts = line.split()
        _, pid = parts[0], int(parts[1])
        proto, src_ip, sport, dst_ip, dport = (parts[2], parts[3],
                                               int(parts[4]), parts[5],
                                               int(parts[6]))
        conn = Conn(protocol=proto, src_ip=src_ip, src_port=sport,
                    dst_ip=dst_ip, dst_port=dport)
        try:
            self.resolver.resolve(conn)
        except Exception:
            pass
        action, duration, note, host_op = decide(conn, self.policy,
                                                 store=self.store,
                                                 ask=self.ask)
        if duration in ("always", "until restart") and (
                conn.process_path or host_op):
            try:                               # never fail the verdict
                self.store.add(rule_from_decision(
                    conn, action,
                    "always" if duration == "always" else "until restart",
                    host=host_op))
            except Exception:
                pass
        try:
            ctl.sendto(
                f"{'ALLOW' if action == 'allow' else 'DROP'} {pid}".encode(),
                self._control_path)
        except BlockingIOError:
            pass        # worker behind → its 250 ms sweep ACCEPTs, fail-open
        except OSError:
            pass
        # Bounded logging: ≤10 allow events/s, denies always kept. One event
        # per SYN during a storm is what filled the daemon's memory cap.
        now = time.monotonic()
        if action != "allow" or now - self._log_last >= 0.1:
            if self._log_suppressed:
                self.on_event(
                    f"appfw: {self._log_suppressed} allow event(s) throttled")
                self._log_suppressed = 0
            self.on_event(f"appfw {conn.app_name} → {conn.host}:"
                          f"{conn.dst_port} {action} [{note}]")
            self._log_last = now
        else:
            self._log_suppressed += 1

    # config-aware reconcile (a Settings toggle lands without a rebuild)
    def config_changed(self) -> bool:
        return config.mtime(self.data_dir) != self._cfg_mtime