from __future__ import annotations

import fcntl
import json
import os
import time
import pathlib
import socket
import subprocess
import sys
import threading

from . import config, history, sites
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
    try:
        doc = json.loads(enable_path(data_dir).read_text())
        return bool(doc.get("enabled"))
    except (OSError, ValueError, AttributeError):
        return False


def write_enabled(data_dir, enabled: bool) -> None:
    from .atomicio import write_json_atomic
    path = enable_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(path, {"enabled": bool(enabled)})


class Engine:

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
        self.state = "stopped"
        self._stop = threading.Event()
        self._ctl_sock = None
        self._stall_since = 0.0
        self._watchdog_thread = None
        self._log_last = 0.0
        self._log_suppressed = 0
        self._backlog_fails = 0            # watchdog measurement failures
        self._last_backlog = None          # last measured verdict backlog
        self._whitelist_suspended = False
        self._whitelist_down_since = 0.0
        self._sites_at = 0.0               # named-sites resolve lane
        self._sites_thread = None
        self._reader_gen = 0               # respawned readers are numbered

    SIOCOUTQ = 0x5411

    def _query_backlog(self) -> int | None:
        """Unsent verdict bytes queued on the control socket: SIOCOUTQ
        must be used through fcntl.ioctl() on AF_UNIX sockets —
        getsockopt(SOL_SOCKET, SIOCOUTQ) is not a valid query and fails.
        A failed measurement returns None (UNKNOWN), never "empty".

        The third ioctl argument is a POINTER to an int. Passing 0 gives
        EFAULT on this kernel (verified, which the watchdog
        reported as "backlog measurement failed" forever — the stall
        detector was blind while claiming to be degraded. Pass a 4-byte
        mutable buffer; ioctl returns the filled buffer.
        """
        sock = self._ctl_sock
        if sock is None:
            return None
        try:
            raw = fcntl.ioctl(sock.fileno(), self.SIOCOUTQ, b"\0\0\0\0")
            return int.from_bytes(raw[:4], sys.byteorder)
        except (OSError, ValueError):
            return None

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
            # the detailed reason was already emitted by _install_nft
            return False
        self.running = True
        self.state = "running"
        self._stop.clear()
        self._stall_since = 0.0
        # A previous run's runtime hazards never carry in (round-3 audit
        # R3-F7): a whitelist valve left suspended (or a watchdog whose
        # measured failures accumulated) belongs to the run that tripped
        # it, and the next arm starts with clean state.
        self._whitelist_suspended = False
        self._whitelist_down_since = 0.0
        self._backlog_fails = 0
        self._watchdog_thread = threading.Thread(
            target=self._watchdog, daemon=True, name="appfw-failopen-watchdog")
        self._watchdog_thread.start()
        history.record(self.data_dir, "arm",
                       reason=f"queue {config.load(self.data_dir).get('nfqueue_num')}")
        self.on_event("appfw engine: running "
                      f"(queue {config.load(self.data_dir).get('nfqueue_num')}, "
                      f"worker {self._worker_bin.name})")
        return True

    def stop(self, reason: str = "switch") -> None:
        self._stop.set()
        self.running = False
        self.state = f"off ({reason})"
        history.record(self.data_dir, "stop", reason=reason)
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
            # Retire this generation BEFORE the join (round-3 audit
            # R3-F3): the reader's last recvfrom can wake into the 0.5 s
            # window, and without the bump a verdict it scrapes lands in
            # the NEXT run - the run that did not ask for it.
            self._reader_gen += 1
            reader.join(timeout=0.5)   # drained, not abandoned mid-recvfrom
        self._reader = None
        for path in (self._events_path, self._control_path):
            try:
                pathlib.Path(path).unlink(missing_ok=True)
            except OSError:
                pass
        self._remove_nft()
        self.on_event("appfw engine: stopped")

    @staticmethod
    def _ensure_queue_module() -> str | None:
        """Load the kernel modules the 'queue' nft statement needs.

        The ruleset queues new TCP connections to an NFQUEUE. That needs
        nft_queue (the nft 'queue' expression) and nfnetlink_queue (the
        queue handler itself). They ship on disk but nothing loads them on
        this machine, so 'nft -f' fails and the engine can never arm.
        modprobe is idempotent; loading them by name is an explicit,
        auditable action. Returns an error string, or None when both are
        loaded."""
        for mod in ("nfnetlink_queue", "nft_queue"):
            run = subprocess.run(["modprobe", mod], capture_output=True,
                                 text=True, timeout=15)
            if run.returncode != 0:
                err = (run.stderr or "").strip().splitlines()
                return (f"kernel module unavailable: {mod} "
                        f"({err[-1] if err else 'modprobe failed'})")
        # verify, do not assume: a silent autoload failure must surface
        for mod in ("nfnetlink_queue", "nft_queue"):
            if not pathlib.Path(f"/sys/module/{mod}").exists():
                return f"kernel module not loaded: {mod}"
        return None

    def _install_nft(self) -> bool:
        script = config.build_ruleset(config.load(self.data_dir))
        mod_err = self._ensure_queue_module()
        if mod_err:
            self.on_event(f"appfw engine: {mod_err} - OFF")
            return False
        # Clear a leftover table FIRST. A previous failed arm can leave
        # "greywatch_appfw" behind, and then every retry dies on
        # "add table ... File exists" — the switch looks dead forever
        #. Deleting an absent table is harmless.
        self._remove_nft()
        run = subprocess.run(["nft", "-f", "-"], input=script,
                             capture_output=True, text=True, timeout=10)
        if run.returncode == 0:
            return True
        try:                      # keep the full text for the next diagnosis
            (self.data_dir / "appfw" / "nft-error.log").write_text(
                (run.stderr or "") + "\n--- script ---\n" + script)
        except OSError:
            pass
        lines = (run.stderr or "").strip().splitlines()
        # nft prints "Error: ..." first and a caret line last; keeping the
        # last line turned every failure into a row of ^^^^^ in the UI.
        detail = next((ln for ln in lines if ln.startswith("Error:")),
                      lines[-1] if lines else f"exit {run.returncode}")
        history.record(self.data_dir, "fail",
                       reason="nftables install failed",
                       detail=detail.strip())
        self.on_event(f"appfw engine: nftables install failed "
                      f"({detail.strip()}) - OFF")
        self._remove_nft()        # never leave a half-installed table
        return False

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
        cfg = config.load(self.data_dir)
        env = dict(os.environ,
                   NFQ_CONTROL_PATH=self._control_path,
                   NFQ_EVENTS_PATH=self._events_path,
                   # Same number the ruleset's `queue` statement sends to
                   # (config.queue_num); a mismatch binds the worker to a
                   # queue no packet ever reaches.
                   NFQ_QUEUE_NUM=str(config.queue_num(cfg)))
        if not cfg.get("fail_open", True):
            # In whitelist mode an unanswered ask must not
            # open after 250 ms like the standard mode does (audit F4):
            # the worker's sweep drops instead of accepting.
            env["GREYWATCH_ASK_FAIL_CLOSED"] = "1"
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
        # One reader per worker: a respawned reader is numbered ahead of
        # the old one, and the old loop exits within one socket timeout so
        # two threads never race for the same verdict stream.
        sock.settimeout(1.0)
        gen = self._reader_gen + 1
        self._reader_gen = gen
        self._reader = threading.Thread(target=self._recv_loop,
                                        args=(gen, sock), daemon=True,
                                        name="appfw-worker-reader")
        self._reader.start()

        def _monitor(worker_spawn=self._proc):
            try:
                worker_spawn.wait(timeout=86400)
            except Exception:
                pass
            else:
                if not self._stop.is_set():
                    history.record(self.data_dir, "respawn",
                                   reason="worker exited; watchdog will "
                                          "restart it")
                    self.on_event("appfw worker exited - respawning")
        threading.Thread(target=_monitor, daemon=True,
                         name="appfw-worker-monitor").start()

    def _recv_loop(self, gen: int = 0, sock: socket.socket | None = None) -> None:
        ctl = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        ctl.setblocking(False)
        self._ctl_sock = ctl
        while not self._stop.is_set() and gen == self._reader_gen:
            try:
                data, _ = (sock or self._events_sock).recvfrom(512)
            except (socket.timeout, TimeoutError):
                continue                 # timeout: re-check the generation
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
                self.on_event(f"appfw packet error - {e}")
        for s in (ctl, sock):            # an old generation's own socket
            try:
                if s is not self._events_sock:
                    s.close()
                else:
                    pass                 # stop() still owns the live one
            except OSError:
                pass

    def _watchdog(self) -> None:
        while not self._stop.wait(2.0):
            if not self.running:
                return
            try:
                self._watchdog_step()
            except Exception:            # noqa: BLE001 - a watchdog that
                continue                 # dies would be one silent alarm
            self._sites_step()

    def _sites_step(self) -> None:
        """Named trust entries only match once resolved; the slow lane
        refreshes that map off-thread (DNS never runs in the packet
        path), and a running pass skips the next one."""
        now = time.monotonic()
        if now - self._sites_at < sites.REFRESH_SECONDS:
            return
        self._sites_at = now
        if self._sites_thread is not None and self._sites_thread.is_alive():
            return
        self._sites_thread = threading.Thread(
            target=self._refresh_sites, daemon=True,
            name="appfw-sites-resolve")
        self._sites_thread.start()

    def _refresh_sites(self) -> None:
        try:
            entries = set(self.policy.site_entries())
        except Exception:                # noqa: BLE001 - never a hunt stop
            return
        if not entries:
            return
        prev = sites.load(self.data_dir).get("entries") or {}
        resolved = sites.resolve_entries(entries)
        merged = {k: list(v) for k, v in prev.items() if k in entries}
        for k, v in resolved.items():
            if v or k not in merged:
                merged[k] = v
        # An entry the resolver could not reach this pass keeps its last
        # known addresses (stale coverage beats none, and the next pass
        # retries); a removed entry loses its coverage row.
        sites.store(self.data_dir, merged)

    def table_present(self) -> bool:
        """Cheap, root-only presence check. A missing table means some
        other tool (ufw reload, docker, a manual flush) removed ours."""
        try:
            run = subprocess.run(
                ["nft", "list", "table", "inet", NFT_TABLE],
                capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        return run.returncode == 0

    def _worker_healthy(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _respawn_worker(self) -> bool:
        try:
            self._bind_worker()
            history.record(self.data_dir, "respawn",
                           reason="worker was down")
            return True
        except Exception as e:          # noqa: BLE001 - keep the table armed
            history.record(self.data_dir, "fail",
                           reason=f"respawn: {e}")
            return False

    def _rearm(self, reason: str) -> bool:
        self.state = "re-arming"
        ok = self._install_nft()
        history.record(self.data_dir, "reinstall" if ok else "fail",
                       reason=reason)
        if ok:
            if not self._worker_healthy() and not self._respawn_worker():
                self.state = "off (failed: worker unavailable)"
                return False
            self.state = "running"
        return ok

    def _suspend_whitelist(self) -> None:
        if self._whitelist_suspended:
            return
        safe = dict(config.load(self.data_dir), fail_open=True)
        script = config.build_ruleset(safe)
        self._remove_nft()
        try:
            run = subprocess.run(["nft", "-f", "-"], input=script,
                                 capture_output=True, text=True, timeout=10)
            ok = run.returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        self._whitelist_suspended = True
        self.state = ("suspended (whitelist safety valve)" if ok else
                      "suspended (whitelist valve; install failed)")
        history.record(self.data_dir, "suspend" if ok else "fail",
                       reason="worker unavailable 5 s - traffic restored "
                              "fail-open" if ok else
                              "safety-valve ruleset install failed; with "
                              "the table down the queue never sees packets")
        self.on_event("appfw: whitelist suspended for safety - traffic "
                      "is fail-open until the worker returns" if ok else
                      "appfw: whitelist suspended for safety - the "
                      "fail-open ruleset failed to install; traffic flows "
                      "unfiltered until the worker returns")

    def _resume_whitelist(self) -> None:
        ok = self._rearm("whitelist worker healthy again")
        self._whitelist_down_since = 0.0
        if not ok:
            # Still suspended: the valve stays open until a re-arm works,
            # and an untruthful "fail-closed again" line would be worse
            # than the open state it hides.
            history.record(self.data_dir, "fail",
                           reason="whitelist re-arm failed; valve stays "
                                  "open")
            self.on_event("appfw: whitelist re-arm failed - traffic stays "
                          "fail-open until it succeeds")
            return
        self._whitelist_suspended = False
        history.record(self.data_dir, "resume", reason="worker healthy")
        self.on_event("appfw: whitelist re-armed - traffic is fail-closed "
                      "again")

    def _watchdog_step(self) -> bool:
        """Keep the table armed. Never disarm on trouble: the nftables
        queue already carries 'flags bypass' in standard mode, so a sick
        worker degrades to per-packet bypass instead of an open network.
        Returns False only when the engine itself could not stay armed."""
        cfg = config.load(self.data_dir)
        whitelist = bool(cfg.get("strict_mode")) and not cfg.get(
            "fail_open", True)
        try:                       # popup/wizard/unblock-panel rules are
            self.store.refresh_if_changed()   # written from other processes
        except Exception:          # noqa: BLE001 - a refresh miss
            pass                   # costs only until the next step
        if whitelist and self._worker_healthy():
            if self._whitelist_suspended:
                self._resume_whitelist()
            # A worker that recovered on its own must not carry a stale
            # down-stamp: the next outage then suspends without its own
            # 5-second grace, skipping what the valve is supposed to do.
            self._whitelist_down_since = 0.0
        elif whitelist and not self._whitelist_suspended:
            # Fail-closed arms are the one place where a dead worker is a
            # total outage: every new connection would sit in the queue
            # until its bypass window, so the valve restores traffic
            # fail-open until the worker is back. The operator's config is
            # never rewritten — this is a runtime state, not a setting.
            if self._whitelist_down_since == 0.0:
                self._whitelist_down_since = time.monotonic()
            elif time.monotonic() - self._whitelist_down_since >= 5.0:
                self._suspend_whitelist()
        if not self.table_present():
            self.on_event("appfw watchdog: table was removed - reinstalling")
            self._rearm("table was removed externally")
        if not self._worker_healthy():
            self.on_event("appfw watchdog: worker gone - respawning")
            self._respawn_worker()
        else:
            reader = getattr(self, "_reader", None)
            if reader is None or not reader.is_alive():
                # A live worker with a dead reader is invisible to the
                # process probe: verdicts stop being read, and every
                # packet rides the worker's 250 ms fail-open sweep
                # unheard (recovery audit A4). Respawning re-binds and
                # renumbers the generation, retiring any zombie reader.
                self.on_event(
                    "appfw watchdog: reader thread is gone - respawning")
                self._respawn_worker()
        q = self._query_backlog()
        if q is None:
            # measurement failed — that is NOT "queue empty". Keep the
            # fail-open design (worker monitor + stall sweep still
            # catch a dead worker) but surface the degraded watcher.
            self._last_backlog = None
            self._stall_since = 0.0
            self._backlog_fails += 1
            if self._backlog_fails == 1 or self._backlog_fails % 15 == 0:
                self.on_event(
                    f"appfw watchdog: backlog measurement failed "
                    f"×{self._backlog_fails} - cannot confirm a stall; "
                    "watcher degraded")
            return True
        self._backlog_fails = 0
        self._last_backlog = q
        if q > 65536:
            if not self._whitelist_suspended:
                self.state = "running (bypassing: queue full)"
            if self._stall_since == 0.0:
                self._stall_since = time.monotonic()
            elif time.monotonic() - self._stall_since >= 2.0:
                history.record(self.data_dir, "stall",
                               reason=f"verdict backlog {q} B")
                self.on_event(
                    f"appfw watchdog: verdict backlog {q} B - worker "
                    "restarted, firewall stays armed")
                self._respawn_worker()
                self._stall_since = 0.0
        else:
            self._stall_since = 0.0
            if self.state == "running (bypassing: queue full)":
                self.state = "running"
        return True

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
        if duration in ("always", "until restart"):
            # host_op is either a mode ("trust", "block-host", …) or the
            # destination itself. Passing the mode through as the rule
            # value stored a rule for a host literally named "trust-block",
            # so "Block this site" never matched anything.
            target = ""
            if host_op:
                target = (conn.host if str(host_op) in
                          ("host", "block-host", "trust", "trust-block")
                          else str(host_op))
            try:                               # never fail the verdict
                if target:
                    self.store.add(rule_from_decision(
                        conn, action,
                        "always" if duration == "always" else "until restart",
                        host=target))
                elif conn.process_path:
                    self.store.add(rule_from_decision(
                        conn, action,
                        "always" if duration == "always" else "until restart"))
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

    def config_changed(self) -> bool:
        return config.mtime(self.data_dir) != self._cfg_mtime
