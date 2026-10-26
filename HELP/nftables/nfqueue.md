# nftables NFQUEUE — digest + THE VERDICT-DEFECT RECORD

Raw: nftables/nfqueue.html (wiki) + nftables/nft.8.html (man). The rules
live in appfw/engine.py (NFT_INSTALL) — read that first.

## Facts (verified live)
- `queue num 111 bypass`: bypass passes packets ONLY when **no userspace
  listener exists**; a present-but-dead listener does NOT bypass (the
  2026-10-24 outage) → the daemon supervises pump health + re-arms.
- `queue_total` in /proc/net/netfilter/nfnetlink_queue (root) = packets
  parked awaiting verdicts; the columns are
  queue,peer_portid,queue_total,copy_mode,copy_range,queue_dropped,
  user_dropped,... Our live read during the jam: mode 2 (COPY_PACKET),
  range 4016 (= the binding's MaxCopySize), **total 223 and climbing**
  while the handler streamed "allow" events → verdicts SENT, packets
  STUCK.
- DNS + loopback are now KERNEL-EXEMPTED (accept rules before the queue)
  on purpose: per-process control there buys nothing and stalls the name
  resolution stack (2026-10-25 incidents #1 and #2).

## THE DEFECT (open, evidence-backed)
Python binding python3-netfilterqueue 1.1.0-4 (Cython, frozen
`BufferSize=4096`, `MaxCopySize=4016`):
- run(block=False) is a NO-OP for our cadence → packets queue, no verdicts
  (incident #2). Use run(block=True).
- run(block=True) + handler + pkt.accept() → `nfq_set_verdict` via the qh
  (checked in the shipped _impl.pyx: accept → verdict(NF_ACCEPT) → sync).
- STILL: TCP SYNs stall the full 39 s SYN-retry window with "allow"
  decisions streaming; queue_total builds. Cap of copy range to 256 did
  NOT fix it (tested live, bounded window).
- CONCLUSION: the binding's queue handling on this stack does not reliably
  land verdicts for TCP new-conn traffic patterns we generate. NEXT
  (decided): replace the Python queue client with a tiny native C verdict
  worker (gcc + libnetfilter_queue-dev installed) — kernel-side verdict
  worker + JSON/Unix-socket policy channel to greywatch (the architecture
  real products use). The Python engine keeps rules/policy/UI; ONLY the
  netlink transport moves to C.

## Rules currently installed by the engine
table inet greywatch_appfw / chain out (hook output priority filter):
1. ip daddr 127.0.0.0/8 accept        (loopback exempt)
2. ip6 daddr ::1 accept
3. udp dport 53 accept                (resolver lane exempt)
4. tcp dport 53 accept
5. ct state new counter queue num 111 bypass

## Panic button (works with everything dead)
sudo nft delete table inet greywatch_appfw

## INTEGRATED (2026-10-25, task #13)
The queue client is now `appfw/bin/nfq_worker` (C, source nfq_worker.c,
clean -Wall build, 17.5 KB): binds queue 111 (copy 256), HOLDS each packet
≤250 ms, asks the policy engine over
`/run/greywatch/nfq_events.sock` ← "PKT id proto src sport dst dport"
and applies "ALLOW id"/"DROP id" from `/run/greywatch/nfq_worker.sock`;
fail-open sweep + overflow-accept + signal-accept make a lockout
impossible at the binary level. The engine (appfw/engine.py) spawns the
worker when armed, routes tuples through the EXISTING policy chain, and
redirects worker stdio to DEVNULL (the pipe-retention discovery that
wedged the functional tests once — fixed). Config-first: data/appfw/config.json drives the
ruleset generator (appfw/config.py) — ipv6_enabled toggle, nfqueue number,
interval seconds — with loopback + DNS 53 exemptions ALWAYS present.
TESTS: 498 green incl. the 10-scenario matrix + worker-transport batteries;
fake worker at tests/fake_worker.py needs the exec bit + never hang
(recv timeout, exit 1).
PENDING VERIFICATION (next live window): worker-as-root queue binding +
curl-fast-with-queue-live (the previous arm used the old python path).
