# Optimized device config + tool verification — 2026-10-24

Reads with doc/appfw-audit-2026-10-24.md. Applies when the relaunch gate is passed
(gates 1–9). These are the values to SET, and the checks that passed.

## Device config to apply (the "don't gimp me" config)
| key / unit | value now | value to set | why |
|---|---|---|---|
| data/appfw/enable.json | disabled (knockout) | stays OFF until gate passes | enforcement before repair is how we got three outages |
| appfw fail_open | true | forced TRUE at install; refuse to start if false (config.py:25) | fail_open=false = intentional traffic trap |
| ipv6_enabled | false (live) | false, and ruleset generated from ONE spec (config↔nft drift closed) | halves queue volume; default-True code must not regress it |
| data/firewall-mode.json block_unknown | absent | stay absent (off) | block-unknown under a stall = full-block machine |
| CPUQuota (greywatch.service) | 10% | 25% ONLY while appfw armed, else 10% | verdict path needs headroom; audit finding 1/8 |
| watchdog engine supervision | 10s | < 5s + silent-queue re-arm (gate 5) | orphan/stall recovery |
| yara-tmp-scan.timer | every 15 min | keep (user scope, idle I/O) | no network-path effect |
| clam-scan.timer / aide 06:35 / cve Sun 04:30 | as installed | keep | fine |
| suricata legacy timers (digest/rate-alert/ruleset-refresh, root 4th 04:40) | still installed | DELETE — tool purged | scheduled work for a dead binary |
| fail2ban jails suricata-egress + recidive | on disk, service off | service stays off until gate 7; then jails reworked with ignoreip/≤1w | destination-side egress bans = self-harm |
| registry.json | no enable flags (roster only) | add per-tool enabled flag | relaunch should arm a known set, not "what's on the host" |
| pre_seeded_allow | dead key | implement program allowlist in decide() OR delete key | config that pretends to protect and doesn't |

## Tool verification (ran 2026-10-24, read-only probes)
- yara 4.5.2 ✅ clamscan 1.4.3 (defs 2026-10-23) ✅ rkhunter 1.4.6 ✅
- lynis 3.1.4 ✅ aide 0.19.1 ✅ nft 1.1.3 ✅ fail2ban-client 1.1.0 ✅ (OFF per gate)
- pkexec 126 + greywatch.apply.policy ✅ gcc 14.2.0 (worker build) ✅
- daemon/cli/collectors/rules/status imports: all resolve ✅
- suricata: MISSING by design (net-watch replaced it) — legacy timers to remove ❗
- netfilterqueue python module: unavailable (why the C worker exists) — do NOT
  "fix" back to Python transport
- netwatch-events.jsonl: 0 lines (quiet = healthy analyzer, no packet mirror)
- blocklist: StevenBlack 71,489 domains, refreshed 2026-10-23, consulted
  in-policy only (no DNS override) ✅

## Launch order when gates pass
1. gates 1–5 (transport hardening) + burst regression test green
2. fail2ban reworked (gate 7) BEFORE fail2ban restarts for any reason
3. arming = optimized config table above, appfw enabled LAST
4. 24 h soak with verdict-latency + queue stats logged before any strict mode