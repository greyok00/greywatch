# HELP/ — authoritative references (owner order 2026-10-25: consult before every change)

Raw fetched pages: `*.html` files beside each digest. **The digests (`*.md`)
carry the distilled truth + LIVE FINDINGS from this machine** — read the
digest first, the raw page for depth.

| Path | Covers |
|---|---|
| systemd/systemd.service.md | the unit directives + the 226/NAMESPACE case |
| systemd/systemd.exec.md | sandboxing/paths/Watchdog + the re-tighten protocol |
| nftables/nfqueue.md | NFQUEUE semantics + THE VERDICT-DEFECT RECORD (the definitive incident file) |
| nftables/nft.8.html | raw nft man |
| gtk/gtk4-tray.md | GTK4 tray (SNI over D-Bus) + what we built |
| polkit/pkexec.md | pkexec + our allowlist discipline |
| procfs/proc-net-tcp.md | /proc/net parsing + the resolver perf contract |
| tools/ | per-tool log formats (parsers.py is the live truth; fixtures in tests/) |

RULE: no network fetches at runtime (offline machine discipline) — these
files are the consulting layer. When a fix lands, UPDATE its digest with the
finding; the digests are the institutional memory.