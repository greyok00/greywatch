# freshclam — Freshclam (virus definition updates)

Source: man page freshclam(1), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: The ClamAV database updater. Freshclam fetches the daily and
bytecode signature databases so clamd/clamscan can recognize current
malware. It runs on a timer; its health is the freshness guarantee for
every ClamAV verdict on the dashboard — a red freshclam makes all
"clean" ClamAV results older than the outage suspect.

WHAT ITS WARNINGS MEAN: an update failure row (network error, DNS,
mirror 429) means signature staleness started now. The tool's verdict
turns RED on failed runs, and the ClamAV cards carry the same staleness
honesty line before any "clean" is trusted.

HEURISTICS:
- Red freshclam after a network change: check the resolver first, then
  the mirror — the row's error text names which failed.
- A single mirror 429 (rate limit) is transient: the timer retries;
  manual retries hammering the mirror make it worse.
- Stale DB older than a week is a yellow honesty line on the ClamAV
  card even when freshclam last succeeded — old signatures miss new
  malware, and the dashboard keeps saying so.
- After a DB update, a one-shot rescan of recently-written files catches
  anything written while signatures were stale.
