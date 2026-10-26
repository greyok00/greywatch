# /proc process-to-socket mapping — digest + the perf contract

Raw: procfs/proc_pid_net.5.html + procfs/proc-net-tcp.html (man pages).
Implementation: appfw/resolve.py; formats in _parse_net_file/_hex_ip.

- /proc/net/tcp|tcp6|udp|udp6 rows: local/remote addresses are little-endian
  hex ip:port; inode column (f[9]) links to /proc/PID/fd/*
  "socket:[inode]"; cmdline/exe give path+args. tcp AND tcp6 both needed;
  udp too (the incident class).
- Read the FULL resolver perf contract in resolve.py's docstring — after
  the two outages it is: inode-keyed permanent cache, one shared /proc/net
  snapshot per ~250 ms burst, fd scans only for never-seen inodes, tuple
  TTL cache. NO DNS anywhere near the pump (incident #1: 10 s stalls).
- The queue pump is single-threaded: per-packet cost is the machine's
  ceiling. Any new per-packet work must fit the contract or use the
  kernel-exemption rules instead.