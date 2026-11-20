# tetragon — Tetragon (kernel eBPF)

Source: man page tetragon(8) and the GreyWatch tetragon wizard lane, digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: The kernel-level eBPF observer. Tetragon watches system calls
and process lifecycle straight from the kernel, so what it reports doesn't
depend on log files: process execution, file access, network activity and
privilege changes are traced in place. GreyWatch joins these traces to the
wizard-configured lane and publishes the events on the Protections wall.

WHAT ITS WARNINGS MEAN: a Tetragon row is an observed kernel action — a
process started, a file opened, a socket connected — usually annotated
with the binary path and the policy verdict. LOW/INFO rows are the OS
working normally; repeat rows naming an unexpected binary deserve a look
via the row's next-step buttons, never manual shell work.

HEURISTICS:
- An exec row naming a path under /tmp, /dev/shm or a user Downloads dir
  is the classic dropper shape — open the finding and act from the row.
- Repeat exec failures (permission denied) on the same binary mean a
  service is hunting for a missing or moved file: fix the unit, don't
  blanket-permit the path.
- Kernel traces keep flowing when logs rotate, so a "silent" tool with a
  live Tetragon feed is NOT silent — trust the row timestamps.
- The eBPF lane is read-only by design: it observes, it never blocks. A
  drop you see on the dashboard came from the firewall lane, not here.
