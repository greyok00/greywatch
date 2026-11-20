# net-watch — Net Watch (light IDS)

Source: the GreyWatch net-watch lane records, curated into gw-tools.

WHAT IT IS: The light intrusion detector for the local segment. It
watches connection patterns per host and per app: port scans (many
ports attempted against this machine), connection bursts, and ARP
changes when paired with arpwatch. It looks at the traffic the machine
actually sees — no deep packet inspection, no signatures — so a finding
is a shape (scan, burst, new host) rather than a named exploit.

WHAT ITS WARNINGS MEAN: a scan row lists the address and the ports it
attempted within the detection window. Bursts name the app that opened
them. These rows are leads: the responder question is whether the
shape belongs to a program you run on purpose (a sync client polling
is a burst) or to something you don't recognize.

HEURISTICS:
- Single address touching many ports: check whether anything of yours
  listens there (ss -tlnp); an expected service answers, an unexpected
  listener is the finding to chase, not the scanner.
- Bursts tied to a known app with a cooldown are normal churn; the same
  burst from an unknown path is the actionable row.
- ARP flips paired with arpwatch rows mean a device changed identity on
  the LAN — investigate the device before trusting the MAC.
- Findings here join the same threat-scale ladder as every other lane:
  L1/L2 stay quiet rows, L3/L4 surface as cards with next-step buttons.
