# arpwatch — LAN device watcher

Source: man page arpwatch(8), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: Watches ARP traffic on an interface and records
IP/MAC pairings. New pairings ("new station"), changed pairings, and
flip-flops are logged. GreyWatch republishes notable stations as
findings/decisions so the owner can allow or block a device.

WHAT ITS EVENTS MEAN: "new device 10.0.0.x (MAC)" = a machine joined the
LAN the watcher has not seen before. Allowed devices become permanent
entries; an unknown device's connections can be decided from the row.

HEURISTICS:
- New device = recognize it (printer, phone, laptop) then Allow with a
  permanent rule, or Block it same-minute if it appeared while nothing
  was being installed.
- Flip-flop (an IP switching MACs) is either DHCP reuse or ARP spoofing:
  if two devices share an IP, quarantine the newcomer from the row.
- Resolution keys (rule, MAC) — an allowed device never re-asks per boot.
- arpwatch needs its interface up at daemon start; "watcher down" on the
  tool card is a restart first, config second.
