# ufw — UFW (uncomplicated firewall)

Source: man page ufw(8), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: The host firewall's user-facing layer. UFW carries the
default policy (deny incoming, allow outgoing), the named application
profiles and whatever explicit allow/deny rules the owner added. Its
rules are enforced by the kernel — the same layer the GreyWatch app
firewall (nftables) sits beneath — so ufw is the persistent policy and
nft is the live enforcement view.

WHAT ITS WARNINGS MEAN: a ufw BLOCK row is the kernel dropping a packet
the persistent policy rejects. One block is noise; a wall of blocks from
one address is scanning. UFW rows are also the honest signal for the
firewall being disabled: "status: inactive" must read as the firewall
being OFF, never as "no attacks happening".

HEURISTICS:
- Repeated blocks from one source with no request you recognize: add an
  explicit deny, and check whether the same address reached anything.
- The config editor is read-only by design — rule changes happen in a
  terminal you control, then the dashboard re-reads and re-renders.
- ufw inactive on a machine that faces the internet is an immediate fix
  (ufw enable) from the tool's own guidance, not a monitoring question.
- UFW and the app firewall are layers, not rivals: ufw says what the
  host always rejects; the app firewall adds per-program asks on top.
