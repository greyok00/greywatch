# fail2ban — Fail2ban (bans)

Source: man page fail2ban(8) + jail.conf(5), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: The login-brute-force responder. Fail2ban watches auth logs
per jail (sshd is the default), counts failures per address inside a
find-time window, and bans by inserting a firewall rule with an
expiration (bantime). The GreyWatch heuristic watches for re-ban
patterns: the same address landing in a jail three times in a window is
carded, because a self-expiring ban invites a patient attacker back.

WHAT ITS WARNINGS MEAN: a Ban row names the jail, the address and the
port hit. It is the response already taken, not a question. A chain of
bans for one address means the bans are working OR the window is too
short — the card asks which.

HEURISTICS:
- Repeated single bans of the same address: consider the permafix —
  raise bantime or make the ban permanent (`fail2ban-client set <jail>
  banip --with-daily-retry` semantics vary; check the jail config).
- Your own address banned (you mis-typed a password repeatedly): unban
  from the row — that is what the Unblock button is for.
- The config editor is read-only by design; jail tuning happens in a
  terminal, then the dashboard re-reads and re-renders the state.
- Every banned address should also be checked for SUCCESSFUL logins
  before the ban window — a ban proves attempts, not failure.
