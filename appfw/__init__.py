"""appfw — the App Firewall, greywatch's OWN per-process outbound firewall.

Rebuilt in-project (owner order 2026-10-23): the external firewall daemon is
gone from the system; the parts that mattered were re-implemented here and
renamed. One decision chain (policy.py), one rule model (rules.py),
/proc-based process resolution (resolve.py), one NFQUEUE engine (engine.py)
bound to its own nftables table — nothing here touches an external
program, its config, or its protocol.
"""