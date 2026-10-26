# WIZARD_SPEC.md — the six topic wizards (master prompt §5, refined per D3)

Shared chassis (all six): multi-step GTK dialog, Back/Next/Cancel; every
step validates inline (refuse + inline error, never a silent pass); a final
plain-language summary + preview of the exact file write BEFORE Apply;
writes happen through the decision pipeline / daemon-side store — the UI
never constructs privileged commands; Cancel at any step leaves nothing.
Existing tool wizards (ufw, fail2ban, tetragon, yara, arpwatch) are separate
lanes and remain; these six are the appfw-suite topics.

## W-T1 Trust-List Wizard
1. Pick: auto-allow or auto-deny. 2. Enter domain (suffix matching OK,
`*.example` accepted) or IP; validate host/IP inline. 3. Optional comment
label. 4. Preview: exact trust-list.json entry + effect sentence ("matched
subdomains included"). 5. Apply → daemon-side write; list refreshes live
(mtime re-read verified). Edge cases: duplicate = inline warning, not an
error; block entry overrides allow on suffix overlap (verified semantics).

## W-T2 Trusted Program Wizard
1. Browse or paste the program path; inline existence check (warn only if
absent — rules for not-yet-installed programs are legitimate). 2. Optional
arg-folder scope (owner's interpreter-run-tools pattern: trust
`~/project/` args, not every python). 3. Preview: rule JSON + "programs
never prompt". 4. Apply → rules store. Edge: interpreter path + arg-folder
stored as separate op kinds (process.path vs process.args-prefix).

## W-T3 Loopback Service Wizard
1. Port (inline range check) + label. 2. Confirmation that ONLY loopback
matches (cannot open the network — verified invariant: remote host never
matches). 3. Preview: LOCAL_SERVICE_PORTS extension entry. 4. Apply.
Defaults preserved: 8888 (SearXNG), 8899 (browser control).

## W-T4 Blocklist Wizard
1. Choose: subscribe URL or upload file (hosts-format). 2. Refresh interval
inline-validated (≥1 h). 3. Offline behavior explained: cache used, failure
logged honestly (never silent). 4. Preview: entry count + sample lines.
5. Apply → blocklist file+meta via daemon.

## W-T5 Learning Mode Wizard
1. Window length (minutes) + posture (allow-once default / block-once).
2. Optional auto-approve threshold (none = manual only — never auto-promote
without confirmation, per master prompt). 3. Review interval for the
learning-pending queue. 4. Preview: learning.json + mode file writes.
5. Apply. Edge: expiry shown visually (countdown state in dashboard).

## W-T6 Strict Mode Wizard (block-unknown)
1. Toggle block-unknown (deny + record). 2. One-click-unblock list view
(learning-pending + blocked bursts). 3. Panic-button behavior choice:
disable engine switch only vs disable + flush nft table (both owner-runnable;
the sudo panic button always remains). 4. Preview: firewall-mode.json +
appfw/enable.json writes. 5. Apply.

## Non-goals (owner rules)
No scrolling notification surfaces anywhere; no duplicate of the ufw lane;
no auto-promotion of learning entries; the bare appfw CLI wizard
 wiz/appfw_wizard.py stays as the headless path (parity with these dialogs).