# pkexec / polkit — digest

Raw: polkit/pkexec.html. Our discipline (verified):
- ONLY the 16 allowlisted scripts in apply/ execute via pkexec; the policy
  lives at apply/polkit/greywatch.apply.policy →
  /usr/share/polkit-1/actions/. The GUI/CLI pass structured argv; they never
  build shell commands; helper args are daemon-extracted + (Pass 1)
  schema-validated (schemas/helper-args.schema.json).
- Every helper call is logged to data/helper-actions.log.
- Buttons that cross pkexec need the owner's password — MANUAL-CONFIRM
  buttons in the functional battery (tests/test_buttons_functional.py);
  everything else is effect-verified in a sandboxed data dir.
- The appfw lane deliberately does NOT use pkexec: data/appfw/enable.json is
  grey-owned — resume/pause = flip the switch file (no password ever).