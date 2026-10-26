"""wizard/baseline.py — the Setup Wizard's adaptive baseline generator.

stdlib only. `generate(scan_result, controls, profile)` turns the system
inventory (wizard/detector.py probe results) plus the loaded controls
(hardening/controls.py) into the Step-3 preview cards the owner sees,
applying the master prompt's adaptive rules verbatim:

  * ClamAV absent            -> an install-PROMPT card ("Install ClamAV");
                                it is never installed silently.
  * SSH not installed        -> no SSH cards AT ALL (nothing to harden).
  * No WiFi hardware         -> wireless cards skipped entirely.
  * UFW active               -> FLAG-not-remove: the working firewall
                                stays; the card only flags the frontend
                                situation for the owner's own call.
  * IPv6 already disabled
    kernel-wide              -> shown as done, not a toggle.
  * break_risk medium+       -> unchecked by default, card carries the
                                "may break your workflow" warning.
  * fresh-install conditions -> auto-checked for FRESH installs only; on
    an existing install the card is a flag pointing at the Harden view
    (reconciliation rule 1: no breaking-posture flip without the owner).

Cards are plain dicts (the shape wizard/changeset.build() consumes):
{"control_id", "title", "what", "nist", "cis", "nist_family", "cis_ref",
 "risk", "checked", "action", "state", "note", "current", "recommended"}
— `current`/`recommended` are the Step-3 preview-table columns, filled
from the scan facts the card already reads and from the rule outcome.
`action` is one of APPLY_ACTION, INSTALL_PROMPT_ACTION, FLAG_ACTION,
DONE_ACTION. Safety tags and plain-english risk strings come straight
from the controls file — the generator never hard-codes a verdict for a
control it was not handed. The `profile` argument tunes presentation
ONLY — Workstation/Hardened/Custom colouring and ordering are W6's
visual layer; the safety rules below are identical for every profile.

Honesty rule: a probe the scan cannot answer (CANT-CHECK / missing key)
means the card is emitted as a WHITE advisory (state CANT-CHECK,
unchecked, flagged) or skipped-with-honesty — never silently treated as
PASS and never fabricated.

Identifier rule: no serials/uuids/MACs pass through; cards carry only
control text from the file and boolean facts from the scan.
"""
from __future__ import annotations

from hardening.controls import Control

_CANT = "CANT-CHECK"      # shared vocabulary with detector/apply
_PASS = "PASS"

PROFILES = frozenset({"workstation", "hardened", "custom"})

APPLY_ACTION = "apply"
INSTALL_PROMPT_ACTION = "install-prompt"
FLAG_ACTION = "flag"
DONE_ACTION = "done"

# The warning sentences are constants, not scattered prose: the tests pin
# them and the UI renders them verbatim. Dictionary (runbook 03): short
# sentences, plain words, no em-dashes.
BREAK_RISK_SENTENCE = "This may break your workflow: review before applying."
UFW_A = "UFW is active, so it stays. The preview never removes it."
UFW_B = "A frontend handover is your call, in the Harden view."
UFW_SENTENCE = UFW_A + " " + UFW_B
NOT_INSTALLED_NOTE = (
    "Not installed: the wizard offers to install it with your click."
)
NOT_INSTALLED_UNKNOWN_NOTE = (
    "Could not tell whether the package is installed. Shown unchecked."
)
IPv6_DONE_NOTE = "IPv6 is already disabled kernel-wide: done, not a toggle."
EXISTING_INSTALL_NOTE = (
    "Existing install: this change waits for your hand in the Harden view."
)
UFW_UNKNOWN_NOTE = (
    "Could not tell whether UFW is active. The probe could not run."
)
FRESH_UNKNOWN_NOTE = (
    "Not sure whether this is a fresh install. The Harden view decides."
)

# adaptive families -> the words that put a control in the family.
# Matching is whole-word over the control's identifying fields
# (id, group, probe, fix) with every non-alphanumeric a token boundary,
# so "assured" can never carry "sshd" and "disable_ipv6" finds ipv6.
_FAMILY_WORDS = {
    "ssh": ("ssh", "sshd", "openssh"),
    "ufw": ("ufw",),
    "ipv6": ("ipv6",),
    "wireless": ("wifi", "wireless", "wlan"),
}

_RISKY = ("medium", "high")


def _words(text: str) -> set[str]:
    lowered = str(text).lower()
    for ch in "-_. /[]{},:'\"":
        lowered = lowered.replace(ch, " ")
    # keep dotted sysctl keys one token: "net.ipv6.conf.all.disable_ipv6"
    # becomes "net", "ipv6.conf.all.disable_ipv6" — so re-split what is
    # left on dots when the word itself carries a dot.
    out: set[str] = set()
    for tok in lowered.split():
        out.update(part for part in tok.split(".") if part)
    return out


def _is_family(control: Control, family: str) -> bool:
    """Does this control belong to the named adaptive family?"""
    tokens: set[str] = set()
    for text in (control.id, control.group, control.probe, *control.fix):
        for part in (text if isinstance(text, (list, tuple)) else (text,)):
            tokens |= _words(part)
    return bool(tokens & set(_FAMILY_WORDS[family]))


# ── scan-value access ───────────────────────────────────────────────────
def _value(scan_result, key, kind):
    """Pull one probe answer out of the scan, or None when unknown.

    scan_result may store (a) the ProbeResult objects wizard/detector.py
    produces — honesty states are honoured, only PASS values count —
    or (b) already-distilled values (bool/str/dict) for table-driven
    tests. A value of the wrong kind is unknown, never coerced.
    """
    raw = scan_result.get(key) if isinstance(scan_result, dict) \
        else getattr(scan_result, key, None)
    if raw is None:
        return None
    state = getattr(raw, "state", None)
    if state is not None:  # a ProbeResult: only PASS values are answers
        if state != _PASS:
            return None
        raw = getattr(raw, "value", None)
    if kind is bool and isinstance(raw, bool):
        return raw
    if kind is str and isinstance(raw, str):
        return raw
    if kind is dict and isinstance(raw, dict):
        return raw
    return None


def _pkg_installed(pkgs, name: str):
    """'Is <name> installed?' from the scan's package map. Two shapes are
    accepted per entry: a plain bool, or a ProbeResult (honesty honoured);
    anything else — including the key's absence — is unknown (None)."""
    if not isinstance(pkgs, dict):
        return None
    return _value(pkgs, name, bool)


# ── risk string ─────────────────────────────────────────────────────────
def _risk_text(control: Control) -> str:
    risk = (control.break_risk or "").lower()
    severity = (control.severity or "").upper()
    if risk in _RISKY:
        return f"Break risk {risk}. {BREAK_RISK_SENTENCE}"
    if severity in ("HIGH", "CRITICAL"):
        return f"Severity {severity.lower()}: this closes a real lane."
    if risk == "none":
        return "Break risk none: should not change how you work."
    return f"Break risk {risk or 'unknown'}: read the card before applying."


# ── card assembly ───────────────────────────────────────────────────────
_ACTION_RECOMMENDED = {
    APPLY_ACTION: "Apply",
    FLAG_ACTION: "Flag only: nothing is touched",
    INSTALL_PROMPT_ACTION: "Install with your one click",
    DONE_ACTION: "Nothing to do: already in place",
}


def _recommended(card: dict) -> str:
    card["recommended"] = _ACTION_RECOMMENDED[card["action"]]
    return card


def _base_card(control: Control) -> dict:
    return {
        "control_id": control.id,
        "title": control.what,
        "what": control.what,
        "nist": list(control.nist),
        "cis": list(control.cis),
        "nist_family": control.nist_family or control.family,
        "cis_ref": control.cis_ref or ("; ".join(control.cis) or None),
        "risk": _risk_text(control),
        "checked": False,
        "action": APPLY_ACTION,
        "state": _PASS,
        "note": "",
        "current": "",
        "recommended": _ACTION_RECOMMENDED[APPLY_ACTION],
    }


def _white_card(control: Control, note: str, action: str) -> dict:
    card = _base_card(control)
    card["state"] = _CANT
    card["action"] = action
    card["note"] = note
    return _recommended(card)


def generate(scan_result, controls, profile: str = "workstation") -> list:
    """Adaptive baseline: the Step-3 card list.

    scan_result keys (values may be distilled or ProbeResult-shaped):
      "packages"      dict pkg-name -> installed bool (or probe results)
      "fresh_install" bool (None = cannot tell)
      "wireless"      bool (WiFi hardware present; None = cannot tell)
      "ufw_status"    str ("active" / "inactive" / other word)
      "ipv6_disable"  str (sysctl net.ipv6.conf.all.disable_ipv6 value)
    controls: list[Control] from hardening.controls.load_controls().
    profile: workstation | hardened | custom — the wizard's role
      selector; the adaptive rules above are the same for every profile
      (the profile tunes presentation, never safety).
    """
    if profile not in PROFILES:
        raise ValueError(
            f"profile must be one of {sorted(PROFILES)}, got {profile!r}")

    pkgs = _value(scan_result, "packages", dict) or {}
    fresh = _value(scan_result, "fresh_install", bool)

    cards = []
    for control in controls:
        ssh_card = _is_family(control, "ssh")
        ufw_card = _is_family(control, "ufw")
        ipv6_card = _is_family(control, "ipv6")
        wireless_card = _is_family(control, "wireless")

        # rule: SSH not installed -> skip SSH cards entirely. Both
        # package aliases count: "openssh-server" (the deb name) and
        # "sshd" (the rpm/generic server name). A card is skipped when
        # NO alias is installed, and at least one says so explicitly.
        if ssh_card:
            ssh_states = [_pkg_installed(pkgs, alias)
                         for alias in ("openssh-server", "sshd")]
            if any(state is True for state in ssh_states):
                pass          # SSH exists: the cards stay.
            elif any(state is False for state in ssh_states) and \
                    all(state is False for state in ssh_states
                        if state is not None):
                continue      # explicitly not installed anywhere: skip.
            # all-unknown stays: absence was never asserted.
        # rule: no WiFi hardware -> skip wireless cards. Unknown hardware
        # (CANT / missing) is not asserted absence, so the card stays.
        if wireless_card \
                and _value(scan_result, "wireless", bool) is False:
            continue

        # rule: UFW active -> flag-not-remove, verbatim sentence.
        ufw_current = ""
        if ufw_card:
            status = _value(scan_result, "ufw_status", str)
            if status == "active":
                card = _base_card(control)
                card["action"] = FLAG_ACTION
                card["note"] = UFW_SENTENCE
                card["current"] = "UFW active"
                card["recommended"] = _ACTION_RECOMMENDED[FLAG_ACTION]
                cards.append(card)
                continue
            if status is None:
                cards.append(_white_card(control, UFW_UNKNOWN_NOTE,
                                         FLAG_ACTION))
                continue
            # inactive / other word: falls through, carrying the fact
            # into the generic card below.
            ufw_current = f"UFW {status}"

        # condition: not-installed:<pkg> (ClamAV) -> install prompt.
        if control.condition.startswith("not-installed:"):
            pkg = control.condition.split(":", 1)[1].strip()
            installed = _pkg_installed(pkgs, pkg)
            if installed is False:
                card = _base_card(control)
                card["action"] = control.action or INSTALL_PROMPT_ACTION
                card["note"] = NOT_INSTALLED_NOTE
                card["current"] = f"{pkg}: not installed"
                card["recommended"] = _ACTION_RECOMMENDED[card["action"]]
                cards.append(card)
                continue
            if installed is True:
                continue  # condition does not apply — no card at all
            cards.append(_white_card(control, NOT_INSTALLED_UNKNOWN_NOTE,
                                     FLAG_ACTION))
            continue

        # condition: fresh-install (IPv6 block-all).
        if control.condition == "fresh-install":
            disable = _value(scan_result, "ipv6_disable", str)
            if ipv6_card and disable == "1":
                # rule: already disabled -> done, not a toggle.
                card = _base_card(control)
                card["action"] = DONE_ACTION
                card["note"] = IPv6_DONE_NOTE
                card["current"] = "IPv6 disabled kernel-wide (value 1)"
                card["recommended"] = _ACTION_RECOMMENDED[DONE_ACTION]
                cards.append(card)
                continue
            if fresh is True:
                card = _base_card(control)
                card["current"] = (
                    f"IPv6 value {disable}" if disable is not None else "")
                if control.default is True:
                    card["checked"] = True   # auto-checked, fresh only
                cards.append(card)
                continue
            # existing (or unknowable) install: flag, never flip silently.
            card = _base_card(control)
            card["action"] = FLAG_ACTION
            card["note"] = EXISTING_INSTALL_NOTE if fresh is False \
                else FRESH_UNKNOWN_NOTE
            card["current"] = (f"IPv6 value {disable}"
                               if disable is not None else
                               f"IPv6 value unknown (sysctl)")
            if fresh is None:
                card["state"] = _CANT
            card["recommended"] = _ACTION_RECOMMENDED[FLAG_ACTION]
            cards.append(card)
            continue

        # generic controls: pre-check per default, but break_risk medium+
        # is unchecked by default (the warning already sits in the risk
        # text); FLAG-ONLY / advisory cards flag, never apply.
        card = _base_card(control)
        if ufw_current:
            card["current"] = ufw_current
        if control.default == "FLAG-ONLY" or control.advisory:
            card["action"] = FLAG_ACTION
        else:
            card["checked"] = (control.default is True) \
                and (control.break_risk or "").lower() not in _RISKY
        cards.append(_recommended(card))
    return cards
