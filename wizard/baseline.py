from __future__ import annotations

from hardening.controls import Control

_CANT = "CANT-CHECK"      # shared vocabulary with detector/apply
_PASS = "PASS"

PROFILES = frozenset({"workstation", "hardened", "custom"})

APPLY_ACTION = "apply"
INSTALL_PROMPT_ACTION = "install-prompt"
FLAG_ACTION = "flag"
DONE_ACTION = "done"

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
    out: set[str] = set()
    for tok in lowered.split():
        out.update(part for part in tok.split(".") if part)
    return out


def _is_family(control: Control, family: str) -> bool:
    tokens: set[str] = set()
    for text in (control.id, control.group, control.probe, *control.fix):
        for part in (text if isinstance(text, (list, tuple)) else (text,)):
            tokens |= _words(part)
    return bool(tokens & set(_FAMILY_WORDS[family]))


def _value(scan_result, key, kind):
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
    if not isinstance(pkgs, dict):
        return None
    return _value(pkgs, name, bool)


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

        if ssh_card:
            ssh_states = [_pkg_installed(pkgs, alias)
                         for alias in ("openssh-server", "sshd")]
            if any(state is True for state in ssh_states):
                pass          # SSH exists: the cards stay.
            elif any(state is False for state in ssh_states) and \
                    all(state is False for state in ssh_states
                        if state is not None):
                continue      # explicitly not installed anywhere: skip.
        if wireless_card \
                and _value(scan_result, "wireless", bool) is False:
            continue

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
            ufw_current = f"UFW {status}"

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

        if control.condition == "fresh-install":
            disable = _value(scan_result, "ipv6_disable", str)
            if ipv6_card and disable == "1":
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
            card = _base_card(control)
            card["action"] = FLAG_ACTION
            card["note"] = EXISTING_INSTALL_NOTE if fresh is False \
                else FRESH_UNKNOWN_NOTE
            card["current"] = (f"IPv6 value {disable}"
                               if disable is not None else
                               "IPv6 value unknown (sysctl)")
            if fresh is None:
                card["state"] = _CANT
            card["recommended"] = _ACTION_RECOMMENDED[FLAG_ACTION]
            cards.append(card)
            continue

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
