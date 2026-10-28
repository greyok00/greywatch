from __future__ import annotations

import fnmatch
import json
import os
import pathlib
import re
import time
from dataclasses import dataclass

from .base import ACTIONS, DURATIONS


IP_RE = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)" \
        r"(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"


class ValidationError(ValueError):
    pass


OP_KINDS = ("process.path", "dst.host", "dst.ip", "dst.port", "protocol")
HOST_RE = r"^[A-Za-z0-9*._-]{1,120}$"
RULE_NAME_RE = r"^[A-Za-z0-9_.-]{1,80}$"


@dataclass
class Rule:
    name: str
    action: str
    duration: str
    op_kind: str
    op_value: str
    created: int = 0


def validate(name, action, duration, op_kind, op_value) -> Rule:
    if action not in ACTIONS:
        raise ValidationError(f"action invalid: {action!r}")
    if duration not in DURATIONS:
        raise ValidationError(f"duration invalid: {duration!r}")
    if op_kind not in OP_KINDS:
        raise ValidationError(f"op_kind invalid: {op_kind!r}")
    if not isinstance(op_value, str) or not op_value.strip():
        raise ValidationError("op_value is mandatory (empty operator rule "
                              "matches nothing — the 10x-clicks bug)")
    op_value = op_value.strip()
    if op_kind == "dst.host" and not re.match(HOST_RE, op_value):
        raise ValidationError(f"host invalid: {op_value!r}")
    if op_kind == "dst.ip" and "*" not in op_value \
            and not re.match(IP_RE, op_value) and ":" not in op_value:
        raise ValidationError(f"ip invalid: {op_value!r}")
    if op_kind == "dst.port":
        if not op_value.isdigit() or not 1 <= int(op_value) <= 65535:
            raise ValidationError(f"port invalid: {op_value!r}")
    if op_kind == "protocol" and op_value not in ("tcp", "udp", "icmp"):
        raise ValidationError(f"protocol invalid: {op_value!r}")
    if op_kind == "process.path":
        if len(op_value) > 200 or any(c in op_value for c in "\x00\n;|&$"):
            raise ValidationError(f"path invalid: {op_value!r}")
    if not re.match(RULE_NAME_RE, name):
        name = re.sub(r"[^A-Za-z0-9_.-]", "-", name)[:80] or "unnamed-rule"
    return Rule(name=name, action=action, duration=duration,
                op_kind=op_kind, op_value=op_value,
                created=int(time.time()))


def matches(rule: Rule, conn) -> bool:
    v = rule.op_value
    if rule.op_kind == "process.path":
        val = str(conn.process_path or "")
    elif rule.op_kind == "dst.host":
        # conn.dst_host is only filled when something resolved a name; the
        # engine works in addresses, so a host/address rule has to compare
        # against conn.host or every site rule silently never matches
        # ("Block this site" did nothing, 2026-10-28).
        val = str(conn.host or "")
    elif rule.op_kind == "dst.ip":
        val = str(conn.dst_ip or "")
    elif rule.op_kind == "dst.port":
        return str(conn.dst_port or 0) == v
    elif rule.op_kind == "protocol":
        return str(conn.protocol or "").lower() == v.lower()
    else:
        val = ""
    if any(c in v for c in "*?"):
        return fnmatch.fnmatch(val.lower(), v.lower())
    return val.lower() == v.lower()


def _address_like(value: str) -> bool:
    value = str(value or "")
    return bool(value) and ("*" in value or ":" in value
                            or re.match(IP_RE, value))


def rule_from_decision(conn, action: str, duration: str,
                       host: str | None = None) -> Rule:
    if host:
        # The engine works in addresses; a site rule is an address rule
        # unless something really resolved a name.
        kind = "dst.ip" if _address_like(host) else "dst.host"
        return validate(f"appfw-site-{host}", action, duration, kind, host)
    path = str(conn.process_path or "")
    if not path:
        # An empty path would be a catch-all "rule" that validates to
        # nothing and matches no connection — refuse it instead of
        # writing a phantom.
        raise ValidationError("no process path and no host to remember")
    return validate(f"appfw-app-{pathlib.Path(path).name}",
                    action, duration, "process.path", path)


def _to_dict(rule: Rule) -> dict:
    return {"name": rule.name, "action": rule.action,
            "duration": rule.duration, "op_kind": rule.op_kind,
            "op_value": rule.op_value, "created": rule.created}


def _from_dict(d: dict) -> Rule:
    return validate(d.get("name", "unnamed"), d.get("action", "deny"),
                    d.get("duration", "always"),
                    d.get("op_kind"), d.get("op_value", ""))


class RuleStore:
    ALLOW_FILE = "allow-always.json"
    DENY_FILE = "deny-always.json"
    SESSION_FILE = "session-only.json"
    PENDING_FILE = "learning-pending.json"

    def __init__(self, rules_dir):
        self.dir = pathlib.Path(rules_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.memory: list[Rule] = []      # session-only (until restart)
        self._pending: dict[str, Rule] = {}
        self._allow: dict[str, Rule] = {}
        self._deny: dict[str, Rule] = {}
        self.load_errors: list[str] = []
        self.legacy_migrate()
        self.reload()

    def _write(self, fname: str, rules: list[Rule]) -> None:
        from schemas.validate import validate_rules
        from appfw.atomicio import write_json_atomic
        doc = {"kind": fname.replace(".json", ""),
               "rules": [_to_dict(r) for r in rules]}
        errs = validate_rules(doc)
        if errs:                        # schema gate BEFORE anything hits disk
            self.load_errors.extend(f"{fname} write refused: {e}" for e in errs)
            return
        write_json_atomic(self.dir / fname, doc)

    def _load_kind(self, fname: str, bucket: dict) -> None:
        p = self.dir / fname
        try:
            if not p.exists():
                return
        except OSError as e:
            # EACCES on exists() (e.g. 0700 root-owned dir seen by a
            # non-root probe): treat as "no rules" — NOT a crash. The
            # root daemon reads these fine; an unprivileged test probe
            # must not take the engine down.
            self.load_errors.append(f"{fname}: inaccessible ({e}) — skipped")
            return
        try:
            doc = json.loads(p.read_text())
        except (OSError, ValueError) as e:
            self.load_errors.append(f"{fname}: unreadable ({e}) — skipped")
            return
        entries = doc.get("rules", []) if isinstance(doc, dict) else doc
        if not isinstance(entries, list):
            self.load_errors.append(f"{fname}: not a rules container")
            return
        for i, entry in enumerate(entries):
            try:
                rule = _from_dict(entry)
            except (ValueError, ValidationError, KeyError, TypeError,
                    AttributeError) as e:
                self.load_errors.append(f"{fname}[{i}]: skipped ({e})")
                continue
            bucket[rule.name] = rule

    def legacy_migrate(self) -> None:
        try:
            legacy = [p for p in sorted(self.dir.glob("*.json"))
                      if p.name not in (self.ALLOW_FILE, self.DENY_FILE,
                                        self.SESSION_FILE, self.PENDING_FILE)
                      and not p.name.endswith(".tmp")]
        except OSError:
            return                         # dir unreadable: nothing to migrate
        if not legacy:
            return
        self._load_kind(self.ALLOW_FILE, self._allow)
        self._load_kind(self.DENY_FILE, self._deny)
        moved: dict[str, list[Rule]] = {"allow": [], "deny": []}
        for p in legacy:
            try:
                rule = _from_dict(json.loads(p.read_text()))
            except (OSError, ValueError, ValidationError):
                continue
            moved["allow" if rule.action == "allow" else "deny"].append(rule)
        backup = self.dir / "legacy-backup"
        backup.mkdir(exist_ok=True)
        for p in legacy:
            try:
                os.replace(str(p), str(backup / p.name))
            except OSError:
                self.load_errors.append(f"legacy-backup failed: {p.name}")
        if moved["allow"]:
            self._allow.update({r.name: r for r in moved["allow"]})
            self._write(self.ALLOW_FILE, list(self._allow.values()))
        if moved["deny"]:
            self._deny.update({r.name: r for r in moved["deny"]})
            self._write(self.DENY_FILE, list(self._deny.values()))

    def reload(self) -> None:
        self._allow, self._deny, self._pending = {}, {}, {}
        self.load_errors = []
        self._load_kind(self.ALLOW_FILE, self._allow)
        self._load_kind(self.DENY_FILE, self._deny)
        self._load_kind(self.PENDING_FILE, self._pending)
        self._load_kind(self.SESSION_FILE, {})   # recorded, not trusted

    def _known(self) -> set:
        rules = [*self._allow.values(), *self._deny.values(),
                 *self._pending.values(), *self.memory]
        return {(r.op_kind, r.op_value.lower()) for r in rules}

    def add(self, rule: Rule) -> None:
        if (rule.op_kind, rule.op_value.lower()) in self._known():
            return
        if rule.duration == "always":
            bucket = self._allow if rule.action == "allow" else self._deny
            bucket[rule.name] = rule
            self._write(self.ALLOW_FILE if rule.action == "allow"
                        else self.DENY_FILE, list(bucket.values()))
        elif rule.duration == "until restart":
            self.memory.append(rule)
            self._write(self.SESSION_FILE, self.memory)
        else:
            raise ValidationError(
                "duration 'once' never becomes a stored rule")

    def add_pending(self, rule: Rule) -> None:
        if (rule.op_kind, rule.op_value.lower()) in self._known():
            return
        self._pending[rule.name] = rule
        self._write(self.PENDING_FILE, list(self._pending.values()))

    def approve_pending(self, name: str) -> bool:
        rule = self._pending.pop(name, None)
        if rule is None:
            return False
        self._write(self.PENDING_FILE, list(self._pending.values()))
        persisted = validate(rule.name, "allow", "always",
                             rule.op_kind, rule.op_value)
        self._allow.setdefault(persisted.name, persisted)
        self._write(self.ALLOW_FILE, list(self._allow.values()))
        return True

    def revoke_pending(self, name: str) -> bool:
        rule = self._pending.pop(name, None)
        if rule is None:
            return False
        self._write(self.PENDING_FILE, list(self._pending.values()))
        return True

    def remove(self, name_or_prefix: str) -> int:
        n = 0
        for bucket, fname in ((self._allow, self.ALLOW_FILE),
                              (self._deny, self.DENY_FILE)):
            doomed = [k for k in bucket if k == name_or_prefix
                      or k.startswith(name_or_prefix)]
            for k in doomed:
                bucket.pop(k)
                n += 1
            self._write(fname, list(bucket.values()))
        return n

    def all_rules(self, include_session: bool = True) -> list[Rule]:
        rules = [*self._allow.values(), *self._deny.values()]
        if include_session:
            rules += self.memory
        rules.sort(key=lambda r: r.created, reverse=True)
        return rules

    def pending_rules(self) -> list[Rule]:
        return sorted(self._pending.values(), key=lambda r: r.created,
                      reverse=True)

    def decide(self, conn) -> Rule | None:
        for rule in self.all_rules():
            if matches(rule, conn):
                return rule
        return None

    def session_reset(self) -> int:
        n = len(self.memory)
        self.memory.clear()
        try:
            self._write(self.SESSION_FILE, [])
        except Exception:
            pass
        return n

    def session_purge(self) -> int:
        return self.session_reset()
