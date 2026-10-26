from __future__ import annotations

import pathlib
import sys

IP_RE = r"^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$"
JAIL_RE = r"^[A-Za-z0-9_-]{1,64}$"
NAME_RE = r"^[A-Za-z0-9_.-]{1,64}$"


def rules_main(args) -> int:
    tool = getattr(args, "tool", "") or ""
    rest = list(getattr(args, "rest", None) or [])
    if tool == "appfw":
        from wiz.appfw_wizard import appfw_main
        return appfw_main(rest)
    if tool:
        print(f"no wizard yet for {tool!r}; available: appfw", file=sys.stderr)
        return 1
    print("rule wizards: greywatch rules appfw "
          "allow|deny PROGRAM | trust|block SITE | approve | list | remove NAME")
    return 0

UFW_ACTIONS = ("allow", "deny", "reject", "limit")
PROTO = ("tcp", "udp", "icmp")
DIRECTIONS = ("in", "out")


class ValidationError(ValueError):
    pass


def _match(value, pattern, what):
    import re
    if not isinstance(value, str) or not re.match(pattern, value):
        raise ValidationError(f"{what} invalid: {value!r}")
    return value



def ufw_build(spec: dict) -> list:
    action = _match(spec.get("action", ""), r"^(allow|deny|reject|limit)$", "action")
    direction = _match(spec.get("direction", ""), r"^(in|out)$", "direction")
    cmd = ["ufw", action, direction]
    if spec.get("from"):
        _match(spec["from"], IP_RE, "from-ip")
        cmd += ["from", spec["from"]]
    if spec.get("port"):
        port = _match(str(spec["port"]), r"^\d{1,5}$", "port")
        if not 1 <= int(port) <= 65535:
            raise ValidationError(f"port out of range: {port}")
        proto = _match(spec.get("proto", ""), r"^(tcp|udp|icmp)$", "proto")
        cmd += ["to", "any", "port", port, "proto", proto]
    if spec.get("comment"):
        c = spec["comment"]
        if not isinstance(c, str) or len(c) > 64 or any(ch in c for ch in ";|&$\n\\'\""):
            raise ValidationError("comment invalid")
        cmd += ["comment", c]
    return cmd


def ufw_exact_string(spec: dict) -> str:
    return " ".join(ufw_build(spec))


def ufw_rollback(cmd: list) -> list:
    return ["ufw", "delete", "@num"]



def fail2ban_jail(jail: str, bantime: int, findtime: int, maxretry: int,
                  logpath: str, filter_name: str) -> list:
    _match(jail, JAIL_RE, "jail")
    for name, val in (("bantime", bantime), ("findtime", findtime)):
        if not isinstance(val, int) or val < 1 or val > 8640000:
            raise ValidationError(f"{name} out of range: {val}")
    if not isinstance(maxretry, int) or not 1 <= maxretry <= 10000:
        raise ValidationError(f"maxretry out of range: {maxretry}")
    if not isinstance(logpath, str) or any(ch in logpath for ch in "\n;|&$\x00"):
        raise ValidationError("logpath invalid")
    return [
        f"[{jail}]",
        "enabled = true",
        f"filter  = {filter_name}",
        f"logpath = {logpath}",
        f"maxretry = {maxretry}",
        f"findtime = {findtime}",
        f"bantime  = {bantime}",
    ]


def fail2ban_filter(pattern: str) -> list:
    if not isinstance(pattern, str) or not (1 <= len(pattern) <= 400):
        raise ValidationError("pattern invalid")
    for ch in "\n;|&$\x00":
        if ch in pattern:
            raise ValidationError("pattern contains forbidden char")
    return [
        f"failregex = ^{pattern}$",
        "ignoreregex =",
    ]



def tetragon_policy(kind: str, name: str, selector: dict, action: str) -> list:
    _match(name, NAME_RE, "name")
    if kind not in ("exec", "connect", "file_write"):
        raise ValidationError("kind invalid")
    if action not in ("log-only", "block"):
        raise ValidationError("action invalid")
    lines = [
        "apiVersion: cilium.io/v1alpha1",
        "kind: TracingPolicy",
        "metadata:",
        f"  name: greywatch-{name}",
        "spec:",
    ]
    if kind == "exec":
        lines += [
            "  kprobes:",
            "  - call: 'security_bprm_check'",
            "    syscall: false",
            "    args:",
            "    - index: 0",
            "      type: string",
            "  message: '" + (f"exec watch {name}" if action == "log-only"
                              else f"block exec {name}") + "'",
        ]
    elif kind == "file_write":
        lines += [
            "  kprobes:",
            "  - call: 'security_file_permission'",
            "    syscall: false",
            "    args:",
            "    - index: 1",
            "      type: int",
            "      return: false",
            f"  message: 'file_write {action} {name}'",
        ]
    else:  # connect
        lines += [
            "  kprobes:",
            "  - call: 'security_socket_connect'",
            "    message: 'connect watch'",
        ]
    if action == "block":
        lines += ["    enforce: true"]
    return lines



def yara_source(rules: dict) -> list:
    lines = []
    for name, body in rules.items():
        _match(name, r"^[A-Za-z0-9_-]{1,64}$", "rule name")
        if not isinstance(body, str) or not (1 <= len(body) <= 2000):
            raise ValidationError(f"rule body bad: {name}")
        for ch in "\x00":
            if ch in body:
                raise ValidationError("rule body contains forbidden bytes")
        lines.append(f"rule {name} {{ {body} }}".replace("\x00", ""))
    return lines


YARA_RULES_DIR = pathlib.Path.home() / "yara-rules"


def yara_index(entries) -> list:
    return [f'include "{e}"' for e in entries]



IFACE_RE = r"^[a-z0-9.]{2,15}$"
ARGS_OK = frozenset({"-N", "-p", "-l", "-d"})


def arpwatch_env_file(iface: str, runas: str, args_list, pcap_filter: str) -> list:
    _match(iface, IFACE_RE, "iface")
    _match(runas, r"^[A-Za-z0-9_-]{1,16}$", "runas")
    for a in args_list:
        if a not in ARGS_OK:
            raise ValidationError(f"arg not allowed: {a!r}")
    if len(pcap_filter) > 200 or any(ch in pcap_filter for ch in "\n;|&$\x00"):
        raise ValidationError("pcap filter invalid")
    lines = [f'RUNAS="{runas}"']
    if args_list:
        lines.append(f'ARGS="{" ".join(sorted(args_list))}"')
    if pcap_filter:
        lines.append(f'PCAP_FILTER="{pcap_filter}"')
    return lines
