"""REAL system information for the wizards (owner 2026-10-23: "this is not
something anyone would know off the top of their head... it should not
require me typing anything").

Every list here is read from THIS computer: interfaces from the kernel,
neighbours from the ARP table, ports from the listening sockets, programs
from the desktop entries and /proc, logs from disk, services from systemd,
and sites from the connections that are open right now. Nothing is invented
and nothing raises: a missing tool simply yields an empty list.
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess

# ── small robust runner ─────────────────────────────────────────────────
def _run(argv, timeout=4) -> str:
    try:
        out = subprocess.run(argv, capture_output=True, text=True,
                             timeout=timeout)
        return out.stdout or ""
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""


# ── network devices ─────────────────────────────────────────────────────
# The kernel's own list. Virtual plumbing (veth pairs, docker bridges) is
# noise for an ARP watcher, so it is filtered out; Wi-Fi sorts first.
_VIRTUAL = re.compile(r"^(lo|veth|docker|br-|virbr|tun|tap|zt)")


SYS_NET = "/sys/class/net"


def parse_interfaces(names) -> list:
    out = []
    for name in names:
        if not name or _VIRTUAL.match(name):
            continue
        wireless = pathlib.Path(f"{SYS_NET}/{name}/wireless").exists()
        label = f"{name} ({'Wi-Fi' if wireless else 'wired'})"
        out.append({"name": name, "label": label, "wireless": wireless})
    out.sort(key=lambda i: (not i["wireless"], i["name"]))
    return out


def interfaces() -> list:
    try:
        names = os.listdir(SYS_NET)
    except OSError:
        names = []
    return parse_interfaces(names)


# ── this LAN's computers ────────────────────────────────────────────────
def parse_neighbors(text: str) -> list:
    """`ip neigh show` → usable hosts (skip FAILED / INCOMPLETE / docker)."""
    out, seen = [], set()
    for line in str(text or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        ip, dev = parts[0], ""
        if "dev" in parts:
            dev = parts[parts.index("dev") + 1]
        if _VIRTUAL.match(dev or "lo"):
            continue
        state = parts[-1].upper()
        if state in ("FAILED", "INCOMPLETE", "NOARP") or ip in seen:
            continue
        mac = ""
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]
        seen.add(ip)
        out.append({"ip": ip, "mac": mac, "iface": dev,
                    "reachable": state == "REACHABLE"})
    out.sort(key=lambda h: (not h["reachable"], h["ip"]))
    return out


def lan_hosts() -> list:
    return parse_neighbors(_run(["ip", "neigh", "show"]))


# ── ports that are actually open on this machine ────────────────────────
PORT_NAMES = {
    22: "SSH remote login", 53: "DNS", 80: "web", 443: "secure web",
    3306: "database", 5432: "database", 8080: "web app", 8443: "secure web app",
    8795: "a service already listening here",
}


def parse_listening(text: str) -> list:
    """`ss -tlnH` → ports bound on ALL addresses (reachable from outside)."""
    ports = {}
    for line in str(text or "").splitlines():
        fields = line.split()
        if not fields:
            continue
        local = fields[3] if len(fields) >= 4 else ""
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        if addr in ("127.0.0.1", "[::1]", "::1") or addr.startswith("127."):
            continue
        ports.setdefault(int(port), addr or "*")
    return [{"port": p, "addr": a,
             "label": f"{p} · {PORT_NAMES[p]}" if p in PORT_NAMES
             else f"{p} · a service listening here"}
            for p, a in sorted(ports.items())]


def external_ports() -> list:
    return parse_listening(_run(["ss", "-tlnH"]))


# ── sites this computer is talking to RIGHT NOW ─────────────────────────
def parse_established(text: str) -> list:
    ips = []
    for line in str(text or "").splitlines():
        fields = line.split()
        if len(fields) < 5:                 # State Recv-Q Send-Q Local Peer
            continue
        peer = fields[4]
        addr, _, port = peer.rpartition(":")
        if port.isdigit() and int(port) in (80, 443) \
                and not addr.startswith(("127.", "[::1]", "::1")):
            if addr not in ips:
                ips.append(addr)
    return ips[:10]


def connected_sites() -> list:
    """Reverse names for open web connections (the sites in use right now).
    A name that cannot be resolved is left out — no invented entries."""
    out = []
    for ip in parse_established(_run(["ss", "-tnH", "state", "established"])):
        raw = _run(["getent", "hosts", ip], timeout=2).strip()
        name = raw.split()[1].rstrip(".") if len(raw.split()) > 1 else ""
        if name and name not in out:
            out.append(name)
    return out


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        host = urlsplit(str(url or "")).hostname or ""
    except ValueError:
        return ""
    host = host.lower().rstrip(".")
    # a plain site name only: no localhost, no bare addresses
    if "." not in host or host in ("localhost",) or re.fullmatch(
            r"[\d.]+", host):
        return ""
    return host


def browser_sites(limit=40) -> list:
    """Sites this person actually visited, read from the browser's OWN
    history on this disk (copied first — the live file is locked). Local
    only; nothing is sent anywhere."""
    import sqlite3
    import shutil
    import tempfile

    dbs = []
    try:
        for prof in pathlib.Path.home().glob(".mozilla/firefox/*.default*"):
            p = prof / "places.sqlite"
            if p.is_file():
                # audit: log-only — SQL for the local history DB, never UI
                dbs.append((p, "SELECT host FROM moz_places "
                               "WHERE host IS NOT NULL "
                               "ORDER BY last_visit_date DESC LIMIT 200"))
    except OSError:
        pass
    for pattern in (".config/chromium*/Default/History",
                    ".config/BraveSoftware/*/Default/History"):
        try:
            for p in pathlib.Path.home().glob(pattern):
                if p.is_file():
                    dbs.append((p, "SELECT url FROM urls "
                                   "ORDER BY last_visit_time DESC LIMIT 200"))
        except OSError:
            continue
    out, seen = [], set()
    for path, query in dbs:
        tmp = ""
        try:
            fd, tmp = tempfile.mkstemp(prefix="gw-hist-")
            os.close(fd)
            shutil.copyfile(path, tmp)
            con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            try:
                rows = con.execute(query).fetchall()
            finally:
                con.close()
        except (OSError, sqlite3.Error, ValueError):
            rows = []
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        for (value,) in rows:
            host = (str(value).lower().rstrip(".")
                    if query.startswith("SELECT host") else _host_of(value))
            if host and "." in host and host not in seen:
                seen.add(host)
                out.append(host)
        if len(out) >= limit:
            break
    return out[:limit]


def site_choices() -> list:
    """Everything the wizard can offer for a site, best first: what the
    person already decided, what is in use now, then recent history."""
    out, seen = [], set()
    try:
        from ui.settings import TrustList
        tl = TrustList()
        for e in sorted(tl.allow | tl.block):
            out.append({"host": e, "why": "already on your list"})
            seen.add(e)
    except (OSError, ValueError):
        pass
    for host in connected_sites():
        if host not in seen:
            out.append({"host": host, "why": "in use right now"})
            seen.add(host)
    for host in browser_sites():
        if host not in seen:
            out.append({"host": host, "why": "recently visited"})
            seen.add(host)
    return out


# ── programs: installed desktop entries + what is running now ───────────
def _exec_path(exec_line: str) -> str:
    """Desktop `Exec=` → the real program path (field codes stripped)."""
    line = str(exec_line or "").strip()
    if not line:
        return ""
    token = line.split()[0].strip('"')
    if token.startswith("/"):
        return token if os.path.isfile(token) and os.access(token, os.X_OK) else ""
    found = shutil.which(token)
    return found or ""


def parse_desktop(files) -> list:
    """files = iterable of (path, text). Returns [(friendly, program)]."""
    out, seen = [], set()
    for _path, text in files:
        name, exec_line = "", ""
        for line in str(text or "").splitlines():
            if line.startswith("Name=") and not name:
                name = line[5:].strip()
            elif line.startswith("Exec=") and not exec_line:
                exec_line = line[5:].strip()
            elif line.startswith("NoDisplay=true"):
                name = ""
                break
        prog = _exec_path(exec_line)
        if not prog or prog in seen:
            continue
        seen.add(prog)
        out.append((name or os.path.basename(prog), prog))
    out.sort(key=lambda x: x[0].lower())
    return out


def _desktop_files():
    dirs = [pathlib.Path("/usr/share/applications"),
            pathlib.Path.home() / ".local/share/applications"]
    for d in dirs:
        try:
            for f in sorted(d.glob("*.desktop")):
                try:
                    yield (f, f.read_text(errors="replace"))
                except OSError:
                    continue
        except OSError:
            continue


def running_programs() -> list:
    out, seen = [], set()
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return []
    for pid in pids:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        exe = exe.removesuffix(" (deleted)")
        if not exe.startswith("/") or exe in seen:
            continue
        seen.add(exe)
        out.append(exe)
    return out


def programs(limit=400) -> list:
    """Friendly name + real path, installed apps first, then running ones."""
    found = {}
    for friendly, prog in parse_desktop(_desktop_files()):
        found.setdefault(prog, friendly)
    for prog in running_programs():
        found.setdefault(prog, os.path.basename(prog))
    items = sorted(found.items(), key=lambda kv: kv[1].lower())
    return [{"label": f"{name} · {path}", "name": name, "path": path}
            for path, name in items[:limit]]


# ── logs and services ───────────────────────────────────────────────────
def log_files(limit=80) -> list:
    """Real log files on this disk (existence only; the helper reads them)."""
    out = []
    try:
        for p in sorted(pathlib.Path("/var/log").glob("*.log")):
            if p.is_file():
                out.append(str(p))
    except OSError:
        pass
    for p in ("/var/log/fail2ban.log", "/var/log/aide/aide.log"):
        if pathlib.Path(p).is_file() and p not in out:
            out.append(p)
    return out[:limit]


def journal_units(limit=120) -> list:
    text = _run(["systemctl", "list-units", "--type=service",
                 "--state=running", "--no-legend", "--no-pager"])
    out = []
    for line in text.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.endswith(".service") and name not in out:
            out.append(name)
    return out[:limit]


def enabled_jails() -> list:
    """Jails already switched on in /etc/fail2ban (plain names, real file)."""
    out = []
    for d in (pathlib.Path("/etc/fail2ban/jail.d"),
              pathlib.Path("/etc/fail2ban/jail.local")):
        files = sorted(d.glob("*.conf")) + sorted(d.glob("*.local")) \
            if d.is_dir() else ([d] if d.is_file() else [])
        for f in files:
            try:
                lines = f.read_text(errors="replace").splitlines()
            except OSError:
                continue
            current = None
            for line in lines:
                s = line.strip()
                if s.startswith("[") and s.endswith("]"):
                    current = s[1:-1]
                elif current and re.match(r"^enabled\s*=\s*true$", s):
                    if current.upper() != "DEFAULT" and current not in out:
                        out.append(current)
    return out


# ── ready-made YARA rules (every one compiles with the real scanner) ────
YARA_PRESETS = [
    {"key": "eicar", "title": "The EICAR test virus",
     "about": "The harmless industry test string. Proves the scanner works "
              "end to end.",
     "strings": ['$a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"'],
     "condition": "$a"},
    {"key": "elf", "title": "Any Linux program",
     "about": "Flags any program file. For folders that should only hold "
              "documents.",
     "strings": [], "condition": "uint32(0) == 0x464c457f"},
    {"key": "script", "title": "Any shell script",
     "about": "Flags files that begin with a shell interpreter line.",
     "strings": ['$sh = "#!/bin/sh"', '$bash = "#!/bin/bash"'],
     "condition": "$sh at 0 or $bash at 0"},
    {"key": "webshell", "title": "A hidden web back door",
     "about": "Looks for calls web shells use to run commands.",
     "strings": ['$a = "eval($_POST"', '$b = "base64_decode("',
                 '$c = "passthru("'],
     "condition": "2 of ($a, $b, $c)"},
    {"key": "reverseshell", "title": "A reverse-shell one-liner",
     "about": "Looks for commands that call a shell back to an attacker.",
     "strings": ['$a = "/dev/tcp/"', '$b = "nc -e /bin/sh"',
                 '$c = "bash -i"'],
     "condition": "2 of ($a, $b, $c)"},
    {"key": "ransomnote", "title": "A ransomware note",
     "about": "Looks for the words ransom notes use together.",
     "strings": ['$a = "your files have been encrypted" nocase',
                 '$b = "bitcoin" nocase', '$c = "decrypt" nocase'],
     "condition": "2 of ($a, $b, $c)"},
]


def yara_preset(key: str) -> dict | None:
    return next((p for p in YARA_PRESETS if p["key"] == key), None)


def yara_name(key: str, rules_dir=None) -> str:
    """A valid, unused rule name — the person never types one."""
    rules_dir = str(rules_dir or pathlib.Path.home() / "yara-rules")
    base = "gw_" + re.sub(r"[^A-Za-z0-9_]", "_", key or "rule")
    name, n = base, 1
    while pathlib.Path(rules_dir, name + ".yar").exists():
        n += 1
        name = f"{base}_{n}"
    return name


def yara_source(key: str, name: str) -> str:
    preset = yara_preset(key)
    if not preset:
        return ""
    parts = [f"rule {name} {{\n",
             f"    meta:\n",
             f"        description = \"{preset['title']}\"\n"]
    if preset["strings"]:            # an empty strings: section is invalid
        parts.append("    strings:\n")
        parts.extend("        " + s + "\n" for s in preset["strings"])
    parts.append(f"    condition:\n        {preset['condition']}\n")
    parts.append("}\n")
    return "".join(parts)


# ── fail2ban: plain-English patterns with their real regex ──────────────
F2B_PATTERNS = [
    {"key": "failed-login",
     "title": "Failed login attempts",
     "about": "Matches the usual SSH and system password failure lines.",
     "regex": r".*Failed \S+ for .*? from <HOST>.*"},
    {"key": "password-failure",
     "title": "Password failures from one address",
     "about": "Matches PAM's authentication-failure lines with a remote "
              "address.",
     "regex": r".*(?:authentication failure|password mismatch).*rhost=<HOST>.*"},
    {"key": "web-attack",
     "title": "Requests for known attack paths",
     "about": "Matches web requests that try to climb folders or read "
              "password files.",
     "regex": r"<HOST> .*\"(?:GET|POST) [^\"]*(?:\.\./|/etc/passwd|"
              r"/wp-login\.php)[^\"]*\".*"},
    {"key": "bans",
     "title": "Lines that record a ban",
     "about": "Matches fail2ban's own 'Ban <address>' lines.",
     "regex": r".*\bBan\s+<HOST>.*"},
]


def f2b_pattern(key: str) -> dict | None:
    return next((p for p in F2B_PATTERNS if p["key"] == key), None)


def f2b_name(source: str) -> str:
    """Jail name derived from what it watches — no typing."""
    stem = (source or "log").rsplit(":", 1)[-1].rsplit("/", 1)[-1]
    stem = stem.replace(".service", "").replace(".log", "")
    stem = re.sub(r"[^A-Za-z0-9_-]", "-", stem).strip("-") or "log"
    return (stem[:48] + "-guard")[:64]
