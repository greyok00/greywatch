"""Who is on the other end of this connection?

The app-firewall prompt used to say ``57.144.134.145:443`` and nothing
else, so the operator had no idea whether a program was calling a chat
app or a random host in an unknown country (owner report 2026-10-27).
This module turns an address into a plain-words identity:

  * reverse DNS  — ``edge-dgw-shv-01-phx1.facebook.com`` → Facebook
  * whois        — the network's owner, country, range and AS number
  * GeoIP.dat    — a local country table, used only when whois is silent

and turns a program path into the same kind of answer: its display name,
the package it came from, and who owns the file.

Only the five official registry whois servers are contacted — never a
tracking site — and every answer is cached on disk for a week, so a
repeat prompt paints instantly.
"""

from __future__ import annotations

import json
import os
import pathlib
import pwd
import re
import shutil
import socket
import subprocess
import threading
import time

CACHE_TTL = 7 * 24 * 3600
EMPTY_TTL = 3600            # a miss is retried after an hour, not a week
CACHE_VERSION = "v3"        # bump when the shape of an answer changes
WHOIS_TIMEOUT = 6.0
PTR_TIMEOUT = 2.5

# Registry names are not the network's owner: ARIN answers a European
# address with "RIPE Network Coordination Centre" and delegates onward.
_REGISTRY_RE = re.compile(
    r"(ripe network coordination|american registry for internet numbers"
    r"|\barin\b|\bapnic\b|\blacnic\b|\bafrinic\b"
    r"|reserved|internet assigned numbers authority|\biana\b)", re.I)

# Domain → the name a person would recognise. The fallback below
# capitalises the registrable label, which is usually good enough.
_BRANDS = {
    "facebook.com": "Facebook", "fbcdn.net": "Facebook",
    "instagram.com": "Instagram", "whatsapp.net": "WhatsApp",
    "whatsapp.com": "WhatsApp",
    "google.com": "Google", "googleapis.com": "Google",
    "gstatic.com": "Google", "googleusercontent.com": "Google",
    "youtube.com": "YouTube", "ytimg.com": "YouTube",
    "microsoft.com": "Microsoft", "office365.com": "Microsoft Office",
    "office.com": "Microsoft Office", "windowsupdate.com": "Windows Update",
    "live.com": "Microsoft", "msn.com": "Microsoft", "bing.com": "Bing",
    "akamai.net": "Akamai", "akamaiedge.net": "Akamai",
    "akamaihd.net": "Akamai",
    "cloudfront.net": "Amazon", "amazonaws.com": "Amazon",
    "amazon.com": "Amazon", "media-amazon.com": "Amazon",
    "apple.com": "Apple", "icloud.com": "iCloud", "mzstatic.com": "Apple",
    "cloudflare.com": "Cloudflare", "cloudflare.net": "Cloudflare",
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix",
    "github.com": "GitHub", "githubusercontent.com": "GitHub",
    "slack.com": "Slack", "discord.com": "Discord",
    "discordapp.net": "Discord", "spotify.com": "Spotify",
    "steamserver.com": "Steam", "steamcontent.com": "Steam",
    "steampowered.com": "Steam", "mozilla.com": "Mozilla",
    "mozilla.net": "Mozilla", "ubuntu.com": "Ubuntu",
    "canonical.com": "Ubuntu", "snapcraft.io": "Snap Store",
    "dropbox.com": "Dropbox", "zoom.us": "Zoom",
    "telegram.org": "Telegram", "t.me": "Telegram",
    "twitter.com": "X", "x.com": "X", "reddit.com": "Reddit",
    "tiktok.com": "TikTok", "tiktokcdn.com": "TikTok",
    "pinterest.com": "Pinterest", "adobe.com": "Adobe",
    "epicgames.com": "Epic Games", "battle.net": "Blizzard",
    "protonmail.com": "Proton", "proton.me": "Proton",
    "signal.org": "Signal", "skype.com": "Skype",
}

# "example.co.uk" must keep three labels, "example.com" two.
_2LD = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "or.jp", "co.nz", "co.za", "com.br", "com.mx", "com.tr",
})

_ORG_SUFFIX_RE = re.compile(
    r"[,\s]+(inc\.?|llc|ltd\.?|limited|corp\.?|corporation|gmbh|b\.?v\.?|"
    r"s\.?a\.?|n\.?v\.?|ag|plc|co\.?|company|pty\.?|lp|llp)$", re.I)

_ORG_ALIAS_RE = re.compile(
    r"^(facebook|meta platforms|google|alphabet|amazon|aws|microsoft|"
    r"apple|cloudflare|akamai|netflix|ovh|digitalocean|hetzner|"
    r"linode|oracle|ibm|tencent|alibaba|bytedance)", re.I)


# --------------------------------------------------------------------------
# cache
# --------------------------------------------------------------------------

_lock = threading.Lock()
_cache_lock = threading.Lock()


def cache_file() -> pathlib.Path:
    base = os.environ.get("XDG_CACHE_HOME") or (pathlib.Path.home() / ".cache")
    return pathlib.Path(base) / "greywatch" / "whois.json"


def _load_cache() -> dict:
    try:
        doc = json.loads(cache_file().read_text())
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(doc: dict) -> None:
    path = cache_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, separators=(",", ":")))
        os.replace(tmp, path)
    except OSError:
        pass


def cached(key: str):
    with _cache_lock:
        doc = _load_cache()
    rec = doc.get(key)
    if not isinstance(rec, dict):
        return None
    if time.time() - float(rec.get("at") or 0) > (
            EMPTY_TTL if rec.get("empty") else CACHE_TTL):
        return None
    val = rec.get("v")
    return val if isinstance(val, dict) else None


def remember(key: str, value: dict, empty: bool = False) -> None:
    with _cache_lock:
        doc = _load_cache()
        doc[key] = {"at": time.time(), "empty": bool(empty), "v": value}
        if len(doc) > 4000:                     # keep the file bounded
            for k in sorted(doc, key=lambda k: doc[k].get("at") or 0)[:1000]:
                doc.pop(k, None)
        _save_cache(doc)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


def reverse_name(host: str) -> str:
    """PTR lookup with a hard time limit (the libc resolver has none)."""
    if not is_ip(host):
        return ""
    dig = shutil.which("dig")
    if dig:
        try:
            out = subprocess.run([dig, "+short", "-x", host, "+time=2",
                                  "+tries=1"], capture_output=True,
                                 text=True, timeout=PTR_TIMEOUT).stdout
            for line in out.split():
                name = line.strip().rstrip(".")
                if name and not name.startswith(";;"):
                    return name
            return ""
        except (OSError, subprocess.SubprocessError):
            return ""
    try:
        name, _aliases, _addr = socket.gethostbyaddr(host)
        return name.rstrip(".")
    except (OSError, socket.herror):
        return ""


def registrable(name: str) -> str:
    """``edge-1.phx1.facebook.com`` → ``facebook.com``."""
    labels = (name or "").strip(".").split(".")
    if len(labels) < 2:
        return name or ""
    if len(labels) >= 3 and ".".join(labels[-2:]) in _2LD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def brand_for(domain: str) -> str:
    dom = (domain or "").lower()
    if dom in _BRANDS:
        return _BRANDS[dom]
    label = dom.split(".")[0] if dom else ""
    return label[:1].upper() + label[1:] if label else ""


# --------------------------------------------------------------------------
# whois
# --------------------------------------------------------------------------

def parse_whois(text: str) -> dict:
    """Last value wins: the client prints the registry block first and the
    delegated answer (the real holder) after it."""
    got: dict[str, str] = {}
    for raw in (text or "").splitlines():
        if ":" not in raw or raw.lstrip().startswith(("%", "#", ">")):
            continue
        key, val = raw.split(":", 1)
        key = key.strip().lower()
        val = re.sub(r"\s+", " ", val).strip()
        if key and val:
            got[key] = val            # last wins on purpose
    org = ""
    for key in ("org-name", "orgname", "organisation", "organization"):
        if got.get(key):
            org = got[key]
            break
    if not org and got.get("descr"):
        org = got["descr"]
    asn = ""
    for key in ("origin", "originas", "asnumber", "aut-num"):
        val = got.get(key, "")
        if val and val.upper() != "AS-":
            asn = val if val.upper().startswith("AS") else f"AS{val}"
            break
    return {
        "org": org,
        "netname": got.get("netname", ""),
        "country": (got.get("country") or "")[:2].upper(),
        "asn": asn,
        "range": got.get("inetnum") or got.get("netrange") or got.get("cidr") or "",
        "registry_is_owner": bool(org and _REGISTRY_RE.search(org)),
    }


def run_whois(host: str, timeout: float = WHOIS_TIMEOUT) -> str:
    exe = shutil.which("whois")
    if not exe:
        return ""
    try:
        done = subprocess.run([exe, host], capture_output=True, text=True,
                              errors="replace", timeout=timeout)
        return done.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def geoip_country(host: str) -> tuple[str, str]:
    """(code, name) from the local GeoIP.dat — offline, last resort."""
    try:
        import GeoIP                                   # Debian python3-geoip
    except ImportError:
        return "", ""
    global _geo
    try:
        _geo
    except NameError:
        try:
            _geo = GeoIP.open("/usr/share/GeoIP/GeoIP.dat",
                              GeoIP.GEOIP_STANDARD)
        except Exception:
            _geo = None
    if _geo is None:
        return "", ""
    try:
        if ":" in host:
            return (_geo.country_code_by_addr_v6(host) or "",
                    _geo.country_name_by_addr_v6(host) or "")
        return (_geo.country_code_by_addr(host) or "",
                _geo.country_name_by_addr(host) or "")
    except Exception:
        return "", ""


_PROGRAM_NAMES = {
    "chrome": "Chromium", "chromium": "Chromium",
    "chrome-headless-shell": "Chromium (background)",
    "brave": "Brave", "brave-browser": "Brave",
    "firefox": "Firefox", "firefox-esr": "Firefox",
    "code": "Visual Studio Code", "python3": "Python", "python": "Python",
    "node": "Node.js", "curl": "curl", "wget": "wget", "git": "Git",
    "ssh": "SSH", "docker": "Docker", "java": "Java",
    "telegram-desktop": "Telegram", "spotify": "Spotify",
}

_ARTICLES = frozenset({"united states", "united kingdom", "netherlands",
                       "united arab emirates", "philippines", "bahamas",
                       "czech republic", "dominican republic"})


def country_phrase(name: str) -> str:
    """'United States' → 'the United States', 'Ireland' → 'Ireland'."""
    name = (name or "").strip()
    if not name:
        return ""
    return f"the {name}" if name.lower() in _ARTICLES else name


def short_org(org: str) -> str:
    text = (org or "").strip()
    for _ in range(2):
        text = _ORG_SUFFIX_RE.sub("", text).strip()
    text = re.sub(r"\.(com|net|org)$", "", text, flags=re.I)
    m = _ORG_ALIAS_RE.match(text)
    if m:
        # "Meta Platforms Ireland" → "Meta"
        return {"facebook": "Facebook", "meta platforms": "Meta"}.get(
            m.group(1).lower(), text.split()[0] if text else "")
    if len(text) > 42:
        text = text[:39].rstrip(" ,") + "…"
    return text


def lookup_host(host: str, use_cache: bool = True) -> dict:
    """Identity of a destination address. Safe to call off the UI thread."""
    host = (host or "").strip()
    key = f"{CACHE_VERSION}:host:{host.lower()}"
    if use_cache:
        hit = cached(key)
        if hit is not None:
            return hit
    ident = {"ip": host, "ptr": "", "domain": "", "brand": "",
             "org": "", "country": "", "country_name": "",
             "asn": "", "netname": "", "range": ""}
    ptr = reverse_name(host)
    if ptr:
        ident["ptr"] = ptr
        ident["domain"] = registrable(ptr)
        ident["brand"] = brand_for(ident["domain"])
    text = run_whois(host)
    if text:
        info = parse_whois(text)
        ident["org"] = "" if info["registry_is_owner"] else info["org"]
        ident["netname"] = info["netname"]
        ident["asn"] = info["asn"]
        ident["range"] = info["range"]
        ident["country"] = info["country"]
    if not ident["country"]:
        code, _name = geoip_country(host)
        ident["country"] = code
    if ident["country"]:
        name = country_name(ident["country"])
        ident["country_name"] = name
    if not ident["brand"] and ident["org"]:
        ident["brand"] = short_org(ident["org"])
    empty = not (ptr or ident["org"] or ident["country"])
    if use_cache:
        remember(key, ident, empty=empty)
    return ident


# --------------------------------------------------------------------------
# program identity
# --------------------------------------------------------------------------

def country_name(code: str) -> str:
    code = (code or "").upper()
    if not code:
        return ""
    try:
        import pycountry                             # optional, nice names
        c = pycountry.countries.get(alpha_2=code)
        if c is not None:
            return getattr(c, "common_name", None) or c.name
    except Exception:
        pass
    return _COUNTRIES.get(code, code)


_COUNTRIES = {
    "US": "United States", "GB": "United Kingdom", "IE": "Ireland",
    "DE": "Germany", "FR": "France", "NL": "Netherlands", "BE": "Belgium",
    "CA": "Canada", "AU": "Australia", "NZ": "New Zealand", "JP": "Japan",
    "KR": "South Korea", "CN": "China", "IN": "India", "BR": "Brazil",
    "MX": "Mexico", "ES": "Spain", "IT": "Italy", "SE": "Sweden",
    "NO": "Norway", "DK": "Denmark", "FI": "Finland", "PL": "Poland",
    "CH": "Switzerland", "AT": "Austria", "PT": "Portugal", "RU": "Russia",
    "UA": "Ukraine", "TR": "Türkiye", "IL": "Israel", "AE": "UAE",
    "SG": "Singapore", "HK": "Hong Kong", "TW": "Taiwan", "ZA": "South Africa",
    "AR": "Argentina", "CL": "Chile", "CO": "Colombia", "CZ": "Czechia",
    "RO": "Romania", "HU": "Hungary", "GR": "Greece", "IS": "Iceland",
}

_DESKTOP_DIRS = (pathlib.Path("/usr/share/applications"),
                 pathlib.Path("/usr/local/share/applications"),
                 pathlib.Path.home() / ".local/share/applications")

_app_index: dict[str, dict] | None = None


def _desktop_index() -> dict:
    """binary basename → {name, icon}, built once per process."""
    global _app_index
    if _app_index is not None:
        return _app_index
    idx: dict[str, dict] = {}
    for root in _DESKTOP_DIRS:
        try:
            files = list(root.glob("*.desktop"))
        except OSError:
            continue
        for f in files:
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if re.search(r"^NoDisplay\s*=\s*true", text, re.M | re.I):
                continue
            m = re.search(r"^Exec\s*=\s*(.+)$", text, re.M)
            if not m:
                continue
            cmd = m.group(1).strip().strip('"').split()
            if not cmd:
                continue
            exe = os.path.basename(cmd[0].strip('"'))
            if not exe:
                continue
            name = re.search(r"^Name\s*=\s*(.+)$", text, re.M)
            icon = re.search(r"^Icon\s*=\s*(.+)$", text, re.M)
            prev = idx.get(exe)
            if prev and not re.search(r"URL Handler|Profile Manager",
                                      prev["name"]):
                continue
            idx[exe] = {"name": (name.group(1) if name else exe).strip(),
                        "icon": (icon.group(1) if icon else "").strip()}
    _app_index = idx
    return idx


def owning_package(path: str, timeout: float = 3.0) -> str:
    exe = shutil.which("dpkg")
    if not exe or not path:
        return ""
    try:
        out = subprocess.run([exe, "-S", path], capture_output=True,
                             text=True, errors="replace",
                             timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in out.splitlines():
        if ":" not in line:
            continue
        pkg = line.split(":", 1)[0].strip()
        # dpkg -S prints "diversion by firefox-esr from: /usr/bin/firefox"
        # before the real answer on a diverted binary; a package name has
        # no spaces, so those prose lines are skipped.
        if not pkg or " " in pkg:
            continue
        return pkg
    return ""


def file_owner(path: str) -> str:
    try:
        st = os.stat(path)
    except OSError:
        return ""
    try:
        return pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        return str(st.st_uid)


def lookup_program(path: str, app_name: str = "",
                   use_cache: bool = True) -> dict:
    path = (path or "").strip()
    key = f"{CACHE_VERSION}:app:{path}"
    if use_cache:
        hit = cached(key)
        if hit is not None:
            return hit
    binary = os.path.basename(path) if path else ""
    entry = _desktop_index().get(binary, {}) if binary else {}
    pkg = owning_package(path) if path else ""
    owner = file_owner(path) if path else ""
    kind = ("flatpak" if "/flatpak/" in path else
            "snap" if "/snap/" in path else
            "package" if pkg else "loose" if path else "unknown")
    nice = entry.get("name") or _PROGRAM_NAMES.get(binary.lower(), "")
    ident = {
        "title": nice or app_name or binary or "Unknown program",
        "binary": binary,
        "path": path,
        "package": pkg,
        "owner": owner,
        "icon": entry.get("icon") or "",
        "kind": kind,
    }
    if use_cache and path:
        remember(key, ident, empty=not (pkg or path))
    return ident


# --------------------------------------------------------------------------
# plain words
# --------------------------------------------------------------------------

def host_card(ident: dict) -> dict:
    """Everything the popup needs, already in sentences."""
    brand = ident.get("brand") or ""
    org = short_org(ident.get("org") or "")
    country = ident.get("country_name") or ""
    rows = []
    if ident.get("ptr"):
        rows.append(("Public name", ident["ptr"]))
    if ident.get("domain"):
        rows.append(("Domain", ident["domain"]))
    if ident.get("org"):
        rows.append(("Registered to", ident["org"]))
    if country:
        rows.append(("Country", f"{country} ({ident.get('country')})"))
    if ident.get("asn"):
        rows.append(("Network", ident["asn"]))
    if ident.get("netname"):
        rows.append(("Network name", ident["netname"]))
    if ident.get("range"):
        rows.append(("Address range", ident["range"]))
    if ident.get("ip"):
        rows.append(("Address", ident["ip"]))

    place = country_phrase(country)
    if brand and org and country and \
            org.lower().startswith(brand.lower().split()[0].lower()):
        sentence = f"This is {brand} — a network registered in {place}."
    elif brand and org and country:
        sentence = (f"This is {brand} — a network registered to {org} in "
                    f"{place}.")
    elif brand and (org or country):
        tail = org or place
        sentence = f"This is {brand} — a network registered to {tail}."
    elif brand:
        sentence = f"This is {brand}."
    elif org and country:
        sentence = f"An unnamed server registered to {org} in {place}."
    elif org:
        sentence = f"An unnamed server registered to {org}."
    elif ident.get("ip"):
        sentence = ("Nothing public is known about this address — it may be a "
                    "private server.")
    else:
        sentence = "The destination of this connection is not known."
    warning = ""
    if not ident.get("ptr") and not ident.get("org"):
        warning = ("No public name for this address. Programs often talk to "
                   "servers like this, but it is worth a second look.")
    return {"title": brand or org or "Unknown server",
            "sentence": sentence, "rows": rows, "warning": warning}


def program_card(ident: dict) -> dict:
    title = ident.get("title") or "Unknown program"
    pkg = ident.get("package") or ""
    kind = ident.get("kind") or "unknown"
    rows = [("Real program", ident.get("binary") or "—")]
    if ident.get("path"):
        rows.append(("Full location", ident["path"]))
    if pkg:
        rows.append(("Installed from", f"the {pkg} package"))
    if ident.get("owner"):
        rows.append(("File owner", ident["owner"]))
    warning = ""
    if kind == "package":
        sentence = (f"This is {title}, part of the {pkg} package that came "
                    "with your system.")
    elif kind == "flatpak":
        sentence = f"This is {title}, installed as a Flatpak application."
    elif kind == "snap":
        sentence = f"This is {title}, installed as a Snap application."
    elif kind == "loose":
        sentence = (f"This is {title}. It was not installed from a package, "
                    "so it is not part of your system's software list.")
        warning = "This program was installed outside your system's software."
    else:
        sentence = f"This is {title}."
    return {"title": title, "sentence": sentence, "rows": rows,
            "warning": warning, "kind": kind, "icon": ident.get("icon") or ""}


def describe_connection(host: str, path: str, app_name: str = "") -> dict:
    """One call the popup can run in a worker thread."""
    with _lock:
        h = lookup_host(host)
        p = lookup_program(path, app_name)
    return {"host": h, "program": p,
            "host_card": host_card(h), "program_card": program_card(p)}
