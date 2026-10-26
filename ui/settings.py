"""Settings — TrustList (owner order 2026-10-23: "I NEED SOME SORT OF TRUST
LIST TO AUTO BLOCK SITES") + theme persistence.

The app-fw engine consults the TrustList BEFORE popping a dialog:
- auto_allow: matched dst host → answered `allow, always` (no prompt)
- auto_block: matched dst host → answered `deny, always` (no prompt)
Entries match by suffix (subdomain-aware); patterns are plain strings.
Stored in data/trust-list.json (user-writable — no root, no helper).
"""
from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
TRUST_PATH = ROOT / "data" / "trust-list.json"

_ENTRY_RE = re.compile(r"^(\*\.)?[A-Za-z0-9*.-]{1,120}$")


class TrustList:
    def __init__(self, path=TRUST_PATH):
        self.path = pathlib.Path(path)
        self.allow = set()
        self.block = set()
        self.apps_allow = set()      # trusted PROGRAMS (owner request)
        self.load()

    def load(self):
        try:
            data = json.loads(self.path.read_text())
            self.allow = set(data.get("auto_allow") or [])
            self.block = set(data.get("auto_block") or [])
            self.apps_allow = set(data.get("trusted_apps") or [])
        except (OSError, ValueError):
            pass
        return self

    def save(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({
                "auto_allow": sorted(self.allow),
                "auto_block": sorted(self.block),
                "trusted_apps": sorted(self.apps_allow)}, indent=1))
            return True
        except (OSError, ValueError):
            return False

    @staticmethod
    def _valid(entry: str) -> bool:
        return bool(isinstance(entry, str) and _ENTRY_RE.fullmatch(entry)
                    and len(entry) >= 3)

    def add(self, entry: str, verdict: str) -> bool:
        if not self._valid(entry):
            return False
        # Re-read first: the wizard writes through its OWN TrustList, so a
        # stale in-memory set here silently erased the wizard's site on the
        # next Settings save (Pass 2/3 defect, 2026-10-23).
        self.load()
        if entry.startswith("*."):
            entry = entry          # keep wildcard form
        self.allow.discard(entry)
        self.block.discard(entry)
        if verdict == "allow":
            self.allow.add(entry)
        elif verdict == "block":
            self.block.add(entry)
        else:
            return False
        return self.save()

    def remove(self, entry: str) -> bool:
        self.load()                # same reason as add()
        self.allow.discard(entry)
        self.block.discard(entry)
        return self.save()

    @staticmethod
    def _match(entries: set, host: str) -> bool:
        if not host:
            return False
        host = host.lower()
        for e in entries:
            e = e.lower()
            if host == e or host.endswith("." + e):
                return True          # trust domain → subdomains trusted
            if e.startswith("*.") and (host.endswith(e[1:]) or host == e[2:]):
                return True          # explicit wildcard form
        return False

    def decide(self, host: str) -> str | None:
        """'allow' | 'block' | None (None = ask the user as normal)."""
        if self._match(self.block, host):
            return "block"
        if self._match(self.allow, host):
            return "allow"
        return None

    # ── trusted PROGRAMS (owner 2026-10-23: "or add trusted apps") ──────
    @staticmethod
    def _valid_app(entry: str) -> bool:
        if not isinstance(entry, str):
            return False
        entry = entry.strip()
        return 2 <= len(entry) <= 240 and not any(
            ch in entry for ch in "\n\r\t\x00")

    def add_app(self, entry: str) -> bool:
        entry = str(entry or "").strip()
        if not self._valid_app(entry):
            return False
        self.load()                # never clobber another writer's entries
        self.apps_allow.add(entry)
        return self.save()

    def remove_app(self, entry: str) -> bool:
        self.load()
        self.apps_allow.discard(entry)
        return self.save()

    def decide_app(self, process_path: str, process_args=None) -> str | None:
        """'allow' when the program is trusted; None otherwise.

        Three forms are accepted:
          /path/to/binary      an exact executable
          name                 a basename (e.g. a shell command)
          /path/to/folder/     a trusted project folder
        Interpreter-run tools (python3 ~/project/tool.py) report the
        interpreter as the program, so a trusted folder also matches any
        script argument that lives inside it. That is what lets the owner
        allow a few trusted helper folders without trusting every
        python3 process on the machine."""
        proc = str(process_path or "").strip()
        if not proc:
            return None
        base = proc.rsplit("/", 1)[-1]
        args = [str(a) for a in (process_args or [])]
        for entry in self.apps_allow:
            if entry.endswith("/"):        # trusted folder
                if proc.startswith(entry):
                    return "allow"
                if any(a.startswith(entry) for a in args):
                    return "allow"
                continue
            if proc == entry or base == entry or proc.endswith("/" + entry):
                return "allow"
            if any(a == entry or a.startswith(entry + "/") for a in args):
                return "allow"
        return None


class LearningStore:
    """App-firewall learning mode (owner 2026-10-23: "a LEARNING MODE where
    it can learn as you do things and configure rules").

    While learning is on, the front-end allows each connection ONCE and
    records it in data/learning-seen.jsonl (the daemon writes that file).
    Nothing permanent is created until the person approves a candidate in
    the app — learning never quietly grants access forever.
    """

    def __init__(self, path=None):
        self.path = pathlib.Path(path or (ROOT / "data" / "learning.json"))
        self.until = 0.0
        self.load()

    def load(self):
        try:
            self.until = float(json.loads(self.path.read_text()).get("until") or 0)
        except (OSError, ValueError, TypeError):
            self.until = 0.0
        return self

    def active(self) -> bool:
        import time
        self.load()
        return self.until > time.time()

    def start(self, minutes: int = 60) -> bool:
        import time
        self.until = time.time() + max(1, int(minutes)) * 60
        return self._save()

    def stop(self) -> bool:
        self.until = 0.0
        return self._save()

    def _save(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"until": self.until}, indent=1))
            return True
        except OSError:
            return False


class FirewallModeStore:
    """How the app firewall treats a connection nobody decided yet.

    watch  = let it through (the calm default; nothing is blocked)
    block  = deny it unless a trusted site/program already allows it
    Stored in data/firewall-mode.json; the daemon reads it per connection.
    """

    def __init__(self, path=None):
        self.path = pathlib.Path(path or (ROOT / "data" / "firewall-mode.json"))
        self.block_unknown = False
        self.load()

    def load(self):
        try:
            self.block_unknown = bool(json.loads(
                self.path.read_text()).get("block_unknown"))
        except (OSError, ValueError, TypeError):
            self.block_unknown = False
        return self

    def set_block_unknown(self, value: bool) -> bool:
        self.block_unknown = bool(value)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(
                {"block_unknown": self.block_unknown}, indent=1))
            return True
        except OSError:
            return False


class PausedStore:
    """Which protections the owner paused ON PURPOSE (data/paused.json).
    A deliberate pause is shown as "paused by you", never as a fault."""

    def __init__(self, path=None):
        self.path = pathlib.Path(path or (ROOT / "data" / "paused.json"))
        self.paused = set()
        self.load()

    def load(self):
        try:
            self.paused = set(json.loads(self.path.read_text()).get("paused") or [])
        except (OSError, ValueError):
            pass
        return self

    def save(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"paused": sorted(self.paused)},
                                            indent=1))
            return True
        except (OSError, ValueError):
            return False

    def is_paused(self, name: str) -> bool:
        return name in self.paused

    def set(self, name: str, value: bool) -> bool:
        if value:
            self.paused.add(name)
        else:
            self.paused.discard(name)
        return self.save()

# ── Dashboard workspace preference (Pass 4 leftover, 2026-10-25) ─────────

def ws_pref(data_dir) -> int:
    """The workspace the dashboard launches on (default 3, owner rule).
    Missing/corrupt file ⇒ 3 — the standing preference, never junk."""
    try:
        import json as _json
        doc = _json.loads((pathlib.Path(data_dir) / "workspace.json")
                          .read_text())
        ws = int(doc.get("ws", 3))
    except (OSError, ValueError, TypeError, AttributeError):
        return 3
    return ws if 1 <= ws <= 6 else 3


def ws_set(data_dir, ws: int) -> bool:
    """Atomic persist (P0-a machinery); clamps to 1–6."""
    try:
        from appfw.atomicio import write_json_atomic
        ws = int(ws)
        if not 1 <= ws <= 6:
            return False
        write_json_atomic(pathlib.Path(data_dir) / "workspace.json",
                          {"ws": ws})
        return True
    except (OSError, ValueError):
        return False
