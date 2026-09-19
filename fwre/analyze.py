"""Root-filesystem analyzers.

Each analyzer takes a rootfs path and returns a list of Finding objects. The
top-level analyze_rootfs() runs them all and also gathers structured artifacts
(component list, ELF audit table, credentials, IOCs) for the report/JSON.
"""
from __future__ import annotations

import functools
import os
import re
import shlex
import stat
from dataclasses import dataclass, field

from .finding import Finding, Severity, Site, sites_note
from . import elf as elfmod
from . import cvedb
from . import services as svcmod
from . import defaults as defmod
from . import fsaudit as fsmod
from . import certs as certmod
from . import busybox as bbmod
from . import cloud as cloudmod
from . import bootlog as bootlogmod
from . import uboot as ubootmod
from . import interesting as intmod
from . import netcalls as netmod
from . import pem as pemmod
from .strings_util import strings_file, strings, strings_with_offsets

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_TEXT_EXT = {".sh", ".conf", ".cfg", ".ini", ".txt", ".json", ".xml", ".env",
             ".key", ".pem", ".crt", ".cer", ".lua", ".py", ".pl", ".js",
             ".service", ".rules", ".list", ".cfg", ".htm", ".html", ""}
_MAX_TEXT = 2 * 1024 * 1024


def _rel(rootfs: str, p: str) -> str:
    return os.path.relpath(p, rootfs).replace("\\", "/")


def _read_text(path: str, limit: int = _MAX_TEXT) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("latin1", "replace")
    except OSError:
        return ""


def _read_bytes(path: str, limit: int = _MAX_TEXT) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def _is_probably_text(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in _TEXT_EXT:
        return True
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    return True


_SKIP_NAMES = {".fwre_perms.json"}


def _walk_files(rootfs: str):
    for dirpath, _, files in os.walk(rootfs):
        for f in files:
            if f in _SKIP_NAMES:
                continue
            yield os.path.join(dirpath, f)


def _find_first(rootfs: str, *rel_candidates: str) -> str | None:
    for rc in rel_candidates:
        p = os.path.join(rootfs, rc.replace("/", os.sep))
        if os.path.isfile(p):
            return p
    return None


# ---------------------------------------------------------------------------
# 1. credentials: /etc/passwd + /etc/shadow
# ---------------------------------------------------------------------------

_HASH_MODES = {
    "$1$": ("md5crypt", "500 (john: md5crypt)"),
    "$2a$": ("bcrypt", "3200"),
    "$2b$": ("bcrypt", "3200"),
    "$2y$": ("bcrypt", "3200"),
    "$5$": ("sha256crypt", "7400"),
    "$6$": ("sha512crypt", "1800"),
    "$y$": ("yescrypt", "not-in-hashcat (use john)"),
    "$7$": ("scrypt", "n/a"),
}


@dataclass
class Credential:
    user: str
    hash: str
    hash_type: str
    hashcat_mode: str
    uid: str = ""
    shell: str = ""
    weak: bool = False
    note: str = ""


def analyze_credentials(rootfs: str) -> tuple[list[Finding], list[Credential]]:
    findings: list[Finding] = []
    creds: list[Credential] = []

    passwd = _find_first(rootfs, "etc/passwd")
    shadow = _find_first(rootfs, "etc/shadow")

    shadow_hashes: dict[str, str] = {}
    if shadow:
        for line in _read_text(shadow).splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                shadow_hashes[parts[0]] = parts[1]

    users = []
    if passwd:
        for line in _read_text(passwd).splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                users.append(parts)

    def classify(h: str):
        for pfx, (t, mode) in _HASH_MODES.items():
            if h.startswith(pfx):
                return t, mode
        if h and h not in ("*", "!", "!!", "x") and not h.startswith("$"):
            # 13-char DES crypt
            if re.fullmatch(r"[./0-9A-Za-z]{13}", h):
                return "descrypt", "1500"
        return "unknown", ""

    for parts in users:
        user, pw, uid, gid, gecos, home, shell = parts[:7]
        h = shadow_hashes.get(user, pw)
        weak = False
        note = ""
        if h in ("", ) or (pw == "" and (not shadow or h == "")):
            weak = True
            note = "EMPTY PASSWORD - login with no credentials"
            findings.append(Finding(
                Severity.CRITICAL, "credentials",
                f"account '{user}' has an empty password",
                detail=f"uid={uid} shell={shell}", path="etc/shadow" if shadow else "etc/passwd"))
        elif h in ("*", "!", "!!"):
            note = "login disabled"
        else:
            ht, mode = classify(h)
            c = Credential(user=user, hash=h, hash_type=ht, hashcat_mode=mode,
                           uid=uid, shell=shell)
            if ht == "descrypt":
                c.weak = True
                c.note = "DES crypt - trivially crackable"
                findings.append(Finding(
                    Severity.HIGH, "credentials",
                    f"account '{user}' uses weak DES password hash",
                    detail=f"hash={h}  (hashcat -m 1500)", path="etc/shadow"))
            elif ht == "md5crypt":
                c.weak = True
                c.note = "md5crypt - weak, crack with hashcat -m 500"
                findings.append(Finding(
                    Severity.MEDIUM, "credentials",
                    f"account '{user}' uses weak md5crypt hash",
                    detail=f"hash={h}  (hashcat -m 500)", path="etc/shadow"))
            else:
                findings.append(Finding(
                    Severity.INFO, "credentials",
                    f"account '{user}' has a {ht} password hash",
                    detail=f"crack with hashcat mode {mode}", path="etc/shadow"))
            creds.append(c)
            continue

        creds.append(Credential(user=user, hash=h, hash_type="",
                                hashcat_mode="", uid=uid, shell=shell,
                                weak=weak, note=note))

        # root with a real shell and uid 0 duplicates
        if uid == "0" and user != "root":
            findings.append(Finding(
                Severity.HIGH, "credentials",
                f"non-root account '{user}' has uid 0",
                detail="UID 0 grants full root privileges", path="etc/passwd"))

    return findings, creds


# ---------------------------------------------------------------------------
# 2. secrets, keys, certificates
# ---------------------------------------------------------------------------

# NB: PEM private keys and certificates are *not* in this table - a bare
# `-----BEGIN ... PRIVATE KEY-----` banner is a string constant in every TLS
# stack, so they need whole-block validation (see _scan_pem() / fwre/pem.py).
_SECRET_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     Severity.HIGH, "AWS access key id"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"),
     Severity.HIGH, "AWS temporary access key id"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     Severity.HIGH, "Google API key"),
    (re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
     Severity.HIGH, "GitHub personal access token"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
     Severity.MEDIUM, "JWT token"),
    (re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|passwphrase)\b\s*[:=]\s*['\"]?([^\s'\"#]{6,})"),
     Severity.MEDIUM, "hardcoded credential assignment"),
    (re.compile(r"(?i)\bpsk\s*[:=]\s*['\"]?([0-9A-Fa-f]{8,64})"),
     Severity.HIGH, "Wi-Fi PSK"),
    (re.compile(r"\baws_secret_access_key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})"),
     Severity.CRITICAL, "AWS secret access key"),
    (re.compile(r"\bLTAI[0-9A-Za-z]{12,22}\b"),
     Severity.HIGH, "Alibaba Cloud AccessKey ID"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"),
     Severity.HIGH, "Slack token"),
    (re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
     Severity.MEDIUM, "Telegram bot token"),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
     Severity.HIGH, "Stripe live secret key"),
    (re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
     Severity.MEDIUM, "Twilio Account SID"),
    (re.compile(r"(?i)\b(?:tuya|device)[_-]?secret\b\s*[:=]\s*['\"]?([0-9a-f]{16,64})"),
     Severity.HIGH, "Tuya/device secret"),
    (re.compile(r"\bghs_[0-9A-Za-z]{36}\b"),
     Severity.HIGH, "GitHub server-to-server token"),
]

# generic high-entropy secret-assignment (checked with an entropy gate)
_ENTROPY_ASSIGN = re.compile(
    r"(?i)\b(?:secret|token|apikey|api_key|auth[_-]?key|access[_-]?key|"
    r"app[_-]?secret|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*"
    r"['\"]?([A-Za-z0-9/+_\-]{20,64})")

_KEY_FILE_EXT = {".key", ".pem"}


_VAR_REF = re.compile(r"^\$\{?(\w+)\}?$|^%(\w+)%$")


def _deref_var(val: str, text: str, depth: int = 0) -> tuple[str, bool]:
    """If `val` is a variable reference ($VAR / ${VAR} / %VAR%), resolve it to
    the value assigned in the same file (transitively). Returns
    (resolved_value, was_resolved). This makes `password=$WIFIPWD` dump the real
    password defined elsewhere in the script, not the literal '$WIFIPWD'."""
    if not val or depth > 4:
        return val, depth > 0
    m = _VAR_REF.match(val.strip())
    if not m:
        return val, depth > 0
    name = m.group(1) or m.group(2)
    for pat in (rf"(?m)^[ \t]*(?:export[ \t]+|set[ \t]+)?{re.escape(name)}[ \t]*=[ \t]*(.+)$",
                rf"(?m)^[ \t]*{re.escape(name)}[ \t]*:[ \t]*(.+)$"):
        mm = re.search(pat, text)
        if mm:
            rhs = mm.group(1).strip()
            # strip trailing comment and surrounding quotes
            rhs = re.split(r"\s+#", rhs)[0].strip().strip('"\'').strip()
            if rhs and rhs != val:
                return _deref_var(rhs, text, depth + 1)
    return val, depth > 0  # referenced but not defined in this file


_POSITIONAL = re.compile(r"^\$\{?(\d+)\}?$")
_SCRIPT_EXTS = (".sh", ".cgi", ".rc", ".bash", "")


@functools.lru_cache(maxsize=4)
def _script_index(rootfs: str) -> tuple:
    """(rel, text) for every shell-ish script in the rootfs (cached). Used to
    find where a script is invoked so positional parameters can be resolved."""
    out = []
    for dirpath, _, files in os.walk(rootfs):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            p = os.path.join(dirpath, name)
            try:
                if os.path.getsize(p) > 512 * 1024:
                    continue
                with open(p, "rb") as fh:
                    data = fh.read(512 * 1024)
            except OSError:
                continue
            if b"\x00" in data[:2048]:
                continue
            if ext not in _SCRIPT_EXTS and not data.startswith(b"#!"):
                continue
            rel = os.path.relpath(p, rootfs).replace("\\", "/")
            out.append((rel, data.decode("latin1", "replace")))
    return tuple(out)


def _call_args(text: str, base: str) -> list[list[str]]:
    """Return the argument lists for each invocation of `base` in `text`."""
    results = []
    pat = re.compile(r"""(?:^|[\s;&|`(=])(?:[^\s;&|`'"]*/)?""" + re.escape(base) +
                     r"[ \t]+([^\n;&|)]+)")
    for m in pat.finditer(text):
        argstr = m.group(1).strip()
        try:
            args = shlex.split(argstr, posix=True)
        except ValueError:
            args = argstr.split()
        if args:
            results.append(args)
    return results


def _resolve_positional(script_rel: str, idx: int, rootfs: str,
                        depth: int, seen: frozenset) -> str | None:
    """Find callers of `script_rel` and resolve its $idx positional argument,
    recursing when the caller passes one of *its own* positionals."""
    if depth >= 6:
        return None
    base = os.path.basename(script_rel)
    for caller_rel, caller_text in _script_index(rootfs):
        if caller_rel == script_rel or caller_rel in seen:
            continue
        for args in _call_args(caller_text, base):
            if 1 <= idx <= len(args):
                v, _ = _resolve_value(args[idx - 1], caller_text, caller_rel,
                                      rootfs, depth + 1, seen | {caller_rel})
                if v and not _POSITIONAL.match(v.strip()) \
                        and not _VAR_REF.match(v.strip()):
                    return v
    return None


def _resolve_value(val: str, text: str, rel: str, rootfs: str | None = None,
                   depth: int = 0, seen: frozenset = frozenset()
                   ) -> tuple[str, bool]:
    """Resolve a secret value smartly: same-file variable deref, then (for a
    positional parameter) follow the call graph to the argument actually passed."""
    original = val
    val, ref = _deref_var(val, text)
    pm = _POSITIONAL.match((val or "").strip())
    if pm and rootfs and depth < 6:
        res = _resolve_positional(rel, int(pm.group(1)), rootfs, depth,
                                  seen | {rel})
        if res is not None:
            return res, True
    return val, ref or (val != original)


def _printable_secret(val: str, limit: int = 100) -> str:
    """Return the secret value for display if it is reasonably printable, else
    an empty string. Keeps control-char / binary blobs out of the output."""
    if not val:
        return ""
    v = val.strip()
    if not v.isprintable() or len(v) > limit:
        # for long-but-printable blobs (e.g. PEM headers) show a head slice
        if v.isprintable() and len(v) > limit:
            return v[:limit - 3] + "..."
        return ""
    return v


def _shannon(s: str) -> float:
    import math
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_SECRET_ELF_MAX = 32 * 1024 * 1024


@dataclass
class SecretHit:
    """A recovered secret and exactly where it lives, for optional dumping."""
    desc: str
    value: str
    rel: str
    abs_path: str
    is_binary: bool = False
    offset: int | None = None      # byte offset into the file (binaries)
    line: int | None = None        # 1-based line (text files)
    is_pem: bool = False           # multi-line PEM block worth full extraction

    def where(self) -> str:
        if self.offset is not None:
            return f"{self.rel} @ 0x{self.offset:x}"
        if self.line is not None:
            return f"{self.rel}:{self.line}"
        return self.rel


def _pem_blocks(raw: bytes, text: str, is_binary: bool, finder):
    """Run a fwre.pem finder over one file, returning [(block, offset, line)].

    Text files are scanned as-is. Binaries are scanned over their raw bytes so
    the reported offset is exact; if that finds nothing we retry over the
    extracted string table, which reassembles a block that the linker stored as
    separate NUL-terminated lines."""
    if not is_binary:
        return [(b, None, b.line(text)) for b in finder(text.encode("latin1", "replace"))]
    out = [(b, b.start, None) for b in finder(raw)]
    if not out:
        for b in finder(text.encode("latin1", "replace")):
            off = raw.find(b.block[:64])
            out.append((b, off if off >= 0 else None, None))
    return out


def _scan_pem(raw: bytes, text: str, is_binary: bool, rel: str, path: str,
              lib_vec: bool, findings: list, secrets: list) -> None:
    """Private keys and certificates, matched as complete PEM blocks only.

    The banner alone ("-----BEGIN RSA PRIVATE KEY-----") is a format string in
    every TLS stack - wpa_supplicant, mbedTLS, OpenSSL and friends all carry
    the BEGIN/END pair plus `Proc-Type: 4,ENCRYPTED` next to their PEM parser -
    so it is matched only together with a base64 body that decodes to plausible
    key material. See fwre/pem.py."""
    if lib_vec:
        # a crypto library's own compiled-in test keys/certs are public and
        # usually unused - don't raise them as embedded firmware secrets
        return

    for blk, off, line in _pem_blocks(raw, text, is_binary, pemmod.find_keys):
        loc = (f"{rel} @ 0x{off:x}" if off is not None
               else (f"{rel}:{line}" if line is not None else rel))
        sev = Severity.HIGH if blk.encrypted else Severity.CRITICAL
        note = " (passphrase-protected)" if blk.encrypted else ""
        findings.append(Finding(
            sev, "secrets",
            f"private key material embedded in firmware: {blk.kind}{note}",
            detail=f"{blk.label}, {len(blk.payload)}-byte body, "
                   f"sha256={blk.sha256[:16]}", path=loc))
        secrets.append(SecretHit(
            desc="private key", rel=rel, abs_path=path, is_binary=is_binary,
            value=f"{blk.kind}, {len(blk.payload)}-byte body, "
                  f"sha256={blk.sha256[:16]}",
            offset=off, line=line, is_pem=True))

    for blk, off, line in _pem_blocks(raw, text, is_binary, pemmod.find_certs):
        loc = (f"{rel} @ 0x{off:x}" if off is not None
               else (f"{rel}:{line}" if line is not None else rel))
        findings.append(Finding(
            Severity.LOW, "secrets", "TLS certificate embedded",
            detail=f"{len(blk.payload)}-byte DER, sha256={blk.sha256[:16]}",
            path=loc))
        secrets.append(SecretHit(
            desc="TLS certificate embedded", rel=rel, abs_path=path,
            is_binary=is_binary,
            value=f"X.509, {len(blk.payload)}-byte DER, sha256={blk.sha256[:16]}",
            offset=off, line=line, is_pem=True))


def analyze_secrets(rootfs: str) -> tuple[list[Finding], list[SecretHit]]:
    findings: list[Finding] = []
    secrets: list[SecretHit] = []
    seen_msgs: set[tuple[str, str, str]] = set()
    for path in _walk_files(rootfs):
        rel = _rel(rootfs, path)
        ext = os.path.splitext(path)[1].lower()
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        # key/cert files by extension - the name alone is only a hint, so check
        # the content: a .pem holding nothing but a cert is not a key leak, and
        # an armored key is left to _scan_pem() below, which pins its location
        if ext in _KEY_FILE_EXT:
            head = _read_bytes(path, 512 * 1024)
            if not (pemmod.find_keys(head) and size <= _MAX_TEXT):
                der_key = pemmod.looks_like_der_key(head)
                findings.append(Finding(
                    Severity.HIGH if der_key else Severity.LOW, "secrets",
                    f"{'DER private key' if der_key else 'key/cert'} "
                    f"file present: {rel}", path=rel))
                secrets.append(SecretHit(
                    desc="private key file" if der_key else "key/cert file",
                    value=rel, rel=rel, abs_path=path, is_pem=True))
        # Binaries carry the highest-value secrets on cameras (keys compiled into
        # the app/cloud daemons), so scan ELFs/libraries via their string table
        # rather than skipping them the way the text path used to.
        is_binary = elfmod.is_elf(path) or not _is_probably_text(path)
        if is_binary:
            if size > _SECRET_ELF_MAX:
                continue
            if size < 40 or not (elfmod.is_elf(path)
                                 or ext in (".so", ".bin", ".ko")
                                 or ".so." in os.path.basename(rel)):
                continue
            cap = _SECRET_ELF_MAX
        else:
            if size > _MAX_TEXT:
                continue
            cap = _MAX_TEXT
        try:
            with open(path, "rb") as fh:
                raw = fh.read(cap)
        except OSError:
            continue
        text = "\n".join(strings(raw, min_len=6)) if is_binary \
            else raw.decode("latin1", "replace")

        def _loc(match_text: str, pos: int):
            """Exact location: `path:line` for text, `path @ 0xOFFSET` (byte
            offset) for binaries. Returns (loc_str, offset|None, line|None)."""
            if is_binary:
                off = raw.find(match_text[:120].encode("latin1", "replace"))
                off = off if off >= 0 else None
                return (f"{rel} @ 0x{off:x}" if off is not None else rel), off, None
            line = text.count(chr(10), 0, pos) + 1
            return f"{rel}:{line}", None, line

        lib_vec = is_binary and certmod._is_crypto_lib(rel)
        _scan_pem(raw, text, is_binary, rel, path, lib_vec, findings, secrets)
        for pat, sev, desc in _SECRET_PATTERNS:
            # the loose key=value pattern is noisy against binary string tables
            # (matches help text) - keep it to text/config files only
            if is_binary and desc == "hardcoded credential assignment":
                continue
            for m in pat.finditer(text):
                raw_val = m.group(m.lastindex) if m.lastindex else m.group(0)
                # resolve $VAR/${VAR}/%VAR% in-file, and positional params ($2)
                # by following the call graph to the argument actually passed
                val, was_ref = _resolve_value(raw_val, text, rel,
                                              None if is_binary else rootfs)
                if val and ("%" in val or val in ("...", "xxx", "yyy", "xxxx")):
                    continue
                full = m.group(0)
                snippet = full[:77] + "..." if len(full) > 80 else full
                loc, off, line = _loc(full, m.start())
                key = (loc, desc, snippet)
                if key in seen_msgs:
                    continue
                seen_msgs.add(key)
                # surface the actual secret value + exactly where it lives
                shown = _printable_secret(val)
                ref_note = f"  (resolved from {raw_val})" if was_ref else ""
                title = f"{desc}: {shown}{ref_note}" if shown else desc
                detail = snippet + (f"  [{raw_val} -> {shown}]" if was_ref else "")
                findings.append(Finding(sev, "secrets", title,
                                        detail=detail, path=loc))
                secrets.append(SecretHit(
                    desc=desc, value=val, rel=rel, abs_path=path,
                    is_binary=is_binary, offset=off, line=line,
                    is_pem=("BEGIN" in full)))

        # entropy-gated generic secret assignments (cuts placeholder noise)
        for m in _ENTROPY_ASSIGN.finditer(text):
            val = m.group(1)
            if "%" in val or val.upper() in ("PASSWORD", "SECRET", "CHANGEME"):
                continue
            if _shannon(val) < 3.5:
                continue
            loc, off, line = _loc(m.group(0), m.start())
            key = (loc, "high-entropy secret", val[:24])
            if key in seen_msgs:
                continue
            seen_msgs.add(key)
            shown = _printable_secret(val)
            title = (f"high-entropy secret assignment: {shown}" if shown
                     else "high-entropy secret assignment")
            findings.append(Finding(
                Severity.MEDIUM, "secrets", title,
                detail=m.group(0)[:80], path=loc))
            secrets.append(SecretHit(
                desc="high-entropy secret", value=val, rel=rel, abs_path=path,
                is_binary=is_binary, offset=off, line=line))
    return findings, secrets


# ---------------------------------------------------------------------------
# 3. ELF hardening audit (checksec) + dangerous imports
# ---------------------------------------------------------------------------

@dataclass
class ElfAudit:
    path: str
    info: elfmod.ElfInfo
    setuid: bool = False
    setgid: bool = False
    network_facing: bool = False

_NET_DAEMON_HINTS = ("httpd", "telnetd", "dropbear", "sshd", "ftpd", "boa",
                     "lighttpd", "goahead", "rtsp", "onvif", "mqtt", "upnp",
                     "wsdd", "miniupnp", "webs", "cgi")


def analyze_binaries(rootfs: str, deep: bool = True
                     ) -> tuple[list[Finding], list[ElfAudit]]:
    findings: list[Finding] = []
    audits: list[ElfAudit] = []
    for path in _walk_files(rootfs):
        if not elfmod.is_elf(path):
            continue
        rel = _rel(rootfs, path)
        info = elfmod.parse(path)
        audit = ElfAudit(path=rel, info=info)
        try:
            mode = os.stat(path).st_mode
            audit.setuid = bool(mode & stat.S_ISUID)
            audit.setgid = bool(mode & stat.S_ISGID)
        except OSError:
            pass
        base = os.path.basename(rel).lower()
        audit.network_facing = any(h in base for h in _NET_DAEMON_HINTS)
        audits.append(audit)

        # findings ---------------------------------------------------------
        if info.packed:
            findings.append(Finding(
                Severity.MEDIUM, "elf-hardening",
                f"packed binary ({info.packed}): {rel}",
                "unpack before static analysis; obfuscation is unusual on stock FW",
                rel))
        if info.rwx:
            findings.append(Finding(
                Severity.MEDIUM, "elf-hardening",
                f"writable+executable segment (RWX) in {rel}",
                "self-modifying / JIT-style mapping weakens exploit mitigations",
                rel))

        if audit.setuid:
            sev = Severity.HIGH if not info.canary or not info.nx else Severity.MEDIUM
            findings.append(Finding(
                sev, "elf-hardening", f"setuid binary: {rel}",
                detail=info.summary(), path=rel))

        if audit.network_facing:
            weak = []
            if not info.nx:
                weak.append("no NX")
            if not info.pie:
                weak.append("no PIE")
            if not info.canary:
                weak.append("no stack canary")
            if info.relro == "none":
                weak.append("no RELRO")
            sev = Severity.HIGH if len(weak) >= 3 else Severity.MEDIUM
            if weak:
                findings.append(Finding(
                    sev, "elf-hardening",
                    f"network daemon '{base}' poorly hardened",
                    detail=f"{', '.join(weak)}  |  {info.summary()}", path=rel))
            # dangerous libc usage: dynamic symbols if present, else fall back to
            # a string scan so statically-linked daemons (busybox/httpd) still hit
            dfns = info.dangerous()
            if not dfns and info.static:
                dfns = elfmod.scan_dangerous_strings(path)
            if dfns:
                findings.append(Finding(
                    Severity.MEDIUM, "dangerous-funcs",
                    f"'{base}' uses risky libc funcs",
                    detail=", ".join(dfns[:20]), path=rel))

        if info.rpath or info.runpath:
            rp = info.rpath or info.runpath
            if rp.startswith((".", "/tmp", "/var")) or "$ORIGIN" not in rp and rp.startswith("."):
                findings.append(Finding(
                    Severity.MEDIUM, "elf-hardening",
                    f"insecure RPATH/RUNPATH in {rel}",
                    detail=rp, path=rel))

    # global hardening rollup ---------------------------------------------
    if audits:
        n = len(audits)
        no_nx = sum(1 for a in audits if not a.info.nx)
        no_pie = sum(1 for a in audits if not a.info.pie)
        no_can = sum(1 for a in audits if not a.info.canary)
        findings.append(Finding(
            Severity.INFO, "elf-hardening",
            f"hardening rollup: {n} ELFs - no-NX {no_nx}, no-PIE {no_pie}, "
            f"no-canary {no_can}",
            "baseline mitigation coverage across the image"))
    return findings, audits


# ---------------------------------------------------------------------------
# 4. attack surface: init scripts / network daemons / debug shells
# ---------------------------------------------------------------------------

_INIT_CANDIDATES = [
    "etc/inittab", "etc/init.d/rcS", "etc/init.d/rc.local", "etc/rc.local",
    "etc/rc.d/rcS", "linuxrc", "init", "etc/profile",
]
_DAEMON_RISK = {
    "telnetd": (Severity.HIGH, "telnet daemon - cleartext, often no auth"),
    "utelnetd": (Severity.HIGH, "telnet daemon (util) started"),
    "tcpsvd": (Severity.MEDIUM, "tcpsvd super-server may expose telnet/ftp"),
    "getty": (Severity.LOW, "serial console getty (physical access)"),
    "dropbear": (Severity.INFO, "SSH server (dropbear) started"),
    "sshd": (Severity.INFO, "SSH server started"),
    "ftpd": (Severity.MEDIUM, "FTP daemon started"),
    "tftpd": (Severity.MEDIUM, "TFTP daemon started"),
    "httpd": (Severity.LOW, "HTTP server started - web attack surface"),
    "lighttpd": (Severity.LOW, "lighttpd web server started"),
    "boa": (Severity.MEDIUM, "boa web server (legacy) started"),
    "goahead": (Severity.MEDIUM, "GoAhead web server started"),
    "rtspd": (Severity.LOW, "RTSP server started"),
    "onvif": (Severity.LOW, "ONVIF service started"),
}


def analyze_attack_surface(rootfs: str) -> list[Finding]:
    findings: list[Finding] = []
    # gather init/boot scripts
    scripts = []
    for rc in _INIT_CANDIDATES:
        p = os.path.join(rootfs, rc.replace("/", os.sep))
        if os.path.isfile(p):
            scripts.append(p)
    for sub in ("etc/init.d", "etc/rc.d", "etc/rc.d/init.d",
                "etc/cron.d", "etc/crontab.d", "etc/systemd/system",
                "lib/systemd/system", "etc/systemd/system/multi-user.target.wants"):
        d = os.path.join(rootfs, sub.replace("/", os.sep))
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                if os.path.isfile(fp):
                    scripts.append(fp)
    # cron tables (files, not dirs)
    for rc in ("etc/crontab", "var/spool/cron/crontabs/root",
               "var/spool/cron/root", "etc/cron.d/root"):
        p = os.path.join(rootfs, rc.replace("/", os.sep))
        if os.path.isfile(p):
            scripts.append(p)

    joined_paths = set(scripts)
    for sp in joined_paths:
        rel = _rel(rootfs, sp)
        text = _read_text(sp)
        low = text.lower()
        for name, (sev, msg) in _DAEMON_RISK.items():
            if re.search(rf"\b{name}\b", low):
                findings.append(Finding(sev, "attack-surface",
                                        f"{msg}", detail=f"referenced in {rel}",
                                        path=rel))
        # debug / backdoor shells
        if re.search(r"/bin/sh\s+.*(?:ttyS|console)", low) or "gdbserver" in low:
            findings.append(Finding(
                Severity.MEDIUM, "attack-surface",
                "debug shell / gdbserver referenced in boot", detail=rel, path=rel))
        if "telnetd" in low and "-l" in low and "login" not in low:
            findings.append(Finding(
                Severity.CRITICAL, "attack-surface",
                "telnetd started with a direct shell (-l /bin/sh) - unauth root",
                path=rel))
        # reverse-shell / backdoor idioms
        if re.search(r"\bnc\b[^\n]*\s-e\s", low) or \
                re.search(r"mkfifo[^\n]*(?:/bin/sh|/bin/ash|bash -i)", low) or \
                re.search(r"bash\s+-i\s*>&?\s*/dev/tcp/", low):
            findings.append(Finding(
                Severity.HIGH, "attack-surface",
                "reverse-shell idiom in boot/cron script", detail=rel, path=rel))
        # OTA over cleartext then execute -> supply-chain RCE
        if re.search(r"(?:wget|curl)\s+[^\n|;]*http://", low) and \
                re.search(r"(?:chmod\s+\+?x|/bin/sh|\|\s*sh|\bsh\s+/tmp|\.\s*/tmp)", low):
            findings.append(Finding(
                Severity.HIGH, "attack-surface",
                "downloads over cleartext HTTP then executes (supply-chain RCE)",
                detail=rel, path=rel))
        # firewall being flushed/disabled at boot
        if re.search(r"iptables\s+-F\b", low) or "stop_firewall" in low:
            findings.append(Finding(
                Severity.LOW, "attack-surface",
                "firewall flushed/disabled during boot", detail=rel, path=rel))

    # presence of daemon binaries even if not obviously started
    for base, (sev, msg) in _DAEMON_RISK.items():
        for cand in (f"usr/sbin/{base}", f"sbin/{base}", f"usr/bin/{base}",
                     f"bin/{base}"):
            p = os.path.join(rootfs, cand.replace("/", os.sep))
            if os.path.isfile(p):
                findings.append(Finding(
                    Severity.INFO, "attack-surface",
                    f"daemon binary present: {base}", detail=msg, path=cand))
                break
    return findings


# ---------------------------------------------------------------------------
# 5. component versions + CVE heuristics
# ---------------------------------------------------------------------------

_VERSION_TARGETS = [
    "bin/busybox", "usr/sbin/dropbear", "sbin/dropbear", "usr/bin/dropbear",
    "usr/bin/openssl", "usr/lib/libssl.so", "usr/lib/libcrypto.so",
    "lib/libc.so", "lib/libuClibc.so", "usr/sbin/wpa_supplicant",
    "usr/sbin/hostapd", "usr/sbin/lighttpd", "usr/sbin/dnsmasq",
    "usr/sbin/httpd", "bin/httpd", "usr/sbin/goahead",
]


def analyze_versions(rootfs: str, extra_scan_all_elf: bool = True
                     ) -> tuple[list[Finding], list[cvedb.Component], list[cvedb.CveHit]]:
    strings_map: dict[str, list[str]] = {}

    # targeted known binaries first
    for rel in _VERSION_TARGETS:
        p = os.path.join(rootfs, rel.replace("/", os.sep))
        if os.path.isfile(p):
            strings_map[rel] = strings_file(p, min_len=5, max_read=16 * 1024 * 1024)

    # kernel version often shows in a uImage/zImage or in /proc-ish banners;
    # also scan a couple of likely files
    for rel in ("etc/os-release", "etc/version", "etc/issue"):
        p = os.path.join(rootfs, rel.replace("/", os.sep))
        if os.path.isfile(p):
            strings_map[rel] = _read_text(p).splitlines()

    # optionally scan every ELF's strings for library version banners
    if extra_scan_all_elf:
        for path in _walk_files(rootfs):
            rel = _rel(rootfs, path)
            if rel in strings_map:
                continue
            if not elfmod.is_elf(path):
                continue
            base = os.path.basename(rel).lower()
            if any(k in base for k in ("ssl", "crypto", "curl", "z.so",
                                       "busybox", "dropbear", "wpa", "hostapd")):
                strings_map[rel] = strings_file(path, min_len=5,
                                                max_read=16 * 1024 * 1024)

    comps = cvedb.fingerprint(strings_map)
    hits = cvedb.match_cves(comps)

    findings: list[Finding] = []
    for c in comps:
        findings.append(Finding(Severity.INFO, "component",
                                f"{c.name} {c.version}",
                                detail=c.evidence, path=c.source))
    for h in hits:
        sev = Severity.parse(h.severity)
        findings.append(Finding(
            sev, "cve", f"{h.component} {h.version}: {h.cve}",
            detail=h.note, path=h.source, data={"cve": h.cve}))

    # richer matches from the downloaded CVE corpus, if present
    findings += _corpus_cves(comps)
    return findings, comps, hits


_SEV_MAP = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _corpus_cves(comps) -> list[Finding]:
    """Query the full cvelistV5 SQLite index (if it was downloaded) for each
    detected component. No-op when the corpus hasn't been built."""
    try:
        from . import cvestore
    except Exception:
        return []
    if not cvestore.have_db():
        return []
    out: list[Finding] = []
    for c in comps:
        for hit in cvestore.query(c.name, c.version, limit=25):
            sev = _SEV_MAP.get(hit["severity"], Severity.LOW)
            cvss = f" CVSS {hit['cvss']}" if hit.get("cvss") else ""
            out.append(Finding(
                sev, "cve", f"{c.name} {c.version}: {hit['cve']}{cvss}",
                detail=(hit.get("summary") or "")[:200],
                path=c.source, data={"cve": hit["cve"], "corpus": True}))
    return out


# ---------------------------------------------------------------------------
# 6. network IOCs (URLs, IPs, domains, cloud/MQTT endpoints)
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"\b(?:https?|ftp|mqtt|rtsp|tcp)://[^\s'\"<>\\)]{4,120}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|cn|cloud|tv|co|xyz|aws|me|info)\b", re.I)
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_P2P_HINTS = ("tutk", "kalay", "ppcs", "iotcplatform", "ppstrun", "throughtek",
              "gwell", "ajcloud", "meari", "xmeye", "vstarcam", "ilnk", "pppp",
              "tuya", "aliyuncs", "iotc")
_OTA_HINTS = ("ota", "update", "firmware", "upgrade", "/fw/", "download")

_CLOUD_HINTS = ("amazonaws", "aliyun", "aliyuncs", "tuya", "tutk", "iotcplatform",
                "ipcam", "ppstrun", "ppcs", "kalay", "gwell", "ajcloud",
                "xmeye", "cloud", "mqtt", "ntp", "firmware", "ota", "update")


# how many distinct sites we keep (and print) per IOC value; the rest are
# summarised as "+N more" so a string repeated across a whole rootfs doesn't
# blow up the report
_MAX_IOC_SITES = 5


# an IOC sighting is just a Site (see finding.Site)
IocSite = Site


def _ioc_matches(s: str):
    """Yield (kind, value, char_index) for every IOC inside one string/line."""
    for m in _URL_RE.finditer(s):
        yield "url", m.group(0), m.start()
    for m in _IP_RE.finditer(s):
        ip = m.group(0)
        first = ip.split(".")[0]
        if first.isdigit() and 0 < int(first) < 240 and ip not in ("0.0.0.0",):
            yield "ip", ip, m.start()
    for m in _DOMAIN_RE.finditer(s):
        yield "domain", m.group(0).lower(), m.start()
    for m in _MAC_RE.finditer(s):
        mac = m.group(0).lower()
        if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            yield "mac", mac, m.start()


def analyze_network_iocs(rootfs: str) -> tuple[list[Finding], dict]:
    sites: dict[tuple[str, str], list[IocSite]] = {}
    counts: dict[tuple[str, str], int] = {}

    def add(kind: str, value: str, site: IocSite) -> None:
        key = (kind, value)
        counts[key] = counts.get(key, 0) + 1
        lst = sites.setdefault(key, [])
        if len(lst) < _MAX_IOC_SITES:
            lst.append(site)

    for path in _walk_files(rootfs):
        rel = _rel(rootfs, path)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > 16 * 1024 * 1024:
            continue
        if elfmod.is_elf(path):
            # binary: record the file offset of the match (and the virtual
            # address it maps to, so it can be looked up in a disassembler)
            try:
                with open(path, "rb") as fh:
                    data = fh.read(16 * 1024 * 1024)
            except OSError:
                continue
            segs = elfmod.load_segments(data)
            for off, s, width in strings_with_offsets(data, min_len=6):
                for kind, value, i in _ioc_matches(s):
                    fo = off + i * width
                    va = elfmod.vaddr_for_offset(segs, fo)
                    add(kind, value, IocSite(path=rel, offset=fo,
                                             vaddr=-1 if va is None else va))
        elif _is_probably_text(path):
            # text: record the line number of the match
            for lineno, line in enumerate(_read_text(path).splitlines(), 1):
                for kind, value, _i in _ioc_matches(line):
                    add(kind, value, IocSite(path=rel, line=lineno))
        else:
            continue

    def values(kind: str) -> list[str]:
        return sorted(v for (k, v) in sites if k == kind)

    urls, ips = values("url"), values("ip")
    domains, macs = values("domain"), values("mac")

    def loc(kind: str, value: str) -> tuple[str, str]:
        """(primary location, 'found at ...' note) for one IOC value."""
        lst = sites.get((kind, value), [])
        if not lst:
            return "", ""
        return lst[0].where(), sites_note(lst, counts[(kind, value)])

    findings: list[Finding] = []
    for u in urls:
        ul = u.lower()
        sev = Severity.LOW
        at, note = loc("url", u)
        is_ota = any(h in ul for h in _OTA_HINTS)
        is_p2p = any(h in ul for h in _P2P_HINTS)
        if u.startswith("http://") and is_ota:
            # cleartext firmware/update fetch = classic supply-chain vector
            findings.append(Finding(
                Severity.HIGH, "network-ioc",
                f"cleartext OTA/update endpoint: {u}",
                "unauthenticated HTTP firmware fetch - MITM to implant; "
                + note, path=at))
            continue
        if is_p2p:
            findings.append(Finding(
                Severity.MEDIUM, "network-ioc",
                f"P2P/cloud control endpoint: {u}",
                "device phone-home / remote-access infrastructure; "
                + note, path=at))
            continue
        if u.startswith("http://"):
            sev = Severity.MEDIUM
        if is_ota:
            sev = max(sev, Severity.MEDIUM)
        findings.append(Finding(sev, "network-ioc", f"URL: {u}",
                                detail=note, path=at))

    cloud = sorted(d for d in domains
                   if any(h in d for h in _CLOUD_HINTS + _P2P_HINTS))
    for d in cloud:
        sev = Severity.LOW if any(h in d for h in _P2P_HINTS) else Severity.INFO
        at, note = loc("domain", d)
        findings.append(Finding(sev, "network-ioc",
                                f"cloud/P2P service domain: {d}",
                                detail=note, path=at))

    locations = {kind: {v: [s.to_dict() for s in sites[(k, v)]]
                        for (k, v) in sites if k == kind}
                 for kind in ("url", "ip", "domain", "mac")}
    iocs = {"urls": urls, "ips": ips,
            "domains": domains, "cloud_domains": cloud,
            "macs": macs, "locations": locations,
            "occurrences": {f"{k}:{v}": n for (k, v), n in counts.items()}}
    return findings, iocs


# ---------------------------------------------------------------------------
# orchestrator
# ---------------------------------------------------------------------------

@dataclass
class RootfsReport:
    rootfs: str
    findings: list[Finding] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    recovered_creds: list = field(default_factory=list)  # defmod.RecoveredCred
    elf_audits: list[ElfAudit] = field(default_factory=list)
    components: list[cvedb.Component] = field(default_factory=list)
    cves: list[cvedb.CveHit] = field(default_factory=list)
    iocs: dict = field(default_factory=dict)
    netcalls: list = field(default_factory=list)  # netmod.NetBinary
    stats: dict = field(default_factory=dict)
    certs: list = field(default_factory=list)            # certmod.CertInfo
    key_fps: list = field(default_factory=list)          # private-key sha256s
    cloud: list = field(default_factory=list)            # cloudmod.CloudSDK
    busybox: object | None = None                        # bbmod.BusyBoxInfo
    fs_audit: object | None = None                       # fsmod.FsAudit
    boot: list = field(default_factory=list)             # boot/uImage info dicts
    secrets: list = field(default_factory=list)          # SecretHit (dumpable)
    interesting: list = field(default_factory=list)      # intmod.InterestingBinary


def analyze_rootfs(rootfs: str, *, do_iocs: bool = True,
                   wordlist: list[str] | None = None,
                   image_path: str | None = None) -> RootfsReport:
    rep = RootfsReport(rootfs=rootfs)

    f, creds = analyze_credentials(rootfs)
    rep.findings += f
    rep.credentials = creds

    f, recovered = defmod.analyze_default_creds(rootfs, wordlist)
    rep.findings += f
    rep.recovered_creds = recovered

    f, secs = analyze_secrets(rootfs)
    rep.findings += f
    rep.secrets = secs

    f, audits = analyze_binaries(rootfs)
    rep.findings += f
    rep.elf_audits = audits

    # which binaries actually touch the network, and where in them
    f, nets = netmod.analyze(rootfs, audits)
    rep.findings += f
    rep.netcalls = nets

    # point out the unusual / vendor / stand-out binaries worth manual RE
    f, interesting = intmod.analyze(rootfs, audits)
    rep.findings += f
    rep.interesting = interesting

    rep.findings += analyze_attack_surface(rootfs)

    rep.findings += svcmod.analyze_services(rootfs)

    # filesystem permission audit
    f, fsa = fsmod.analyze(rootfs)
    rep.findings += f
    rep.fs_audit = fsa

    # certificates & private keys
    f, certs_, keys_ = certmod.analyze(rootfs)
    rep.findings += f
    rep.certs = certs_
    # exclude TLS-library test keys from the fleet-correlation fingerprints
    rep.key_fps = [k.sha256 for k in keys_
                   if k.sha256 and not certmod._is_crypto_lib(k.source)]

    # busybox applet surface
    f, bb = bbmod.analyze(rootfs)
    rep.findings += f
    rep.busybox = bb

    # cloud / P2P SDK fingerprint
    f, sdks = cloudmod.analyze(rootfs)
    rep.findings += f
    rep.cloud = sdks

    f, comps, cves = analyze_versions(rootfs)
    rep.findings += f
    rep.components = comps
    rep.cves = cves

    # boot chain: uImage/U-Boot from the raw image + sibling serial boot logs
    if image_path and os.path.isfile(image_path):
        try:
            bf, binfo = ubootmod.analyze(image_path)
            rep.findings += bf
            rep.boot.append({"kind": "uboot", **binfo.__dict__})
        except Exception:
            pass
        for blog in bootlogmod.find_bootlogs(image_path):
            try:
                lf, li = bootlogmod.analyze(blog)
                rep.findings += lf
                rep.boot.append({"kind": "bootlog", **li.__dict__})
            except Exception:
                pass

    if do_iocs:
        f, iocs = analyze_network_iocs(rootfs)
        rep.findings += f
        rep.iocs = iocs

    # stats
    arches = {}
    for a in rep.elf_audits:
        arches[a.info.machine] = arches.get(a.info.machine, 0) + 1
    rep.stats = {
        "elf_count": len(rep.elf_audits),
        "setuid_count": sum(1 for a in rep.elf_audits if a.setuid),
        "arch_histogram": arches,
        "finding_count": len(rep.findings),
        "critical": sum(1 for x in rep.findings if x.severity == Severity.CRITICAL),
        "high": sum(1 for x in rep.findings if x.severity == Severity.HIGH),
    }
    return rep
