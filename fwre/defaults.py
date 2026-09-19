"""Default / weak credential recovery.

Three angles:
  1. Crack /etc/shadow (+passwd) hashes against a curated wordlist of
     credentials that ship on embedded devices, using the pure-python crypt
     implementations in cryptcrack (works on Windows too).
  2. Match hashes against a table of publicly-known vendor default hashes.
  3. Scrape service config / provisioning files for hardcoded default
     login pairs (web UI admin/admin, MQTT, ONVIF, RTSP URLs, etc.).

Recovered plaintext credentials are the highest-value output of the whole
framework, so they are collected into a dedicated structure for printing.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .finding import Finding, Severity
from . import cryptcrack


# --- wordlist of credentials that actually ship on IoT / cameras ----------
# kept deliberately small & high-signal; extend via load_wordlist().
DEFAULT_PASSWORDS = [
    "", "admin", "root", "password", "12345", "123456", "1234", "12345678",
    "888888", "666666", "000000", "111111", "654321", "123123",
    "toor", "pass", "system", "default", "guest", "user", "test",
    "ipcam", "camera", "hikvision", "dahua", "xmhdipc", "juantech",
    "vizxv", "jvbzd", "anko", "zlxx", "7ujMko0admin", "7ujMko0vizxv",
    "meinsm", "klv123", "klv1234", "Zte521", "GMB182", "realtek",
    "1234567890", "admin123", "root123", "abc123", "changeme", "support",
    "service", "supervisor", "administrator", "wbox123", "fliradmin",
    "tlJwpbo6", "hi3518", "hslwificam", "cat1029", "ivdev", "OxhlwSG8",
    "solokey", "tsgoingon", "smcadmin", "ubnt", "thingino", "openipc",
]

# publicly documented vendor default root hashes -> (password, note)
# (heuristic aid; verify before relying on it)
KNOWN_DEFAULT_HASHES = {
    # classic hi35xx / xiongmai / generic camera defaults seen in the wild
    "$1$RYIwEiRA$d5iRRVQ5ZeoTrJDpP4mAT/": ("xmhdipc", "Xiongmai default root"),
    "$1$$qRPK7m23GJusamGpoGLby/": ("(blank)", "empty-password md5crypt"),
}

# service default credential pairs to look for referenced in configs
SERVICE_DEFAULT_PAIRS = [
    ("admin", "admin"), ("admin", ""), ("admin", "password"),
    ("admin", "12345"), ("admin", "123456"), ("root", "root"),
    ("root", ""), ("root", "12345"), ("user", "user"),
    ("guest", "guest"), ("service", "service"),
]

_MAX = 2 * 1024 * 1024


@dataclass
class RecoveredCred:
    user: str
    password: str
    source: str          # "shadow-crack" / "known-hash" / config path
    method: str = ""
    uid: str = ""
    note: str = ""


def load_wordlist(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="latin1") as fh:
            return [ln.rstrip("\n") for ln in fh]
    except OSError:
        return []


def _read(p: str) -> str:
    try:
        with open(p, "rb") as fh:
            return fh.read(_MAX).decode("latin1", "replace")
    except OSError:
        return ""


def _rel(rootfs: str, p: str) -> str:
    return os.path.relpath(p, rootfs).replace("\\", "/")


# ---------------------------------------------------------------------------
# 1 + 2: crack shadow/passwd hashes
# ---------------------------------------------------------------------------

def crack_hashes(rootfs: str, wordlist: list[str] | None = None
                 ) -> tuple[list[Finding], list[RecoveredCred]]:
    words = wordlist or DEFAULT_PASSWORDS
    findings: list[Finding] = []
    recovered: list[RecoveredCred] = []

    passwd = os.path.join(rootfs, "etc", "passwd")
    shadow = os.path.join(rootfs, "etc", "shadow")
    uids: dict[str, str] = {}
    entries: list[tuple[str, str, str]] = []  # (user, hash, source)

    if os.path.isfile(passwd):
        for line in _read(passwd).splitlines():
            p = line.split(":")
            if len(p) >= 3:
                uids[p[0]] = p[2]
                if p[1] and p[1] not in ("x", "*", "!"):
                    entries.append((p[0], p[1], "etc/passwd"))
    if os.path.isfile(shadow):
        for line in _read(shadow).splitlines():
            p = line.split(":")
            if len(p) >= 2 and p[1] and p[1] not in ("*", "!", "!!", "x"):
                entries.append((p[0], p[1], "etc/shadow"))

    seen: set[tuple[str, str]] = set()
    for user, h, src in entries:
        if (user, h) in seen:
            continue
        seen.add((user, h))
        uid = uids.get(user, "")

        # known default hash table
        if h in KNOWN_DEFAULT_HASHES:
            pw, note = KNOWN_DEFAULT_HASHES[h]
            recovered.append(RecoveredCred(user, pw, "known-hash",
                                           "table", uid, note))
            findings.append(Finding(
                Severity.CRITICAL, "default-creds",
                f"'{user}' uses a known default password: {pw!r}",
                f"{note}  ({h})", src))
            continue

        # empty hash field => no password at all
        if h == "":
            recovered.append(RecoveredCred(user, "(none)", src, "empty", uid,
                                           "no password set"))
            findings.append(Finding(
                Severity.CRITICAL, "default-creds",
                f"'{user}' has NO password", "login with no credentials", src))
            continue

        if not cryptcrack.crackable(h):
            # descrypt / bcrypt / yescrypt — note for offline cracking
            continue

        for w in words:
            if cryptcrack.verify(w, h):
                shown = w if w != "" else "(blank)"
                recovered.append(RecoveredCred(user, shown, "shadow-crack",
                                               "wordlist", uid))
                findings.append(Finding(
                    Severity.CRITICAL, "default-creds",
                    f"CRACKED '{user}' password = {shown!r}",
                    f"recovered from {src} via default wordlist", src))
                break
    return findings, recovered


# ---------------------------------------------------------------------------
# 3: hardcoded default creds in config / provisioning files
# ---------------------------------------------------------------------------

_CONFIG_GLOBS = [
    "etc/**/*.conf", "etc/**/*.cfg", "etc/**/*.ini", "etc/**/*.json",
    "etc/**/*.xml", "etc/*.conf", "etc/passwd-*", "etc/*.htpasswd",
    "**/config", "**/*.htpasswd", "**/users", "**/account*",
    "usr/**/*.conf", "var/**/*.conf",
]

# user=... / password=... style assignments
_USER_ASSIGN = re.compile(
    r'(?im)(?:^|[\s,;{"\'])(user(?:name)?|login|account)\s*[:=]\s*["\']?([\w.\-@]{2,32})')
_PASS_ASSIGN = re.compile(
    r'(?im)(?:^|[\s,;{"\'])(pass(?:word|wd)?|passwphrase|secret|pin)\s*[:=]\s*["\']?([^\s"\',;}#]{1,64})')
# creds embedded in URLs: scheme://user:pass@host
_URL_CRED = re.compile(r'([a-z]+)://([^:/\s]+):([^@/\s]+)@')
# .htpasswd lines
_HTPASSWD = re.compile(r'^([\w.\-]+):(\$[16][a-z]?\$[^\s:]+|\{[A-Z]+\}[^\s:]+|[A-Za-z0-9./]{13})',
                       re.M)


def find_hardcoded_creds(rootfs: str) -> tuple[list[Finding], list[RecoveredCred]]:
    import glob
    findings: list[Finding] = []
    recovered: list[RecoveredCred] = []
    seen: set[tuple] = set()

    files: set[str] = set()
    for g in _CONFIG_GLOBS:
        files.update(glob.glob(os.path.join(rootfs, g.replace("/", os.sep)),
                               recursive=True))

    for p in sorted(files):
        if not os.path.isfile(p):
            continue
        try:
            if os.path.getsize(p) > _MAX:
                continue
        except OSError:
            continue
        rel = _rel(rootfs, p)
        text = _read(p)

        # URLs with inline creds (RTSP/HTTP/FTP/MQTT)
        for m in _URL_CRED.finditer(text):
            scheme, u, pw = m.group(1), m.group(2), m.group(3)
            if pw in ("%s", "%d", "***", "xxxx") or "$" in pw:
                continue
            key = ("url", rel, u, pw)
            if key in seen:
                continue
            seen.add(key)
            recovered.append(RecoveredCred(u, pw, rel, f"{scheme}-url"))
            findings.append(Finding(
                Severity.HIGH, "default-creds",
                f"hardcoded {scheme.upper()} credentials {u}:{pw}",
                m.group(0)[:80], rel))

        # .htpasswd hashes -> try to crack
        for m in _HTPASSWD.finditer(text):
            u, h = m.group(1), m.group(2)
            findings.append(Finding(
                Severity.HIGH, "default-creds",
                f"web-auth hash for '{u}' in {rel}", h[:60], rel))
            if cryptcrack.crackable(h):
                for w in DEFAULT_PASSWORDS:
                    if cryptcrack.verify(w, h):
                        recovered.append(RecoveredCred(u, w or "(blank)", rel,
                                                       "htpasswd-crack"))
                        findings.append(Finding(
                            Severity.CRITICAL, "default-creds",
                            f"CRACKED web login {u} = {w or '(blank)'}",
                            f"from {rel}", rel))
                        break

        # explicit user=/password= pairs in the same file
        users = [m.group(2) for m in _USER_ASSIGN.finditer(text)]
        passwords = [m.group(2) for m in _PASS_ASSIGN.finditer(text)]
        if users and passwords:
            u = users[0]
            pw = passwords[0]
            if pw not in ("%s", "%d") and not pw.startswith("$") \
                    and "PASSWORD" not in pw.upper() and len(pw) <= 40:
                key = ("kv", rel, u, pw)
                if key not in seen:
                    seen.add(key)
                    recovered.append(RecoveredCred(u, pw, rel, "config-kv"))
                    findings.append(Finding(
                        Severity.MEDIUM, "default-creds",
                        f"hardcoded credential pair {u}:{pw} in {rel}",
                        path=rel))
    return findings, recovered


# ---------------------------------------------------------------------------
# orchestrator
# ---------------------------------------------------------------------------

def analyze_default_creds(rootfs: str, wordlist: list[str] | None = None
                          ) -> tuple[list[Finding], list[RecoveredCred]]:
    findings: list[Finding] = []
    recovered: list[RecoveredCred] = []

    f, r = crack_hashes(rootfs, wordlist)
    findings += f
    recovered += r
    f, r = find_hardcoded_creds(rootfs)
    findings += f
    recovered += r
    return findings, recovered


def format_creds_table(recovered: list[RecoveredCred]) -> str:
    if not recovered:
        return "(no default/recovered credentials)"
    lines = ["  RECOVERED CREDENTIALS",
             "  " + "-" * 60,
             f"  {'user':<16}{'password':<22}{'source'}"]
    for c in recovered:
        lines.append(f"  {c.user:<16}{c.password:<22}{c.source} ({c.method})")
    return "\n".join(lines)
