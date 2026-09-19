"""Root-filesystem analyzers.

Each analyzer takes a rootfs path and returns a list of Finding objects. The
top-level analyze_rootfs() runs them all and also gathers structured artifacts
(component list, ELF audit table, credentials, IOCs) for the report/JSON.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field

from .finding import Finding, Severity
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
from .strings_util import strings_file

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


def _walk_files(rootfs: str):
    for dirpath, _, files in os.walk(rootfs):
        for f in files:
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

_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     Severity.CRITICAL, "private key material embedded in firmware"),
    (re.compile(r"-----BEGIN CERTIFICATE-----"),
     Severity.LOW, "TLS certificate embedded"),
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


def analyze_secrets(rootfs: str) -> list[Finding]:
    findings: list[Finding] = []
    seen_msgs: set[tuple[str, str, str]] = set()
    for path in _walk_files(rootfs):
        rel = _rel(rootfs, path)
        ext = os.path.splitext(path)[1].lower()
        # key/cert files by extension
        if ext in _KEY_FILE_EXT:
            findings.append(Finding(
                Severity.HIGH, "secrets", f"key/cert file present: {rel}",
                path=rel))
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
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
            text = "\n".join(strings_file(path, min_len=6,
                                          max_read=_SECRET_ELF_MAX))
        else:
            if size > _MAX_TEXT:
                continue
            text = _read_text(path)

        lib_vec = is_binary and certmod._is_crypto_lib(rel)
        for pat, sev, desc in _SECRET_PATTERNS:
            # a crypto library's own compiled-in test keys/certs are public and
            # usually unused - don't raise them as embedded firmware secrets
            if lib_vec and ("private key" in desc or "certificate" in desc):
                continue
            for m in pat.finditer(text):
                val = m.group(m.lastindex) if m.lastindex else m.group(0)
                if val and ("%" in val or val in ("...", "xxx", "yyy", "xxxx")):
                    continue
                snippet = m.group(0)
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                key = (rel, desc, snippet)
                if key in seen_msgs:
                    continue
                seen_msgs.add(key)
                findings.append(Finding(sev, "secrets", desc,
                                        detail=snippet, path=rel))

        # entropy-gated generic secret assignments (cuts placeholder noise)
        for m in _ENTROPY_ASSIGN.finditer(text):
            val = m.group(1)
            if "%" in val or val.upper() in ("PASSWORD", "SECRET", "CHANGEME"):
                continue
            if _shannon(val) < 3.5:
                continue
            key = (rel, "high-entropy secret", val[:24])
            if key in seen_msgs:
                continue
            seen_msgs.add(key)
            findings.append(Finding(
                Severity.MEDIUM, "secrets",
                "high-entropy secret assignment",
                detail=(m.group(0)[:80]), path=rel))
    return findings


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


def analyze_network_iocs(rootfs: str) -> tuple[list[Finding], dict]:
    urls: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()
    macs: set[str] = set()
    for path in _walk_files(rootfs):
        rel = _rel(rootfs, path)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > 16 * 1024 * 1024:
            continue
        if elfmod.is_elf(path):
            text = "\n".join(strings_file(path, min_len=6, max_read=16 * 1024 * 1024))
        elif _is_probably_text(path):
            text = _read_text(path)
        else:
            continue
        for m in _URL_RE.finditer(text):
            urls.add(m.group(0))
        for m in _IP_RE.finditer(text):
            ip = m.group(0)
            first = ip.split(".")[0]
            if first.isdigit() and 0 < int(first) < 240 and ip not in ("0.0.0.0",):
                ips.add(ip)
        for m in _DOMAIN_RE.finditer(text):
            domains.add(m.group(0).lower())
        for m in _MAC_RE.finditer(text):
            mac = m.group(0).lower()
            if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                macs.add(mac)

    findings: list[Finding] = []
    for u in sorted(urls):
        ul = u.lower()
        sev = Severity.LOW
        is_ota = any(h in ul for h in _OTA_HINTS)
        is_p2p = any(h in ul for h in _P2P_HINTS)
        if u.startswith("http://") and is_ota:
            # cleartext firmware/update fetch = classic supply-chain vector
            findings.append(Finding(
                Severity.HIGH, "network-ioc",
                f"cleartext OTA/update endpoint: {u}",
                "unauthenticated HTTP firmware fetch - MITM to implant", path=""))
            continue
        if is_p2p:
            findings.append(Finding(
                Severity.MEDIUM, "network-ioc",
                f"P2P/cloud control endpoint: {u}",
                "device phone-home / remote-access infrastructure", path=""))
            continue
        if u.startswith("http://"):
            sev = Severity.MEDIUM
        if is_ota:
            sev = max(sev, Severity.MEDIUM)
        findings.append(Finding(sev, "network-ioc", f"URL: {u}", path=""))

    cloud = sorted(d for d in domains
                   if any(h in d for h in _CLOUD_HINTS + _P2P_HINTS))
    for d in cloud:
        sev = Severity.LOW if any(h in d for h in _P2P_HINTS) else Severity.INFO
        findings.append(Finding(sev, "network-ioc",
                                f"cloud/P2P service domain: {d}"))
    iocs = {"urls": sorted(urls), "ips": sorted(ips),
            "domains": sorted(domains), "cloud_domains": cloud,
            "macs": sorted(macs)}
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
    stats: dict = field(default_factory=dict)
    certs: list = field(default_factory=list)            # certmod.CertInfo
    key_fps: list = field(default_factory=list)          # private-key sha256s
    cloud: list = field(default_factory=list)            # cloudmod.CloudSDK
    busybox: object | None = None                        # bbmod.BusyBoxInfo
    fs_audit: object | None = None                       # fsmod.FsAudit
    boot: list = field(default_factory=list)             # boot/uImage info dicts


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

    rep.findings += analyze_secrets(rootfs)

    f, audits = analyze_binaries(rootfs)
    rep.findings += f
    rep.elf_audits = audits

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
