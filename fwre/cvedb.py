"""Offline component-version fingerprinting + a curated CVE heuristic table.

This is intentionally a small, hand-maintained knowledge base rather than a
full NVD mirror. It fingerprints the components that dominate embedded-Linux
attack surface (busybox, dropbear, openssl, the kernel, common web servers)
and flags versions with well-known, high-impact issues. Treat matches as leads
to confirm, not proof.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Component:
    name: str
    version: str
    source: str          # rootfs-relative path the banner came from
    evidence: str = ""


@dataclass
class CveHit:
    component: str
    version: str
    cve: str
    severity: str        # CRITICAL/HIGH/MEDIUM
    note: str
    source: str = ""


# --- version fingerprints -------------------------------------------------
# name -> list of compiled regexes with a 'ver' group, run against strings.
_FINGERPRINTS: dict[str, list[re.Pattern]] = {
    "busybox": [re.compile(r"BusyBox v(?P<ver>\d+\.\d+\.\d+)")],
    "dropbear": [re.compile(r"[Dd]ropbear[ _](?:SSH[ _])?v?(?P<ver>\d{4}\.\d+)"),
                 re.compile(r"[Dd]ropbear.*?(?P<ver>\d{4}\.\d+)")],
    "openssl": [re.compile(r"OpenSSL (?P<ver>\d+\.\d+\.\d+[a-z]?)")],
    "libcurl": [re.compile(r"libcurl/(?P<ver>\d+\.\d+\.\d+)"),
                re.compile(r"curl (?P<ver>\d+\.\d+\.\d+)")],
    "wpa_supplicant": [re.compile(r"wpa_supplicant v?(?P<ver>\d+\.\d+)")],
    "hostapd": [re.compile(r"hostapd v?(?P<ver>\d+\.\d+)")],
    "lighttpd": [re.compile(r"lighttpd/(?P<ver>\d+\.\d+\.\d+)")],
    "dnsmasq": [re.compile(r"dnsmasq[- ]v?(?P<ver>\d+\.\d+)")],
    "zlib": [re.compile(r"(?:inflate|deflate) (?P<ver>1\.\d+\.\d+) Copyright")],
    "kernel": [re.compile(r"Linux version (?P<ver>\d+\.\d+(?:\.\d+)?)")],
    "goahead": [re.compile(r"GoAhead[-/ ](?P<ver>\d+\.\d+(?:\.\d+)?)")],
    "boa": [re.compile(r"Boa/(?P<ver>\d+\.\d+\.\d+)")],
    "uclibc": [re.compile(r"uClibc(?:-ng)?[ -](?P<ver>\d+\.\d+\.\d+)")],
    "glibc": [re.compile(r"GNU C Library.*?version (?P<ver>\d+\.\d+)")],
    "openssh": [re.compile(r"OpenSSH_(?P<ver>\d+\.\d+)")],
    "uboot": [re.compile(r"U-Boot(?:\s+SPL)?\s+(?P<ver>\d{4}\.\d{2})")],
    "mbedtls": [re.compile(r"[Mm]bed ?TLS (?P<ver>\d+\.\d+\.\d+)"),
                re.compile(r"PolarSSL (?P<ver>\d+\.\d+\.\d+)")],
    "wolfssl": [re.compile(r"wolfSSL (?P<ver>\d+\.\d+\.\d+)"),
                re.compile(r"CyaSSL (?P<ver>\d+\.\d+\.\d+)")],
    "sqlite": [re.compile(r"(?:SQLite|sqlite3?) (?P<ver>3\.\d+\.\d+)")],
    "expat": [re.compile(r"expat_(?P<ver>\d+\.\d+\.\d+)"),
              re.compile(r"libexpat.*?(?P<ver>\d+\.\d+\.\d+)")],
    "libpng": [re.compile(r"libpng version (?P<ver>\d+\.\d+\.\d+)")],
    "libjpeg": [re.compile(r"libjpeg-turbo version (?P<ver>\d+\.\d+\.\d+)"),
                re.compile(r"jpeg-(?P<ver>\d+[a-z]?) ")],
    "ffmpeg": [re.compile(r"(?:ffmpeg|libav\w+) version (?P<ver>\d+\.\d+)")],
    "live555": [re.compile(r"LIVE555.*?(?P<ver>\d{4}\.\d{2}\.\d{2})")],
    "lua": [re.compile(r"Lua (?P<ver>5\.\d+\.\d+)")],
    "json-c": [re.compile(r"json-c[/ ](?P<ver>\d+\.\d+)")],
    "pppd": [re.compile(r"pppd version (?P<ver>\d+\.\d+\.\d+)")],
    "ntp": [re.compile(r"ntpd (?P<ver>\d+\.\d+\.\d+)"),
            re.compile(r"ntpd? .*?(?P<ver>4\.\d+\.\d+)")],
    "mosquitto": [re.compile(r"mosquitto version (?P<ver>\d+\.\d+\.\d+)")],
}


def _v(s: str) -> tuple:
    """Loose version tuple for comparison. A trailing letter on a component is
    kept as an extra ordinal (openssl 1.0.1g -> (1,0,1,7)) so lettered branches
    like Heartbleed compare correctly; other non-numeric tails are ignored."""
    parts = re.split(r"[.\-_]", s)
    out = []
    for p in parts:
        m = re.match(r"(\d+)([a-zA-Z]?)", p)
        if m:
            out.append(int(m.group(1)))
            if m.group(2):
                out.append(ord(m.group(2).lower()) - 96)  # 'a' -> 1
        else:
            out.append(0)
    return tuple(out)


# --- CVE rules -------------------------------------------------------------
# Each rule: (component, predicate(version_tuple)->bool, cve, severity, note)
_RULES = [
    ("dropbear", lambda v: v < (2016, 74), "CVE-2016-7406/7/8/9",
     "HIGH", "format-string + cmd injection in older Dropbear (<2016.74)"),
    ("dropbear", lambda v: v < (2017, 75), "CVE-2017-9078",
     "HIGH", "post-auth root code exec via -a option (<2017.75)"),
    ("dropbear", lambda v: v < (2020, 79), "CVE-2018-15599",
     "MEDIUM", "recv_msg_userauth_request user-enum (<2018.76)"),
    ("busybox", lambda v: v < (1, 22, 0), "CVE-2011-5325",
     "MEDIUM", "busybox tar path traversal (very old)"),
    ("busybox", lambda v: v < (1, 27, 0), "CVE-2017-16544",
     "MEDIUM", "autocomplete escape-injection in busybox <1.27.0"),
    ("busybox", lambda v: v < (1, 33, 2), "CVE-2021-42374/85/86",
     "HIGH", "multiple awk/unlzma OOB + use-after-free in busybox <1.33.2"),
    ("openssl", lambda v: (1, 0, 1) <= v < (1, 0, 1, 8),
     "CVE-2014-0160", "CRITICAL",
     "Heartbleed - OpenSSL 1.0.1..1.0.1g are vulnerable"),
    ("openssl", lambda v: (1, 0, 0) <= v < (1, 0, 2), "CVE-2016-2107",
     "HIGH", "padding-oracle / many issues in OpenSSL 1.0.x branch"),
    ("openssl", lambda v: (1, 1, 0) <= v < (1, 1, 1), "CVE-2019-1543",
     "MEDIUM", "OpenSSL 1.1.0 branch EOL, unpatched CVEs likely"),
    ("openssl", lambda v: (3, 0, 0) <= v < (3, 0, 7), "CVE-2022-3602/3786",
     "HIGH", "X.509 punycode buffer overflow in OpenSSL 3.0.0..3.0.6"),
    ("dnsmasq", lambda v: v < (2, 83), "CVE-2020-25681",
     "HIGH", "DNSpooq: heap overflow / cache poisoning in dnsmasq <2.83"),
    ("lighttpd", lambda v: v < (1, 4, 51), "CVE-2019-11072",
     "MEDIUM", "path buffer overflow in lighttpd <1.4.51"),
    ("goahead", lambda v: v < (3, 6, 5), "CVE-2017-17562",
     "CRITICAL", "GoAhead RCE via CGI env injection (<3.6.5)"),
    ("kernel", lambda v: v < (3, 10), "EOL-kernel",
     "HIGH", "kernel <3.10 is EOL; numerous unpatched local/remote CVEs"),
    ("kernel", lambda v: (4, 0) <= v < (4, 4), "EOL-kernel",
     "MEDIUM", "kernel 4.0-4.3 EOL; DirtyCOW-era and later fixes missing"),
    ("zlib", lambda v: v < (1, 2, 12), "CVE-2018-25032",
     "MEDIUM", "zlib memory corruption in deflate <1.2.12"),
    ("wpa_supplicant", lambda v: v < (2, 7), "CVE-2017-13077",
     "HIGH", "KRACK key-reinstallation attacks in wpa_supplicant <2.7"),
    ("hostapd", lambda v: v < (2, 7), "CVE-2017-13082",
     "HIGH", "KRACK against the AP/FT handshake in hostapd <2.7"),
    # --- boot chain -------------------------------------------------------
    ("uboot", lambda v: v < (2014, 4), "U-Boot-EOL",
     "MEDIUM", "very old U-Boot (<2014.04) - known env/verified-boot weaknesses; "
     "e.g. CVE-2019-13103/6 (fs) class on unpatched trees"),
    ("uboot", lambda v: (2014, 4) <= v < (2020, 1), "U-Boot-old",
     "LOW", "aging U-Boot; review CVE-2019-1368x (NFS/ext4/DOS) applicability"),
    # --- kernel -----------------------------------------------------------
    ("kernel", lambda v: (3, 10) <= v < (3, 11), "EOL-kernel-3.10",
     "HIGH", "kernel 3.10.x is long EOL (Ingenic isvp BSP) - DirtyCOW "
     "(CVE-2016-5195) and many later fixes are missing"),
    ("kernel", lambda v: (4, 4) <= v < (5, 9), "CVE-2022-0847",
     "HIGH", "Dirty Pipe (CVE-2022-0847) affects 5.8+; verify patch level"),
    # --- libraries --------------------------------------------------------
    ("libcurl", lambda v: v < (7, 87, 0), "curl-old",
     "MEDIUM", "libcurl <7.87 - multiple CVEs (e.g. CVE-2023-38545 SOCKS5 "
     "heap overflow lands <8.4); confirm exact version"),
    ("sqlite", lambda v: v < (3, 32, 0), "CVE-2020-11655",
     "MEDIUM", "SQLite <3.32 - several memory-safety CVEs (e.g. CVE-2020-11655/56)"),
    ("mbedtls", lambda v: v < (2, 16, 9), "mbedtls-old",
     "MEDIUM", "mbedTLS <2.16.9 - Lucky13/side-channel & parsing CVEs"),
    ("expat", lambda v: v < (2, 2, 10), "CVE-2022-25236",
     "HIGH", "libexpat <2.2.10 - XML parsing memory-corruption CVEs"),
    ("dnsmasq", lambda v: v < (2, 90), "CVE-2023-50387",
     "MEDIUM", "dnsmasq <2.90 - DNSSEC 'KeyTrap' CPU-exhaustion exposure"),
]


def fingerprint(name_to_strings: dict[str, list[str]]) -> list[Component]:
    """Given {rootfs_path: [strings...]}, return detected components.

    Only the highest-looking version per component is kept.
    """
    best: dict[str, Component] = {}
    for path, lines in name_to_strings.items():
        blob = "\n".join(lines)
        for comp, pats in _FINGERPRINTS.items():
            for pat in pats:
                for m in pat.finditer(blob):
                    ver = m.group("ver")
                    cur = best.get(comp)
                    if cur is None or _v(ver) > _v(cur.version):
                        best[comp] = Component(comp, ver, path,
                                               evidence=m.group(0)[:80])
                    break  # first matching pattern per comp per file is enough
    return list(best.values())


def match_cves(components: list[Component]) -> list[CveHit]:
    hits = []
    for c in components:
        cv = _v(c.version)
        for comp, pred, cve, sev, note in _RULES:
            if comp != c.name:
                continue
            try:
                if pred(cv):
                    hits.append(CveHit(c.name, c.version, cve, sev, note, c.source))
            except Exception:
                continue
    return hits
