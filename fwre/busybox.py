"""BusyBox applet enumeration + dangerous-applet flagging.

Almost every one of these camera images is a single statically-linked BusyBox
multi-call binary. Which *applets* were compiled in decides the real attack
surface: a build with `telnetd`, `httpd`, `nc`, `tftp` or `crond` is a very
different device from one without. We recover the applet list from the binary's
own string table (BusyBox embeds every applet name) and cross-check the symlink
farm in bin/ sbin/ usr/bin/ usr/sbin/ that actually exposes them on $PATH.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .finding import Finding, Severity
from .strings_util import strings_file


# applet -> (severity, why it matters)
_DANGEROUS_APPLETS = {
    "telnetd":  (Severity.HIGH,   "telnet server applet compiled in (cleartext, often unauth)"),
    "tftp":     (Severity.MEDIUM, "tftp client - arbitrary file pull/push helper"),
    "tftpd":    (Severity.MEDIUM, "tftp server applet compiled in"),
    "nc":       (Severity.MEDIUM, "netcat applet - reverse-shell / data exfil primitive"),
    "netcat":   (Severity.MEDIUM, "netcat applet - reverse-shell primitive"),
    "wget":     (Severity.LOW,    "wget applet - remote payload fetch primitive"),
    "ftpget":   (Severity.LOW,    "ftpget applet"),
    "ftpput":   (Severity.LOW,    "ftpput applet"),
    "crond":    (Severity.LOW,    "cron daemon applet - persistence surface"),
    "httpd":    (Severity.LOW,    "BusyBox httpd applet - CGI attack surface"),
    "dropbear": (Severity.INFO,   "dropbear referenced via busybox build"),
    "ash":      (Severity.INFO,   "ash shell applet present"),
    "sh":       (Severity.INFO,   "sh applet present"),
    "microcom": (Severity.LOW,    "microcom serial applet"),
    "dnsd":     (Severity.LOW,    "BusyBox dnsd applet"),
    "inetd":    (Severity.MEDIUM, "BusyBox inetd super-server applet"),
}

# a compact whitelist of legitimate applet names, used to score whether a
# string table actually *is* a busybox applet list (avoids false positives).
_APPLET_CANARIES = {
    "busybox", "ls", "cat", "cp", "mv", "rm", "mount", "umount", "ps", "kill",
    "ifconfig", "route", "ping", "sh", "ash", "echo", "grep", "sed", "mkdir",
}

_BB_DIRS = ("bin", "sbin", "usr/bin", "usr/sbin")


@dataclass
class BusyBoxInfo:
    path: str = ""
    version: str = ""
    applets: list[str] = field(default_factory=list)
    dangerous: list[str] = field(default_factory=list)
    symlinked: list[str] = field(default_factory=list)  # applets exposed via symlink


def _find_busybox(rootfs: str) -> str | None:
    for rel in ("bin/busybox", "usr/bin/busybox", "sbin/busybox"):
        p = os.path.join(rootfs, rel.replace("/", os.sep))
        if os.path.isfile(p):
            return p
    return None


def _extract_applets(binpath: str) -> tuple[str, list[str]]:
    """Return (version, applet_names). BusyBox stores its applet table as a run
    of consecutive short lowercase tokens; we harvest plausible applet names and
    validate the set against known canaries."""
    version = ""
    candidates: set[str] = set()
    for s in strings_file(binpath, min_len=2, max_read=8 * 1024 * 1024):
        if not version and s.startswith("BusyBox v"):
            version = s.split()[1].lstrip("v")
        # applet names: short, lowercase alnum + a few punct, no spaces
        if 2 <= len(s) <= 20 and s.replace("_", "").replace("-", "").isalnum() \
                and s.lower() == s and not s.isdigit():
            candidates.add(s)
    # keep only names that co-occur with the known applet set to reduce noise
    known = _known_applet_universe()
    applets = sorted(candidates & known)
    return version, applets


def _known_applet_universe() -> set[str]:
    # union of all applet names busybox has ever shipped that we care about,
    # plus the common coreutils/net ones (kept broad but bounded)
    base = {
        "busybox", "sh", "ash", "hush", "ls", "cat", "cp", "mv", "rm", "ln",
        "mkdir", "rmdir", "touch", "chmod", "chown", "chgrp", "dd", "df", "du",
        "mount", "umount", "ps", "kill", "killall", "top", "free", "uptime",
        "ifconfig", "route", "ip", "ping", "ping6", "arp", "arping", "netstat",
        "nslookup", "telnet", "telnetd", "ftpget", "ftpput", "tftp", "tftpd",
        "wget", "nc", "netcat", "httpd", "inetd", "crond", "crontab", "syslogd",
        "klogd", "logger", "dmesg", "init", "reboot", "halt", "poweroff",
        "insmod", "rmmod", "lsmod", "modprobe", "mdev", "udhcpc", "udhcpd",
        "dnsd", "microcom", "vi", "sed", "awk", "grep", "egrep", "fgrep",
        "cut", "sort", "uniq", "head", "tail", "wc", "tr", "tar", "gzip",
        "gunzip", "bzip2", "unzip", "find", "xargs", "env", "printenv", "expr",
        "test", "true", "false", "sleep", "date", "hostname", "uname", "id",
        "whoami", "who", "passwd", "login", "su", "getty", "stty", "mknod",
        "sync", "swapon", "swapoff", "losetup", "mkfs.vfat", "fdisk", "flash_eraseall",
        "nanddump", "nandwrite", "flashcp", "ubiattach", "ubimkvol", "dropbear",
    }
    return base


def analyze(rootfs: str) -> tuple[list[Finding], BusyBoxInfo]:
    findings: list[Finding] = []
    info = BusyBoxInfo()
    bb = _find_busybox(rootfs)
    if not bb:
        return findings, info
    info.path = os.path.relpath(bb, rootfs).replace("\\", "/")
    info.version, info.applets = _extract_applets(bb)

    # which applets are actually exposed as symlinks to busybox on $PATH
    exposed: set[str] = set()
    for d in _BB_DIRS:
        dp = os.path.join(rootfs, d.replace("/", os.sep))
        if not os.path.isdir(dp):
            continue
        try:
            for name in os.listdir(dp):
                fp = os.path.join(dp, name)
                try:
                    if os.path.islink(fp) and "busybox" in os.readlink(fp):
                        exposed.add(name)
                    elif name in _DANGEROUS_APPLETS and os.path.isfile(fp):
                        exposed.add(name)
                except OSError:
                    continue
        except OSError:
            continue
    info.symlinked = sorted(exposed)

    present = set(info.applets) | exposed
    for applet, (sev, why) in _DANGEROUS_APPLETS.items():
        if applet in present:
            info.dangerous.append(applet)
            exposed_note = " (symlinked on $PATH)" if applet in exposed else \
                           " (compiled in)"
            findings.append(Finding(
                sev, "busybox-applet",
                f"busybox applet '{applet}' available{exposed_note}",
                why, info.path))
    return findings, info
