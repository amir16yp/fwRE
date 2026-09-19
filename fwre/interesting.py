"""Surface the *interesting / unusual* binaries in a firmware image.

Most ELFs in a stock image are boring: BusyBox and its applet symlinks, the
libc/loader, a handful of well-known FOSS daemons (dropbear, dnsmasq, ...).
The bugs and backdoors live in the *vendor* code — the proprietary daemon that
talks to the cloud, the setuid helper dropped in ``/tmp``, the one blob built
with a different toolchain, the UPX-packed updater. This module ranks every ELF
by how much it stands out from the rest of the image so a reverse-engineer knows
what to open first.

It reuses the already-parsed ``ElfAudit``/``ElfInfo`` from ``analyze_binaries``
(no re-parsing) and scores each binary on a mix of absolute signals (packed,
setuid, suspicious name, proprietary SDK libs) and *outlier* signals measured
against this image's own population (arch, toolchain, size, strip-state). It
finds nothing about memory safety — it only points, it doesn't judge.
"""
from __future__ import annotations

import os
import statistics
from dataclasses import dataclass, field

from .finding import Finding, Severity

# --- what counts as "boring" ------------------------------------------------

# shared-library basename prefixes that ship with essentially every image
_STOCK_LIB_PREFIXES = (
    "ld-", "ld.so", "libc-", "libc.", "libc.so", "libm", "libdl", "libpthread",
    "librt", "libresolv", "libnss", "libnsl", "libcrypt", "libutil", "libanl",
    "libgcc_s", "libstdc++", "libuclibc", "ld-uclibc", "ld-musl", "libmusl",
    "libatomic", "libitm", "libgomp", "libthread_db", "libcidn",
)

# well-known FOSS components: present ≠ unusual (their *other* signals still count)
_KNOWN_NAMES = {
    "busybox", "busybox.nosuid", "busybox.suid", "toybox",
    "dropbear", "dropbearmulti", "dbclient", "sshd", "ssh", "scp",
    "dnsmasq", "hostapd", "wpa_supplicant", "wpa_cli", "iw", "iwconfig",
    "vsftpd", "proftpd", "bftpd", "pure-ftpd", "tftpd", "telnetd",
    "lighttpd", "nginx", "apache", "httpd", "boa", "thttpd", "mini_httpd",
    "smbd", "nmbd", "samba", "mosquitto", "ntpd", "ntpdate", "chronyd",
    "snmpd", "miniupnpd", "upnpd", "igmpproxy", "openssl", "curl", "wget",
    "iptables", "ip6tables", "ebtables", "brctl", "ip", "tc", "ifconfig",
    "route", "udhcpc", "udhcpd", "dhcpd", "pppd", "openvpn", "stunnel",
    "strongswan", "ipsec", "crond", "syslogd", "klogd", "logrotate",
    "dbus-daemon", "avahi-daemon", "watchdog", "mdev", "ubusd", "ubus",
    "procd", "netifd", "logd", "rpcbind", "portmap", "getty", "login",
    "sqlite3", "lua", "luajit", "python", "perl", "expat",
}

# proprietary / SDK shared libs whose mere presence is a strong "vendor" tell
_SDK_LIB_HINTS = (
    "tuya", "gwell", "ajcloud", "iotc", "tutk", "kalay", "xmeye", "ppcs",
    "cs2", "p2p", "ilnk", "anyka", "hisi", "ingenic", "sstar", "sigma",
    "novatek", "grain", "gokemedia", "fullhan", "goke", "cloud", "aliyun",
    "onvif", "gsoap", "media_sdk", "isp", "venc", "aenc", "mpp",
)

# tokens in a basename that hint at hidden functionality / attack surface
_SUSPICIOUS_TOKENS = (
    "backdoor", "debug", "factory", "diag", "test", "telnet", "shell",
    "cmd", "exec", "root", "super", "hidden", "secret", "recovery",
    "update", "upgrade", "ota", "flash", "cloud", "p2p", "remote",
    "getshell", "adbd", "console", "serial",
)

# standard directories a binary is expected to live in; anything else is odd
_STANDARD_DIRS = (
    "bin", "sbin", "usr/bin", "usr/sbin", "usr/lib", "lib", "lib64",
    "usr/lib64", "usr/libexec", "libexec",
)
# directories that are outright suspicious for an executable to sit in
_ODD_DIRS = (
    "tmp", "var", "home", "root", "mnt", "media", "data", "opt", "app",
    "system", "usr/local", "etc", "www", "web", "run", "dev",
)


@dataclass
class InterestingBinary:
    path: str
    score: int
    reasons: list[str] = field(default_factory=list)
    machine: str = ""
    size: int = 0

    def to_dict(self):
        return {"path": self.path, "score": self.score, "reasons": self.reasons,
                "machine": self.machine, "size": self.size}


def _basename(rel: str) -> str:
    return rel.rsplit("/", 1)[-1].lower()


def _is_stock_lib(base: str) -> bool:
    return base.startswith(_STOCK_LIB_PREFIXES)


def _top_dir(rel: str) -> str:
    """Directory portion, normalised, used to judge whether a location is odd."""
    d = rel.rsplit("/", 1)[0] if "/" in rel else ""
    return d.lower()


def _size_of(rootfs: str, rel: str) -> int:
    try:
        return os.path.getsize(os.path.join(rootfs, rel.replace("/", os.sep)))
    except OSError:
        return 0


def analyze(rootfs: str, audits: list) -> tuple[list[Finding], list[InterestingBinary]]:
    """Rank ``audits`` (list of analyze.ElfAudit) by how unusual each ELF is.

    Returns (findings, ranked) where ``ranked`` is every binary that scored at
    all, most-interesting first, and ``findings`` covers those worth flagging.
    """
    if not audits:
        return [], []

    n = len(audits)
    relatives_ok = n >= 5   # outlier signals need a population to compare against

    # --- corpus statistics for the outlier signals --------------------------
    machines: dict[str, int] = {}
    toolchains: dict[str, int] = {}
    sizes: dict[str, int] = {}
    for a in audits:
        machines[a.info.machine] = machines.get(a.info.machine, 0) + 1
        if a.info.comment:
            toolchains[a.info.comment] = toolchains.get(a.info.comment, 0) + 1
        sizes[a.path] = _size_of(rootfs, a.path)

    majority_machine = max(machines, key=machines.get) if machines else ""
    majority_tc = max(toolchains, key=toolchains.get) if toolchains else ""
    size_vals = [s for s in sizes.values() if s > 0]
    median_size = statistics.median(size_vals) if size_vals else 0
    stripped_count = sum(1 for a in audits if a.info.stripped)
    mostly_stripped = relatives_ok and stripped_count >= 0.6 * n

    ranked: list[InterestingBinary] = []
    for a in audits:
        i = a.info
        rel = a.path
        base = _basename(rel)
        size = sizes.get(rel, 0)
        score = 0
        reasons: list[str] = []

        def add(pts: int, why: str):
            nonlocal score
            score += pts
            reasons.append(why)

        is_module = base.endswith(".ko")
        is_lib = (base.startswith("lib") or ".so" in base) and not is_module
        stock_lib = _is_stock_lib(base)
        known = base in _KNOWN_NAMES
        # applets resolve to busybox and are usually symlinks anyway.

        # 1. custom / unknown-provenance binary — the core "vendor code" signal
        if not stock_lib and not known:
            if is_module:
                add(3, "vendor kernel module")
            elif is_lib:
                add(2, "non-standard shared library")
            else:
                add(3, "custom / non-stock executable")

        # 2. proprietary SDK library or a binary linking one
        sdk_self = any(h in base for h in _SDK_LIB_HINTS)
        sdk_dep = sorted({h for dep in i.needed for h in _SDK_LIB_HINTS
                          if h in dep.lower()})
        if sdk_self:
            add(3, "proprietary SDK / cloud library")
        elif sdk_dep:
            add(2, f"links vendor SDK lib ({', '.join(sdk_dep[:3])})")

        # 3. suspicious name tokens
        hits = [t for t in _SUSPICIOUS_TOKENS if t in base]
        if hits:
            add(3, f"suspicious name token(s): {', '.join(hits[:3])}")

        # 4. privileged
        if a.setuid:
            add(3, "setuid")
        elif a.setgid:
            add(1, "setgid")

        # 5. network-facing name
        if a.network_facing:
            add(2, "network-facing daemon name")

        # 6. packed — very unusual on stock firmware
        if i.packed:
            add(4, f"packed ({i.packed})")

        # 7. RWX segment (self-modifying / JIT / loader stub)
        if i.rwx:
            add(2, "RWX segment")

        # 8. odd filesystem location for an executable
        top = _top_dir(rel)
        if not is_lib and not is_module:
            if top == "":
                add(3, "executable at filesystem root")
            elif not any(top == d or top.startswith(d + "/") for d in _STANDARD_DIRS):
                if any(top == d or top.startswith(d + "/") for d in _ODD_DIRS):
                    add(3, f"unusual location (/{top})")
                else:
                    add(1, f"non-standard location (/{top})")

        # 9. architecture outlier vs the rest of the image
        if relatives_ok and majority_machine and i.machine != majority_machine:
            add(4, f"architecture outlier ({i.machine} vs {majority_machine})")

        # 10. size outlier — a big custom app stands out
        if relatives_ok and median_size and size >= 4 * median_size and size >= 256 * 1024:
            add(2, f"large ({size // 1024} KB vs ~{int(median_size) // 1024} KB median)")

        # 11. symbols left in while the image is otherwise stripped — easy RE
        if mostly_stripped and not i.stripped and not stock_lib:
            add(2, "not stripped (symbols left in a mostly-stripped image)")

        # 12. odd toolchain (drop-in built elsewhere)
        if (relatives_ok and majority_tc and i.comment
                and i.comment != majority_tc):
            add(1, "different toolchain than the rest of the image")

        # 13. attack surface: many dangerous imports
        dang = i.dangerous()
        if len(dang) >= 6:
            add(2, f"heavy dangerous-import use ({len(dang)})")
        elif len(dang) >= 3:
            add(1, f"several dangerous imports ({len(dang)})")

        if score > 0:
            ranked.append(InterestingBinary(
                path=rel, score=score, reasons=reasons,
                machine=i.machine, size=size))

    ranked.sort(key=lambda b: (-b.score, b.path))

    # --- emit findings for the ones worth flagging --------------------------
    findings: list[Finding] = []
    for b in ranked:
        if b.score < 4:
            continue
        sev = Severity.MEDIUM if b.score >= 7 else Severity.LOW
        findings.append(Finding(
            sev, "interesting-binary",
            f"unusual binary worth manual RE: {b.path}",
            detail="; ".join(b.reasons) + f"  (interest score {b.score})",
            path=b.path,
            data={"score": b.score, "reasons": b.reasons, "arch": b.machine}))
    return findings, ranked


def format_table(ranked: list[InterestingBinary], limit: int = 15) -> str:
    """Compact console table of the top interesting binaries."""
    top = [b for b in ranked if b.score >= 3][:limit]
    if not top:
        return "No stand-out binaries (image looks like stock components)."
    L = [f"Interesting binaries (top {len(top)} of {len(ranked)} flagged):"]
    for b in top:
        kb = f"{b.size // 1024}K" if b.size else "?"
        L.append(f"  [{b.score:2}] {b.path}  ({b.machine}, {kb})")
        L.append(f"       {'; '.join(b.reasons)}")
    return "\n".join(L)
