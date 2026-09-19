"""Filesystem-level permission & ownership audit.

Complements the ELF checksec pass with FS-wide hygiene checks: world-writable
files and directories, the full SUID/SGID inventory (scripts as well as ELFs),
writable boot/init scripts (persistence), loosely-permissioned key material,
and unexpected device nodes shipped in the image.

Caveat: SquashFS/UBIFS preserve Unix modes, but a 7z extraction on **Windows**
drops them, so mode-based findings can be empty or unreliable there. We detect
that case and emit an INFO note rather than silently reporting nothing.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field

from .finding import Finding, Severity


_SENSITIVE_NAMES = ("shadow", "passwd", "gshadow", ".htpasswd")
_KEY_SUFFIXES = (".key", ".pem", "_key", "id_rsa", "id_dsa", "id_ecdsa")
_INIT_HINTS = ("init.d", "rc.local", "rcs", "inittab", "profile", "/etc/rc")


def _rel(rootfs: str, p: str) -> str:
    return os.path.relpath(p, rootfs).replace("\\", "/")


@dataclass
class FsAudit:
    world_writable: list[str] = field(default_factory=list)
    suid: list[str] = field(default_factory=list)
    sgid: list[str] = field(default_factory=list)
    writable_init: list[str] = field(default_factory=list)
    loose_keys: list[str] = field(default_factory=list)
    modes_available: bool = False


# perms that only appear when Unix modes are genuinely preserved (a real
# extraction has a *mix* of these; a Windows 7z run makes everything 0777/0666)
_REAL_PERMS = {0o755, 0o644, 0o600, 0o640, 0o750, 0o700, 0o444, 0o555, 0o640}


def _modes_reliable(rootfs: str) -> bool:
    """Decide whether mode bits survived extraction. On Windows, 7z stamps every
    entry 0777/0666, which would make every dir look world-writable - so we only
    trust mode-based findings when we actually observe the varied perms that a
    mode-preserving extraction produces."""
    seen_real = 0
    seen_total = 0
    for dirpath, dirnames, files in os.walk(rootfs):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                perm = os.lstat(p).st_mode & 0o777
            except OSError:
                continue
            seen_total += 1
            if perm in _REAL_PERMS:
                seen_real += 1
            if seen_total >= 400:
                break
        if seen_total >= 400:
            break
    # require a meaningful fraction of "normal" perms to trust the data
    return seen_total > 0 and seen_real >= max(3, seen_total // 20)


def analyze(rootfs: str) -> tuple[list[Finding], FsAudit]:
    findings: list[Finding] = []
    a = FsAudit()
    a.modes_available = _modes_reliable(rootfs)
    if not a.modes_available:
        findings.append(Finding(
            Severity.INFO, "fs-perms",
            "Unix mode bits not preserved by extraction (Windows 7z) - "
            "SUID / world-writable / secret-perm checks skipped",
            "re-extract on Linux (or with a mode-preserving tool) for this pass"))
        return findings, a

    for dirpath, dirnames, files in os.walk(rootfs):
        # directories
        for d in dirnames:
            p = os.path.join(dirpath, d)
            try:
                mode = os.lstat(p).st_mode
            except OSError:
                continue
            if (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
                rel = _rel(rootfs, p)
                a.world_writable.append(rel)
                findings.append(Finding(
                    Severity.MEDIUM, "fs-perms",
                    f"world-writable directory (no sticky bit): {rel}",
                    "any process can plant/replace files here", rel))
        # files
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                continue
            perm = mode & 0o777
            rel = _rel(rootfs, p)
            low = rel.lower()

            if mode & stat.S_ISUID:
                a.suid.append(rel)
                findings.append(Finding(
                    Severity.HIGH, "fs-perms", f"SUID file: {rel}",
                    "runs with owner (often root) privileges", rel))
            if mode & stat.S_ISGID and stat.S_IXGRP & mode:
                a.sgid.append(rel)
                findings.append(Finding(
                    Severity.MEDIUM, "fs-perms", f"SGID file: {rel}", path=rel))

            if mode & stat.S_IWOTH:
                # world-writable executable or script is worst
                sev = Severity.HIGH if (mode & stat.S_IXUSR) else Severity.MEDIUM
                a.world_writable.append(rel)
                if any(h in low for h in _INIT_HINTS):
                    a.writable_init.append(rel)
                    findings.append(Finding(
                        Severity.HIGH, "fs-perms",
                        f"world-writable boot/init script: {rel}",
                        "tamper the boot chain for persistence", rel))
                else:
                    findings.append(Finding(
                        sev, "fs-perms", f"world-writable file: {rel}", path=rel))

            # loosely-permissioned secrets
            if (any(low.endswith(s) or os.path.basename(low) == s
                    for s in _SENSITIVE_NAMES)
                    or any(low.endswith(k) for k in _KEY_SUFFIXES)):
                if perm & 0o077 and perm != 0:
                    a.loose_keys.append(rel)
                    findings.append(Finding(
                        Severity.MEDIUM, "fs-perms",
                        f"secret/key file group/other-readable: {rel} ({perm:o})",
                        "credential material not restricted to owner", rel))

            # device nodes shipped in an image are unusual (and a 7z artifact)
            if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                findings.append(Finding(
                    Severity.INFO, "fs-perms",
                    f"device node in image: {rel}", path=rel))

    return findings, a
