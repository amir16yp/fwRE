"""Boot-log analyzer.

Serial-console boot captures (`*.bootlog.txt`) are gold and usually ignored:
they reveal the U-Boot version, exact kernel banner (+ toolchain), the MTD
partition map (`mtdparts`), the kernel command line (`bootargs`: init=, console=,
root=, rw), detected sensors/Wi-Fi, and sometimes credentials printed at boot.
We parse those out, raise findings for the risky bits, and hand the version
strings to the CVE fingerprinter so kernel/U-Boot CVEs land even without a
rootfs.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .finding import Finding, Severity
from . import cvedb


_UBOOT_RE = re.compile(r"U-Boot(?:\s+SPL)?\s+(\d{4}\.\d{2}[\w.\-]*)")
_LINUX_RE = re.compile(r"Linux version\s+(\S+)")
_GCC_RE = re.compile(r"gcc version\s+([\d.]+)")
_CMDLINE_RE = re.compile(r"(?:Kernel command line|cmdline|bootargs)[\s:=\[]+(.+)")
_MTDPARTS_RE = re.compile(r"mtdparts=([^\s\]]+)")
_PART_RE = re.compile(r"0x[0-9a-fA-F]+-0x[0-9a-fA-F]+\s*:\s*\"([^\"]+)\"")


@dataclass
class BootInfo:
    source: str = ""
    uboot: str = ""
    kernel: str = ""
    gcc: str = ""
    bootargs: str = ""
    mtdparts: str = ""
    partitions: list[str] = field(default_factory=list)


def find_bootlogs(image_or_dir: str) -> list[str]:
    """Given a firmware image path (or a directory), find sibling *.bootlog.txt.
    Matches by shared stem prefix so `foo-virgin.bin` -> `foo.bootlog.txt`."""
    out: list[str] = []
    if os.path.isdir(image_or_dir):
        base_dir, stem = image_or_dir, ""
    else:
        base_dir = os.path.dirname(os.path.abspath(image_or_dir)) or "."
        stem = os.path.basename(image_or_dir)
    stem_key = re.split(r"[-_.]", stem)[0].lower() if stem else ""
    try:
        for name in os.listdir(base_dir):
            if name.lower().endswith(".bootlog.txt"):
                if not stem_key or name.lower().startswith(stem_key):
                    out.append(os.path.join(base_dir, name))
    except OSError:
        pass
    return out


def _read(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(4 * 1024 * 1024).decode("latin1", "replace")
    except OSError:
        return ""


def analyze(bootlog_path: str) -> tuple[list[Finding], BootInfo]:
    findings: list[Finding] = []
    info = BootInfo(source=os.path.basename(bootlog_path))
    text = _read(bootlog_path)
    if not text:
        return findings, info
    rel = info.source

    m = _UBOOT_RE.search(text)
    if m:
        info.uboot = m.group(1)
    m = _LINUX_RE.search(text)
    if m:
        info.kernel = m.group(1)
    m = _GCC_RE.search(text)
    if m:
        info.gcc = m.group(1)
    m = _MTDPARTS_RE.search(text)
    if m:
        info.mtdparts = m.group(1)
    m = _CMDLINE_RE.search(text)
    if m:
        info.bootargs = m.group(1).strip()
    info.partitions = _PART_RE.findall(text)

    # --- bootargs / boot-chain security --------------------------------------
    ba = info.bootargs.lower()
    if info.bootargs:
        findings.append(Finding(Severity.INFO, "boot",
                                f"kernel bootargs recovered", info.bootargs[:200], rel))
        if re.search(r"init=/bin/(?:sh|ash)\b", ba) or "single" in ba.split():
            findings.append(Finding(
                Severity.HIGH, "boot",
                "bootargs drop to a root shell (init=/bin/sh or single)",
                "anyone with console/env access gets unauth root", rel))
        if "console=" in ba:
            findings.append(Finding(
                Severity.LOW, "boot",
                "serial console enabled in bootargs",
                "UART shell available with physical access", rel))
        if re.search(r"\brootfstype=squashfs\b", ba) and re.search(r"\brw\b", ba):
            findings.append(Finding(
                Severity.LOW, "boot",
                "root mounted rw (squashfs is RO; check overlay/jffs mounts)",
                info.bootargs[:120], rel))

    if info.mtdparts:
        findings.append(Finding(Severity.INFO, "boot",
                                "MTD partition layout recovered",
                                info.mtdparts[:200], rel))

    # --- version -> CVE fingerprinting --------------------------------------
    lines = []
    if info.uboot:
        lines.append(f"U-Boot {info.uboot}")
    if info.kernel:
        # normalise the messy Ingenic banner to a plain "Linux version x.y.z"
        kv = re.match(r"(\d+\.\d+(?:\.\d+)?)", info.kernel)
        if kv:
            lines.append(f"Linux version {kv.group(1)}")
    comps = cvedb.fingerprint({rel: lines})
    for c in comps:
        findings.append(Finding(Severity.INFO, "component",
                                f"{c.name} {c.version}", c.evidence, rel))
    for h in cvedb.match_cves(comps):
        findings.append(Finding(Severity.parse(h.severity), "cve",
                                f"{h.component} {h.version}: {h.cve}",
                                h.note, rel, data={"cve": h.cve}))

    # credentials echoed to the console at boot
    for m in re.finditer(r"(?i)(password|passwd|login)\s*[:=]\s*(\S+)", text):
        val = m.group(2)
        if val.lower() not in ("(null)", "null", "none", "") and len(val) <= 32:
            findings.append(Finding(
                Severity.MEDIUM, "boot",
                f"credential-looking token printed at boot: {m.group(1)}={val}",
                "verify whether it is a live credential", rel))
    return findings, info
