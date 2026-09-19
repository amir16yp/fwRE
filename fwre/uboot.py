"""Boot-chain analysis on the raw flash image (pre-extraction).

The extractor throws everything away except the rootfs, but the bootloader and
kernel container carry their own risk. Working directly on the `.bin` we:

  * locate U-Boot version banners,
  * parse legacy uImage headers (magic 0x27051956) for kernel name / load addr /
    OS / arch / compression,
  * carve the U-Boot environment (bootargs / bootcmd) and flag an
    init=/bin/sh drop-to-shell or a boot chain with no image verification.

Everything is offset-agnostic string/struct scanning - no external tools.
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field

from .finding import Finding, Severity
from . import cvedb


_UIMAGE_MAGIC = 0x27051956
# U-Boot image.h enums
_IH_OS = {0: "invalid", 1: "OpenBSD", 2: "NetBSD", 3: "FreeBSD", 5: "Linux",
          17: "U-Boot", 20: "VxWorks", 22: "QNX", 25: "ARM Trusted FW"}
_IH_ARCH = {0: "invalid", 2: "ARM", 3: "x86", 4: "IA64", 5: "MIPS",
            6: "MIPS64", 7: "PPC", 22: "AArch64"}
_IH_TYPE = {2: "kernel", 3: "ramdisk", 5: "multi", 7: "firmware",
            8: "script", 9: "filesystem"}
_IH_COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4"}

_UBOOT_RE = re.compile(rb"U-Boot(?:\s+SPL)?\s+(\d{4}\.\d{2}[\w.\-]*)")
_ENV_KEYS = (b"bootargs=", b"bootcmd=", b"baudrate=", b"ipaddr=", b"serverip=",
             b"bootdelay=")


@dataclass
class UBootInfo:
    uboot: str = ""
    uimages: list[dict] = field(default_factory=list)      # parsed uImage headers
    env: dict = field(default_factory=dict)                 # recovered env vars


def _carve_cstr(d: bytes, start: int, maxlen: int = 512) -> str:
    end = d.find(b"\x00", start, start + maxlen)
    if end < 0:
        end = min(start + maxlen, len(d))
    return d[start:end].decode("latin1", "replace")


def analyze(image_path: str, max_scan: int = 64 * 1024 * 1024
            ) -> tuple[list[Finding], UBootInfo]:
    findings: list[Finding] = []
    info = UBootInfo()
    try:
        with open(image_path, "rb") as fh:
            d = fh.read(max_scan)
    except OSError:
        return findings, info
    rel = os.path.basename(image_path)

    # --- U-Boot version ------------------------------------------------------
    m = _UBOOT_RE.search(d)
    if m:
        info.uboot = m.group(1).decode("latin1")

    # --- uImage headers ------------------------------------------------------
    start = 0
    magic_be = struct.pack(">I", _UIMAGE_MAGIC)
    while True:
        i = d.find(magic_be, start)
        if i < 0 or i + 64 > len(d):
            break
        start = i + 4
        try:
            (magic, _hcrc, _time, size, load, ep, _dcrc, os_, arch, typ,
             comp) = struct.unpack_from(">IIIIIIIBBBB", d, i)
            name = _carve_cstr(d, i + 32, 32)
        except struct.error:
            continue
        if not (0 < size < 64 * 1024 * 1024):
            continue
        uimg = {
            "offset": i, "name": name, "size": size,
            "load": f"0x{load:08x}", "entry": f"0x{ep:08x}",
            "os": _IH_OS.get(os_, str(os_)), "arch": _IH_ARCH.get(arch, str(arch)),
            "type": _IH_TYPE.get(typ, str(typ)), "comp": _IH_COMP.get(comp, str(comp)),
        }
        info.uimages.append(uimg)
        findings.append(Finding(
            Severity.INFO, "boot",
            f"uImage: {uimg['type']} '{name or '(unnamed)'}' "
            f"{uimg['os']}/{uimg['arch']} {uimg['comp']} @0x{i:x}",
            f"load {uimg['load']} entry {uimg['entry']} size {size}", rel))
        if len(info.uimages) >= 16:
            break

    # --- U-Boot environment --------------------------------------------------
    for key in _ENV_KEYS:
        j = d.find(key)
        if j < 0:
            continue
        val = _carve_cstr(d, j + len(key))
        k = key.rstrip(b"=").decode("latin1")
        if val and val.isprintable():
            info.env[k] = val

    ba = info.env.get("bootargs", "")
    if ba:
        findings.append(Finding(Severity.INFO, "boot",
                                "U-Boot bootargs recovered from image",
                                ba[:200], rel))
        if re.search(r"init=/bin/(?:sh|ash)\b", ba) or " single" in f" {ba}":
            findings.append(Finding(
                Severity.HIGH, "boot",
                "U-Boot bootargs drop to a root shell (init=/bin/sh / single)",
                ba[:120], rel))
    bc = info.env.get("bootcmd", "")
    if bc:
        # a bootcmd that bootm's a raw address with no source of a verified/
        # signed image is the norm on these devices - note the lack of FIT/verify
        if "bootm" in bc and "verify" not in bc.lower() and "hash" not in bc.lower():
            findings.append(Finding(
                Severity.MEDIUM, "boot",
                "boot chain has no image verification (plain bootm, no FIT/verify)",
                "a writable kernel/rootfs partition -> persistent implant", rel))
    if info.env.get("bootdelay", "") not in ("", "0", "-1", "-2"):
        findings.append(Finding(
            Severity.LOW, "boot",
            f"U-Boot bootdelay={info.env['bootdelay']} - interruptible boot prompt",
            "physical access to the console can halt boot and edit env", rel))

    # --- version -> CVE ------------------------------------------------------
    if info.uboot:
        comps = cvedb.fingerprint({rel: [f"U-Boot {info.uboot}"]})
        for c in comps:
            findings.append(Finding(Severity.INFO, "component",
                                    f"{c.name} {c.version}", c.evidence, rel))
        for h in cvedb.match_cves(comps):
            findings.append(Finding(Severity.parse(h.severity), "cve",
                                    f"{h.component} {h.version}: {h.cve}",
                                    h.note, rel, data={"cve": h.cve}))
    return findings, info
