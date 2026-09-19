"""Shared finding / severity model used by every analyzer."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, s: str) -> "Severity":
        return cls[s.strip().upper()]


# colourless ascii tags so output is readable when piped to a file
_TAG = {
    Severity.INFO: "INFO",
    Severity.LOW: "LOW ",
    Severity.MEDIUM: "MED ",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRIT",
}


@dataclass(frozen=True)
class Site:
    """Exactly where inside the firmware something was observed.

    Text files carry a 1-based line number; binaries carry a file offset and,
    when it can be mapped through the ELF program headers, the virtual address
    a disassembler would show. `note` tags how the site was obtained
    (e.g. "GOT" for a PLT/GOT relocation, "string ref" for a raw string match).
    """
    path: str            # rootfs-relative file
    line: int = 0        # 1-based line, text files
    offset: int = -1     # file offset, binaries
    vaddr: int = -1      # virtual address for that offset, when resolvable
    note: str = ""

    def where(self) -> str:
        tag = f" ({self.note})" if self.note else ""
        if self.line:
            return f"{self.path}:{self.line}{tag}"
        if self.vaddr >= 0 and self.offset >= 0 and self.vaddr != self.offset:
            return f"{self.path}@0x{self.vaddr:x} (file+0x{self.offset:x}){tag}"
        if self.vaddr >= 0:
            return f"{self.path}@0x{self.vaddr:x}{tag}"
        if self.offset >= 0:
            return f"{self.path}+0x{self.offset:x}{tag}"
        return f"{self.path}{tag}"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"path": self.path, "where": self.where()}
        if self.line:
            d["line"] = self.line
        if self.offset >= 0:
            d["offset"] = self.offset
        if self.vaddr >= 0:
            d["vaddr"] = self.vaddr
        if self.note:
            d["note"] = self.note
        return d


def sites_note(sites: list[Site], total: int = 0, verb: str = "found at") -> str:
    """'found at a.sh:3, bin/x@0x420 (+2 more)' for a finding's detail line."""
    if not sites:
        return ""
    more = (total or len(sites)) - len(sites)
    return (verb + " " + ", ".join(s.where() for s in sites)
            + (f" (+{more} more)" if more > 0 else ""))


@dataclass
class Finding:
    """A single observation produced by an analyzer."""
    severity: Severity
    category: str            # e.g. "credentials", "elf-hardening", "cve"
    title: str               # one-line summary
    detail: str = ""         # longer explanation / evidence
    path: str = ""           # rootfs-relative path the finding anchors to
    data: dict[str, Any] = field(default_factory=dict)  # structured extras

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d

    def line(self) -> str:
        loc = f" [{self.path}]" if self.path else ""
        return f"{_TAG[self.severity]}  {self.category}: {self.title}{loc}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), f.category, f.title))
