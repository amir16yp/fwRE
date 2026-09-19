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
