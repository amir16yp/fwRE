"""ASCII/UTF-16 string extraction, like `strings(1)` but in-process."""
from __future__ import annotations

import functools
import re


@functools.lru_cache(maxsize=16)
def _ascii_re(min_len: int) -> re.Pattern:
    return re.compile(rb"[\x20-\x7e]{%d,}" % min_len)


@functools.lru_cache(maxsize=16)
def _utf16_re(min_len: int) -> re.Pattern:
    return re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)


def strings(data: bytes, min_len: int = 4, utf16: bool = True) -> list[str]:
    out = []
    for m in _ascii_re(min_len).finditer(data):
        out.append(m.group().decode("latin1"))
    if utf16:
        for m in _utf16_re(min_len).finditer(data):
            out.append(m.group().decode("utf-16-le", "replace"))
    return out


def strings_file(path: str, min_len: int = 4, max_read: int = 64 * 1024 * 1024,
                 utf16: bool = True) -> list[str]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_read)
    except OSError:
        return []
    return strings(data, min_len, utf16)


def iter_string_blob(path: str, min_len: int = 4,
                     max_read: int = 64 * 1024 * 1024) -> str:
    """Return all extracted strings joined by newlines (cheap grep target)."""
    return "\n".join(strings_file(path, min_len, max_read))
