"""Terminal colour + banner helpers.

Colour is ON by default (disable with --nocolors); it is auto-suppressed when
stdout isn't a TTY unless forced. A figlet-style "fwRE" banner is printed at
startup (disable with --nologo). Stdlib only; enables ANSI on Windows consoles.
"""
from __future__ import annotations

import os
import sys

from .finding import Severity, _TAG

_USE_COLOR = True

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

_SEV_COLOR = {
    Severity.CRITICAL: "\033[1;97;41m",  # bold white on red
    Severity.HIGH: "\033[1;91m",         # bright red
    Severity.MEDIUM: "\033[93m",         # yellow
    Severity.LOW: "\033[96m",            # cyan
    Severity.INFO: "\033[90m",           # grey
}

# figlet "standard" font, "fwRE"
_F = ["  __ ", " / _|", "| |_ ", "|  _|", "|_|  "]
_W = ["          ", "__      __", "\\ \\ /\\ / /", " \\ V  V / ", "  \\_/\\_/  "]
_R = [" ____  ", "|  _ \\ ", "| |_) |", "|  _ < ", "|_| \\_\\"]
_E = [" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"]
_BANNER_LINES = ["".join(p) for p in zip(_F, _W, _R, _E)]


def _enable_windows_vt() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        for handle in (-11, -12):  # stdout, stderr
            h = k.GetStdHandle(handle)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VT_PROCESSING
    except Exception:
        pass


def configure(nocolors: bool = False) -> None:
    global _USE_COLOR
    _USE_COLOR = not nocolors and (os.environ.get("NO_COLOR") is None)
    if _USE_COLOR:
        _enable_windows_vt()


def enabled() -> bool:
    return _USE_COLOR


def color(s: str, code: str) -> str:
    return f"{code}{s}{RESET}" if _USE_COLOR else s


def banner(stream=sys.stderr) -> None:
    lines = _BANNER_LINES
    if _USE_COLOR:
        out = "\n".join(f"\033[96m{ln}\033[0m" for ln in lines)
        tag = "\033[2mLinux firmware RE / vuln framework\033[0m"
    else:
        out = "\n".join(lines)
        tag = "Linux firmware RE / vuln framework"
    print("\n" + out + "\n  " + tag + "\n", file=stream)


def finding_line(f) -> str:
    tag = _TAG[f.severity]
    loc = f" [{f.path}]" if f.path else ""
    if not _USE_COLOR:
        return f"{tag}  {f.category}: {f.title}{loc}"
    c = _SEV_COLOR.get(f.severity, "")
    return (f"{c}{tag}{RESET}  {BOLD}{f.category}{RESET}: {f.title}"
            f"{DIM}{loc}{RESET}")


def _prefix(sym: str, code: str) -> str:
    return color(sym, code)


def info(msg: str) -> str:
    return f"{_prefix('[*]', '\033[96m')} {msg}"


def ok(msg: str) -> str:
    return f"{_prefix('[+]', '\033[92m')} {msg}"


def warn(msg: str) -> str:
    return f"{_prefix('[!]', '\033[93m')} {msg}"
