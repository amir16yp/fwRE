"""Minimal, dependency-free ELF parser with a checksec-style hardening audit.

Enough of the ELF format is parsed to answer the questions that matter for
firmware triage: architecture, static/dynamic, stripped, and the exploit
mitigations (NX, PIE, RELRO, stack canary, FORTIFY, RPATH/RUNPATH), plus the
list of imported dynamic symbols so we can flag dangerous libc usage.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# e_machine values we care about
_MACHINES = {
    0x00: "none", 0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC",
    0x16: "S390", 0x28: "ARM", 0x2A: "SuperH", 0x32: "IA-64",
    0x3E: "x86-64", 0xB7: "AArch64", 0xF3: "RISC-V", 0x5343: "Xtensa",
}

# dynamic section tags
DT_NULL, DT_NEEDED, DT_PLTRELSZ = 0, 1, 2
DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ = 5, 6, 7, 8
DT_STRSZ, DT_SYMENT = 10, 11
DT_REL, DT_RELSZ, DT_RELENT = 17, 18, 19
DT_PLTREL, DT_JMPREL = 20, 23
DT_FLAGS, DT_FLAGS_1 = 30, 0x6ffffffb
DT_BIND_NOW = 24
DT_RPATH, DT_RUNPATH = 15, 29
DT_GNU_HASH, DT_HASH = 0x6ffffef5, 4

DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 3, 0x6474e551, 0x6474e552
ET_DYN = 3
PF_X = 0x1

# libc symbols that are classic memory-safety / command-injection footguns
DANGEROUS_FUNCS = {
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve",
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "fscanf", "vscanf", "memcpy", "strncpy", "strncat", "snprintf",
    "realpath", "getwd", "mktemp", "tmpnam", "tempnam", "alloca",
    "syslog", "getenv",
}
# fortify presence => _chk variants
_FORTIFY_SUFFIX = "_chk"


@dataclass
class ElfInfo:
    path: str = ""
    is_elf: bool = False
    bits: int = 0            # 32 / 64
    endian: str = ""         # "little" / "big"
    machine: str = ""
    etype: int = 0
    static: bool = True
    interp: str = ""
    stripped: bool = True
    # mitigations
    nx: bool = False
    pie: bool = False
    relro: str = "none"      # none / partial / full
    canary: bool = False
    fortify: bool = False
    rpath: str = ""
    runpath: str = ""
    dyn_symbols: list[str] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def kind(self) -> str:
        return "static" if self.static else "dynamic"

    def dangerous(self) -> list[str]:
        s = set(self.dyn_symbols)
        return sorted(f for f in DANGEROUS_FUNCS if f in s)

    def summary(self) -> str:
        m = []
        m.append("NX" if self.nx else "no-NX")
        m.append("PIE" if self.pie else "no-PIE")
        m.append(f"RELRO:{self.relro}")
        m.append("Canary" if self.canary else "no-canary")
        if self.fortify:
            m.append("FORTIFY")
        if self.rpath:
            m.append(f"RPATH={self.rpath}")
        if self.runpath:
            m.append(f"RUNPATH={self.runpath}")
        return " ".join(m)


def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def parse(path: str, max_read: int = 64 * 1024 * 1024) -> ElfInfo:
    info = ElfInfo(path=path)
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_read)
    except OSError as e:
        info.error = str(e)
        return info
    if data[:4] != b"\x7fELF":
        return info
    info.is_elf = True
    try:
        _parse(data, info)
    except Exception as e:  # never let a malformed binary crash a scan
        info.error = f"parse error: {e}"
    return info


def _parse(d: bytes, info: ElfInfo) -> None:
    ei_class = d[4]
    ei_data = d[5]
    info.bits = 64 if ei_class == 2 else 32
    info.endian = "big" if ei_data == 2 else "little"
    en = ">" if ei_data == 2 else "<"
    is64 = ei_class == 2

    if is64:
        (e_type, e_machine, _ver, _entry, e_phoff, e_shoff, _flags,
         _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            struct.unpack_from(en + "HHIQQQIHHHHHH", d, 16)
    else:
        (e_type, e_machine, _ver, _entry, e_phoff, e_shoff, _flags,
         _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            struct.unpack_from(en + "HHIIIIIHHHHHH", d, 16)

    info.etype = e_type
    info.machine = _MACHINES.get(e_machine, f"0x{e_machine:x}")

    # --- program headers: NX, RELRO(seg), PIE-interp, static/dynamic ----------
    has_dynamic = False
    gnu_stack_x = True  # default executable if no GNU_STACK
    has_relro_seg = False
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(d):
            break
        if is64:
            p_type, p_flags = struct.unpack_from(en + "II", d, off)
            p_offset, p_vaddr = struct.unpack_from(en + "QQ", d, off + 8)
        else:
            p_type = struct.unpack_from(en + "I", d, off)[0]
            p_offset, p_vaddr = struct.unpack_from(en + "II", d, off + 4)
            p_flags = struct.unpack_from(en + "I", d, off + 24)[0]
        if p_type == PT_GNU_STACK:
            gnu_stack_x = bool(p_flags & PF_X)
        elif p_type == PT_GNU_RELRO:
            has_relro_seg = True
        elif p_type == PT_DYNAMIC:
            has_dynamic = True
            dyn_off, dyn_vaddr = p_offset, p_vaddr
        elif p_type == PT_INTERP:
            end = d.find(b"\x00", p_offset)
            info.interp = d[p_offset:end].decode("latin1", "replace")

    info.nx = not gnu_stack_x
    info.static = not has_dynamic
    info.pie = (e_type == ET_DYN)

    # --- section headers: stripped?, section->offset map for symtab -----------
    sections = []  # (name, sh_type, offset, size, link, entsize)
    shstr_off = shstr_size = 0
    if e_shoff and e_shnum:
        # first pass to get shstrtab
        base = e_shoff + e_shstrndx * e_shentsize
        if base + e_shentsize <= len(d):
            if is64:
                _n, _t, _f, _a, s_off, s_sz = struct.unpack_from(en + "IIQQQQ", d, base)
            else:
                _n, _t, _f, _a, s_off, s_sz = struct.unpack_from(en + "IIIIII", d, base)
            shstr_off, shstr_size = s_off, s_sz
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > len(d):
                break
            if is64:
                (name, stype, _fl, _ad, s_off, s_sz, s_link, _info2,
                 _al, s_ent) = struct.unpack_from(en + "IIQQQQIIQQ", d, off)
            else:
                (name, stype, _fl, _ad, s_off, s_sz, s_link, _info2,
                 _al, s_ent) = struct.unpack_from(en + "IIIIIIIIII", d, off)
            nm = _cstr(d, shstr_off + name) if shstr_off else ""
            sections.append((nm, stype, s_off, s_sz, s_link, s_ent))

    secnames = {s[0] for s in sections}
    # SHT_SYMTAB == 2 present and not empty => not stripped
    info.stripped = not any(s[1] == 2 for s in sections)

    # --- dynamic section: RELRO(full), canary/fortify, rpath, symbols --------
    if has_dynamic:
        _parse_dynamic(d, info, en, is64, dyn_off, has_relro_seg, sections, secnames)


def _parse_dynamic(d, info, en, is64, dyn_off, has_relro_seg, sections, secnames):
    entsz = 16 if is64 else 8
    tag_fmt = en + ("qQ" if is64 else "iI")
    strtab = strsz = symtab = syment = 0
    flags = flags1 = 0
    bind_now = False
    jmprel = pltrelsz = 0
    entries = []
    off = dyn_off
    while off + entsz <= len(d):
        tag, val = struct.unpack_from(tag_fmt, d, off)
        off += entsz
        if tag == DT_NULL:
            break
        entries.append((tag, val))

    for tag, val in entries:
        if tag == DT_STRTAB:
            strtab = val
        elif tag == DT_STRSZ:
            strsz = val
        elif tag == DT_SYMTAB:
            symtab = val
        elif tag == DT_SYMENT:
            syment = val
        elif tag == DT_FLAGS:
            flags = val
        elif tag == DT_FLAGS_1:
            flags1 = val
        elif tag == DT_BIND_NOW:
            bind_now = True
        elif tag == DT_JMPREL:
            jmprel = val
        elif tag == DT_PLTRELSZ:
            pltrelsz = val

    # RELRO
    if has_relro_seg:
        now = bind_now or bool(flags & DF_BIND_NOW) or bool(flags1 & DF_1_NOW)
        info.relro = "full" if now else "partial"
    else:
        info.relro = "none"
    if flags1 & DF_1_PIE:
        info.pie = True

    # We need to translate virtual addresses (strtab/symtab) to file offsets.
    # Build a vaddr->offset map from PT_LOAD segments already parsed? We only
    # kept sections; use section vaddr/offset instead by matching names.
    v2o = _vaddr_map(d, en, is64)

    def voff(v):
        return v2o(v)

    # rpath / runpath / needed / symbols
    stroff = voff(strtab)
    if stroff is not None and strsz:
        for tag, val in entries:
            if tag == DT_RPATH:
                info.rpath = _cstr(d, stroff + val)
            elif tag == DT_RUNPATH:
                info.runpath = _cstr(d, stroff + val)
            elif tag == DT_NEEDED:
                info.needed.append(_cstr(d, stroff + val))

    # dynamic symbols: iterate .dynsym via symtab/syment, names via strtab
    symoff = voff(symtab)
    if symoff is not None and syment and stroff is not None:
        names = _read_dynsyms(d, en, is64, symoff, syment, stroff, strsz)
        info.dyn_symbols = names
        s = set(names)
        info.canary = "__stack_chk_fail" in s or "__stack_chk_guard" in s
        info.fortify = any(n.endswith(_FORTIFY_SUFFIX) and n.startswith("__")
                           for n in names)


def _vaddr_map(d, en, is64):
    """Return a function mapping a virtual address to a file offset using the
    program headers' PT_LOAD segments."""
    e_phoff, e_phentsize, e_phnum = _phdr_meta(d, en, is64)
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(d):
            break
        if is64:
            p_type = struct.unpack_from(en + "I", d, off)[0]
            p_offset, p_vaddr = struct.unpack_from(en + "QQ", d, off + 8)
            p_filesz = struct.unpack_from(en + "Q", d, off + 32)[0]
        else:
            p_type = struct.unpack_from(en + "I", d, off)[0]
            p_offset, p_vaddr = struct.unpack_from(en + "II", d, off + 4)
            p_filesz = struct.unpack_from(en + "I", d, off + 16)[0]
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))

    def f(v):
        for vaddr, offset, filesz in loads:
            if vaddr <= v < vaddr + filesz:
                return offset + (v - vaddr)
        return None
    return f


def _phdr_meta(d, en, is64):
    if is64:
        e_phoff = struct.unpack_from(en + "Q", d, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", d, 54)
    else:
        e_phoff = struct.unpack_from(en + "I", d, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", d, 42)
    return e_phoff, e_phentsize, e_phnum


def _read_dynsyms(d, en, is64, symoff, syment, stroff, strsz):
    names = []
    off = symoff
    limit = len(d)
    count = 0
    while off + syment <= limit and count < 100000:
        if is64:
            st_name = struct.unpack_from(en + "I", d, off)[0]
        else:
            st_name = struct.unpack_from(en + "I", d, off)[0]
        if st_name == 0 and count > 0:
            # many nulls means we ran off the end of the table
            pass
        if st_name and (strsz == 0 or st_name < strsz):
            nm = _cstr(d, stroff + st_name)
            if nm:
                names.append(nm)
        off += syment
        count += 1
        # heuristic stop: dynsym usually < a few thousand entries; keep bounded
        if count > 20000:
            break
    # dedupe preserving order
    seen = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _cstr(d: bytes, off: int, maxlen: int = 4096) -> str:
    if off < 0 or off >= len(d):
        return ""
    end = d.find(b"\x00", off, off + maxlen)
    if end < 0:
        end = min(off + maxlen, len(d))
    return d[off:end].decode("latin1", "replace")
