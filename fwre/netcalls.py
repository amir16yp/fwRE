"""Where a binary actually talks to the network: socket/TLS/HTTP API usage.

The IOC scan (``analyze.analyze_network_iocs``) answers *what* endpoints a
firmware references. This module answers *which binary reaches out, and from
where in it* - the BSD socket API, resolver, TLS and HTTP/MQTT client calls,
each reported with a concrete address you can jump to in a disassembler.

Evidence, best to worst:

* **GOT** - the symbol has a PLT/GOT relocation, so the reported address is the
  GOT slot the call goes through. This is the address to breakpoint.
* **dynsym** - the symbol is imported but no relocation names it (common on
  MIPS, whose PLT is driven by the GOT/dynsym ordering instead); the address is
  where its name sits in ``.dynstr``.
* **string ref** - statically linked or stripped, so the name is only matched in
  the raw bytes. Weakest: a name may appear for an unrelated reason.

Stdlib only; the relocation/symbol walk is a small extension of ``elf.py``.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from .finding import Finding, Severity, Site, sites_note
from . import elf as elfmod
from . import interesting as intmod

# dynamic tags used here but not exported by elf.py
DT_RELAENT = 9
DT_PLTGOT = 3
DT_MIPS_LOCAL_GOTNO = 0x7000000A
DT_MIPS_GOTSYM = 0x70000013
EM_MIPS = 8

# --- the API surface we look for -------------------------------------------
# name -> group. Groups drive severity and the one-line summary.
_NET_APIS: dict[str, str] = {
    # server side: something listens, so the device exposes attack surface
    "bind": "listen", "listen": "listen", "accept": "listen",
    "accept4": "listen",
    # outbound connections
    "connect": "connect",
    # socket plumbing (present in both directions)
    "socket": "socket", "socketpair": "socket", "setsockopt": "socket",
    "getsockopt": "socket", "getsockname": "socket", "getpeername": "socket",
    "shutdown": "socket", "if_nametoindex": "socket",
    # data transfer
    "send": "io", "sendto": "io", "sendmsg": "io", "sendfile": "io",
    "recv": "io", "recvfrom": "io", "recvmsg": "io",
    # name resolution
    "gethostbyname": "resolve", "gethostbyname2": "resolve",
    "gethostbyaddr": "resolve", "getaddrinfo": "resolve",
    "getnameinfo": "resolve", "res_query": "resolve", "res_search": "resolve",
    "res_init": "resolve", "__res_init": "resolve",
    # address helpers - weak alone, useful as corroboration
    "inet_addr": "addr", "inet_aton": "addr", "inet_ntoa": "addr",
    "inet_pton": "addr", "inet_ntop": "addr",
    # TLS
    "SSL_connect": "tls", "SSL_accept": "tls", "SSL_new": "tls",
    "SSL_CTX_new": "tls", "SSL_read": "tls", "SSL_write": "tls",
    "SSL_do_handshake": "tls", "SSL_CTX_set_verify": "tls",
    "SSL_get_verify_result": "tls", "SSL_CTX_load_verify_locations": "tls",
    "mbedtls_ssl_handshake": "tls", "mbedtls_net_connect": "tls",
    "mbedtls_ssl_conf_authmode": "tls", "wolfSSL_connect": "tls",
    "gnutls_handshake": "tls",
    # HTTP / app protocol clients
    "curl_easy_init": "http", "curl_easy_setopt": "http",
    "curl_easy_perform": "http", "curl_global_init": "http",
    "curl_multi_perform": "http",
    "mosquitto_connect": "mqtt", "mosquitto_new": "mqtt",
    "mosquitto_loop_forever": "mqtt", "MQTTClient_connect": "mqtt",
    "MQTTAsync_connect": "mqtt",
    # raw / privileged capture
    "pcap_open_live": "raw", "pcap_loop": "raw",
}

# command execution - not network on its own, but "reads a socket AND spawns a
# shell" is the shape of a command-injection bug, so it is worth correlating
_EXEC_FUNCS = {"system", "popen", "execl", "execlp", "execle", "execv",
               "execvp", "execve", "vfork"}

_GROUP_LABEL = {
    "listen": "listening socket", "connect": "outbound connect",
    "socket": "socket setup", "io": "socket I/O", "resolve": "DNS resolution",
    "addr": "address parsing", "tls": "TLS", "http": "HTTP client",
    "mqtt": "MQTT client", "raw": "raw packet capture",
}

# groups that on their own prove real network use (address parsing does not)
_STRONG_GROUPS = {"listen", "connect", "socket", "io", "resolve", "tls",
                  "http", "mqtt", "raw"}

# names too short/common to trust from a raw string match alone
_WEAK_AS_STRING = {"bind", "listen", "accept", "connect", "socket", "send",
                   "recv", "shutdown", "read", "write"}

_MAX_SITES_PER_API = 3
_MAX_APIS_IN_DETAIL = 14


@dataclass
class NetBinary:
    """Network API usage of one ELF."""
    path: str
    groups: list[str] = field(default_factory=list)
    apis: dict[str, list[Site]] = field(default_factory=dict)
    exec_apis: dict[str, list[Site]] = field(default_factory=dict)
    evidence: str = ""          # got / dynsym / string ref

    @property
    def listens(self) -> bool:
        return "listen" in self.groups

    def summary(self) -> str:
        return ", ".join(_GROUP_LABEL.get(g, g) for g in self.groups)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "evidence": self.evidence,
            "groups": self.groups,
            "listens": self.listens,
            "apis": {k: [s.to_dict() for s in v] for k, v in self.apis.items()},
            "exec_apis": {k: [s.to_dict() for s in v]
                          for k, v in self.exec_apis.items()},
        }


# ---------------------------------------------------------------------------
# ELF dynamic relocation / symbol walk
# ---------------------------------------------------------------------------

def _dyn_entries(d: bytes, en: str, is64: bool) -> dict[int, int]:
    """Tag -> value for the PT_DYNAMIC array (last value wins)."""
    e_phoff, e_phentsize, e_phnum = elfmod._phdr_meta(d, en, is64)
    dyn_off = dyn_sz = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(d):
            break
        if struct.unpack_from(en + "I", d, off)[0] != elfmod.PT_DYNAMIC:
            continue
        if is64:
            dyn_off = struct.unpack_from(en + "Q", d, off + 8)[0]
            dyn_sz = struct.unpack_from(en + "Q", d, off + 32)[0]
        else:
            dyn_off = struct.unpack_from(en + "I", d, off + 4)[0]
            dyn_sz = struct.unpack_from(en + "I", d, off + 16)[0]
        break
    if not dyn_off:
        return {}
    step = 16 if is64 else 8
    fmt = en + ("Qq" if is64 else "Ii")
    out: dict[int, int] = {}
    end = min(dyn_off + (dyn_sz or len(d)), len(d))
    p = dyn_off
    while p + step <= end:
        tag, val = struct.unpack_from(fmt, d, p)
        if tag == elfmod.DT_NULL:
            break
        out[tag] = val & 0xFFFFFFFFFFFFFFFF
        p += step
    return out


def _sym_name(d: bytes, en: str, is64: bool, symtab_off: int, syment: int,
              strtab_off: int, idx: int) -> str:
    off = symtab_off + idx * syment
    if off + 4 > len(d):
        return ""
    st_name = struct.unpack_from(en + "I", d, off)[0]
    return elfmod._cstr(d, strtab_off + st_name, 256)


@dataclass
class _Dynamic:
    """The pieces of an ELF's dynamic section this module needs."""
    en: str
    is64: bool
    segs: list
    dyn: dict[int, int]
    symtab_off: int
    strtab_off: int
    syment: int
    nsyms: int

    def foff(self, vaddr: int) -> int | None:
        return elfmod.offset_for_vaddr(self.segs, vaddr)


def _dynamic(d: bytes) -> _Dynamic | None:
    """Locate the dynamic symbol/string tables, or None for a static ELF."""
    if len(d) < 64 or d[:4] != b"\x7fELF":
        return None
    is64 = d[4] == 2
    en = ">" if d[5] == 2 else "<"
    segs = elfmod.load_segments(d)
    if not segs:
        return None
    dyn = _dyn_entries(d, en, is64)
    if not dyn:
        return None
    syment = dyn.get(elfmod.DT_SYMENT) or (24 if is64 else 16)
    symtab_v, strtab_v = dyn.get(elfmod.DT_SYMTAB, 0), dyn.get(elfmod.DT_STRTAB, 0)
    symtab_off = elfmod.offset_for_vaddr(segs, symtab_v) if symtab_v else None
    strtab_off = elfmod.offset_for_vaddr(segs, strtab_v) if strtab_v else None
    if symtab_off is None or strtab_off is None or syment <= 0:
        return None

    # symbol count: DT_HASH's nchain is exact; otherwise .dynstr normally
    # follows .dynsym, which bounds it well enough for our purposes
    nsyms = 0
    hash_v = dyn.get(elfmod.DT_HASH)
    if hash_v:
        ho = elfmod.offset_for_vaddr(segs, hash_v)
        if ho is not None and ho + 8 <= len(d):
            nsyms = struct.unpack_from(en + "I", d, ho + 4)[0]
    if not nsyms and strtab_off > symtab_off:
        nsyms = (strtab_off - symtab_off) // syment
    nsyms = min(nsyms or 0, 200000)
    return _Dynamic(en=en, is64=is64, segs=segs, dyn=dyn, symtab_off=symtab_off,
                    strtab_off=strtab_off, syment=syment, nsyms=nsyms)


def _imports(d: bytes, dy: _Dynamic) -> dict[str, int]:
    """Names this object *calls* -> dynamic symbol index.

    Only symbols left undefined (SHN_UNDEF) count: excluding defined ones is
    what keeps libc itself (which *exports* ``accept``, ``system``, ...) out of
    the results.
    """
    out: dict[str, int] = {}
    want = set(_NET_APIS) | _EXEC_FUNCS
    for i in range(dy.nsyms):
        off = dy.symtab_off + i * dy.syment
        if off + dy.syment > len(d):
            break
        st_name = struct.unpack_from(dy.en + "I", d, off)[0]
        if not st_name:
            continue
        # st_shndx: 32-bit at +14, 64-bit at +6; 0 == SHN_UNDEF == imported
        shndx = struct.unpack_from(dy.en + "H", d, off + (6 if dy.is64 else 14))[0]
        if shndx != 0:
            continue
        name = elfmod._cstr(d, dy.strtab_off + st_name, 256)
        if name in want and name not in out:
            out[name] = i
    return out


def _mips_got_sites(d: bytes, rel: str, dy: _Dynamic,
                    imports: dict[str, int]) -> dict[str, list[Site]]:
    """GOT slot per imported symbol on MIPS.

    MIPS has no symbol-named PLT relocation: every external symbol from index
    DT_MIPS_GOTSYM onwards gets a GOT entry, laid out right after the local
    ones, so the slot address is pure arithmetic.
    """
    if struct.unpack_from(dy.en + "H", d, 18)[0] != EM_MIPS:
        return {}
    pltgot = dy.dyn.get(DT_PLTGOT)
    local_gotno = dy.dyn.get(DT_MIPS_LOCAL_GOTNO)
    gotsym = dy.dyn.get(DT_MIPS_GOTSYM)
    if not pltgot or local_gotno is None or gotsym is None:
        return {}
    wsz = 8 if dy.is64 else 4
    out: dict[str, list[Site]] = {}
    for name, idx in imports.items():
        if idx < gotsym:
            continue
        va = pltgot + (local_gotno + (idx - gotsym)) * wsz
        fo = dy.foff(va)
        out[name] = [Site(path=rel, vaddr=va,
                          offset=-1 if fo is None else fo, note="GOT")]
    return out


def _reloc_sites(d: bytes, rel: str, dy: _Dynamic,
                 want: set[str]) -> dict[str, list[Site]]:
    """symbol name -> GOT/relocation sites, from the dynamic relocations."""
    out: dict[str, list[Site]] = {}
    en, is64, dyn = dy.en, dy.is64, dy.dyn
    foff = dy.foff
    symtab_off, strtab_off, syment = dy.symtab_off, dy.strtab_off, dy.syment

    # (table vaddr, table size, entry size) for every relocation table present
    tables: list[tuple[int, int, int]] = []
    rela_ent = dyn.get(DT_RELAENT) or (24 if is64 else 12)
    rel_ent = dyn.get(elfmod.DT_RELENT) or (16 if is64 else 8)
    if dyn.get(elfmod.DT_RELA) and dyn.get(elfmod.DT_RELASZ):
        tables.append((dyn[elfmod.DT_RELA], dyn[elfmod.DT_RELASZ], rela_ent))
    if dyn.get(elfmod.DT_REL) and dyn.get(elfmod.DT_RELSZ):
        tables.append((dyn[elfmod.DT_REL], dyn[elfmod.DT_RELSZ], rel_ent))
    if dyn.get(elfmod.DT_JMPREL) and dyn.get(elfmod.DT_PLTRELSZ):
        ent = rela_ent if dyn.get(elfmod.DT_PLTREL) == elfmod.DT_RELA else rel_ent
        tables.append((dyn[elfmod.DT_JMPREL], dyn[elfmod.DT_PLTRELSZ], ent))

    for tab_v, tab_sz, ent in tables:
        base = foff(tab_v)
        if base is None or ent <= 0:
            continue
        count = min(tab_sz // ent, 200000)  # cap: malformed sizes happen
        for i in range(count):
            off = base + i * ent
            if off + ent > len(d):
                break
            if is64:
                r_offset, r_info = struct.unpack_from(en + "QQ", d, off)
                sym_idx = r_info >> 32
            else:
                r_offset, r_info = struct.unpack_from(en + "II", d, off)
                sym_idx = r_info >> 8
            if not sym_idx:
                continue
            name = _sym_name(d, en, is64, symtab_off, syment, strtab_off,
                             sym_idx)
            if name not in want:
                continue
            lst = out.setdefault(name, [])
            if len(lst) >= _MAX_SITES_PER_API:
                continue
            fo = foff(r_offset)
            lst.append(Site(path=rel, vaddr=r_offset,
                            offset=-1 if fo is None else fo, note="GOT"))
    return out


def _dynstr_sites(d: bytes, rel: str, names: set[str]) -> dict[str, list[Site]]:
    """Fallback for imports with no relocation: locate the name in .dynstr."""
    out: dict[str, list[Site]] = {}
    segs = elfmod.load_segments(d)
    for n in names:
        needle = b"\x00" + n.encode() + b"\x00"
        i = d.find(needle)
        if i < 0:
            continue
        off = i + 1
        va = elfmod.vaddr_for_offset(segs, off)
        out[n] = [Site(path=rel, offset=off,
                       vaddr=-1 if va is None else va, note="dynsym")]
    return out


def _string_sites(d: bytes, rel: str) -> dict[str, list[Site]]:
    """Static/stripped fallback: NUL-delimited name matches in the raw image."""
    out: dict[str, list[Site]] = {}
    segs = elfmod.load_segments(d)
    for n in list(_NET_APIS) + sorted(_EXEC_FUNCS):
        if n in _WEAK_AS_STRING:
            continue  # "bind"/"send"/... match far too much unrelated text
        needle = b"\x00" + n.encode() + b"\x00"
        start = 0
        sites: list[Site] = []
        while len(sites) < _MAX_SITES_PER_API:
            i = d.find(needle, start)
            if i < 0:
                break
            off = i + 1
            va = elfmod.vaddr_for_offset(segs, off)
            sites.append(Site(path=rel, offset=off,
                              vaddr=-1 if va is None else va,
                              note="string ref"))
            start = i + len(needle)
        if sites:
            out[n] = sites
    return out


def scan_binary(path: str, rel: str, info=None,
                max_read: int = 32 * 1024 * 1024) -> NetBinary | None:
    """Network API usage of one ELF, or None if it makes no network calls."""
    try:
        with open(path, "rb") as fh:
            d = fh.read(max_read)
    except OSError:
        return None
    if d[:4] != b"\x7fELF":
        return None

    hits: dict[str, list[Site]] = {}
    evidence = ""
    try:
        dy = _dynamic(d)
    except Exception:  # a malformed dynamic section must not kill the scan
        dy = None

    if dy is not None:
        imported = _imports(d, dy)
        if imported:
            try:
                hits = _reloc_sites(d, rel, dy, set(imported))
            except Exception:
                hits = {}
            missing = {n: i for n, i in imported.items() if n not in hits}
            if missing:
                try:
                    hits.update(_mips_got_sites(d, rel, dy, missing))
                except Exception:
                    pass
            evidence = "GOT" if hits else "dynsym"
            # anything still unplaced: point at its name in .dynstr
            still = set(imported) - set(hits)
            if still:
                hits.update(_dynstr_sites(d, rel, still))
    else:
        # statically linked: no import table, raw string match is all we have
        hits = _string_sites(d, rel)
        evidence = "string ref"

    apis = {k: v for k, v in hits.items() if k in _NET_APIS}
    exec_apis = {k: v for k, v in hits.items() if k in _EXEC_FUNCS}
    groups = sorted({_NET_APIS[k] for k in apis})
    if not (set(groups) & _STRONG_GROUPS):
        return None  # only htons()/inet_ntoa() - not evidence of a connection
    return NetBinary(path=rel, groups=groups, apis=apis, exec_apis=exec_apis,
                     evidence=evidence)


def _detail(nb: NetBinary) -> str:
    """The per-API location list that goes into a finding's detail."""
    order = sorted(nb.apis, key=lambda n: (list(_GROUP_LABEL).index(
        _NET_APIS[n]) if _NET_APIS[n] in _GROUP_LABEL else 99, n))
    parts = [f"{n}() {sites_note(nb.apis[n], verb='at')}"
             for n in order[:_MAX_APIS_IN_DETAIL]]
    more = len(order) - len(parts)
    if more > 0:
        parts.append(f"(+{more} more API{'s' if more > 1 else ''})")
    return f"[{nb.evidence}] " + "; ".join(parts)


def analyze(rootfs: str, audits: list | None = None
            ) -> tuple[list[Finding], list[NetBinary]]:
    """Scan every ELF for network API usage.

    `audits` are the already-parsed ElfAudit objects from analyze_binaries; when
    given, their dynamic symbol lists are reused and `network_facing` is set on
    any binary where real socket evidence turns up.
    """
    by_rel = {a.path: a for a in (audits or [])}
    out: list[NetBinary] = []
    findings: list[Finding] = []

    if audits:
        targets = [(os.path.join(rootfs, a.path.replace("/", os.sep)), a.path)
                   for a in audits]
    else:
        targets = []
        for dirpath, _, files in os.walk(rootfs):
            for name in files:
                p = os.path.join(dirpath, name)
                if elfmod.is_elf(p):
                    targets.append(
                        (p, os.path.relpath(p, rootfs).replace("\\", "/")))

    for path, rel in targets:
        if not os.path.isfile(path):
            continue
        audit = by_rel.get(rel)
        nb = scan_binary(path, rel, getattr(audit, "info", None))
        if not nb:
            continue
        out.append(nb)
        if audit is not None and nb.evidence != "string ref":
            # real imports beat the filename guess analyze_binaries made
            audit.network_facing = True

        base = os.path.basename(rel)
        detail = _detail(nb)
        # a raw string match only says the name is present, not that it is
        # called, so it never carries a finding above MEDIUM; and a stock FOSS
        # daemon doing this is expected, while vendor code doing it is the
        # thing worth opening first
        weak = nb.evidence == "string ref"
        stock = base.lower() in intmod._KNOWN_NAMES
        if nb.listens and nb.exec_apis:
            names = ", ".join(f"{n}()" for n in sorted(nb.exec_apis))
            sev = Severity.MEDIUM if (weak or stock) else Severity.HIGH
            findings.append(Finding(
                sev, "network-api",
                f"'{base}' listens on a socket and spawns commands",
                f"{names} reachable from a listening service - check every "
                f"path from recv() to exec for injection. {detail}",
                path=rel, data={"groups": nb.groups}))
        elif nb.listens:
            findings.append(Finding(
                Severity.LOW if stock else Severity.MEDIUM, "network-api",
                f"'{base}' binds/listens on a socket",
                f"exposed service surface ({nb.summary()}). {detail}",
                path=rel, data={"groups": nb.groups}))
        else:
            sev = Severity.LOW if (nb.exec_apis and not stock) else Severity.INFO
            findings.append(Finding(
                sev, "network-api",
                f"'{base}' makes outbound network calls",
                f"{nb.summary()}. {detail}",
                path=rel, data={"groups": nb.groups}))

    out.sort(key=lambda n: (not n.listens, n.path))
    return findings, out
