"""fwre command-line interface.

Subcommands:
  extract   IMAGE [-o DIR]              7z-extract a firmware image
  analyze   ROOTFS_OR_DIR               analyze an already-extracted rootfs
  run       IMAGE [-o DIR]              extract + analyze in one shot
  batch     GLOB_OR_DIR [-o DIR]        run over many images, write a summary
  checksec  ELF...                      quick per-binary hardening report
  interesting ROOTFS                    rank the unusual / vendor binaries worth RE
  strings   FILE                        dump printable strings
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from . import extract as extractor
from . import analyze as analyzer
from . import report as reporter
from . import elf as elfmod
from . import correlate as correlator
from . import sbom as sbommod
from . import term
from .strings_util import strings_file
from .finding import sort_findings

import builtins


def _c(s: str) -> str:
    """Colourise a leading status tag ([*]/[+]/[!]) if colour is enabled."""
    for tag, code in (("[*]", "\033[96m"), ("[+]", "\033[92m"),
                      ("[!]", "\033[91m")):
        if s.startswith(tag):
            return term.color(tag, code) + s[len(tag):]
    return s


def print(*args, **kwargs):  # noqa: A001 - deliberate module-local shadow
    """Module-local print that (a) colourises status-line prefixes and (b) routes
    progress/status lines ([*]/[+]/[!]) to stderr so --json / --sbom / strings
    stdout stays machine-clean. Every print() in this file routes through it."""
    if args and isinstance(args[0], str):
        s = args[0]
        if "file" not in kwargs and s.lstrip().startswith(("[*]", "[+]", "[!]")):
            kwargs["file"] = sys.stderr
        args = (_c(s),) + args[1:]
    builtins.print(*args, **kwargs)


def _print_findings(rep, details: bool = False):
    for f in sort_findings(rep.findings):
        print("  " + term.finding_line(f))
        # the detail line carries the evidence (file:line / GOT address), which
        # is otherwise only in the -o report
        if details and f.detail:
            print("      " + term.color(f.detail, term.DIM))


def cmd_extract(args):
    if not _require_image(args.image):
        return 2
    res = extractor.extract(args.image, args.out or _default_out(args.image),
                            recurse=not args.no_recurse)
    print(f"[+] extracted to {res.out_dir}")
    print(f"[+] rootfs: {res.rootfs or '(not found - check output tree)'}")
    if not res.ok:
        print("[!] 7z reported errors (often just device nodes on Windows)")
    return 0


def cmd_analyze(args):
    rootfs = _resolve_rootfs(args.rootfs)
    if not rootfs:
        print(f"[!] no rootfs found under {args.rootfs}", file=sys.stderr)
        return 2
    print(f"[*] analyzing {rootfs}")
    rep = analyzer.analyze_rootfs(rootfs, do_iocs=not args.no_iocs)
    _emit(rep, args, image=os.path.basename(args.rootfs.rstrip("/\\")))
    return 0


def cmd_run(args):
    if not _require_image(args.image):
        return 2
    out = args.out or _default_out(args.image)
    print(f"[*] extracting {args.image} -> {out}")
    res = extractor.extract(args.image, out, recurse=not args.no_recurse)
    if not res.rootfs:
        print("[!] no rootfs detected after extraction", file=sys.stderr)
        if res.detected_fs:
            print(f"    filesystems seen: {', '.join(res.detected_fs)}", file=sys.stderr)
        if res.hint:
            print(f"    hint: {res.hint}", file=sys.stderr)
        return 2
    print(f"[*] analyzing {res.rootfs}")
    rep = analyzer.analyze_rootfs(res.rootfs, do_iocs=not args.no_iocs,
                                  image_path=args.image)
    _emit(rep, args, image=os.path.basename(args.image))
    return 0


def cmd_batch(args):
    images = _expand_images(args.target)
    if not images:
        print(f"[!] no .bin images matched {args.target}", file=sys.stderr)
        return 2
    out_root = args.out or "fwre_out"
    os.makedirs(out_root, exist_ok=True)
    rows = []
    corr_records = []
    for img in images:
        name = os.path.splitext(os.path.basename(img))[0]
        print(f"[*] {name}")
        edir = os.path.join(out_root, name)
        try:
            res = extractor.extract(img, edir, recurse=not args.no_recurse)
        except Exception as e:
            print(f"    [!] extract failed: {e}")
            continue
        if not res.rootfs:
            fs = ", ".join(res.detected_fs) if res.detected_fs else "unknown"
            print(f"    [!] no 7z-extractable rootfs (fs: {fs})"
                  + (f" - {res.hint}" if res.hint else ""))
            continue
        rep = analyzer.analyze_rootfs(res.rootfs, do_iocs=not args.no_iocs,
                                      image_path=img)
        corr_records.append(correlator.record(name, rep))
        # non-interactive dumps only when explicitly requested (batch = bulk)
        if getattr(args, "crack", False):
            _crack_assist(rep, args, name)
        if getattr(args, "dumpsecrets", False):
            _dump_secrets(rep, args, name)
        # write per-image reports
        with open(os.path.join(out_root, name + ".md"), "w", encoding="utf-8") as fh:
            fh.write(reporter.to_markdown(rep, image=name))
        with open(os.path.join(out_root, name + ".json"), "w", encoding="utf-8") as fh:
            fh.write(reporter.to_json(rep, image=name))
        top = ""
        crit = [f for f in rep.findings if f.severity.label == "CRITICAL"]
        if crit:
            top = crit[0].title
        rows.append({
            "image": name,
            "critical": rep.stats.get("critical", 0),
            "high": rep.stats.get("high", 0),
            "elf_count": rep.stats.get("elf_count", 0),
            "cves": len(rep.cves),
            "top": top,
        })
        print(f"    crit={rep.stats.get('critical',0)} high={rep.stats.get('high',0)} "
              f"elfs={rep.stats.get('elf_count',0)} cve={len(rep.cves)}")
    summary = reporter.batch_summary_markdown(rows)
    correlation = correlator.build_report(corr_records)
    with open(os.path.join(out_root, "SUMMARY.md"), "w", encoding="utf-8") as fh:
        fh.write(summary)
        if correlation:
            fh.write(correlation)
    print("\n" + summary)
    if correlation:
        print(correlation)
    print(f"[+] reports written to {out_root}/")
    return 0


def cmd_creds(args):
    from . import defaults
    rootfs = _resolve_rootfs(args.rootfs)
    if not rootfs:
        print(f"[!] no rootfs found under {args.rootfs}", file=sys.stderr)
        return 2
    wl = defaults.load_wordlist(args.wordlist) if args.wordlist else None
    if wl:
        print(f"[*] using wordlist {args.wordlist} ({len(wl)} entries)")
    findings, recovered = defaults.analyze_default_creds(rootfs, wl)
    if args.json:
        print(json.dumps({"recovered": [c.__dict__ for c in recovered],
                          "findings": [f.to_dict() for f in findings]}, indent=2))
        return 0
    for f in sort_findings(findings):
        print("  " + term.finding_line(f))
    print("\n" + defaults.format_creds_table(recovered))
    return 0


def cmd_cvedb(args):
    from . import cvestore
    if args.action == "status":
        st = cvestore.status()
        if not st.get("present"):
            print("[!] CVE corpus not built. Run: fwre cvedb refresh")
            return 1
        print(f"[+] CVE index: {st['path']}")
        print(f"    built:   {st.get('built','?')}")
        print(f"    records: {st.get('records','?')}  rows: {st.get('rows','?')}"
              f"  size: {st.get('size_mb','?')} MB")
        return 0
    if args.action == "refresh":
        rows = cvestore.refresh(keep_zip=not args.no_keep_zip)
        print(f"[+] CVE index rebuilt: {rows} affected-rows -> {cvestore.db_path()}")
        return 0
    if args.action == "build":
        rows = cvestore.build_index()
        print(f"[+] CVE index built from cached zip: {rows} rows")
        return 0
    if args.action == "query":
        if not args.product:
            print("[!] query needs --product and --pver", file=sys.stderr)
            return 2
        hits = cvestore.query(args.product, args.pver or "0", limit=args.limit)
        for h in hits:
            print(f"  [{h['severity'] or '?':8}] {h['cve']}  "
                  f"CVSS={h['cvss']}  {h['product']}")
            if args.verbose and h.get("summary"):
                print(f"      {h['summary'][:160]}")
        print(f"\n[+] {len(hits)} matches for {args.product} {args.pver or ''}")
        return 0
    return 2


def cmd_interesting(args):
    from . import interesting as intmod
    rootfs = _resolve_rootfs(args.rootfs)
    if not rootfs:
        print(f"[!] no rootfs found under {args.rootfs}", file=sys.stderr)
        return 2
    print(f"[*] scanning binaries under {rootfs}")
    _, audits = analyzer.analyze_binaries(rootfs)
    _, ranked = intmod.analyze(rootfs, audits)
    if args.json:
        builtins.print(json.dumps([b.to_dict() for b in ranked], indent=2))
        return 0
    print(f"[+] {len(audits)} ELF binaries scanned")
    print("\n" + intmod.format_table(ranked, limit=args.top))
    return 0


def cmd_checksec(args):
    for path in args.elf:
        if not elfmod.is_elf(path):
            print(f"{path}: not an ELF")
            continue
        i = elfmod.parse(path)
        print(f"{path}")
        print(f"  {i.machine} {i.bits}-bit {i.endian}-endian {i.kind}"
              f"{' stripped' if i.stripped else ''}")
        print(f"  {i.summary()}")
        d = i.dangerous()
        if d:
            print(f"  dangerous imports: {', '.join(d)}")
    return 0


def cmd_strings(args):
    for s in strings_file(args.file, min_len=args.min):
        print(s)
    return 0


def cmd_bootlog(args):
    from . import bootlog as blmod
    targets = []
    if os.path.isfile(args.target) and args.target.lower().endswith(".txt"):
        targets = [args.target]
    else:
        targets = blmod.find_bootlogs(args.target)
    if not targets:
        print(f"[!] no *.bootlog.txt found for {args.target}", file=sys.stderr)
        return 2
    for t in targets:
        findings, info = blmod.analyze(t)
        print(f"[*] {os.path.basename(t)}")
        print(f"    U-Boot={info.uboot or '?'}  kernel={info.kernel or '?'}"
              f"  gcc={info.gcc or '?'}")
        if info.mtdparts:
            print(f"    mtdparts={info.mtdparts}")
        if info.bootargs:
            print(f"    bootargs={info.bootargs}")
        for f in sort_findings(findings):
            print("    " + term.finding_line(f))
    return 0


def cmd_uboot(args):
    from . import uboot as ubmod
    if not _require_image(args.image):
        return 2
    findings, info = ubmod.analyze(args.image)
    print(f"[*] {os.path.basename(args.image)}")
    print(f"    U-Boot={info.uboot or '?'}  uImages={len(info.uimages)}")
    for k, v in info.env.items():
        print(f"    env {k}={v[:120]}")
    for f in sort_findings(findings):
        print("    " + term.finding_line(f))
    return 0


def cmd_sbom(args):
    rootfs = _resolve_rootfs(args.rootfs)
    if not rootfs:
        print(f"[!] no rootfs found under {args.rootfs}", file=sys.stderr)
        return 2
    rep = analyzer.analyze_rootfs(rootfs, do_iocs=False)
    doc = sbommod.to_cyclonedx(rep.components, rep.cves,
                               image=os.path.basename(args.rootfs.rstrip("/\\")))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(doc)
        print(f"[+] CycloneDX SBOM written to {args.output}")
    else:
        print(doc)
    return 0


# --- helpers ---------------------------------------------------------------

def _require_image(path: str) -> bool:
    """Verify the image exists before extracting; on a miss, print a clear error
    and suggest close filename matches (catches typos like virgin/vergin)."""
    if os.path.isfile(path):
        return True
    print(f"[!] image not found: {path}", file=sys.stderr)
    import difflib
    d = os.path.dirname(path) or "."
    try:
        cands = [f for f in os.listdir(d)
                 if f.lower().endswith((".bin", ".img", ".rom", ".dump"))]
    except OSError:
        cands = []
    near = difflib.get_close_matches(os.path.basename(path), cands, n=3, cutoff=0.5)
    if near:
        print("    did you mean:", file=sys.stderr)
        for nm in near:
            print(f"      {os.path.join(d, nm)}", file=sys.stderr)
    elif not os.path.isdir(d):
        print(f"    (directory does not exist: {d})", file=sys.stderr)
    return False


def _default_out(image: str) -> str:
    base = os.path.splitext(os.path.basename(image))[0]
    return os.path.join("fwre_out", base)


def _resolve_rootfs(path: str) -> str | None:
    # if it already looks like a rootfs, use it
    markers = ("etc", "bin", "sbin", "lib")
    if sum(os.path.isdir(os.path.join(path, m)) for m in markers) >= 2:
        return path
    return extractor._find_rootfs(path)


def _expand_images(target: str) -> list[str]:
    if os.path.isdir(target):
        return sorted(glob.glob(os.path.join(target, "*.bin")))
    return sorted(glob.glob(target))


def _short(val: str, n: int = 48) -> str:
    v = (val or "").strip()
    if not v.isprintable():
        return "<binary>"
    return v if len(v) <= n else v[:n - 3] + "..."


def _extract_secret_bytes(s) -> bytes:
    """Best-effort recovery of the full secret material for dumping: the whole
    PEM block for keys/certs, otherwise the matched value."""
    try:
        with open(s.abs_path, "rb") as fh:
            data = fh.read()
    except OSError:
        return (s.value or "").encode("latin1", "replace")
    if getattr(s, "is_pem", False):
        start = s.offset if s.offset is not None else data.find(b"-----BEGIN")
        if start is None or start < 0:
            start = 0
        end = data.find(b"-----END", start)
        if end >= 0:
            nl = data.find(b"\n", end)
            return data[start:(nl + 1) if nl >= 0 else end + 40]
        return data[start:start + 8192]
    return (s.value or "").encode("latin1", "replace")


def _is_cert(s) -> bool:
    return "certificate" in s.desc.lower()


def _secret_filename(outdir: str, s, idx: int) -> str:
    base = s.rel.replace("/", "_").replace("\\", "_")
    tag = f"0x{s.offset:x}" if s.offset is not None else \
        (f"L{s.line}" if s.line is not None else "f")
    ext = "cert.pem" if _is_cert(s) else "secret"
    prefix = "cert" if _is_cert(s) else "secret"
    return os.path.join(outdir, f"{prefix}_{idx:03d}_{base}_{tag}.{ext}")


def _write_secret(outdir, s, idx, state):
    """Dump one secret to a per-item file; returns True on success."""
    data = _extract_secret_bytes(s)
    if not state["made"]:
        os.makedirs(outdir, exist_ok=True)
        state["made"] = True
    fn = _secret_filename(outdir, s, idx)
    try:
        with open(fn, "wb") as fh:
            fh.write(data)
    except OSError as e:
        print(f"[!] could not write {fn}: {e}")
        return False
    print(f"[+] {s.desc} @ {s.where()} -> {fn} ({len(data)} bytes)")
    return True


def _dump_secrets(rep, args, image=""):
    """Post-analysis secret-dump phase. --dumpsecrets dumps all silently;
    --skipdumpsecrets prints a skip note; otherwise prompt y/N per secret -
    except embedded certificates, which are offered as a single all-or-nothing
    group (each still written to its own accurately-named file)."""
    secrets = getattr(rep, "secrets", [])
    if not secrets:
        return
    n = len(secrets)
    if getattr(args, "skipdumpsecrets", False):
        print(f"[*] {n} secret(s) located; dumping skipped (--skipdumpsecrets)")
        return
    dump_all = getattr(args, "dumpsecrets", False)
    certs = [s for s in secrets if _is_cert(s)]
    others = [s for s in secrets if not _is_cert(s)]
    print(f"\n[*] secret-dump phase - {len(others)} secret(s), {len(certs)} "
          f"certificate(s)" + (" (--dumpsecrets: dumping all)" if dump_all else ""))
    outdir = os.path.join("fwre_secrets", image or "rootfs")
    state = {"made": False}
    dumped = 0
    idx = 0

    # individual secrets: per-item confirm
    for s in others:
        idx += 1
        if not dump_all:
            try:
                ans = input(_c(f"[?] dump {s.desc} ({_short(s.value)}) "
                               f"at {s.where()}? [y/N] "))
            except (EOFError, KeyboardInterrupt):
                print()
                print(f"[*] secret dump aborted ({dumped} dumped)")
                return
            if ans.strip().lower() not in ("y", "yes"):
                continue
        dumped += _write_secret(outdir, s, idx, state)

    # embedded certificates: one prompt for the whole set
    if certs:
        do_certs = dump_all
        if not dump_all:
            try:
                ans = input(_c(f"[?] dump ALL {len(certs)} embedded "
                               f"certificate(s)? [y/N] "))
                do_certs = ans.strip().lower() in ("y", "yes")
            except (EOFError, KeyboardInterrupt):
                print()
                print(f"[*] secret dump aborted ({dumped} dumped)")
                return
        if do_certs:
            for s in certs:
                idx += 1
                dumped += _write_secret(outdir, s, idx, state)

    print(f"[+] dumped {dumped}/{n} item(s)" + (f" to {outdir}/" if dumped else ""))


# hash types fast enough to attack directly (brute/mask feasible); everything
# else is slow and only makes sense with a wordlist.
_FAST_HASHES = {"descrypt", "md5crypt"}
# suggested brute masks for the fast ones (IoT passwords are short)
_BRUTE_MASK = {"descrypt": "?a?a?a?a?a?a?a?a", "md5crypt": "?a?a?a?a?a?a?a?a"}
# on Windows the binary is hashcat.exe; elsewhere it's plain hashcat
_HASHCAT = "hashcat.exe" if os.name == "nt" else "hashcat"


def _crack_assist(rep, args, image=""):
    """Post-analysis credential-hash crack assist. Prints each recovered hash;
    for fast/weak hashes it offers to generate a hashcat command (and optionally
    run or save it); strong hashes only get a saved wordlist-based command."""
    import shutil
    creds = [c for c in getattr(rep, "credentials", [])
             if c.hash and c.hash not in ("*", "!", "!!", "x", "")
             and c.hash_type and c.hash_type != "unknown"]
    if not creds:
        return
    if getattr(args, "skipcrack", False):
        print(f"[*] {len(creds)} password hash(es) present; crack-assist skipped "
              f"(--skipcrack)")
        return
    auto = getattr(args, "crack", False)
    print(f"\n[*] hash crack-assist phase - {len(creds)} hash(es)")
    outdir = os.path.join("fwre_secrets", image or "rootfs")
    have_hc = shutil.which(_HASHCAT) is not None

    for c in creds:
        mode = c.hashcat_mode.split()[0] if c.hashcat_mode and \
            c.hashcat_mode[0].isdigit() else ""
        fast = c.hash_type in _FAST_HASHES
        # always print the hash itself
        print(f"[+] {c.user}:{c.hash}  ({c.hash_type}"
              + (f", hashcat -m {mode}" if mode else "") + ")")
        if not mode:
            print(f"    (no hashcat mode for {c.hash_type} - try john)")
            continue

        if not auto:
            q = (f"[?] generate a hashcat command for '{c.user}' "
                 f"({'fast - bruteforceable' if fast else 'slow - needs a wordlist'})? [y/N] ")
            try:
                if input(_c(q)).strip().lower() not in ("y", "yes"):
                    continue
            except (EOFError, KeyboardInterrupt):
                print()
                print("[*] crack-assist aborted")
                return

        os.makedirs(outdir, exist_ok=True)
        hashfile = os.path.join(outdir, f"{c.user}.hash")
        # newline="\n": hashcat needs a bare LF (or none). On Windows the default
        # text mode would translate "\n" to "\r\n", and the stray CR gets counted
        # as part of the hash -> "Token length exception" for fixed-length formats
        # like descrypt (-m 1500).
        with open(hashfile, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(c.hash + "\n")

        if fast:
            mask = _BRUTE_MASK.get(c.hash_type, "?a?a?a?a?a?a?a")
            cmd = f"{_HASHCAT} -m {mode} -a 3 {hashfile} {mask} -i"
            wl_cmd = f"{_HASHCAT} -m {mode} -a 0 {hashfile} <WORDLIST>"
            print(f"    brute:    {cmd}")
            print(f"    wordlist: {wl_cmd}")
            action = "s"
            if not auto:
                try:
                    action = (input(_c("    [r]un now / [s]ave / [n]othing? "))
                              .strip().lower() or "n")
                except (EOFError, KeyboardInterrupt):
                    action = "n"
            if action.startswith("r"):
                if not have_hc:
                    print(f"[!] {_HASHCAT} not on PATH - saving instead")
                    action = "s"
                else:
                    print(f"[*] running: {cmd}")
                    import subprocess
                    try:
                        subprocess.run(cmd.split(), check=False)
                    except Exception as e:
                        print(f"[!] hashcat run failed: {e}")
            if action.startswith("s") or auto:
                _save_crack_cmd(outdir, c, [cmd, wl_cmd])
        else:
            # strong hash: wordlist only, save (never brute/run)
            cmd = f"{_HASHCAT} -m {mode} -a 0 {hashfile} <WORDLIST>"
            print(f"    {c.hash_type} is slow - supply a wordlist:")
            print(f"    {cmd}")
            _save_crack_cmd(outdir, c, [cmd])
    print(f"[+] crack-assist artifacts under {outdir}/")


def _save_crack_cmd(outdir, c, cmds):
    # write a runnable script in the host's native format
    if os.name == "nt":
        fn = os.path.join(outdir, f"{c.user}.crack.bat")
        nl = "\r\n"
        header = f"@echo off{nl}REM hashcat command(s) for {c.user} ({c.hash_type}){nl}"
    else:
        fn = os.path.join(outdir, f"{c.user}.crack.sh")
        nl = "\n"
        header = f"#!/bin/sh{nl}# hashcat command(s) for {c.user} ({c.hash_type}){nl}"
    with open(fn, "w", encoding="utf-8", newline="") as fh:
        fh.write(header)
        for cmd in cmds:
            fh.write(cmd + nl)
    if os.name != "nt":
        try:
            os.chmod(fn, 0o755)
        except OSError:
            pass
    print(f"[+] saved {fn}")


def _emit(rep, args, image=""):
    if getattr(args, "sbom", None):
        doc = sbommod.to_cyclonedx(rep.components, rep.cves, image=image)
        with open(args.sbom, "w", encoding="utf-8") as fh:
            fh.write(doc)
        print(f"[+] CycloneDX SBOM written to {args.sbom}")
    if args.json:
        out = reporter.to_json(rep, image=image)
    else:
        out = reporter.to_markdown(rep, image=image)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[+] report written to {args.output}")
    elif args.json:
        print(out)
    else:
        # to console: compact finding list + hint
        _print_findings(rep, details=getattr(args, "details", False))
        if rep.interesting:
            from .interesting import format_table
            tbl = format_table(rep.interesting)
            if not tbl.startswith("No stand-out"):
                print("\n" + tbl)
        if rep.recovered_creds:
            from .defaults import format_creds_table
            print("\n" + format_creds_table(rep.recovered_creds))
        print(f"\n[+] {rep.stats.get('finding_count',0)} findings "
              f"({rep.stats.get('critical',0)} critical, "
              f"{rep.stats.get('high',0)} high). "
              f"Use -o report.md for the full report.")

    # interactive post-analysis phases (never in machine/JSON mode).
    # flush first so the findings are fully written before these run.
    if not args.json:
        sys.stdout.flush()
        _crack_assist(rep, args, image)
        _dump_secrets(rep, args, image)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fwre",
                                description="Linux firmware RE / vuln framework")
    p.add_argument("--nocolors", action="store_true", help="disable coloured output")
    p.add_argument("--nologo", action="store_true", help="don't print the banner")
    # same flags on a parent so they also work AFTER the subcommand; SUPPRESS
    # keeps them from clobbering the top-level values when omitted
    common_g = argparse.ArgumentParser(add_help=False)
    common_g.add_argument("--nocolors", action="store_true",
                          default=argparse.SUPPRESS, help="disable coloured output")
    common_g.add_argument("--nologo", action="store_true",
                          default=argparse.SUPPRESS, help="don't print the banner")
    sub = p.add_subparsers(dest="cmd", required=True)

    common_an = argparse.ArgumentParser(add_help=False)
    common_an.add_argument("--json", action="store_true", help="JSON output")
    common_an.add_argument("-o", "--output", help="write report to file")
    common_an.add_argument("-v", "--details", action="store_true",
                           help="print each finding's evidence (exact file:line "
                                "/ address where it was found)")
    common_an.add_argument("--no-iocs", action="store_true",
                           help="skip network-IOC scan (faster)")
    common_an.add_argument("--sbom", metavar="PATH",
                           help="also write a CycloneDX SBOM to PATH")
    common_an.add_argument("--dumpsecrets", action="store_true",
                           help="dump every located secret (no prompts)")
    common_an.add_argument("--skipdumpsecrets", action="store_true",
                           help="skip the post-analysis secret-dump prompts")
    common_an.add_argument("--crack", action="store_true",
                           help="auto-save a hashcat command for every crackable hash")
    common_an.add_argument("--skipcrack", action="store_true",
                           help="skip the post-analysis hash crack-assist prompts")
    common_ex = argparse.ArgumentParser(add_help=False)
    common_ex.add_argument("--no-recurse", action="store_true",
                           help="don't recurse into nested archives")

    e = sub.add_parser("extract", parents=[common_ex, common_g], help="7z-extract an image")
    e.add_argument("image")
    e.add_argument("-o", "--out")
    e.set_defaults(func=cmd_extract)

    a = sub.add_parser("analyze", parents=[common_an, common_g], help="analyze a rootfs")
    a.add_argument("rootfs")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("run", parents=[common_an, common_ex, common_g],
                       help="extract + analyze")
    r.add_argument("image")
    r.add_argument("--out", help="extraction dir")
    r.set_defaults(func=cmd_run)

    b = sub.add_parser("batch", parents=[common_an, common_ex, common_g],
                       help="run over many images + summary")
    b.add_argument("target", help="dir of .bin files or a glob")
    b.add_argument("--out", help="output root dir (default fwre_out)")
    b.set_defaults(func=cmd_batch)

    cr = sub.add_parser("creds", parents=[common_g], help="recover default/weak credentials")
    cr.add_argument("rootfs")
    cr.add_argument("--wordlist", help="extra password wordlist (one per line)")
    cr.add_argument("--json", action="store_true")
    cr.set_defaults(func=cmd_creds)

    cd = sub.add_parser("cvedb", parents=[common_g], help="manage the downloaded CVE corpus")
    cd.add_argument("action", choices=["status", "refresh", "build", "query"],
                    help="status | refresh (download+index) | build (from cached zip) | query")
    cd.add_argument("--product", help="product name for query")
    cd.add_argument("--pver", help="product version for query")
    cd.add_argument("--limit", type=int, default=40)
    cd.add_argument("--verbose", action="store_true")
    cd.add_argument("--no-keep-zip", action="store_true",
                    help="delete the downloaded zip after indexing")
    cd.set_defaults(func=cmd_cvedb)

    it = sub.add_parser("interesting", parents=[common_g],
                        help="rank the unusual / vendor binaries worth manual RE")
    it.add_argument("rootfs")
    it.add_argument("--top", type=int, default=25, help="how many to list")
    it.add_argument("--json", action="store_true")
    it.set_defaults(func=cmd_interesting)

    c = sub.add_parser("checksec", parents=[common_g], help="ELF hardening report")
    c.add_argument("elf", nargs="+")
    c.set_defaults(func=cmd_checksec)

    s = sub.add_parser("strings", parents=[common_g], help="dump printable strings")
    s.add_argument("file")
    s.add_argument("--min", type=int, default=4)
    s.set_defaults(func=cmd_strings)

    bl = sub.add_parser("bootlog", parents=[common_g], help="parse serial boot logs (*.bootlog.txt)")
    bl.add_argument("target", help="a .bootlog.txt file, an image, or a directory")
    bl.set_defaults(func=cmd_bootlog)

    ub = sub.add_parser("uboot", parents=[common_g], help="analyze U-Boot / uImage in a raw image")
    ub.add_argument("image")
    ub.set_defaults(func=cmd_uboot)

    sb = sub.add_parser("sbom", parents=[common_g], help="emit a CycloneDX SBOM for a rootfs")
    sb.add_argument("rootfs")
    sb.add_argument("-o", "--output", help="write SBOM to file (else stdout)")
    sb.set_defaults(func=cmd_sbom)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    term.configure(nocolors=getattr(args, "nocolors", False))
    # banner goes to stderr so it never pollutes --json / strings / sbom stdout
    if not getattr(args, "nologo", False):
        term.banner(sys.stderr)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
