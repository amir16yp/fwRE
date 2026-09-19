"""fwre command-line interface.

Subcommands:
  extract   IMAGE [-o DIR]              7z-extract a firmware image
  analyze   ROOTFS_OR_DIR               analyze an already-extracted rootfs
  run       IMAGE [-o DIR]              extract + analyze in one shot
  batch     GLOB_OR_DIR [-o DIR]        run over many images, write a summary
  checksec  ELF...                      quick per-binary hardening report
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
from .strings_util import strings_file
from .finding import sort_findings


def _print_findings(rep):
    for f in sort_findings(rep.findings):
        print("  " + f.line())


def cmd_extract(args):
    res = extractor.extract(args.image, args.out or _default_out(args.image),
                            recurse=not args.no_recurse)
    print(f"[+] extracted to {res.out_dir}")
    print(f"[+] rootfs: {res.rootfs or '(not found — check output tree)'}")
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
    rep = analyzer.analyze_rootfs(res.rootfs, do_iocs=not args.no_iocs)
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
                  + (f" — {res.hint}" if res.hint else ""))
            continue
        rep = analyzer.analyze_rootfs(res.rootfs, do_iocs=not args.no_iocs)
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
    with open(os.path.join(out_root, "SUMMARY.md"), "w", encoding="utf-8") as fh:
        fh.write(summary)
    print("\n" + summary)
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
        print("  " + f.line())
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


# --- helpers ---------------------------------------------------------------

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


def _emit(rep, args, image=""):
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
        _print_findings(rep)
        if rep.recovered_creds:
            from .defaults import format_creds_table
            print("\n" + format_creds_table(rep.recovered_creds))
        print(f"\n[+] {rep.stats.get('finding_count',0)} findings "
              f"({rep.stats.get('critical',0)} critical, "
              f"{rep.stats.get('high',0)} high). "
              f"Use -o report.md for the full report.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fwre",
                                description="Linux firmware RE / vuln framework")
    sub = p.add_subparsers(dest="cmd", required=True)

    common_an = argparse.ArgumentParser(add_help=False)
    common_an.add_argument("--json", action="store_true", help="JSON output")
    common_an.add_argument("-o", "--output", help="write report to file")
    common_an.add_argument("--no-iocs", action="store_true",
                           help="skip network-IOC scan (faster)")
    common_ex = argparse.ArgumentParser(add_help=False)
    common_ex.add_argument("--no-recurse", action="store_true",
                           help="don't recurse into nested archives")

    e = sub.add_parser("extract", parents=[common_ex], help="7z-extract an image")
    e.add_argument("image")
    e.add_argument("-o", "--out")
    e.set_defaults(func=cmd_extract)

    a = sub.add_parser("analyze", parents=[common_an], help="analyze a rootfs")
    a.add_argument("rootfs")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("run", parents=[common_an, common_ex],
                       help="extract + analyze")
    r.add_argument("image")
    r.add_argument("--out", help="extraction dir")
    r.set_defaults(func=cmd_run)

    b = sub.add_parser("batch", parents=[common_an, common_ex],
                       help="run over many images + summary")
    b.add_argument("target", help="dir of .bin files or a glob")
    b.add_argument("--out", help="output root dir (default fwre_out)")
    b.set_defaults(func=cmd_batch)

    cr = sub.add_parser("creds", help="recover default/weak credentials")
    cr.add_argument("rootfs")
    cr.add_argument("--wordlist", help="extra password wordlist (one per line)")
    cr.add_argument("--json", action="store_true")
    cr.set_defaults(func=cmd_creds)

    cd = sub.add_parser("cvedb", help="manage the downloaded CVE corpus")
    cd.add_argument("action", choices=["status", "refresh", "build", "query"],
                    help="status | refresh (download+index) | build (from cached zip) | query")
    cd.add_argument("--product", help="product name for query")
    cd.add_argument("--pver", help="product version for query")
    cd.add_argument("--limit", type=int, default=40)
    cd.add_argument("--verbose", action="store_true")
    cd.add_argument("--no-keep-zip", action="store_true",
                    help="delete the downloaded zip after indexing")
    cd.set_defaults(func=cmd_cvedb)

    c = sub.add_parser("checksec", help="ELF hardening report")
    c.add_argument("elf", nargs="+")
    c.set_defaults(func=cmd_checksec)

    s = sub.add_parser("strings", help="dump printable strings")
    s.add_argument("file")
    s.add_argument("--min", type=int, default=4)
    s.set_defaults(func=cmd_strings)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
