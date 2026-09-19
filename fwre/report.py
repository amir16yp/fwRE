"""Render a RootfsReport as Markdown or JSON."""
from __future__ import annotations

import json
from .analyze import RootfsReport
from .finding import sort_findings, Severity


def to_json(rep: RootfsReport, image: str = "") -> str:
    obj = {
        "image": image,
        "rootfs": rep.rootfs,
        "stats": rep.stats,
        "findings": [f.to_dict() for f in sort_findings(rep.findings)],
        "recovered_credentials": [c.__dict__ for c in rep.recovered_creds],
        "credentials": [c.__dict__ for c in rep.credentials],
        "components": [c.__dict__ for c in rep.components],
        "cves": [c.__dict__ for c in rep.cves],
        "elf_audits": [
            {"path": a.path, "arch": a.info.machine, "bits": a.info.bits,
             "endian": a.info.endian, "kind": a.info.kind,
             "stripped": a.info.stripped, "setuid": a.setuid,
             "network_facing": a.network_facing,
             "nx": a.info.nx, "pie": a.info.pie, "relro": a.info.relro,
             "canary": a.info.canary, "fortify": a.info.fortify,
             "rpath": a.info.rpath, "runpath": a.info.runpath,
             "dangerous": a.info.dangerous()}
            for a in rep.elf_audits
        ],
        "iocs": rep.iocs,
        "certs": [c.__dict__ for c in rep.certs],
        "cloud_sdks": [c.__dict__ for c in rep.cloud],
        "busybox": rep.busybox.__dict__ if rep.busybox else None,
        "boot": rep.boot,
        "key_fingerprints": rep.key_fps,
    }
    return json.dumps(obj, indent=2)


def to_markdown(rep: RootfsReport, image: str = "") -> str:
    L: list[str] = []
    ap = L.append
    ap(f"# Firmware analysis: {image or rep.rootfs}\n")

    s = rep.stats
    ap("## Summary\n")
    ap(f"- ELF binaries: **{s.get('elf_count', 0)}** "
       f"(setuid: {s.get('setuid_count', 0)})")
    ap(f"- Architectures: {', '.join(f'{k}×{v}' for k, v in s.get('arch_histogram', {}).items()) or 'n/a'}")
    ap(f"- Findings: **{s.get('finding_count', 0)}** "
       f"(critical: {s.get('critical', 0)}, high: {s.get('high', 0)})\n")

    # findings by severity
    ap("## Findings\n")
    fs = sort_findings(rep.findings)
    cur = None
    for f in fs:
        if f.severity != cur:
            cur = f.severity
            ap(f"\n### {f.severity.label}\n")
        loc = f" - `{f.path}`" if f.path else ""
        det = f"  \n  {f.detail}" if f.detail else ""
        ap(f"- **{f.category}**: {f.title}{loc}{det}")
    if not fs:
        ap("_No findings._")

    # recovered / default credentials - highest value, show first
    if rep.recovered_creds:
        ap("\n## ⚠ Recovered / default credentials\n")
        ap("| user | password | source | method |")
        ap("|---|---|---|---|")
        for c in rep.recovered_creds:
            ap(f"| `{c.user}` | `{c.password}` | `{c.source}` | {c.method} |")

    # credentials table
    if rep.credentials:
        ap("\n## Credentials (/etc/passwd + /etc/shadow)\n")
        ap("| user | uid | shell | hash type | hashcat | note |")
        ap("|---|---|---|---|---|---|")
        for c in rep.credentials:
            ap(f"| {c.user} | {c.uid} | {c.shell} | {c.hash_type or '-'} | "
               f"{c.hashcat_mode or '-'} | {c.note or ''} |")
        # dump crackable hashes for convenience
        crk = [c for c in rep.credentials if c.hash and c.hash not in ('*', '!', '!!', 'x')]
        if crk:
            ap("\n<details><summary>hashes (john/hashcat input)</summary>\n")
            ap("```")
            for c in crk:
                ap(f"{c.user}:{c.hash}")
            ap("```\n</details>")

    # components / CVE
    if rep.components:
        ap("\n## Components & known-CVE leads\n")
        ap("| component | version | source |")
        ap("|---|---|---|")
        for c in rep.components:
            ap(f"| {c.name} | {c.version} | `{c.source}` |")
    if rep.cves:
        ap("\n**CVE heuristics** (confirm before trusting):\n")
        for h in rep.cves:
            ap(f"- `{h.severity}` **{h.component} {h.version}** → {h.cve}: {h.note}")

    # ELF audit table (compact)
    if rep.elf_audits:
        ap("\n## ELF hardening (checksec)\n")
        ap("| binary | arch | kind | NX | PIE | RELRO | Canary | strip | setuid | net |")
        ap("|---|---|---|---|---|---|---|---|---|---|")
        def yn(b): return "✓" if b else "✗"
        # sort: network + setuid first, then weakest
        def weakness(a):
            i = a.info
            return -(int(a.network_facing) * 4 + int(a.setuid) * 4
                     + int(not i.nx) + int(not i.pie) + int(not i.canary))
        for a in sorted(rep.elf_audits, key=weakness):
            i = a.info
            ap(f"| `{a.path}` | {i.machine} | {i.kind} | {yn(i.nx)} | "
               f"{yn(i.pie)} | {i.relro} | {yn(i.canary)} | "
               f"{yn(i.stripped)} | {yn(a.setuid)} | {yn(a.network_facing)} |")

    # boot chain (uImage / U-Boot / serial boot logs)
    if rep.boot:
        ap("\n## Boot chain\n")
        for b in rep.boot:
            if b.get("kind") == "uboot":
                ap(f"- **U-Boot**: {b.get('uboot') or '(version n/a)'}")
                for u in b.get("uimages", [])[:8]:
                    ap(f"  - uImage `{u.get('name','')}` "
                       f"{u.get('os','')}/{u.get('arch','')} {u.get('comp','')} "
                       f"load {u.get('load','')}")
                env = b.get("env", {})
                if env.get("bootargs"):
                    ap(f"  - bootargs: `{env['bootargs'][:160]}`")
            elif b.get("kind") == "bootlog":
                ap(f"- **boot log** `{b.get('source','')}`: "
                   f"U-Boot {b.get('uboot') or '?'}, kernel {b.get('kernel') or '?'}")
                if b.get("mtdparts"):
                    ap(f"  - mtdparts: `{b['mtdparts'][:160]}`")
                if b.get("bootargs"):
                    ap(f"  - bootargs: `{b['bootargs'][:160]}`")

    # cloud / P2P SDKs
    if rep.cloud:
        ap("\n## Cloud / P2P SDKs\n")
        for c in rep.cloud:
            ap(f"- **{c.name}** ({c.vendor}) - `{c.source}` (marker `{c.evidence}`)")

    # certificates
    if rep.certs:
        ap("\n## Embedded certificates\n")
        ap("| source | key | sig | valid until | self-signed | sha256 |")
        ap("|---|---|---|---|---|---|")
        for c in rep.certs:
            key = f"{c.key_type}{('/'+str(c.key_bits)) if c.key_bits else ''}"
            ap(f"| `{c.source}` | {key or '?'} | {c.sig_algo or '?'} | "
               f"{c.not_after or '?'}{' (EXPIRED)' if c.expired else ''} | "
               f"{'yes' if c.self_signed else 'no'} | `{c.sha256[:16]}` |")

    # busybox applets
    if rep.busybox and rep.busybox.dangerous:
        ap("\n## BusyBox applet surface\n")
        ap(f"- version: **{rep.busybox.version or '?'}**")
        ap(f"- notable applets: {', '.join(rep.busybox.dangerous)}")

    # fs permission summary
    if rep.fs_audit:
        a = rep.fs_audit
        if a.suid or a.world_writable or a.writable_init:
            ap("\n## Filesystem permissions\n")
            ap(f"- SUID files: {len(a.suid)}  |  world-writable: "
               f"{len(a.world_writable)}  |  writable init scripts: "
               f"{len(a.writable_init)}")

    # IOCs
    if rep.iocs:
        ap("\n## Network IOCs\n")
        if rep.iocs.get("urls"):
            ap("**URLs:**")
            for u in rep.iocs["urls"][:60]:
                ap(f"- {u}")
        if rep.iocs.get("cloud_domains"):
            ap("\n**Cloud/service domains:** " +
               ", ".join(rep.iocs["cloud_domains"][:40]))
        if rep.iocs.get("ips"):
            ap("\n**IPs:** " + ", ".join(rep.iocs["ips"][:40]))

    return "\n".join(L) + "\n"


def batch_summary_markdown(rows: list[dict]) -> str:
    """rows: [{image, critical, high, elf_count, cves, top}]"""
    L = ["# Firmware batch summary\n",
         "| image | crit | high | ELFs | CVE leads | notable |",
         "|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda x: (-x["critical"], -x["high"])):
        L.append(f"| {r['image']} | {r['critical']} | {r['high']} | "
                 f"{r['elf_count']} | {r['cves']} | {r.get('top', '')} |")
    return "\n".join(L) + "\n"
