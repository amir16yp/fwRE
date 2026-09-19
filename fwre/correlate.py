"""Cross-image (fleet) correlation.

A corpus of 80 camera images is worth more than 80 independent scans: the same
ODM ships the same secrets across a whole product line. This pass cross-links
per-image results to surface *shared* material - one crack or one stolen key
compromises every device that shares it:

  * identical /etc/shadow hashes  -> crack once, own the fleet
  * identical embedded TLS certs  -> fleet-wide TLS impersonation / MITM
  * identical private keys        -> same as above, worse
  * identical recovered passwords -> confirmed reuse
  * shared BusyBox build / cloud SDK -> shared CVE blast radius

`record()` distils a RootfsReport into a compact dict; `build_report()` takes the
list of those and renders a Markdown section for the batch SUMMARY.
"""
from __future__ import annotations

from collections import defaultdict


def record(image: str, rep) -> dict:
    shadow = {}
    for c in getattr(rep, "credentials", []):
        h = getattr(c, "hash", "")
        if h and h not in ("*", "!", "!!", "x", ""):
            shadow[c.user] = h
    cracked = {c.user: c.password for c in getattr(rep, "recovered_creds", [])}
    # only real device certs matter for fleet MITM - drop library test vectors
    cert_fps = [ci.sha256 for ci in getattr(rep, "certs", [])
                if not getattr(ci, "library_vector", False)]
    key_fps = list(getattr(rep, "key_fps", []))
    bb = getattr(rep, "busybox", None)
    return {
        "image": image,
        "shadow": shadow,
        "cracked": cracked,
        "cert_fps": cert_fps,
        "key_fps": key_fps,
        "busybox": getattr(bb, "version", "") if bb else "",
        "cloud": [s.name for s in getattr(rep, "cloud", [])],
    }


def _group(records, key_iter):
    """key_iter(rec) -> iterable of (key, label); returns {key: [(image,label)]}."""
    buckets = defaultdict(list)
    for r in records:
        for key, label in key_iter(r):
            buckets[key].append((r["image"], label))
    return {k: v for k, v in buckets.items() if len({i for i, _ in v}) >= 2}


def build_report(records: list[dict]) -> str:
    if not records:
        return ""
    L = ["\n## Cross-image correlation (shared secrets)\n"]
    any_shared = False

    shared_hash = _group(
        records, lambda r: ((h, f"{u}") for u, h in r["shadow"].items()))
    if shared_hash:
        any_shared = True
        L.append("### Shared /etc/shadow hashes - crack once, own every listed device\n")
        for h, imgs in sorted(shared_hash.items(), key=lambda kv: -len(kv[1])):
            names = ", ".join(sorted({i for i, _ in imgs}))
            L.append(f"- `{h[:32]}...` ({len(set(i for i,_ in imgs))} devices): {names}")
        L.append("")

    shared_cert = _group(records, lambda r: ((f, "cert") for f in r["cert_fps"]))
    if shared_cert:
        any_shared = True
        L.append("### Shared TLS certificates - fleet-wide impersonation / MITM\n")
        for f, imgs in sorted(shared_cert.items(), key=lambda kv: -len(kv[1])):
            names = ", ".join(sorted({i for i, _ in imgs}))
            L.append(f"- cert `{f[:16]}...`: {names}")
        L.append("")

    shared_key = _group(records, lambda r: ((f, "key") for f in r["key_fps"]))
    if shared_key:
        any_shared = True
        L.append("### Shared private keys - identical key material across devices\n")
        for f, imgs in sorted(shared_key.items(), key=lambda kv: -len(kv[1])):
            names = ", ".join(sorted({i for i, _ in imgs}))
            L.append(f"- key `{f[:16]}...`: {names}")
        L.append("")

    shared_pw = _group(
        records, lambda r: ((f"{u}:{p}", u) for u, p in r["cracked"].items()))
    if shared_pw:
        any_shared = True
        L.append("### Reused recovered credentials\n")
        for up, imgs in sorted(shared_pw.items(), key=lambda kv: -len(kv[1])):
            names = ", ".join(sorted({i for i, _ in imgs}))
            L.append(f"- `{up}`: {names}")
        L.append("")

    if not any_shared:
        L.append("_No shared secrets detected across the analyzed images._\n")
    return "\n".join(L)
