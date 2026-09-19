"""CycloneDX SBOM export.

Turns fwre's fingerprinted component list (and its CVE leads) into a CycloneDX
1.5 JSON document so results are consumable by standard supply-chain tooling and
diffable across firmware revisions. Pure stdlib.
"""
from __future__ import annotations

import datetime as _dt
import json
import uuid


# map fwre component names -> (purl type, cpe vendor, cpe product)
_PURL = {
    "busybox": ("generic", "busybox", "busybox"),
    "dropbear": ("generic", "dropbear_ssh_project", "dropbear_ssh"),
    "openssl": ("generic", "openssl", "openssl"),
    "openssh": ("generic", "openbsd", "openssh"),
    "libcurl": ("generic", "haxx", "libcurl"),
    "zlib": ("generic", "zlib", "zlib"),
    "kernel": ("generic", "linux", "linux_kernel"),
    "uboot": ("generic", "denx", "u-boot"),
    "dnsmasq": ("generic", "thekelleys", "dnsmasq"),
    "lighttpd": ("generic", "lighttpd", "lighttpd"),
    "wpa_supplicant": ("generic", "w1.fi", "wpa_supplicant"),
    "hostapd": ("generic", "w1.fi", "hostapd"),
    "goahead": ("generic", "embedthis", "goahead"),
    "boa": ("generic", "boa", "boa"),
    "uclibc": ("generic", "uclibc", "uclibc"),
    "glibc": ("generic", "gnu", "glibc"),
}


def _component(c):
    typ, vendor, product = _PURL.get(c.name, ("generic", c.name, c.name))
    purl = f"pkg:{typ}/{product}@{c.version}" if c.version else f"pkg:{typ}/{product}"
    return {
        "type": "library" if c.name not in ("kernel", "uboot") else "operating-system"
        if c.name == "kernel" else "firmware",
        "name": c.name,
        "version": c.version,
        "purl": purl,
        "cpe": f"cpe:2.3:a:{vendor}:{product}:{c.version}:*:*:*:*:*:*:*",
        "evidence": {"identity": {"field": "name",
                                  "methods": [{"technique": "binary-analysis",
                                               "value": c.evidence,
                                               "confidence": 0.6}]}},
        "properties": [{"name": "fwre:source", "value": c.source}],
    }


def to_cyclonedx(components, cves=None, image: str = "") -> str:
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    comps = [_component(c) for c in components]
    vulns = []
    for h in (cves or []):
        vulns.append({
            "id": h.cve,
            "source": {"name": "fwre-curated"},
            "ratings": [{"severity": (h.severity or "unknown").lower()}],
            "description": h.note,
            "affects": [{"ref": f"pkg:generic/{h.component}@{h.version}"}],
        })
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "fwre", "name": "fwre", "version": "0.1.0"}],
            "component": {"type": "firmware", "name": image or "firmware-image"},
        },
        "components": comps,
    }
    if vulns:
        doc["vulnerabilities"] = vulns
    return json.dumps(doc, indent=2)
