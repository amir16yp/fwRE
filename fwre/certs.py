"""X.509 certificate & private-key analyzer (pure stdlib DER parser).

Finds PEM/DER certificates and private keys anywhere in the rootfs, parses the
certificates enough to flag the things that matter for firmware - weak signature
algorithms (MD5/SHA1), short RSA keys, self-signed device certs, and expired /
not-yet-valid windows - and fingerprints each cert (SHA-256 of DER) so the
cross-image pass can spot the *same* certificate/key shipped across an entire
product line (fleet-wide MITM).

No third-party crypto: just enough ASN.1 to read the fields we report on.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
from dataclasses import dataclass, field

from .finding import Finding, Severity
from . import pem as pemmod

_SIG_OIDS = {
    "1.2.840.113549.1.1.4": ("md5WithRSA", True),
    "1.2.840.113549.1.1.5": ("sha1WithRSA", True),
    "1.2.840.113549.1.1.11": ("sha256WithRSA", False),
    "1.2.840.113549.1.1.12": ("sha384WithRSA", False),
    "1.2.840.113549.1.1.13": ("sha512WithRSA", False),
    "1.2.840.10040.4.3": ("dsa-with-sha1", True),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", True),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", False),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", False),
}
_KEY_OIDS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10040.4.1": "DSA",
}
_MAX = 8 * 1024 * 1024


# TLS libraries ship their own *test* certs/keys as compiled-in constants; those
# are public, well-known, and (usually) not the device's real material, so we
# report them at reduced severity rather than crying "fleet-wide MITM".
_CRYPTO_LIB_RE = re.compile(
    r"(?:libmbed|libmbedtls|libmbedx509|libssl|libcrypto|libwolfssl|libgnutls|"
    r"libtomcrypt|libcyassl)", re.I)


def _is_crypto_lib(source: str) -> bool:
    return bool(_CRYPTO_LIB_RE.search(os.path.basename(source)))


@dataclass
class CertInfo:
    source: str
    sha256: str
    sig_algo: str = ""
    weak_sig: bool = False
    key_type: str = ""
    key_bits: int = 0
    not_before: str = ""
    not_after: str = ""
    self_signed: bool = False
    expired: bool = False
    not_yet_valid: bool = False
    library_vector: bool = False


@dataclass
class KeyFile:
    source: str
    kind: str
    sha256: str = ""


# --------------------------------------------------------------------------- DER
def _tlv(d: bytes, i: int):
    """Return (tag, content_start, content_len, next_index) for one DER element."""
    tag = d[i]
    n = d[i + 1]
    i += 2
    if n & 0x80:
        nb = n & 0x7F
        length = int.from_bytes(d[i:i + nb], "big")
        i += nb
    else:
        length = n
    return tag, i, length, i + length


def _children(d: bytes, start: int, end: int):
    i = start
    while i < end:
        tag, cs, cl, nxt = _tlv(d, i)
        yield tag, cs, cl, nxt
        i = nxt


def _oid(d: bytes, cs: int, cl: int) -> str:
    b = d[cs:cs + cl]
    if not b:
        return ""
    first = b[0]
    out = [str(first // 40), str(first % 40)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            out.append(str(val))
            val = 0
    return ".".join(out)


def _parse_time(d: bytes, cs: int, cl: int, tag: int):
    s = d[cs:cs + cl].decode("latin1", "replace").rstrip("Z")
    try:
        if tag == 0x17:  # UTCTime YYMMDDHHMMSS
            yy = int(s[:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            rest = s[2:]
        else:            # GeneralizedTime YYYYMMDDHHMMSS
            year = int(s[:4])
            rest = s[4:]
        mo, da, ho = int(rest[0:2]), int(rest[2:4]), int(rest[4:6])
        mi = int(rest[6:8]) if len(rest) >= 8 else 0
        se = int(rest[8:10]) if len(rest) >= 10 else 0
        return s, _dt.datetime(year, mo, da, ho, mi, se, tzinfo=_dt.timezone.utc)
    except (ValueError, IndexError):
        return s, None


def parse_cert(der: bytes, source: str):
    ci = CertInfo(source=source, sha256=hashlib.sha256(der).hexdigest())
    try:
        _, cs, cl, _ = _tlv(der, 0)                 # Certificate SEQUENCE
        kids = list(_children(der, cs, cs + cl))
        tbs_tag, tbs_cs, tbs_cl, _ = kids[0]        # tbsCertificate
        _, sig_cs, sig_cl, _ = kids[1]              # signatureAlgorithm
        for t, c2, l2, _ in _children(der, sig_cs, sig_cs + sig_cl):
            if t == 0x06:
                oid = _oid(der, c2, l2)
                name, weak = _SIG_OIDS.get(oid, (oid, False))
                ci.sig_algo, ci.weak_sig = name, weak
                break

        tbs = list(_children(der, tbs_cs, tbs_cs + tbs_cl))
        idx = 0
        if tbs and tbs[0][0] == 0xA0:               # [0] version
            idx = 1
        idx += 1                                     # serialNumber
        idx += 1                                     # signature AlgId
        issuer = tbs[idx]; idx += 1                  # issuer Name
        validity = tbs[idx]; idx += 1                # validity
        subject = tbs[idx]; idx += 1                 # subject Name
        spki = tbs[idx]                              # subjectPublicKeyInfo

        iss_der = der[issuer[1]:issuer[1] + issuer[2]]
        sub_der = der[subject[1]:subject[1] + subject[2]]
        ci.self_signed = iss_der == sub_der

        vkids = list(_children(der, validity[1], validity[1] + validity[2]))
        if len(vkids) >= 2:
            ci.not_before, nb = _parse_time(der, vkids[0][1], vkids[0][2], vkids[0][0])
            ci.not_after, na = _parse_time(der, vkids[1][1], vkids[1][2], vkids[1][0])
            now = _dt.datetime.now(_dt.timezone.utc)
            if na and na < now:
                ci.expired = True
            if nb and nb > now:
                ci.not_yet_valid = True

        sp = list(_children(der, spki[1], spki[1] + spki[2]))
        alg = sp[0]
        for t, c2, l2, _ in _children(der, alg[1], alg[1] + alg[2]):
            if t == 0x06:
                ci.key_type = _KEY_OIDS.get(_oid(der, c2, l2), "?")
                break
        # RSA modulus bit length lives in the BIT STRING (skip leading 0 byte)
        if ci.key_type == "RSA" and len(sp) >= 2:
            bit = sp[1]
            inner = bit[1]
            if der[inner] == 0x00:
                inner += 1
            _, rcs, rcl, _ = _tlv(der, inner)        # RSAPublicKey SEQUENCE
            for t, c2, l2, _ in _children(der, rcs, rcs + rcl):
                if t == 0x02:                        # modulus INTEGER
                    mod = der[c2:c2 + l2].lstrip(b"\x00")
                    ci.key_bits = len(mod) * 8
                    break
    except Exception:
        return ci  # partial info is still useful (fingerprint at least)
    return ci


def _rel(rootfs: str, p: str) -> str:
    return os.path.relpath(p, rootfs).replace("\\", "/")


def analyze(rootfs: str):
    findings: list[Finding] = []
    certs: list[CertInfo] = []
    keys: list[KeyFile] = []
    seen: set[str] = set()

    for dirpath, _, files in os.walk(rootfs):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                if os.path.getsize(p) > _MAX:
                    continue
                with open(p, "rb") as fh:
                    blob = fh.read(_MAX)
            except OSError:
                continue
            rel = _rel(rootfs, p)

            # Whole-block match only: the bare "-----BEGIN PRIVATE KEY-----"
            # banner is a string constant in every TLS stack (wpa_supplicant,
            # mbedTLS, OpenSSL), so a header without a decodable body is a
            # PEM *parser*, not key material. See fwre/pem.py.
            pem_keys = pemmod.find_keys(blob)
            for k in pem_keys:
                # fingerprint the decoded key body so the fleet pass spots the
                # same private key shipped across devices even when re-wrapped
                keys.append(KeyFile(rel, f"PEM private key, {k.kind}", k.sha256))
            if not pem_keys and pemmod.looks_like_der_key(blob) and \
                    name.lower().endswith((".key", ".der", ".p8", ".pk8")):
                keys.append(KeyFile(rel, "DER private key",
                                    hashlib.sha256(blob).hexdigest()))

            found_der = [b.payload for b in pemmod.find_certs(blob)]
            if not found_der and blob[:1] == b"\x30" and len(blob) >= 64 and \
                    name.lower().endswith((".der", ".crt", ".cer")):
                found_der.append(blob)

            lib_vec = _is_crypto_lib(rel)
            for der in found_der:
                ci = parse_cert(der, rel)
                if not ci or ci.sha256 in seen:
                    continue
                ci.library_vector = lib_vec
                seen.add(ci.sha256)
                certs.append(ci)
                _emit_cert_findings(findings, ci)

    return findings, certs, keys


def _emit_cert_findings(findings, ci):
    tag = " (TLS-library test vector, likely unused)" if ci.library_vector else ""

    def sev(s):
        if not ci.library_vector:
            return s
        return {Severity.HIGH: Severity.LOW, Severity.MEDIUM: Severity.INFO,
                Severity.LOW: Severity.INFO}.get(s, s)

    findings.append(Finding(
        Severity.INFO if ci.library_vector else Severity.LOW, "cert",
        f"embedded certificate ({ci.key_type or '?'}"
        f"{'/' + str(ci.key_bits) if ci.key_bits else ''}, {ci.sig_algo or '?'}){tag}",
        f"{ci.source}  sha256={ci.sha256[:16]}  valid {ci.not_before}..{ci.not_after}",
        ci.source, data={"sha256": ci.sha256, "library_vector": ci.library_vector}))
    if ci.weak_sig:
        findings.append(Finding(
            sev(Severity.HIGH), "cert",
            f"certificate uses weak signature algorithm ({ci.sig_algo}){tag}",
            "forgeable - MD5/SHA1 collisions are practical", ci.source))
    if ci.key_type == "RSA" and 0 < ci.key_bits < 2048:
        findings.append(Finding(
            sev(Severity.HIGH), "cert",
            f"short RSA key in certificate ({ci.key_bits}-bit){tag}",
            "keys < 2048-bit are below current strength floor", ci.source))
    if ci.expired and not ci.library_vector:
        findings.append(Finding(
            Severity.MEDIUM, "cert",
            f"certificate expired ({ci.not_after})", path=ci.source))
    if ci.self_signed and not ci.library_vector:
        findings.append(Finding(
            Severity.LOW, "cert",
            "self-signed certificate (no CA chain - TLS trust bootstrapped locally)",
            path=ci.source))
