"""Whole-block PEM detection (private keys and certificates).

Matching the `-----BEGIN ... PRIVATE KEY-----` banner on its own is the biggest
source of false "private key material embedded in firmware" findings: every TLS
stack shipped in a firmware image (wpa_supplicant, mbedTLS, OpenSSL, wolfSSL,
curl, ...) carries those banners as *string constants* for its own PEM parser,
sitting right next to the matching END banners and the `Proc-Type: 4,ENCRYPTED`
/ `DEK-Info:` header literals. The banner means "this binary can parse keys",
not "this binary contains a key".

A real key is a complete block: a BEGIN line, optional RFC 1421 headers, a
base64 body that decodes to something structurally plausible (a DER SEQUENCE
whose length covers the payload exactly for PKCS#1/SEC1/PKCS#8, the
`openssh-key-v1\\0` magic for OpenSSH, an OpenPGP packet header for PGP armor),
and an END line whose label matches the BEGIN. This module does that check once
so every analyzer agrees on what counts as key material.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field

_MAX_BLOCK = 128 * 1024   # largest PEM body we will consider
_MIN_KEY = 48             # smallest plausible key payload (bytes)
_MIN_CERT = 64

_BEGIN_KEY_RE = re.compile(rb"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----")
_BEGIN_CERT_RE = re.compile(rb"-----BEGIN ((?:TRUSTED |X509 )?CERTIFICATE)-----")

_B64_RE = re.compile(rb"\A[A-Za-z0-9+/]+={0,2}\Z")
_HDR_RE = re.compile(rb"\A[A-Za-z][A-Za-z0-9-]*:[ \t]?\S.*\Z")
_PGP_CRC_RE = re.compile(rb"\A=[A-Za-z0-9+/]{4}\Z")

_KINDS = {
    "RSA PRIVATE KEY": "RSA (PKCS#1)",
    "DSA PRIVATE KEY": "DSA",
    "EC PRIVATE KEY": "EC (SEC1)",
    "PRIVATE KEY": "PKCS#8",
    "ENCRYPTED PRIVATE KEY": "PKCS#8 (encrypted)",
    "OPENSSH PRIVATE KEY": "OpenSSH",
    "SSH2 PRIVATE KEY": "SSH2",
    "PGP PRIVATE KEY BLOCK": "PGP",
    "CERTIFICATE": "X.509",
    "TRUSTED CERTIFICATE": "X.509",
    "X509 CERTIFICATE": "X.509",
}


@dataclass
class PemBlock:
    label: str                 # e.g. "RSA PRIVATE KEY"
    kind: str                  # short human kind, e.g. "RSA (PKCS#1)"
    start: int                 # offset of "-----BEGIN"
    end: int                   # offset just past "-----END ...-----"
    block: bytes               # the complete armored block
    payload: bytes             # base64-decoded body (DER for most kinds)
    encrypted: bool = False
    headers: dict = field(default_factory=dict)

    @property
    def sha256(self) -> str:
        """Fingerprint of the *payload*, so the same key still matches across
        images that re-wrap it with different line endings or PEM headers."""
        return hashlib.sha256(self.payload).hexdigest()

    def line(self, data: bytes | str) -> int:
        """1-based line number of the BEGIN line within `data`."""
        nl = b"\n" if isinstance(data, bytes) else "\n"
        return data.count(nl, 0, self.start) + 1


# --------------------------------------------------------------------- parsing
def _der_ok(d: bytes, minimum: int) -> bool:
    """True when `d` is a single DER SEQUENCE whose length covers it exactly."""
    if len(d) < minimum or d[0] != 0x30:
        return False
    n = d[1]
    if n & 0x80:
        nb = n & 0x7F
        if nb == 0 or nb > 4 or len(d) < 2 + nb:
            return False
        length = int.from_bytes(d[2:2 + nb], "big")
        hdr = 2 + nb
    else:
        length, hdr = n, 2
    return hdr + length == len(d)


def _decode_body(body: bytes):
    """(payload, headers) for a PEM body, or None when it is not a real body.

    Handles RFC 1421 headers (`Proc-Type:`/`DEK-Info:`), PGP armor headers and
    the trailing PGP CRC24 line.
    """
    lines = [ln.strip(b"\r \t") for ln in body.split(b"\n")]
    lines = [ln for ln in lines if ln]
    headers: dict[str, str] = {}
    i = 0
    while i < len(lines) and _HDR_RE.match(lines[i]):
        k, _, v = lines[i].partition(b":")
        headers[k.decode("latin1").lower()] = v.strip().decode("latin1", "replace")
        i += 1
    lines = lines[i:]
    if lines and _PGP_CRC_RE.match(lines[-1]):
        lines = lines[:-1]
    b64 = b"".join(lines)
    if not b64 or len(b64) % 4 or not _B64_RE.match(b64):
        return None
    try:
        payload = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    return payload, headers


def _plausible_key(label: bytes, payload: bytes, headers: dict) -> bool:
    if len(payload) < _MIN_KEY:
        return False
    if b"OPENSSH" in label:
        return payload.startswith(b"openssh-key-v1\x00")
    if b"PGP" in label:
        return bool(payload[0] & 0x80)          # OpenPGP packet header
    if "proc-type" in headers:
        # traditional passphrase-encrypted key: the body is raw ciphertext, not
        # DER, so all we can ask for is a whole number of cipher blocks
        return len(payload) % 8 == 0
    return _der_ok(payload, _MIN_KEY)


def _iter_blocks(data: bytes, begin_re: re.Pattern):
    """Yield (begin_start, body_start, body_end, block_end, label) for every
    BEGIN banner that has a matching END banner. Scans every banner rather than
    consuming the input, so a nested/garbled pair cannot hide a real one."""
    for m in begin_re.finditer(data):
        label = m.group(1)
        end_pat = b"-----END " + label + b"-----"
        end = data.find(end_pat, m.end(), m.end() + _MAX_BLOCK)
        if end < 0:
            continue
        yield m.start(), m.end(), end, end + len(end_pat), label


def _blocks(data: bytes, begin_re: re.Pattern, validate) -> list[PemBlock]:
    out: list[PemBlock] = []
    for bs, body_s, body_e, be, label in _iter_blocks(data, begin_re):
        dec = _decode_body(data[body_s:body_e])
        if dec is None:
            continue
        payload, headers = dec
        if not validate(label, payload, headers):
            continue
        lab = label.decode("latin1")
        out.append(PemBlock(
            label=lab, kind=_KINDS.get(lab, lab), start=bs, end=be,
            block=data[bs:be], payload=payload,
            encrypted=("ENCRYPTED" in lab or "proc-type" in headers),
            headers=headers))
    return out


# ----------------------------------------------------------------------- API
def find_keys(data: bytes) -> list[PemBlock]:
    """Every complete, structurally plausible PEM private key in `data`."""
    return _blocks(data, _BEGIN_KEY_RE, _plausible_key)


def find_keys_text(text: str) -> list[PemBlock]:
    """find_keys() over a latin1-ish string; offsets are character indices."""
    return find_keys(text.encode("latin1", "replace"))


def find_certs(data: bytes) -> list[PemBlock]:
    """Every complete PEM certificate in `data`."""
    return _blocks(data, _BEGIN_CERT_RE,
                   lambda label, payload, hdrs: _der_ok(payload, _MIN_CERT))


def looks_like_der_key(data: bytes) -> bool:
    """True for a raw (un-armored) DER private key: a SEQUENCE whose first
    element is the version INTEGER 0/1, the way PKCS#1, PKCS#8 and SEC1 all
    start. A certificate is a SEQUENCE of SEQUENCE, so it does not match."""
    if len(data) < _MIN_KEY or data[0] != 0x30:
        return False
    n = data[1]
    hdr = 2 + (n & 0x7F) if n & 0x80 else 2
    return data[hdr:hdr + 2] == b"\x02\x01" and data[hdr + 2:hdr + 3] in (b"\x00", b"\x01")


def has_key(data: bytes | str) -> bool:
    if isinstance(data, str):
        return bool(find_keys_text(data))
    return bool(find_keys(data))


def has_key_banner(data: bytes | str) -> bool:
    """True when a BEGIN PRIVATE KEY banner is present at all - on its own this
    only means the file knows the PEM format (a parser, a template, a doc)."""
    if isinstance(data, str):
        data = data.encode("latin1", "replace")
    return bool(_BEGIN_KEY_RE.search(data))
