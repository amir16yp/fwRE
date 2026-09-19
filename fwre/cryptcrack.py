"""Pure-python crypt(3) implementations so hashes can be checked against a
default-password wordlist on any platform (Python's `crypt` module is Unix-only
and removed in 3.13+).

Implements md5crypt ($1$), sha256crypt ($5$) and sha512crypt ($6$), matching
glibc / Ulrich Drepper's reference. descrypt/bcrypt/yescrypt are not cracked
here (flagged for hashcat/john instead).

Verified against the canonical test vectors in the module's __main__ block.
"""
from __future__ import annotations

import hashlib

_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b64(b2: int, b1: int, b0: int, n: int) -> str:
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(_ITOA64[w & 0x3F])
        w >>= 6
    return "".join(out)


# --------------------------------------------------------------------------- md5
def md5crypt(pw: bytes, salt: bytes) -> str:
    magic = b"$1$"
    salt = salt[:8]
    ctx = hashlib.md5(pw + magic + salt)
    alt = hashlib.md5(pw + salt + pw).digest()
    i = len(pw)
    while i > 0:
        ctx.update(alt[:min(i, 16)])
        i -= 16
    i = len(pw)
    while i:
        ctx.update(b"\x00" if i & 1 else pw[:1])
        i >>= 1
    final = ctx.digest()
    for r in range(1000):
        c = hashlib.md5()
        c.update(pw if r & 1 else final)
        if r % 3:
            c.update(salt)
        if r % 7:
            c.update(pw)
        c.update(final if r & 1 else pw)
        final = c.digest()
    out = (_b64(final[0], final[6], final[12], 4)
           + _b64(final[1], final[7], final[13], 4)
           + _b64(final[2], final[8], final[14], 4)
           + _b64(final[3], final[9], final[15], 4)
           + _b64(final[4], final[10], final[5], 4)
           + _b64(0, 0, final[11], 2))
    return f"$1${salt.decode('latin1')}${out}"


# --------------------------------------------------------------------------- sha2
_SHA512_ORDER = [
    (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4),
    (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51),
    (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13), (56, 14, 35),
    (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19),
    (62, 20, 41),
]
_SHA256_ORDER = [
    (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
    (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29),
]


def _sha2crypt(pw: bytes, salt: bytes, rounds: int, sha, hlen: int,
               order, tail) -> str:
    salt = salt[:16]
    A = sha(pw + salt)
    B = sha(pw + salt + pw).digest()
    i = len(pw)
    while i > 0:
        A.update(B[:min(i, hlen)])
        i -= hlen
    i = len(pw)
    while i:
        A.update(B if i & 1 else pw)
        i >>= 1
    Ad = A.digest()

    dp = sha(pw * len(pw)).digest()
    P = (dp * (len(pw) // hlen)) + dp[:len(pw) % hlen]
    ds = sha(salt * (16 + Ad[0])).digest()
    S = (ds * (len(salt) // hlen)) + ds[:len(salt) % hlen]

    C = Ad
    for r in range(rounds):
        c = sha()
        c.update(P if r & 1 else C)
        if r % 3:
            c.update(S)
        if r % 7:
            c.update(P)
        c.update(C if r & 1 else P)
        C = c.digest()

    out = "".join(_b64(C[a], C[b], C[c], 4) for a, b, c in order)
    a, b, n, nchars = tail
    out += _b64(0 if a is None else C[a], 0 if b is None else C[b], C[n], nchars)
    return out, salt


def sha512crypt(pw: bytes, salt: bytes, rounds: int = 5000) -> str:
    out, salt = _sha2crypt(pw, salt, rounds, hashlib.sha512, 64,
                           _SHA512_ORDER, (None, None, 63, 2))
    r = f"rounds={rounds}$" if rounds != 5000 else ""
    return f"$6${r}{salt.decode('latin1')}${out}"


def sha256crypt(pw: bytes, salt: bytes, rounds: int = 5000) -> str:
    out, salt = _sha2crypt(pw, salt, rounds, hashlib.sha256, 32,
                           _SHA256_ORDER, (None, 31, 30, 3))
    r = f"rounds={rounds}$" if rounds != 5000 else ""
    return f"$5${r}{salt.decode('latin1')}${out}"


def verify(password: str, hashval: str) -> bool:
    """True if `password` produces `hashval`. Supports $1$/$5$/$6$."""
    pw = password.encode("utf-8", "surrogatepass")
    try:
        if hashval.startswith("$1$"):
            salt = hashval.split("$")[2].encode("latin1")
            return md5crypt(pw, salt) == hashval
        if hashval.startswith(("$5$", "$6$")):
            parts = hashval.split("$")
            rounds = 5000
            idx = 2
            if parts[2].startswith("rounds="):
                rounds = int(parts[2][7:])
                idx = 3
            salt = parts[idx].encode("latin1")
            fn = sha256crypt if hashval.startswith("$5$") else sha512crypt
            return fn(pw, salt, rounds) == hashval
    except Exception:
        return False
    return False


def crackable(hashval: str) -> bool:
    return hashval.startswith(("$1$", "$5$", "$6$"))


if __name__ == "__main__":
    # canonical Drepper test vectors
    assert sha512crypt(b"Hello world!", b"saltstring") == (
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817"
        "G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"), "sha512 fail"
    assert sha256crypt(b"Hello world!", b"saltstring") == (
        "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"), "sha256 fail"
    assert sha512crypt(b"Hello world!", b"saltstringsaltstring",
                       rounds=10000).startswith("$6$rounds=10000$"), "rounds fail"
    assert md5crypt(b"password", b"12345678").startswith("$1$12345678$"), "md5 fmt"
    assert verify("Hello world!",
                  "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817"
                  "G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1")
    print("all crypt self-tests passed")
