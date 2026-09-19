"""Full-CVE-corpus backend.

Downloads the CVEProject/cvelistV5 repository zip once, stream-parses every CVE
JSON record straight out of the zip (no multi-GB extraction to disk), and builds
a compact SQLite index keyed by product name. Subsequent runs reuse the cached
DB. `refresh()` rebuilds it; the CLI exposes this as `fwre cvedb`.

The index feeds fwre's version->CVE matching in addition to the small curated
rules in cvedb.py (which remain the always-available baseline when no corpus has
been downloaded).
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import urllib.request
import zipfile

from .cache import cache_path

CVE_ZIP_URL = "https://codeload.github.com/CVEProject/cvelistV5/zip/refs/heads/main"
_ZIP_NAME = "cvelistV5-main.zip"
_DB_NAME = "cve.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS affected(
    cve         TEXT,
    vendor      TEXT,
    product     TEXT,          -- lowercased
    version     TEXT,          -- start / exact
    less_than   TEXT,          -- exclusive upper bound (or NULL)
    less_eq     TEXT,          -- inclusive upper bound (or NULL)
    status      TEXT,          -- affected / unaffected
    cvss        REAL,
    severity    TEXT,
    summary     TEXT
);
CREATE INDEX IF NOT EXISTS idx_product ON affected(product);
"""


def db_path() -> str:
    return cache_path(_DB_NAME)


def zip_path() -> str:
    return cache_path(_ZIP_NAME)


def have_db() -> bool:
    p = db_path()
    return os.path.isfile(p) and os.path.getsize(p) > 0


# --------------------------------------------------------------------------- download
def download(url: str = CVE_ZIP_URL, dest: str | None = None,
             progress: bool = True) -> str:
    dest = dest or zip_path()
    tmp = dest + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": "fwre/0.1"})
    with urllib.request.urlopen(req) as resp, open(tmp, "wb") as out:
        total = int(resp.headers.get("Content-Length", 0))
        got = 0
        t0 = time.time()
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)
            got += len(chunk)
            if progress:
                mb = got / 1e6
                tot = f"/{total/1e6:.0f}" if total else ""
                rate = mb / max(time.time() - t0, 0.01)
                sys.stderr.write(f"\r    downloading... {mb:.0f}{tot} MB "
                                 f"({rate:.1f} MB/s)")
                sys.stderr.flush()
    if progress:
        sys.stderr.write("\n")
    os.replace(tmp, dest)
    return dest


# --------------------------------------------------------------------------- parse
def _v(s: str) -> tuple:
    import re
    out = []
    for p in re.split(r"[.\-_]", str(s)):
        m = re.match(r"(\d+)", p)
        out.append(int(m.group(1)) if m else 0)
    return tuple(out) or (0,)


def _extract_metrics(cna: dict) -> tuple[float | None, str]:
    best_score = None
    best_sev = ""
    for m in (cna.get("metrics") or []):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            c = m.get(key)
            if c and "baseScore" in c:
                score = c.get("baseScore")
                sev = c.get("baseSeverity", "")
                if best_score is None or (score or 0) > best_score:
                    best_score = score
                    best_sev = sev
    return best_score, best_sev


def _rows_from_record(rec: dict):
    """Yield affected-rows from a single CVE 5.x JSON record."""
    meta = rec.get("cveMetadata", {})
    cve = meta.get("cveId") or rec.get("id") or ""
    containers = rec.get("containers", {})
    cna = containers.get("cna", {})
    cvss, sev = _extract_metrics(cna)
    # description
    summary = ""
    for d in (cna.get("descriptions") or []):
        if d.get("lang", "en").startswith("en"):
            summary = (d.get("value") or "")[:300]
            break
    for aff in (cna.get("affected") or []):
        vendor = (aff.get("vendor") or "").strip().lower()
        product = (aff.get("product") or "").strip().lower()
        if not product or product in ("n/a", "unspecified"):
            continue
        versions = aff.get("versions") or []
        if not versions:
            # whole-product affected, unknown version
            yield (cve, vendor, product, "*", None, None, "affected",
                   cvss, sev, summary)
            continue
        for ver in versions:
            status = ver.get("status", "affected")
            if status != "affected":
                continue
            v = str(ver.get("version", "*"))
            lt = ver.get("lessThan")
            le = ver.get("lessThanOrEqual")
            yield (cve, vendor, product, v,
                   str(lt) if lt else None, str(le) if le else None,
                   status, cvss, sev, summary)


def build_index(zip_file: str | None = None, progress: bool = True) -> int:
    """Stream every CVE JSON out of the zip into a fresh SQLite index.
    Returns the number of affected-rows inserted."""
    zip_file = zip_file or zip_path()
    if not os.path.isfile(zip_file):
        raise FileNotFoundError(f"{zip_file} not present - download first")

    dbp = db_path()
    tmp_db = dbp + ".building"
    if os.path.exists(tmp_db):
        os.remove(tmp_db)
    con = sqlite3.connect(tmp_db)
    con.executescript(_SCHEMA)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")

    rows = 0
    files = 0
    t0 = time.time()
    batch = []
    with zipfile.ZipFile(zip_file) as zf:
        names = [n for n in zf.namelist()
                 if n.endswith(".json") and "/cves/" in n
                 and os.path.basename(n).startswith("CVE-")]
        for n in names:
            try:
                with zf.open(n) as fh:
                    rec = json.load(fh)
            except Exception:
                continue
            files += 1
            for row in _rows_from_record(rec):
                batch.append(row)
            if len(batch) >= 5000:
                con.executemany(
                    "INSERT INTO affected VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
                rows += len(batch)
                batch.clear()
            if progress and files % 5000 == 0:
                sys.stderr.write(
                    f"\r    indexing... {files} records, {rows} rows "
                    f"({files/max(time.time()-t0,0.01):.0f} rec/s)")
                sys.stderr.flush()
    if batch:
        con.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
        rows += len(batch)
    con.execute("INSERT OR REPLACE INTO meta VALUES ('built', ?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"),))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('records', ?)", (str(files),))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('rows', ?)", (str(rows),))
    con.commit()
    con.close()
    os.replace(tmp_db, dbp)
    if progress:
        sys.stderr.write(f"\r    indexed {files} records, {rows} rows "
                         f"in {time.time()-t0:.0f}s\n")
    return rows


def refresh(*, keep_zip: bool = True, progress: bool = True) -> int:
    """Download (if needed) + rebuild the index."""
    zp = zip_path()
    if progress:
        sys.stderr.write("[*] fetching cvelistV5 (this is large, done once)\n")
    download(dest=zp, progress=progress)
    rows = build_index(zp, progress=progress)
    if not keep_zip:
        try:
            os.remove(zp)
        except OSError:
            pass
    return rows


def ensure(auto_download: bool = False) -> bool:
    """Return True if a usable DB exists (optionally building it)."""
    if have_db():
        return True
    if auto_download:
        refresh()
        return have_db()
    return False


# --------------------------------------------------------------------------- query
_ALIASES = {  # normalise fwre component names to corpus product names
    "kernel": ["linux_kernel", "kernel", "linux"],
    "openssl": ["openssl"],
    "busybox": ["busybox"],
    "dropbear": ["dropbear_ssh", "dropbear", "dropbear ssh server"],
    "libcurl": ["curl", "libcurl"],
    "wpa_supplicant": ["wpa_supplicant", "hostapd/wpa_supplicant"],
    "hostapd": ["hostapd"],
    "lighttpd": ["lighttpd"],
    "dnsmasq": ["dnsmasq"],
    "zlib": ["zlib"],
    "openssh": ["openssh"],
    "goahead": ["goahead"],
}


def _version_matches(v: tuple, start: str, lt, le) -> bool:
    if start in ("*", "0", "", None) and not lt and not le:
        return True  # whole product / unknown
    try:
        if lt:
            lo = _v(start) if start not in ("*", "0", "") else (0,)
            return lo <= v < _v(lt)
        if le:
            lo = _v(start) if start not in ("*", "0", "") else (0,)
            return lo <= v <= _v(le)
        # exact
        return _v(start) == v
    except Exception:
        return False


def query(product: str, version: str, limit: int = 40) -> list[dict]:
    if not have_db():
        return []
    names = _ALIASES.get(product, [product])
    con = sqlite3.connect(db_path())
    con.row_factory = sqlite3.Row
    v = _v(version)
    out = []
    seen = set()
    try:
        qmarks = ",".join("?" * len(names))
        cur = con.execute(
            f"SELECT * FROM affected WHERE product IN ({qmarks})", names)
        for r in cur:
            if _version_matches(v, r["version"], r["less_than"], r["less_eq"]):
                if r["cve"] in seen:
                    continue
                seen.add(r["cve"])
                out.append({
                    "cve": r["cve"], "product": r["product"],
                    "vendor": r["vendor"], "cvss": r["cvss"],
                    "severity": (r["severity"] or "").upper(),
                    "summary": r["summary"],
                })
    finally:
        con.close()
    # rank by cvss desc
    out.sort(key=lambda x: (x["cvss"] or 0), reverse=True)
    return out[:limit]


def status() -> dict:
    if not have_db():
        return {"present": False}
    con = sqlite3.connect(db_path())
    try:
        meta = dict(con.execute("SELECT k, v FROM meta").fetchall())
    finally:
        con.close()
    meta["present"] = True
    meta["path"] = db_path()
    meta["size_mb"] = round(os.path.getsize(db_path()) / 1e6, 1)
    return meta
