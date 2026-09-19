"""SquashFS extraction that preserves Unix permissions on any host.

7-Zip on Windows unpacks a SquashFS rootfs but **drops the Unix mode bits,
ownership and symlink/device metadata**, which blinds the permission/SUID audit.
This module extracts SquashFS with the pure-Python `dissect.squashfs` reader and
writes a sidecar manifest (`.fwre_perms.json`) recording every entry's real
st_mode / uid / gid / symlink target — so the analysis layer sees genuine
permissions regardless of the host OS.

`dissect.squashfs` is an OPTIONAL dependency (same model as jefferson/ubi_reader
for JFFS2/UBI). When it isn't installed, extraction falls back to 7-Zip and the
permission checks are skipped with an INFO note.
"""
from __future__ import annotations

import io
import json
import os
import stat
import struct

MANIFEST_NAME = ".fwre_perms.json"
_MAGIC = 0x73717368  # "hsqs" little-endian


def available() -> bool:
    try:
        import dissect.squashfs  # noqa: F401
        return True
    except Exception:
        return False


def _read_super(image: str, offset: int):
    """Return (block_size, comp, block_log, ver_major, bytes_used) or None."""
    try:
        with open(image, "rb") as fh:
            fh.seek(offset)
            head = fh.read(96)
    except OSError:
        return None
    if len(head) < 96 or struct.unpack_from("<I", head, 0)[0] != _MAGIC:
        return None
    block_size = struct.unpack_from("<I", head, 12)[0]
    comp, block_log = struct.unpack_from("<HH", head, 20)
    ver_major = struct.unpack_from("<H", head, 28)[0]
    bytes_used = struct.unpack_from("<Q", head, 40)[0]
    return block_size, comp, block_log, ver_major, bytes_used


def can_handle(image: str, offset: int) -> bool:
    """A valid SquashFS 4.0 superblock is present and the reader is installed."""
    if not available():
        return False
    s = _read_super(image, offset)
    if not s:
        return False
    block_size, comp, block_log, ver_major, bytes_used = s
    if ver_major != 4 or comp not in (1, 2, 3, 4, 5, 6):
        return False
    if not (4096 <= block_size <= (1 << 20)) or block_size != (1 << block_log):
        return False
    return 0 < bytes_used <= 512 * 1024 * 1024


def _load_slice(image: str, offset: int, bytes_used: int) -> io.BytesIO:
    with open(image, "rb") as fh:
        fh.seek(offset)
        return io.BytesIO(fh.read(bytes_used))


def extract(image: str, offset: int, dest: str) -> tuple[bool, str, str]:
    """Extract the SquashFS at `offset` into `dest`, writing a permission
    manifest. Returns (ok, rootfs_dir, log)."""
    if not available():
        return False, "", "dissect.squashfs not installed"
    s = _read_super(image, offset)
    if not s:
        return False, "", "no SquashFS superblock at offset"
    bytes_used = s[4]
    try:
        from dissect.squashfs import SquashFS
        sq = SquashFS(_load_slice(image, offset, bytes_used))
    except Exception as e:
        return False, "", f"squashfs open: {e}"

    os.makedirs(dest, exist_ok=True)
    manifest: dict[str, dict] = {}
    log = [f"squashfs (dissect): comp {s[1]}, block {s[0]}, {bytes_used} bytes"]

    def walk(node, relpath: str, depth: int):
        if depth > 64:
            return
        for entry in node.listdir().values():
            name = entry.name
            if name in (".", ".."):
                continue
            rel = f"{relpath}/{name}" if relpath else name
            disk = os.path.join(dest, rel.replace("/", os.sep))
            try:
                rec = {"mode": int(entry.mode), "uid": int(entry.uid),
                       "gid": int(entry.gid)}
            except Exception:
                rec = {"mode": 0, "uid": 0, "gid": 0}
            try:
                if entry.is_dir():
                    os.makedirs(disk, exist_ok=True)
                    manifest[rel] = rec
                    walk(entry, rel, depth + 1)
                elif entry.is_symlink():
                    target = getattr(entry, "link", "") or ""
                    rec["symlink"] = target
                    manifest[rel] = rec
                    try:
                        os.symlink(target, disk)
                    except (OSError, NotImplementedError):
                        # Windows w/o privilege: placeholder file; truth stays
                        # in the manifest so symlink-aware analyzers still work
                        with open(disk, "w", encoding="latin1") as fh:
                            fh.write(target)
                elif entry.is_file():
                    manifest[rel] = rec
                    with entry.open() as src, open(disk, "wb") as out:
                        out.write(src.read())
                else:  # device / fifo / socket
                    manifest[rel] = rec
            except Exception as e:
                log.append(f"  {rel}: {e}")

    try:
        walk(sq.root, "", 0)
    except Exception as e:
        return False, "", f"squashfs walk: {e}"

    with open(os.path.join(dest, MANIFEST_NAME), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    log.append(f"  extracted {len(manifest)} entries with permissions")
    return True, dest, "\n".join(log)


def load_manifest(rootfs: str) -> dict | None:
    """Return {relpath: {mode,uid,gid,symlink?}} if a fwre perm manifest is
    present in this rootfs, else None."""
    p = os.path.join(rootfs, MANIFEST_NAME)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None
