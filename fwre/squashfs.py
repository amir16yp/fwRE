"""Pure-Python SquashFS 4.0 reader/extractor.

Why this exists: 7-Zip on Windows extracts a SquashFS rootfs but **drops the
Unix mode bits, ownership and symlink/device metadata** — which blinds the
permission/SUID audit. This reader parses SquashFS directly, writes file
contents to disk *and* emits a sidecar permission manifest (`.fwre_perms.json`)
recording every entry's real st_mode / uid / gid / symlink target, so the
analysis layer sees genuine permissions regardless of host OS.

Supported compressors: gzip (zlib), xz + legacy lzma, zstd (Python 3.14+).
lz4 / lzo are not stdlib-decodable — those images fall back to the 7z path.
Stdlib only.
"""
from __future__ import annotations

import json
import os
import stat
import struct
import zlib

MANIFEST_NAME = ".fwre_perms.json"

_MAGIC = 0x73717368  # "hsqs" little-endian

# compression ids
_C_GZIP, _C_LZMA, _C_LZO, _C_XZ, _C_LZ4, _C_ZSTD = 1, 2, 3, 4, 5, 6

# inode types
_T_DIR, _T_FILE, _T_SYMLINK, _T_BLKDEV, _T_CHRDEV, _T_FIFO, _T_SOCKET = range(1, 8)
_T_XDIR, _T_XFILE, _T_XSYMLINK, _T_XBLKDEV, _T_XCHRDEV, _T_XFIFO, _T_XSOCKET = range(8, 15)

_TYPEBITS = {
    _T_DIR: stat.S_IFDIR, _T_XDIR: stat.S_IFDIR,
    _T_FILE: stat.S_IFREG, _T_XFILE: stat.S_IFREG,
    _T_SYMLINK: stat.S_IFLNK, _T_XSYMLINK: stat.S_IFLNK,
    _T_BLKDEV: stat.S_IFBLK, _T_XBLKDEV: stat.S_IFBLK,
    _T_CHRDEV: stat.S_IFCHR, _T_XCHRDEV: stat.S_IFCHR,
    _T_FIFO: stat.S_IFIFO, _T_XFIFO: stat.S_IFIFO,
    _T_SOCKET: stat.S_IFSOCK, _T_XSOCKET: stat.S_IFSOCK,
}


class SquashError(Exception):
    pass


def _make_decompressor(comp_id: int):
    if comp_id == _C_GZIP:
        return lambda b: zlib.decompress(b)
    if comp_id in (_C_XZ, _C_LZMA):
        import lzma

        def _dec(b):
            try:
                return lzma.decompress(b)  # xz autodetect
            except lzma.LZMAError:
                # legacy raw/alone lzma
                return lzma.decompress(b, format=lzma.FORMAT_ALONE)
        return _dec
    if comp_id == _C_ZSTD:
        try:
            from compression import zstd  # Python 3.14+
            return lambda b: zstd.decompress(b)
        except Exception:
            try:
                import zstandard  # third-party, optional
                return lambda b: zstandard.ZstdDecompressor().decompress(b)
            except Exception:
                raise SquashError("zstd compression needs Python 3.14 or the "
                                  "'zstandard' package")
    raise SquashError(f"unsupported SquashFS compressor id {comp_id} "
                      "(lz4/lzo not stdlib-decodable)")


class _Sqfs:
    def __init__(self, blob: bytes):
        self.blob = blob
        self._parse_super()
        self.dec = _make_decompressor(self.comp)
        self.ids = self._read_id_table()
        self.fragments = self._read_fragment_table()
        self.inode_region, self.inode_index = self._read_region(
            self.inode_table_start, self.directory_table_start)
        dir_end = self._next_after(self.directory_table_start)
        self.dir_region, self.dir_index = self._read_region(
            self.directory_table_start, dir_end)

    # ---- superblock -----------------------------------------------------
    def _parse_super(self):
        b = self.blob
        if len(b) < 96 or struct.unpack_from("<I", b, 0)[0] != _MAGIC:
            raise SquashError("not a SquashFS superblock")
        (self.magic, self.inode_count, self.mod_time, self.block_size,
         self.frag_count, self.comp, self.block_log, self.flags,
         self.id_count, self.ver_major, self.ver_minor) = \
            struct.unpack_from("<IIIIIHHHHHH", b, 0)
        (self.root_ref, self.bytes_used, self.id_table_start,
         self.xattr_table_start, self.inode_table_start,
         self.directory_table_start, self.fragment_table_start,
         self.export_table_start) = struct.unpack_from("<QQQQQQQQ", b, 40)
        if self.ver_major != 4:
            raise SquashError(f"unsupported SquashFS version {self.ver_major}")

    def _next_after(self, pos: int) -> int:
        cands = [self.fragment_table_start, self.id_table_start,
                 self.xattr_table_start, self.export_table_start,
                 self.bytes_used]
        nxt = [c for c in cands if 0 < c <= self.bytes_used and c > pos]
        return min(nxt) if nxt else self.bytes_used

    # ---- metadata blocks ------------------------------------------------
    def _read_block(self, pos: int):
        hdr = struct.unpack_from("<H", self.blob, pos)[0]
        size = hdr & 0x7FFF
        compressed = not (hdr & 0x8000)
        raw = self.blob[pos + 2:pos + 2 + size]
        data = self.dec(raw) if compressed else raw
        return data, pos + 2 + size

    def _read_region(self, start: int, end: int):
        buf = bytearray()
        index = {}
        p = start
        while p < end:
            index[p - start] = len(buf)
            data, p = self._read_block(p)
            buf += data
            if not data and p >= end:
                break
        return bytes(buf), index

    def _read_id_table(self):
        n_blocks = (self.id_count * 4 + 8191) // 8192
        ptrs = struct.unpack_from("<%dQ" % n_blocks, self.blob,
                                  self.id_table_start)
        ids = []
        for ptr in ptrs:
            data, _ = self._read_block(ptr)
            ids += list(struct.unpack("<%dI" % (len(data) // 4), data))
        return ids[:self.id_count]

    def _read_fragment_table(self):
        if self.frag_count == 0 or self.fragment_table_start >= self.bytes_used:
            return []
        n_blocks = (self.frag_count * 16 + 8191) // 8192
        ptrs = struct.unpack_from("<%dQ" % n_blocks, self.blob,
                                  self.fragment_table_start)
        frags = []
        for ptr in ptrs:
            data, _ = self._read_block(ptr)
            for off in range(0, len(data), 16):
                if off + 16 > len(data):
                    break
                start, size, _unused = struct.unpack_from("<QII", data, off)
                frags.append((start, size))
        return frags[:self.frag_count]

    # ---- inode parsing --------------------------------------------------
    def _inode_pos(self, ref: int) -> int:
        block = (ref >> 16) & 0xFFFFFFFFFFFF
        offset = ref & 0xFFFF
        return self.inode_index[block] + offset

    def parse_inode(self, ref: int) -> dict:
        d = self.inode_region
        p = self._inode_pos(ref)
        itype, mode, uid_i, gid_i, mtime, ino = struct.unpack_from("<HHHHII", d, p)
        p += 16
        node = {"type": itype, "perm": mode & 0xFFF,
                "uid": self.ids[uid_i] if uid_i < len(self.ids) else 0,
                "gid": self.ids[gid_i] if gid_i < len(self.ids) else 0,
                "ino": ino}
        if itype == _T_DIR:
            start_block, nlink, fsize, offset, parent = \
                struct.unpack_from("<IIHHI", d, p)
            node.update(dir_start=start_block, dir_offset=offset, dir_size=fsize)
        elif itype == _T_XDIR:
            nlink, fsize, start_block, parent, idx_count, offset, xattr = \
                struct.unpack_from("<IIIIHHI", d, p)
            node.update(dir_start=start_block, dir_offset=offset, dir_size=fsize)
        elif itype == _T_FILE:
            start_block, frag, offset, fsize = struct.unpack_from("<IIII", d, p)
            p += 16
            nblocks = (fsize // self.block_size if frag != 0xFFFFFFFF
                       else (fsize + self.block_size - 1) // self.block_size)
            bs = struct.unpack_from("<%dI" % nblocks, d, p) if nblocks else ()
            node.update(data_start=start_block, frag=frag, frag_off=offset,
                        size=fsize, block_sizes=bs)
        elif itype == _T_XFILE:
            start_block, fsize, sparse, nlink, frag, offset, xattr = \
                struct.unpack_from("<QQQIIII", d, p)
            p += 40
            nblocks = (fsize // self.block_size if frag != 0xFFFFFFFF
                       else (fsize + self.block_size - 1) // self.block_size)
            bs = struct.unpack_from("<%dI" % nblocks, d, p) if nblocks else ()
            node.update(data_start=start_block, frag=frag, frag_off=offset,
                        size=fsize, block_sizes=bs)
        elif itype in (_T_SYMLINK, _T_XSYMLINK):
            nlink, tsize = struct.unpack_from("<II", d, p)
            p += 8
            node["symlink"] = d[p:p + tsize].decode("latin1", "replace")
        elif itype in (_T_BLKDEV, _T_CHRDEV, _T_XBLKDEV, _T_XCHRDEV):
            nlink, rdev = struct.unpack_from("<II", d, p)
            node["rdev"] = rdev
        return node

    # ---- directory listing ---------------------------------------------
    def list_dir(self, node: dict):
        if "dir_start" not in node:
            return
        pos = self.dir_index.get(node["dir_start"])
        if pos is None:
            return
        end = pos + max(0, node["dir_size"] - 3)
        d = self.dir_region
        while pos + 12 <= end:
            count, start_block, ino_base = struct.unpack_from("<IiI", d, pos)
            pos += 12
            for _ in range(count + 1):
                if pos + 8 > len(d):
                    return
                offset, ioff, etype, nsize = struct.unpack_from("<HhHH", d, pos)
                pos += 8
                name = d[pos:pos + nsize + 1].decode("latin1", "replace")
                pos += nsize + 1
                yield name, (start_block << 16) | offset

    # ---- file content ---------------------------------------------------
    def read_file(self, node: dict) -> bytes:
        out = bytearray()
        pos = node["data_start"]
        for bs in node["block_sizes"]:
            if bs == 0:
                out += b"\x00" * self.block_size
                continue
            realsize = bs & 0xFFFFFF
            compressed = not (bs & 0x1000000)
            chunk = self.blob[pos:pos + realsize]
            pos += realsize
            out += self.dec(chunk) if compressed else chunk
        if node["frag"] != 0xFFFFFFFF and node["frag"] < len(self.fragments):
            fstart, fsize = self.fragments[node["frag"]]
            realsize = fsize & 0xFFFFFF
            compressed = not (fsize & 0x1000000)
            fblock = self.blob[fstart:fstart + realsize]
            fdata = self.dec(fblock) if compressed else fblock
            tail = fdata[node["frag_off"]:node["frag_off"] + (node["size"] - len(out))]
            out += tail
        return bytes(out[:node["size"]])


def _load_slice(image: str, offset: int, max_bytes: int = 512 * 1024 * 1024) -> bytes:
    with open(image, "rb") as fh:
        fh.seek(offset)
        head = fh.read(96)
        if len(head) < 96 or struct.unpack_from("<I", head, 0)[0] != _MAGIC:
            raise SquashError("no SquashFS magic at offset")
        bytes_used = struct.unpack_from("<Q", head, 48)[0]
        if not (0 < bytes_used <= max_bytes):
            raise SquashError(f"implausible bytes_used {bytes_used}")
        fh.seek(offset)
        return fh.read(bytes_used)


def extract(image: str, offset: int, dest: str) -> tuple[bool, str, str]:
    """Extract the SquashFS at `offset` in `image` into `dest`, preserving
    permissions via a manifest. Returns (ok, rootfs_dir, log)."""
    try:
        blob = _load_slice(image, offset)
        sq = _Sqfs(blob)
    except (SquashError, struct.error, OSError, Exception) as e:
        return False, "", f"squashfs: {e}"

    os.makedirs(dest, exist_ok=True)
    manifest: dict[str, dict] = {}
    log = [f"squashfs: {sq.inode_count} inodes, block {sq.block_size}, "
           f"comp {sq.comp}"]

    def walk(ref: int, relpath: str, depth: int):
        if depth > 64:
            return
        try:
            node = sq.parse_inode(ref)
        except Exception:
            return
        st_mode = node["perm"] | _TYPEBITS.get(node["type"], 0)
        entry = {"mode": st_mode, "uid": node["uid"], "gid": node["gid"]}
        disk = os.path.join(dest, relpath.replace("/", os.sep)) if relpath else dest
        t = node["type"]
        if t in (_T_DIR, _T_XDIR):
            if relpath:
                os.makedirs(disk, exist_ok=True)
                manifest[relpath] = entry
            for name, child in sq.list_dir(node):
                if name in (".", ".."):
                    continue
                child_rel = f"{relpath}/{name}" if relpath else name
                walk(child, child_rel, depth + 1)
        elif t in (_T_FILE, _T_XFILE):
            manifest[relpath] = entry
            try:
                data = sq.read_file(node)
                with open(disk, "wb") as fh:
                    fh.write(data)
            except Exception as e:
                log.append(f"  file {relpath}: {e}")
        elif t in (_T_SYMLINK, _T_XSYMLINK):
            entry["symlink"] = node.get("symlink", "")
            manifest[relpath] = entry
            try:
                os.symlink(node["symlink"], disk)
            except (OSError, NotImplementedError):
                # Windows without privilege: drop a placeholder, keep the truth
                # in the manifest so analyzers still see the link + target
                try:
                    with open(disk, "w", encoding="latin1") as fh:
                        fh.write(node["symlink"])
                except OSError:
                    pass
        else:  # device / fifo / socket
            if "rdev" in node:
                entry["rdev"] = node["rdev"]
            manifest[relpath] = entry

    try:
        walk(sq.root_ref, "", 0)
    except Exception as e:
        return False, "", f"squashfs walk: {e}"

    with open(os.path.join(dest, MANIFEST_NAME), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    log.append(f"  extracted {len(manifest)} entries with permissions")
    return True, dest, "\n".join(log)


def can_handle(image: str, offset: int) -> bool:
    """Quick probe: SquashFS magic + a compressor we can actually decode."""
    try:
        with open(image, "rb") as fh:
            fh.seek(offset)
            head = fh.read(96)
        if len(head) < 96 or struct.unpack_from("<I", head, 0)[0] != _MAGIC:
            return False
        comp = struct.unpack_from("<H", head, 20)[0]
        if comp in (_C_LZO, _C_LZ4):
            return False
        _make_decompressor(comp)
        return True
    except Exception:
        return False


def load_manifest(rootfs: str) -> dict | None:
    """Return {relpath: {mode,uid,gid,symlink?,rdev?}} if a fwre perm manifest
    is present in this rootfs, else None."""
    p = os.path.join(rootfs, MANIFEST_NAME)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None
