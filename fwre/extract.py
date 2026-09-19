"""Firmware extraction - 7-Zip driver with carve fallback and external
extractors for the filesystems 7z can't read.

The raw .bin flash dumps carry a bootloader, one or more uImage kernels and a
root filesystem. 7z locates and unpacks SquashFS/cramfs/ext/gzip regardless of
offset; when it grabs the wrong (earlier) archive we locate filesystem magics
and hand 7z a carved [offset:EOF] slice per candidate. For JFFS2 and UBI/UBIFS
- which 7z cannot unpack - we drive `jefferson` and `ubi_reader`, which are pure
Python packages: we call their `main()` in-process (so they are compiled into
the standalone Nuitka binary and need no separate install), falling back to the
PATH executable when the module isn't importable.
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field


# Filesystem/container magics we may need to point 7z at when it latches onto
# the wrong (earlier) archive in a multi-partition flash dump. We only *locate*
# these - 7z still does the actual unpacking on the carved [offset:EOF] slice.
_FS_MAGICS = [
    (b"hsqs", "squashfs"), (b"sqsh", "squashfs-be"),
    (b"sqlz", "squashfs-lzma"), (b"qshs", "squashfs"),
    (b"\x45\x3d\xcd\x28", "cramfs"), (b"\x28\xcd\x3d\x45", "cramfs-be"),
    (b"UBI#", "ubi"), (b"\x31\x18\x10\x06", "ubifs"),
    (b"\x85\x19\x03\x20", "jffs2"), (b"\x19\x85", "jffs2-be"),
    (b"\x53\xef", "ext"),  # ext2/3/4 superblock magic (at +0x438, handled below)
    (b"\x1f\x8b\x08", "gzip"),
]


# archive-ish things worth trying to recurse into after the first pass
_NESTED_EXT = {
    ".squashfs", ".sqsh", ".jffs2", ".cramfs", ".ubi", ".ubifs",
    ".tar", ".gz", ".tgz", ".xz", ".bz2", ".lzma", ".zip", ".cpio",
    ".img", ".rootfs", ".ext2", ".ext3", ".ext4",
}
_NESTED_NAMES = {"rootfs", "root", "system", "app", "appfs"}


def find_7z() -> str:
    """Locate a 7z executable, preferring 7z then 7za/7zz."""
    for name in ("7z", "7z.exe", "7za", "7zz"):
        p = shutil.which(name)
        if p:
            return p
    # common Windows install path
    for p in (r"C:\Program Files\7-Zip\7z.exe",
              r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(
        "7z not found on PATH. Install 7-Zip (scoop install 7zip) and retry."
    )


@dataclass
class ExtractResult:
    image: str
    out_dir: str
    ok: bool
    rootfs: str | None = None      # best guess at the extracted root filesystem
    log: str = ""
    nested: list[str] = field(default_factory=list)
    detected_fs: list[str] = field(default_factory=list)  # magics seen in image
    tools_used: list[str] = field(default_factory=list)   # external extractors run
    hint: str = ""                 # guidance when 7z can't handle the FS


# filesystems 7z cannot unpack -> external tool + install hint
_FS_TOOL_HINT = {
    "ubi": "UBI not extractable by 7z - install ubi_reader (pip install ubi_reader)",
    "ubifs": "UBIFS not extractable by 7z - install ubi_reader (pip install ubi_reader)",
    "jffs2": "JFFS2 not extractable by 7z - install jefferson (pip install jefferson)",
    "jffs2-be": "JFFS2 not extractable by 7z - install jefferson (pip install jefferson)",
}

# which external extractor handles which detected filesystem kind
_JFFS2_KINDS = {"jffs2", "jffs2-be"}
_UBI_KINDS = {"ubi", "ubifs"}


def find_jefferson() -> str | None:
    return shutil.which("jefferson")


def find_ubireader() -> str | None:
    return shutil.which("ubireader_extract_files")


def _module_available(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def _have_jefferson() -> bool:
    """jefferson usable either as a bundled/importable module or a PATH tool."""
    return _module_available("jefferson") or find_jefferson() is not None


def _have_ubireader() -> bool:
    return _module_available("ubireader") or find_ubireader() is not None


def _run_cmd(cmd: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", timeout=1800)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"{e}"
    return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")


def _run_pymodule(target: str, argv: list[str]) -> "tuple[bool, str] | None":
    """Invoke a console-script `main()` in-process, e.g. "jefferson.cli:main".

    These extractors are pure-Python packages, so calling their entry point
    directly means they work inside the standalone binary (where there is no
    `jefferson`/`ubireader_extract_files` on PATH). Returns (ok, log), or None
    if the module isn't importable so the caller can fall back to a PATH tool.
    """
    mod_name, _, func_name = target.partition(":")
    try:
        mod = importlib.import_module(mod_name)
    except Exception:
        return None
    func = getattr(mod, func_name, None)
    if func is None:
        return None
    buf = io.StringIO()
    saved_argv = sys.argv
    sys.argv = [mod_name.split(".")[0], *argv]
    code = 0
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                func()
            except SystemExit as e:          # both tools sys.exit() on completion
                code = e.code if isinstance(e.code, int) else (0 if not e.code else 1)
            except Exception as e:            # a parse failure must not crash us
                buf.write(f"\n[in-proc {mod_name}] {e}\n")
                code = 1
    finally:
        sys.argv = saved_argv
    return code == 0, buf.getvalue()


def _extract_jffs2(image: str, offset: int, sub: str) -> tuple[bool, str]:
    """Carve [offset:EOF] and run jefferson on it (no offset flag in jefferson)."""
    with tempfile.NamedTemporaryFile(suffix=".jffs2", delete=False) as tf:
        tmp = tf.name
    try:
        _carve_slice(image, offset, tmp)
        argv = [tmp, "-d", sub, "-f"]
        r = _run_pymodule("jefferson.cli:main", argv)   # bundled / importable
        if r is not None:
            return r
        tool = find_jefferson()                          # PATH fallback
        if not tool:
            return False, "jefferson not installed"
        return _run_cmd([tool, *argv])
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# common UBIFS logical-eraseblock sizes (decimal); ubi_reader can auto-detect
# PEB size for wrapped UBI images but needs the LEB size for a bare UBIFS.
_COMMON_LEB = (129024, 126976, 258048, 253952, 64512, 520192, 516096, 32256)


def _extract_ubi(image: str, offset: int, sub: str) -> tuple[bool, str]:
    """Drive ubi_reader. For a wrapped UBI image it auto-detects geometry; for a
    bare UBIFS it needs the LEB size, so we try the common ones. Bounded and
    fails fast (ubi_reader rejects wrong geometry immediately)."""
    if not _have_ubireader():
        return False, "ubi_reader not installed"
    tool = find_ubireader()  # None when only the importable module is present
    attempts = [
        [image, "-o", sub],                            # wrapped UBI, auto
        [image, "-o", sub, "-g", "0"],                 # guess UBI offset
    ]
    for leb in _COMMON_LEB:                             # bare UBIFS geometries
        attempts.append([image, "-o", sub, "-s", str(offset), "-e", str(leb)])
    log = ""
    for argv in attempts:
        r = _run_pymodule("ubireader.scripts.ubireader_extract_files:main", argv)
        if r is None:                                  # module gone -> PATH tool
            r = _run_cmd([tool, *argv]) if tool else (False, "ubi_reader missing")
        _ok, out = r
        log += f"\n$ ubireader_extract_files {' '.join(argv)}\n{out[-200:]}"
        if _find_rootfs(sub) is not None:
            return True, log
    return False, log


def _run_7z(sevenz: str, archive: str, dest: str) -> tuple[bool, str]:
    os.makedirs(dest, exist_ok=True)
    proc = subprocess.run(
        [sevenz, "x", archive, f"-o{dest}", "-y", "-bsp0", "-bse0"],
        capture_output=True, text=True, errors="replace",
    )
    # 7z returns 2 for fatal, 1 for warnings (e.g. dev nodes on Windows).
    ok = proc.returncode in (0, 1)
    return ok, (proc.stdout or "") + (proc.stderr or "")


def _looks_like_rootfs(path: str) -> bool:
    markers = ("etc", "bin", "sbin", "lib")
    hits = sum(os.path.isdir(os.path.join(path, m)) for m in markers)
    return hits >= 2


def _find_rootfs(root: str) -> str | None:
    """Walk the extraction tree and return the dir that looks most like a
    Linux rootfs (has etc/bin/sbin/lib children)."""
    best: tuple[int, str] | None = None
    for dirpath, dirnames, _ in os.walk(root):
        markers = ("etc", "bin", "sbin", "lib", "usr")
        hits = sum(d in dirnames for d in markers)
        if hits >= 2:
            # prefer the shallowest, richest match
            depth = dirpath[len(root):].count(os.sep)
            score = hits * 100 - depth
            if best is None or score > best[0]:
                best = (score, dirpath)
    return best[1] if best else None


def _nested_archives(root: str) -> list[str]:
    out = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            low = f.lower()
            stem, ext = os.path.splitext(low)
            if ext in _NESTED_EXT or stem in _NESTED_NAMES:
                out.append(os.path.join(dirpath, f))
    return out


def _scan_fs_offsets(image: str, max_scan: int = 256 * 1024 * 1024) -> list[tuple[int, str]]:
    """Locate filesystem magics in the raw image (offset, kind), best-first.

    This does NOT validate - it just finds candidate offsets so we can hand a
    carved [offset:EOF] slice to 7z when the first archive it sees isn't the
    root filesystem. SquashFS/UBI/cramfs/ext are prioritised over gzip.
    """
    try:
        with open(image, "rb") as fh:
            data = fh.read(max_scan)
    except OSError:
        return []
    priority = {"squashfs": 0, "squashfs-be": 0, "squashfs-lzma": 0,
                "ubi": 1, "ubifs": 1, "cramfs": 1, "cramfs-be": 1,
                "ext": 2, "jffs2": 3, "jffs2-be": 3, "gzip": 5}
    hits: list[tuple[int, str]] = []
    for magic, kind in _FS_MAGICS:
        start = 0
        found = 0
        while found < 8:
            i = data.find(magic, start)
            if i < 0:
                break
            off = i - 0x438 if kind == "ext" else i  # ext magic sits at +0x438
            if off >= 0:
                hits.append((off, kind))
            start = i + 1
            found += 1
    # sort by (priority, offset); dedupe near-identical offsets
    hits.sort(key=lambda h: (priority.get(h[1], 9), h[0]))
    return hits


def _carve_slice(image: str, offset: int, dest_bin: str,
                 chunk: int = 8 * 1024 * 1024) -> None:
    """Copy [offset:EOF] of image to dest_bin without loading it all in RAM."""
    with open(image, "rb") as src, open(dest_bin, "wb") as dst:
        src.seek(offset)
        while True:
            buf = src.read(chunk)
            if not buf:
                break
            dst.write(buf)


def _try_builtin_squashfs(image: str, out_dir: str, recurse: bool,
                          max_depth: int, sevenz: str) -> "ExtractResult | None":
    """Extract SquashFS partition(s) with the pure-Python reader (perm-preserving).
    Returns an ExtractResult if a rootfs was recovered, else None to fall back."""
    from . import squashfs as sqfs
    if not sqfs.available():
        return None
    offsets = _scan_fs_offsets(image)
    sq_offsets = [(o, k) for o, k in offsets if k.startswith("squashfs")]
    if not sq_offsets:
        return None
    res = ExtractResult(image=image, out_dir=out_dir, ok=False)
    res.detected_fs = sorted({k for _, k in offsets})
    best = None
    for idx, (off, _kind) in enumerate(sq_offsets):
        if not sqfs.can_handle(image, off):
            continue
        sub = os.path.join(out_dir, f"_sqfs_{idx:02d}_0x{off:x}")
        ok, root, log = sqfs.extract(image, off, sub)
        res.log += f"\n[squashfs @0x{off:x}] ok={ok}\n{log[-400:]}"
        if not ok:
            continue
        res.tools_used.append("dissect.squashfs")
        if recurse and max_depth > 0:
            _recurse_nested(sevenz, sub, res, max_depth)
        rootfs = _find_rootfs(sub)
        if rootfs:
            # prefer the richest rootfs (a full linux tree over an app partition)
            score = sum(os.path.isdir(os.path.join(rootfs, m))
                        for m in ("etc", "bin", "sbin", "lib", "usr"))
            if best is None or score > best[0]:
                best = (score, rootfs)
            if score >= 4:  # clearly the main rootfs; stop early
                break
    if best:
        res.rootfs = best[1]
        res.ok = True
        return res
    return None


def extract(image: str, out_dir: str, *, recurse: bool = True,
            max_depth: int = 3, sevenz: str | None = None,
            carve_fallback: bool = True) -> ExtractResult:
    """Extract `image` into `out_dir` using 7z, recursing into nested archives.

    If 7z's direct pass doesn't yield something that looks like a Linux rootfs
    (common when the first archive in a flash dump is the compressed kernel),
    fall back to locating filesystem magics and handing 7z a carved
    [offset:EOF] slice for each candidate until a rootfs appears.

    Returns an ExtractResult with a best-guess `rootfs` path for analysis.
    """
    sevenz = sevenz or find_7z()
    os.makedirs(out_dir, exist_ok=True)

    # Prefer the built-in SquashFS reader when available: unlike 7z on Windows
    # it preserves Unix mode bits / ownership / symlinks (written to a sidecar
    # manifest), which the permission audit depends on. Falls through to 7z for
    # non-SquashFS images or when the reader isn't installed.
    if carve_fallback:
        builtin = _try_builtin_squashfs(image, out_dir, recurse, max_depth, sevenz)
        if builtin is not None and builtin.rootfs:
            return builtin

    ok, log = _run_7z(sevenz, image, out_dir)
    res = ExtractResult(image=image, out_dir=out_dir, ok=ok, log=log)

    if recurse and max_depth > 0:
        _recurse_nested(sevenz, out_dir, res, max_depth)

    res.rootfs = _find_rootfs(out_dir)

    # Fallback: 7z grabbed the wrong partition (e.g. gzip kernel), or the FS is
    # one 7z can't read (JFFS2/UBIFS). Locate the real filesystem(s) and dispatch
    # each candidate to the right extractor: 7z for squashfs/cramfs/ext/gzip,
    # jefferson for JFFS2, ubi_reader for UBI/UBIFS.
    if res.rootfs is None and carve_fallback:
        offsets = _scan_fs_offsets(image)
        res.detected_fs = sorted({k for _, k in offsets})
        for idx, (off, kind) in enumerate(offsets):
            sub = os.path.join(out_dir, f"_carved_{idx:02d}_{kind}_0x{off:x}")
            os.makedirs(sub, exist_ok=True)

            if kind in _JFFS2_KINDS:
                cok, clog = _extract_jffs2(image, off, sub)
                res.tools_used.append("jefferson")
            elif kind in _UBI_KINDS:
                cok, clog = _extract_ubi(image, off, sub)
                res.tools_used.append("ubi_reader")
            else:
                with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
                    tmp_bin = tf.name
                try:
                    _carve_slice(image, off, tmp_bin)
                    cok, clog = _run_7z(sevenz, tmp_bin, sub)
                finally:
                    try:
                        os.unlink(tmp_bin)
                    except OSError:
                        pass
            res.log += f"\n[{kind} @0x{off:x}] ok={cok}\n{clog[-500:]}"

            if recurse and max_depth > 0:
                _recurse_nested(sevenz, sub, res, max_depth)
            rootfs = _find_rootfs(sub)
            if rootfs:
                res.rootfs = rootfs
                res.ok = True
                break

    # No rootfs found. If a JFFS2/UBI extractor is missing, tell the user to
    # install it; otherwise the FS types just didn't yield a Linux rootfs.
    if res.rootfs is None and res.detected_fs:
        missing = []
        if any(k in _JFFS2_KINDS for k in res.detected_fs) and not _have_jefferson():
            missing.append(_FS_TOOL_HINT["jffs2"])
        if any(k in _UBI_KINDS for k in res.detected_fs) and not _have_ubireader():
            missing.append(_FS_TOOL_HINT["ubi"])
        if missing:
            res.hint = "; ".join(missing)
        else:
            res.hint = (f"detected {', '.join(res.detected_fs)} but no Linux "
                        f"rootfs recovered (may be initramfs-in-kernel or a "
                        f"NAND dump with OOB data)")

    return res


def _recurse_nested(sevenz: str, root: str, res: ExtractResult,
                    max_depth: int) -> None:
    seen: set[str] = set()
    for _ in range(max_depth):
        new = [a for a in _nested_archives(root) if a not in seen]
        if not new:
            break
        for arc in new:
            seen.add(arc)
            sub = arc + ".extracted"
            sok, slog = _run_7z(sevenz, arc, sub)
            res.log += f"\n[nested] {arc}\n{slog[-300:]}"
            if sok:
                res.nested.append(sub)
