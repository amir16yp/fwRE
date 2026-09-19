#!/usr/bin/env bash
# ============================================================================
#  Build a standalone Linux executable (dist/fwre) with Nuitka.
#
#  Produces a single self-contained ELF. The pure-Python extraction backends
#  (dissect.squashfs, jefferson, ubi_reader) are compiled IN, so the binary can
#  unpack SquashFS/JFFS2/UBI on its own. Only 7-Zip stays external (system tool,
#  used for cramfs/ext/gzip and nested archives) -- keep 7z on PATH if you need
#  those.
#
#  Usage:  ./build_nuitka.sh
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"

echo "[*] Installing Nuitka + extraction backends to bundle..."
"$PY" -m pip install --quiet --upgrade nuitka ordered-set zstandard
"$PY" -m pip install --quiet -r requirements.txt

echo "[*] Compiling dist/fwre (this can take a few minutes)..."
# fwre imports the extractors lazily (by string), so Nuitka won't discover them
# from --include-package=fwre alone; each must be named explicitly to be bundled.
"$PY" -m nuitka \
    --onefile \
    --assume-yes-for-downloads \
    --output-dir=dist \
    --output-filename=fwre \
    --include-package=fwre \
    --include-package=dissect.squashfs \
    --include-package=jefferson \
    --include-package=ubireader \
    --company-name=fwre \
    --product-name=fwre \
    --file-version=0.1.0 \
    --product-version=0.1.0 \
    --file-description="Linux firmware RE / vulnerability framework" \
    fwre_main.py

echo
echo "[+] Built dist/fwre"
echo "    Test:  ./dist/fwre --help"
