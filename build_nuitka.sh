#!/usr/bin/env bash
# ============================================================================
#  Build a standalone Linux executable (dist/fwre) with Nuitka.
#
#  Produces a single self-contained ELF. The external extractors
#  (7z, jefferson, ubireader_extract_files) are NOT bundled -- they are called
#  via subprocess, so keep them on PATH on the target machine.
#
#  Usage:  ./build_nuitka.sh
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"

echo "[*] Ensuring Nuitka is installed..."
"$PY" -m pip install --quiet --upgrade nuitka ordered-set zstandard

echo "[*] Compiling dist/fwre (this can take a few minutes)..."
"$PY" -m nuitka \
    --onefile \
    --assume-yes-for-downloads \
    --output-dir=dist \
    --output-filename=fwre \
    --include-package=fwre \
    --company-name=fwre \
    --product-name=fwre \
    --file-version=0.1.0 \
    --product-version=0.1.0 \
    --file-description="Linux firmware RE / vulnerability framework" \
    fwre_main.py

echo
echo "[+] Built dist/fwre"
echo "    Test:  ./dist/fwre --help"
