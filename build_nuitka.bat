@echo off
REM ===========================================================================
REM  Build a standalone Windows executable (dist\fwre.exe) with Nuitka.
REM
REM  Produces a single self-contained fwre.exe. The pure-Python extraction
REM  backends (dissect.squashfs, jefferson, ubi_reader) are compiled IN, so the
REM  binary unpacks SquashFS/JFFS2/UBI on its own. Only 7-Zip stays external
REM  (system tool for cramfs/ext/gzip and nested archives) -- keep 7z on PATH if
REM  you need those.
REM
REM  Usage:  build_nuitka.bat
REM ===========================================================================
setlocal
cd /d "%~dp0"

echo [*] Installing Nuitka + extraction backends to bundle...
python -m pip install --quiet --upgrade nuitka ordered-set zstandard || goto :err
python -m pip install --quiet -r requirements.txt || goto :err

echo [*] Compiling fwre.exe (this can take a few minutes)...
REM fwre imports the extractors lazily (by string), so Nuitka won't discover
REM them from --include-package=fwre alone; each must be named explicitly.
python -m nuitka ^
    --onefile ^
    --assume-yes-for-downloads ^
    --output-dir=dist ^
    --output-filename=fwre.exe ^
    --include-package=fwre ^
    --include-package=dissect.squashfs ^
    --include-package=jefferson ^
    --include-package=ubireader ^
    --company-name=fwre ^
    --product-name=fwre ^
    --file-version=0.1.0 ^
    --product-version=0.1.0 ^
    --file-description="Linux firmware RE / vulnerability framework" ^
    fwre_main.py || goto :err

echo.
echo [+] Built dist\fwre.exe
echo     Test:  dist\fwre.exe --help
goto :eof

:err
echo [!] Build failed.
exit /b 1
