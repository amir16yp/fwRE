@echo off
REM ===========================================================================
REM  Build a standalone Windows executable (dist\fwre.exe) with Nuitka.
REM
REM  Produces a single self-contained fwre.exe. The external extractors
REM  (7z.exe, jefferson, ubireader_extract_files) are NOT bundled -- they are
REM  called via subprocess, so keep them on PATH on the target machine.
REM
REM  Usage:  build_nuitka.bat
REM ===========================================================================
setlocal
cd /d "%~dp0"

echo [*] Ensuring Nuitka is installed...
python -m pip install --quiet --upgrade nuitka ordered-set zstandard || goto :err

echo [*] Compiling fwre.exe (this can take a few minutes)...
python -m nuitka ^
    --onefile ^
    --assume-yes-for-downloads ^
    --output-dir=dist ^
    --output-filename=fwre.exe ^
    --include-package=fwre ^
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
