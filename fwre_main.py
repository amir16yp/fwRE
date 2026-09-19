#!/usr/bin/env python3
"""Standalone entry point for Nuitka/PyInstaller builds.

Equivalent to `python -m fwre`. External tools (7z, jefferson,
ubireader_extract_files) are invoked via subprocess at runtime, so they are NOT
compiled in — install them separately and keep them on PATH.
"""
import sys

from fwre.cli import main

if __name__ == "__main__":
    sys.exit(main())
