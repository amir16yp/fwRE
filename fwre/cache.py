"""Cache-directory helpers. Everything downloaded/derived lives under one dir
so it is built once and reused across runs. Override with $FWRE_CACHE."""
from __future__ import annotations

import os


def cache_dir() -> str:
    d = os.environ.get("FWRE_CACHE")
    if not d:
        d = os.path.join(os.path.expanduser("~"), ".fwre", "cache")
    os.makedirs(d, exist_ok=True)
    return d


def cache_path(*parts: str) -> str:
    return os.path.join(cache_dir(), *parts)
