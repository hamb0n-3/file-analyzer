
#!/usr/bin/env python3
from __future__ import annotations

import math, os, re, hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

TEXT_EXTENSIONS = {
    ".txt",".md",".py",".js",".ts",".tsx",".jsx",".json",".yml",".yaml",".xml",".ini",".cfg",
    ".conf",".properties",".env",".php",".rb",".java",".go",".rs",".c",".cpp",".h",".sh",".ps1",".bat",
    ".toml",".gradle",".cs",".pl",".swift",".kt",".m",".pem",".key",".crt",".cer",".sql",".css",".scss"
}

DEFAULT_EXCLUDES = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env", ".idea", ".vscode",
    "__pycache__", "dist", "build", "out", "target", ".mypy_cache", ".pytest_cache"
}

def is_probably_text(path: Path, sample_size: int = 2048) -> bool:
    try:
        with open(path, "rb") as f:
            b = f.read(sample_size)
        if not b:
            return True
        if b"\x00" in b:
            return False
        # If mostly ASCII/UTF-8 bytes, treat as text
        textlike = sum(1 for ch in b if ch in b"\t\r\n\f\b" or 32 <= ch <= 126 or ch >= 128)
        return textlike / max(1, len(b)) > 0.70
    except Exception:
        return False

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    # Limit to sane length for speed
    s = s[:4096]
    freq = {ch: s.count(ch) for ch in set(s)}
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

def mask_secret(s: str, keep: int = 3) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + ("*" * max(0, len(s) - keep*2)) + s[-keep:]

def rel_to(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except Exception:
        return str(p)

def fingerprint(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()

def should_skip(path: Path, excludes: set[str], follow_symlinks: bool) -> bool:
    name = path.name
    if any(part in excludes for part in path.parts):
        return True
    if not follow_symlinks and path.is_symlink():
        return True
    return False
