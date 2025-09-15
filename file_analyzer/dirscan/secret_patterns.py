#!/usr/bin/env python3
"""Backward-compatible shim for secret detection rules.

The canonical list of secret-detection rules now lives in
``file_analyzer.plugins.sensitive``. This module re-exports the same API so
callers importing ``dirscan.secret_patterns`` continue to function without
modification.
"""

from __future__ import annotations

from ..plugins.sensitive import DEFAULT_RULES, Rule, load_rules

__all__ = ["Rule", "load_rules", "DEFAULT_RULES"]
