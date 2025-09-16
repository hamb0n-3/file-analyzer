#!/usr/bin/env python3
"""Compatibility shim exporting secrets plugin symbols."""

from __future__ import annotations

from .secrets import *  # noqa: F401,F403

__all__ = [
    'AnalyzerPlugin',
    'Rule',
    'DEFAULT_RULES',
    'load_rules',
    'Finding',
    'ScanConfig',
    'SecretScanner',
    'SensitiveAnalyzer',
]
