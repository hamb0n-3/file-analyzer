#!/usr/bin/env python3
"""Compatibility shim exporting the secrets plugin."""

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
    'SecretsAnalyzer',
]
