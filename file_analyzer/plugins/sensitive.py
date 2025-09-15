#!/usr/bin/env python3
# Secrets analyzer plugin leveraging dirscan/secret_patterns rules

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Optional, Set

from .base_plugin import AnalyzerPlugin
from ..dirscan.secret_patterns import load_rules, Rule


class SensitiveAnalyzer(AnalyzerPlugin):
    """
    Plugin that scans file content for secrets/credentials using the curated
    rules defined in dirscan/secret_patterns.py.

    Findings are normalized into existing result keys so they show up in
    standard reports and in plugin aggregation.
    """

    # This plugin needs the full content for quality matches
    requires_full_content: bool = True

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"secret", "sensitive"}
        # Load and cache compiled rules
        self.rules: list[Rule] = load_rules()
        # Additional migrated patterns (formerly in data_patterns)
        self.migrated_patterns = {
            'email': r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b",
            'username': r"(?i)\b(?:username|user|login)\b\s*[:=]\s*['\"]((?!example|sample|test|dummy|admin)['\"\w.@+-]{4,})['\"]",
            'api_key': r"(?i)(?:\b(?:api[_-]?key|apikey|apiKey|client[_-]?secret|secret[_-]?key|access[_-]?key)\b)\s*[:=]\s*['\"]((?!changeme|example|sample|test|dummy|password|secret|redacted)[^'\"\s]{16,})['\"]",
            'base64_encoded': r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])",
            'credit_card': r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            'social_security': r"\b\d{3}-\d{2}-\d{4}\b",
            'database_connection': r"(?i)(?:mysql|postgres(?:ql)?|mongodb|sqlserver)://[^:\s]+:[^@\s]+@[^:\s]+(?::\d+)?/[A-Za-z0-9._-]+",
        }

    @property
    def plugin_type(self) -> str:
        return "secret_analyzer"

    @property
    def supported_file_types(self) -> Set[str]:
        # Apply broadly to text-like files; analyzer already gates non-text
        return {"*"}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        # Only run on text-like content
        if file_type != "text":
            return False
        # Skip if no content provided (e.g., chunked mode without content)
        return content is not None and len(content) > 0

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]):
        logging.debug(f"Analyzing secrets in {file_path}")
        if not content:
            return results

        # Line-oriented passes for most rules
        lines = content.splitlines()
        for rule in self.rules:
            # Fast path: multiline-only rules handled in a separate pass
            if self._is_multiline_rule(rule):
                continue
            try:
                for i, line in enumerate(lines, start=1):
                    for m in rule.pattern.finditer(line):
                        value = self._extract_value(rule, m)
                        key = self._map_rule_to_result_key(rule)
                        if key and value:
                            results.setdefault(key, set()).add(value)
            except re.error:
                # Ignore malformed patterns in this context
                continue

        # Multiline rules like PEM blocks, JWTs
        for rule in self.rules:
            if not self._is_multiline_rule(rule):
                continue
            try:
                for m in rule.pattern.finditer(content):
                    value = self._extract_value(rule, m)
                    key = self._map_rule_to_result_key(rule)
                    if key and value:
                        results.setdefault(key, set()).add(value)
            except re.error:
                continue

        # Additional direct regex scans for migrated patterns
        from ..utils.file_utils import is_valid_base64
        for key, pat in self.migrated_patterns.items():
            try:
                for m in re.finditer(pat, content):
                    val = m.group(1) if m.lastindex else m.group(0)
                    if key == 'base64_encoded' and not is_valid_base64(val):
                        continue
                    results.setdefault(key, set()).add(val)
            except re.error:
                continue

        return results

    # -------- helpers --------
    def _is_multiline_rule(self, rule: Rule) -> bool:
        name = rule.name.upper()
        return ("PRIVATE KEY" in name) or ("CERTIFICATE" in name) or (rule.rule_id in {"JWT"})

    def _extract_value(self, rule: Rule, match: re.Match) -> str:
        # If the rule captures a group for the secret, prefer that group
        if match.lastindex:
            for idx in range(match.lastindex, 0, -1):
                g = match.group(idx)
                if g:
                    return g
        return match.group(0)

    def _map_rule_to_result_key(self, rule: Rule) -> Optional[str]:
        # Specific IDs first
        rid = rule.rule_id.upper()
        name = rule.name.lower()
        provider = (rule.provider or "").lower()
        cat = (rule.category or "").lower()

        # Cloud/provider specifics
        if provider == "aws":
            return "aws_key"

        if rid in {"JWT"} or "jwt" in name:
            return "jwt"

        if rid in {"PRIVATE_KEY", "GENERIC_PRIVATE_KEY"} or "private key" in name:
            return "private_key"

        if rid == "CERTIFICATE" or "certificate" in name:
            return "certificate"

        if rid in {"SLACK_WEBHOOK"} or "webhook" in name:
            return "webhook_url"

        if rid in {"BASIC_AUTH_IN_URL"}:
            return "url"

        if rid in {"VA_GOV_URL"}:
            return "va_gov_url"
        if rid in {"VA_GOV_DOMAIN"}:
            return "va_gov_domain"

        # URLs in general
        if cat == "url":
            return "url"

        # Credentials
        if cat == "password":
            return "password"
        if cat == "username":
            return "username"

        # Keys/tokens
        if cat == "key":
            # Could be encryption key or API key; map to encryption_key by default
            # API keys from providers above are already handled
            return "encryption_key"
        if cat == "token":
            # Default bucket for tokens
            return "api_token"

        # PII and misc
        if cat == "pii":
            return "email"  # fall back into Sensitive Data; better mapping requires provider-specific rules

        if rid == "HIGH_ENTROPY":
            return "high_entropy_strings"

        # Database URIs
        if any(x in rid for x in ("POSTGRES_URI", "MYSQL_URI", "MONGODB_URI", "REDIS_URI", "AMQP_URI")):
            return "database_connection"

        # Authorization header
        if rid == "AUTH_BEARER":
            return "authorization_header"

        # Last resort
        return "api_token"
