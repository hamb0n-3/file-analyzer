#!/usr/bin/env python3
# Secrets analyzer plugin with inlined secret scanning rules

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Set

from .base_plugin import AnalyzerPlugin
from ..utils.file_utils import calculate_entropy, is_valid_base64


@dataclass(frozen=True)
class Rule:
    """Secret detection rule with metadata used by the analyzer."""

    rule_id: str
    name: str
    pattern: Pattern
    description: str
    category: str  # credential | token | key | certificate | url | username | password | pii | other
    provider: Optional[str] = None
    severity: str = "high"  # critical | high | medium | low
    tags: Optional[List[str]] = None
    redact: bool = True  # redact match by default


def _c(rx: str, flags: int = re.MULTILINE) -> Pattern:
    """Compile patterns with multiline enabled by default."""

    return re.compile(rx, flags)


def load_rules() -> List[Rule]:
    """Return the curated rule set originally hosted in dirscan.secret_patterns."""

    rules: List[Rule] = [
        # === Cloud / SCM tokens ===================================================
        Rule("AWS_ACCESS_KEY_ID", "AWS Access Key ID",
             _c(r"(?<![A-Z0-9])((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16})(?![A-Z0-9])"),
             "Looks like an AWS Access Key ID.", "token", "AWS", "high", ["cloud","aws","credential"]),
        Rule("AWS_SECRET_ACCESS_KEY", "AWS Secret Access Key",
             _c(r"(?i)(?:aws)?[_-]?(?:secret)?[_-]?(?:access)?[_-]?key(?:id)?\s*[:=]\s*([A-Za-z0-9/+=]{40})"),
             "Possible AWS Secret Access Key.", "key", "AWS", "critical", ["cloud","aws","credential"]),
        Rule("AWS_SESSION_TOKEN", "AWS Session Token",
             _c(r"(?i)(?:aws_)?session[_-]?token\s*[:=]\s*([A-Za-z0-9/+=]{16,})"),
             "Possible temporary AWS session token.", "token", "AWS", "high", ["cloud","aws","sts"]),

        Rule("GITHUB_TOKEN", "GitHub Token (classic)",
             _c(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
             "GitHub personal/access token.", "token", "GitHub", "high", ["scm","github","credential"]),
        Rule("GITHUB_PAT_V2", "GitHub Fine-Grained PAT",
             _c(r"github_pat_[0-9a-zA-Z_]{22,}"),
             "GitHub fine-grained PAT (v2).", "token", "GitHub", "high", ["scm","github","credential"]),

        Rule("GITLAB_TOKEN", "GitLab Token",
             _c(r"glpat-[A-Za-z0-9_-]{20,}"),
             "GitLab personal access token.", "token", "GitLab", "high", ["scm","gitlab","credential"]),

        Rule("BITBUCKET_APP_PASSWORD", "Bitbucket App Password",
             _c(r"(?i)(?:bitbucket|bb)_?(?:app)?_?password\s*[:=]\s*[A-Za-z0-9-_]{20,}"),
             "Bitbucket App Password (contextual).", "password", "Bitbucket", "high", ["scm","bitbucket","credential"]),

        # === Collaboration & Messaging ===========================================
        Rule("SLACK_TOKEN", "Slack Token",
             _c(r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
             "Slack token.", "token", "Slack", "high", ["collab","slack","credential"]),
        Rule("SLACK_WEBHOOK", "Slack Incoming Webhook URL",
             _c(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[A-Za-z0-9]{24,}"),
             "Slack incoming webhook.", "url", "Slack", "high", ["collab","slack","webhook"]),

        Rule("DISCORD_TOKEN", "Discord Bot/User Token",
             _c(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
             "Discord bot/user token.", "token", "Discord", "high", ["chat","discord","credential"]),

        Rule("TELEGRAM_BOT_TOKEN", "Telegram Bot Token",
             _c(r"\b[0-9]{8,10}:AA[0-9A-Za-z_-]{33}\b"),
             "Telegram bot token.", "token", "Telegram", "high", ["chat","telegram","credential"]),

        # === Payments / Comms / SaaS ============================================
        Rule("STRIPE_SECRET", "Stripe Secret Key",
             _c(r"sk_(live|test)_[A-Za-z0-9]{24,}"),
             "Stripe secret key.", "key", "Stripe", "high", ["payments","stripe"]),

        Rule("SENDGRID_API_KEY", "SendGrid API Key",
             _c(r"SG\.[A-Za-z0-9_-]{16,}\.([A-Za-z0-9_-]{16,})"),
             "SendGrid API key.", "key", "SendGrid", "high", ["email","sendgrid"]),

        Rule("MAILGUN_API_KEY", "Mailgun API Key",
             _c(r"key-[0-9a-zA-Z]{32}"),
             "Mailgun API key.", "key", "Mailgun", "high", ["email","mailgun"]),

        Rule("TWILIO_ACCOUNT_SID", "Twilio Account SID",
             _c(r"\bAC[a-f0-9]{32}\b", re.IGNORECASE),
             "Twilio Account SID.", "username", "Twilio", "medium", ["telephony","twilio"]),
        Rule("TWILIO_AUTH_TOKEN", "Twilio Auth Token (hex)",
             _c(r"(?i)twilio[_-]?auth[_-]?token\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"),
             "Twilio Auth Token (32 hex).", "password", "Twilio", "high", ["telephony","twilio"]),

        Rule("NOTION_SECRET", "Notion Internal Integration Secret",
             _c(r"secret_[A-Za-z0-9]{43}"),
             "Notion integration secret.", "token", "Notion", "high", ["productivity","notion"]),

        Rule("DATADOG_API_KEY", "Datadog API Key",
             _c(r"\b(?:DD_)?API[_-]?KEY\s*[:=]\s*[a-f0-9]{32}\b", re.IGNORECASE),
             "Datadog API Key (32 hex).", "key", "Datadog", "high", ["observability","datadog"]),

        Rule("SENTRY_DSN", "Sentry DSN",
             _c(r"https://[0-9a-fA-F]{32}@o\d+\.ingest\.sentry\.io/\d+"),
             "Sentry DSN (server key).", "url", "Sentry", "high", ["observability","sentry","dsn"]),

        # === Cloud Platform / APIs ==============================================
        Rule("GOOGLE_API_KEY", "Google API Key",
             _c(r"AIza[0-9A-Za-z\-_]{35}"),
             "Google API key.", "token", "Google", "medium", ["google","api"]),

        Rule("OPENAI_API_KEY", "OpenAI API Key",
             _c(r"\b(?:sk-[A-Za-z0-9]{32,}|sk-proj-[A-Za-z0-9]{32,})\b"),
             "OpenAI API key.", "token", "OpenAI", "high", ["ai","openai","credential"]),

        Rule("AZURE_SAS", "Azure SAS Token",
             _c(r"(?i)se=\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}z&sp=[a-z]+&spr=https?&sv=\d{4}-\d{2}-\d{2}&sr=[a-z]+&sig=[a-z0-9%/+_=]+"),
             "Azure Shared Access Signature (SAS) query parameters.", "token", "Azure", "high", ["cloud","azure"]),

        Rule("SUPABASE_KEY", "Supabase Key (anon/service)",
             _c(r"(?i)SUPABASE_(ANON|SERVICE)_KEY\s*[:=]\s*(eyJ[\w.-]{10,})"),
             "Supabase anon/service JWT-like key.", "token", "Supabase", "high", ["supabase","jwt","credential"]),
        Rule("HEROKU_API_KEY", "Heroku API Key",
             _c(r"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?"),
             "Heroku API key.", "token", "Heroku", "high", ["heroku","credential"]),
        Rule("CLOUDFLARE_API_TOKEN", "Cloudflare API Token",
             _c(r"(?i)cloudflare[_-]?(?:global|api)?[_-]?token\s*[:=]\s*['\"]?([A-Za-z0-9-_=]{30,60})['\"]?"),
             "Cloudflare API token.", "token", "Cloudflare", "high", ["cloudflare","credential"]),
        Rule("OKTA_API_TOKEN", "Okta API Token",
             _c(r"(?i)okta[_-]?(?:api|access)?[_-]?token\s*[:=]\s*['\"]?(00[a-zA-Z0-9-_]{40})['\"]?"),
             "Okta API token (00-prefixed).", "token", "Okta", "high", ["okta","credential"]),
        Rule("SHOPIFY_ACCESS_TOKEN", "Shopify Private Access Token",
             _c(r"shp(?:at|ca|pa|ua)_[a-f0-9]{32}"),
             "Shopify private access token.", "token", "Shopify", "high", ["shopify","credential"]),
        Rule("CIRCLECI_PERSONAL_TOKEN", "CircleCI Personal Token",
             _c(r"(?i)circleci[_-]?(?:api|personal)?[_-]?token\s*[:=]\s*['\"]?([A-Za-z0-9]{40})['\"]?"),
             "CircleCI personal API token.", "token", "CircleCI", "high", ["circleci","credential"]),

        # === Keys & Certificates ==================================================
        Rule("PRIVATE_KEY", "Private Key Block",
             _c(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ED25519) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|EC|DSA|OPENSSH|PGP|ED25519) PRIVATE KEY-----"),
             "PEM private key material.", "key", None, "critical", ["pem","privatekey"]),

        # === High-entropy generic candidates ====================================
        # This intentionally casts a wide net but remains filtered by the scanner
        # using additional heuristics (e.g., surrounding keywords or length).
        Rule("HIGH_ENTROPY", "High-Entropy Candidate",
             _c(r"(?<![A-Za-z0-9=+_-])([A-Za-z0-9=+_-]{24,})(?![A-Za-z0-9=+_-])"),
            "Generic high-entropy credential-like value.", "token", None, "medium", ["entropy","generic"]),

        # === Contextual username/password patterns ===============================
        Rule("PASSWORD_ASSIGN", "Password Assignment",
             _c(r"(?i)\b(pass|password|pwd|secret)\b\s*[:=]\s*([\S]{4,})"),
             "Inline password/secret assignment.", "password", None, "high", ["password","assignment"]),
        Rule("USERNAME_PASSWORD_PAIR", "Username/Password Pair",
             _c(r"(?i)\b(user(name)?|login)\b\s*[:=]\s*\S+\s*[;,\n]+\s*\b(pass|password|pwd)\b\s*[:=]\s*\S+"),
             "Adjacent username/password pair.", "credential", None, "high", ["password","username","pair"]),
    ]
    return rules


DEFAULT_RULES: List[Rule] = load_rules()


class SensitiveAnalyzer(AnalyzerPlugin):
    """
    Plugin that scans file content for secrets/credentials using the curated
    rules defined in this module.

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
                for line in lines:
                    for m in rule.pattern.finditer(line):
                        value = self._extract_value(rule, m)
                        key = self._map_rule_to_result_key(rule)
                        if key and value and self._should_keep(rule, value):
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
                    if key and value and self._should_keep(rule, value):
                        results.setdefault(key, set()).add(value)
            except re.error:
                continue

        # Additional direct regex scans for migrated patterns
        for key, pat in self.migrated_patterns.items():
            try:
                for m in re.finditer(pat, content):
                    val = m.group(1) if m.lastindex else m.group(0)
                    if key == 'base64_encoded' and not is_valid_base64(val):
                        continue
                    if key == 'credit_card' and not self._passes_luhn(val):
                        continue
                    if key == 'social_security' and not self._valid_social_security(val):
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

    def _should_keep(self, rule: Rule, value: str) -> bool:
        """Apply rule-specific heuristics to limit false positives."""
        if not value:
            return False

        # Normalize whitespace for comparisons without mutating stored value
        candidate = value.strip()

        if rule.rule_id == "HIGH_ENTROPY":
            if len(candidate) < 24:
                return False
            classes = sum(bool(re.search(regex, candidate)) for regex in (r"[A-Z]", r"[a-z]", r"\d", r"[_=+\-]"))
            if classes < 3:
                return False
            if calculate_entropy(candidate) < 3.5:
                return False

        if rule.rule_id == "PASSWORD_ASSIGN":
            # Skip assignments pointing to lookups or placeholders (not real secrets)
            lowered = candidate.lower()
            if any(marker in lowered for marker in ("os.environ", "getenv", "input(", "changeme", "example", "sample", "todo")):
                return False

        return True

    def _passes_luhn(self, value: str) -> bool:
        """Validate credit-card like numbers using the Luhn checksum."""
        digits = re.sub(r"\D", "", value)
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        double = False
        for ch in reversed(digits):
            n = int(ch)
            if double:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
            double = not double
        return total % 10 == 0

    def _valid_social_security(self, value: str) -> bool:
        """Reject impossible SSNs (000/666 prefixes, invalid groups)."""
        digits = re.sub(r"\D", "", value)
        if len(digits) != 9:
            return False
        area, group, serial = digits[:3], digits[3:5], digits[5:]
        if area in {"000", "666"} or area >= "900":
            return False
        if group == "00" or serial == "0000":
            return False
        return True
