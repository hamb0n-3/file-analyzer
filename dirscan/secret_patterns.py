
#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern, Optional, List, Dict

@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    pattern: Pattern
    description: str
    category: str  # credential | token | key | certificate | url | username | password | pii | other
    provider: Optional[str] = None
    severity: str = "high"  # high | medium | low
    tags: Optional[List[str]] = None
    redact: bool = True  # redact match by default

def _c(rx: str, flags: int = re.MULTILINE) -> Pattern:
    return re.compile(rx, flags)

def load_rules() -> List[Rule]:
    """
    Curated, reasonably conservative rules to keep false positives low.
    You can extend at runtime by passing --rules-file in dirscan.main (JSON/YAML).
    """
    rules: List[Rule] = [
        # --- Cloud / API tokens ---
        Rule("AWS_ACCESS_KEY_ID", "AWS Access Key ID",
             _c(r"(?<![A-Z0-9])[A-Z0-9]{4}?(AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{12}(?![A-Z0-9])"),
             "Looks like an AWS Access Key ID.", "token", "AWS", "high", ["cloud","aws","credential"]),
        Rule("AWS_SECRET_ACCESS_KEY", "AWS Secret Access Key",
             _c(r"(?i)(?:aws)?[_-]?(?:secret)?[_-]?(?:access)?[_-]?key(?:id)?\s*[:=]\s*([A-Za-z0-9/+=]{40})"),
             "Possible AWS Secret Access Key.", "key", "AWS", "high", ["cloud","aws","credential"]),
        Rule("GITHUB_TOKEN", "GitHub Token",
             _c(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
             "GitHub personal/access token.", "token", "GitHub", "high", ["scm","github","credential"]),
        Rule("GITLAB_TOKEN", "GitLab Token",
             _c(r"glpat-[A-Za-z0-9_-]{20,}"),
             "GitLab personal access token.", "token", "GitLab", "high", ["scm","gitlab","credential"]),
        Rule("SLACK_TOKEN", "Slack Token",
             _c(r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
             "Slack token.", "token", "Slack", "high", ["collab","slack","credential"]),
        Rule("STRIPE_SECRET", "Stripe Secret Key",
             _c(r"sk_(live|test)_[A-Za-z0-9]{24,}"),
             "Stripe secret key.", "key", "Stripe", "high", ["payments","stripe"]),
        Rule("AZURE_SAS", "Azure SAS Token",
             _c(r"sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&st=.*?&spr=https?&sig=[A-Za-z0-9%/+_=]+"),
             "Azure Shared Access Signature (SAS).", "token", "Azure", "high", ["cloud","azure"]),
        Rule("GOOGLE_API_KEY", "Google API Key",
             _c(r"AIza[0-9A-Za-z\-_]{35}"),
             "Google API key.", "token", "Google", "medium", ["google","api"]),
        Rule("OPENAI_KEY", "OpenAI API Key",
             _c(r"sk-[A-Za-z0-9]{20,}"),
             "OpenAI API key.", "key", "OpenAI", "high", ["ai","openai"]),
        # --- Generic credentials ---
        Rule("PASSWORD_ASSIGNMENT", "Password Assignment",
             _c(r"(?i)\b(pass(word)?|pwd)\b\s*[:=]\s*([\'\"][^\'\"]+[\'\"]|[^#\n\r]+)"),
             "Password-like assignment.", "password", None, "high", ["generic","assignment"]),
        Rule("USERNAME_ASSIGNMENT", "Username Assignment",
             _c(r"(?i)\b(user(name)?|login)\b\s*[:=]\s*([\'\"][^\'\"]+[\'\"]|[^#\n\r]+)"),
             "Username-like assignment.", "username", None, "medium", ["generic","assignment"]),
        # --- Certificates / keys ---
        Rule("PRIVATE_KEY", "Private Key Block",
             _c(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ED25519) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|EC|DSA|OPENSSH|PGP|ED25519) PRIVATE KEY-----"),
             "PEM private key material.", "key", None, "critical", ["pem","privatekey"]),
        Rule("CERTIFICATE", "X.509 Certificate",
             _c(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----"),
             "PEM certificate block.", "certificate", None, "low", ["pem","certificate"]),
        # --- URLs / Links ---
        Rule("URL_HTTP", "HTTP URL",
             _c(r"(?i)\bhttps?://[^\s\'\"<>]+"),
             "HTTP(S) URL.", "url", None, "low", ["url"]),
        Rule("CLOUD_ENDPOINT", "Cloud Endpoint URL",
             _c(r"(?i)\bhttps?://(?:[^/\s]+\.)?(?:amazonaws|azure|cloudfront|googleapis|gcp|digitaloceanspaces|herokuapp)\.[^\s\'\"<>]+"),
             "Cloud service endpoint URL.", "url", None, "low", ["cloud","url"]),
        # --- JWT ---
        Rule("JWT", "JSON Web Token",
             _c(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"),
             "Likely JWT token.", "token", None, "medium", ["jwt","token"]),
        # --- Generic high-entropy secrets ---
        Rule("HIGH_ENTROPY", "High-Entropy Candidate",
             _c(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9/_-]{20,})"),
             "Generic high-entropy credential-like value.", "token", None, "medium", ["entropy","generic"], None),
    ]
    return rules
