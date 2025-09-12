
#!/usr/bin/env python3
"""
secret_patterns_improved.py

A curated, reasonably conservative—but broad—set of secret/credential patterns
intended for source, config, and log scanning. The focus is on *low false
positives* while still covering a wide range of common providers and
credential shapes. This module is drop-in compatible with the original
`Rule`/`load_rules()` structure while expanding coverage and tightening
ambiguous regexes.

Design goals
------------
1) **Conservative defaults**: Prefer explicit shapes and/or provider prefixes.
2) **Context-aware where possible**: Require surrounding keywords for noisy
   credentials (e.g., passwords) to limit false positives.
3) **Right-sized severities**: Highly sensitive materials (private keys,
   cloud provider secrets) are "critical"/"high"; URLs and generic candidates
   are "low"/"medium".
4) **Redaction defaults**: All rules redact by default unless noted.

You can extend at runtime by passing custom rules to your scanner or by
monkey-patching `load_rules()` to append additional `Rule` instances.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern, Optional, List

# ----------------------------- Datamodel -------------------------------------

@dataclass(frozen=True)
class Rule:
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
    """Compile with sane defaults (multiline by default)."""
    return re.compile(rx, flags)

# ----------------------------- Rules -----------------------------------------

def load_rules() -> List[Rule]:
    """
    Curated, conservative rules to keep false positives low *while*
    being more all-encompassing across common providers and secret types.
    """
    rules: List[Rule] = [
        # === Cloud / SCM tokens ===================================================
        Rule("AWS_ACCESS_KEY_ID", "AWS Access Key ID",
             _c(r"(?<![A-Z0-9])[A-Z0-9]{4}?(AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{12}(?![A-Z0-9])"),
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
             _c(r"(?i)(?:(?:twilio_)?auth[_-]?token\s*[:=]\s*)?\b[a-f0-9]{32}\b"),
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
             _c(r"sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9]{20,}"),
             "OpenAI API key.", "token", "OpenAI", "high", ["ai","openai","credential"]),

        Rule("AZURE_SAS", "Azure SAS Token",
             _c(r"(?i)se=\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}z&sp=[a-z]+&spr=https?&sv=\d{4}-\d{2}-\d{2}&sr=[a-z]+&sig=[a-z0-9%/+_=]+"),
             "Azure Shared Access Signature (SAS) query parameters.", "token", "Azure", "high", ["cloud","azure"]),

        Rule("FIREBASE_DB_URL", "Firebase Realtime Database URL",
             _c(r'https://[A-Za-z0-9-]+\.firebaseio\.com/[^\s"\'<>]+'),
             "Firebase Realtime Database URL.", "url", "Firebase", "low", ["google","firebase","url"]),

        Rule("SUPABASE_URL", "Supabase Project URL",
             _c(r"https://[a-z]{15,}\.supabase\.co\b"),
             "Supabase project URL.", "url", "Supabase", "low", ["supabase","url"]),
        Rule("SUPABASE_KEY", "Supabase Key (anon/service)",
             _c(r"(?i)SUPABASE_(ANON|SERVICE)_KEY\s*[:=]\s*(eyJ[\w.-]{10,})"),
             "Supabase anon/service JWT-like key.", "token", "Supabase", "high", ["supabase","jwt","credential"]),

        # === Keys & Certificates ==================================================
        Rule("PRIVATE_KEY", "Private Key Block",
             _c(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ED25519) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|EC|DSA|OPENSSH|PGP|ED25519) PRIVATE KEY-----"),
             "PEM private key material.", "key", None, "critical", ["pem","privatekey"]),
        Rule("GENERIC_PRIVATE_KEY", "Generic PEM Private Key",
             _c(r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----"),
             "Unlabeled PEM private key.", "key", None, "critical", ["pem","privatekey"]),

        Rule("CERTIFICATE", "X.509 Certificate",
             _c(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----"),
             "PEM certificate block.", "certificate", None, "low", ["pem","certificate"]),

        # === Database & Connection Strings =======================================
        Rule("POSTGRES_URI", "PostgreSQL Connection URI",
             _c(r"(?i)postgres(?:ql)?://[^\s:@/]+(?::[^\s@/]*)?@[^\s/:?#]+(?::\d+)?/[^\s?#]+"),
             "PostgreSQL URI with possible credentials.", "url", "PostgreSQL", "high", ["db","uri","credential"]),
        Rule("MYSQL_URI", "MySQL Connection URI",
             _c(r"(?i)mysql://[^\s:@/]+(?::[^\s@/]*)?@[^\s/:?#]+(?::\d+)?/[^\s?#]+"),
             "MySQL URI with possible credentials.", "url", "MySQL", "high", ["db","uri","credential"]),
        Rule("MONGODB_URI", "MongoDB Connection URI",
             _c(r"(?i)mongodb(?:\+srv)?://[^\s:@/]+(?::[^\s@/]*)?@[^\s/:?#]+(?::\d+)?/[^\s?#]+"),
             "MongoDB URI with possible credentials.", "url", "MongoDB", "high", ["db","uri","credential"]),
        Rule("REDIS_URI", "Redis Connection URI",
             _c(r"(?i)rediss?://(?::[^@\s]+@)?[^\s/:?#]+(?::\d+)?(?:/\d+)?"),
             "Redis URI with optional password.", "url", "Redis", "high", ["db","uri","credential"]),
        Rule("AMQP_URI", "AMQP/RabbitMQ URI",
             _c(r"(?i)amqps?://[^\s:@/]+(?::[^\s@/]*)?@[^\s/:?#]+(?::\d+)?/[^\s?#]*"),
             "AMQP URI with possible credentials.", "url", "RabbitMQ", "high", ["mq","uri","credential"]),

        Rule("BASIC_AUTH_IN_URL", "URL with Basic Auth Credentials",
             _c(r'https?://[^\s/:@]+:[^\s/@]+@[^\s"\'<>]+'),
             "URL embedding user:password@", "url", None, "high", ["url","basic-auth","credential"]),

        # === JWT & Bearer ========================================================
        Rule("JWT", "JSON Web Token",
             _c(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"),
             "Likely JWT token.", "token", None, "medium", ["jwt","token"]),

        Rule("AUTH_BEARER", "HTTP Authorization Bearer",
             _c(r"(?i)Authorization\s*:\s*Bearer\s+[A-Za-z0-9._-]{20,}"),
             "HTTP Authorization: Bearer <token> header.", "token", None, "medium", ["http","auth"]),

        # === URLs / Cloud endpoints =============================================
        Rule("URL_HTTP", "HTTP URL",
             _c(r"(?i)\bhttps?://[^\s\'\"<>]+"),
             "HTTP(S) URL.", "url", None, "low", ["url"]),
        # Veterans Affairs (va.gov) specific URLs/domains
        Rule("VA_GOV_URL", "VA.gov URL",
             _c(r"(?i)\bhttps?://(?:[A-Za-z0-9-]+\.)*va\.gov(?:/[^\s\'\"<>]*)?"),
             "Veterans Affairs (va.gov) URL.", "url", "VA", "low", ["va.gov","us-gov","url"]),
        Rule("VA_GOV_DOMAIN", "VA.gov Domain",
             _c(r"(?i)\b(?:[A-Za-z0-9-]+\.)*va\.gov\b"),
             "Veterans Affairs (va.gov) domain.", "url", "VA", "low", ["va.gov","us-gov","domain"]),
        Rule("CLOUD_ENDPOINT", "Cloud Endpoint URL",
             _c(r"(?i)\bhttps?://(?:[^/\s]+\.)?(?:amazonaws|azurewebsites|windows|cloudfront|googleapis|appspot|firebaseio|digitaloceanspaces|herokuapp|supabase|vercel|render)\.[^\s\'\"<>]+"),
             "Cloud service endpoint URL.", "url", None, "low", ["cloud","url"]),

        # === High-entropy generic candidates ====================================
        # This intentionally casts a wide net but remains filtered by the scanner
        # using additional heuristics (e.g., surrounding keywords or length).
        Rule("HIGH_ENTROPY", "High-Entropy Candidate",
             _c(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9/_-]{24,})"),
             "Generic high-entropy credential-like value.", "token", None, "medium", ["entropy","generic"]),

        # === Contextual username/password patterns ===============================
        Rule("PASSWORD_ASSIGN", "Password Assignment",
             _c(r"(?i)\b(pass|password|pwd|secret)\b\s*[:=]\s*([\S]{6,})"),
             "Inline password/secret assignment.", "password", None, "high", ["password","assignment"]),
        Rule("USERNAME_PASSWORD_PAIR", "Username/Password Pair",
             _c(r"(?i)\b(user(name)?|login)\b\s*[:=]\s*\S+\s*[;,\n]+\s*\b(pass|password|pwd)\b\s*[:=]\s*\S+"),
             "Adjacent username/password pair.", "credential", None, "high", ["password","username","pair"]),
    ]
    return rules

# Export a default for convenience
DEFAULT_RULES: List[Rule] = load_rules()
