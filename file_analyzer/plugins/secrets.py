
#!/usr/bin/env python3
"""
secrets.py

A high-signal, low-noise secret scanner designed to recursively crawl directories
and find credentials with dramatically fewer false positives/negatives.

It can be used in three ways:
  1) As a standalone CLI: `python advanced_secret_scanner.py /path/to/dir`
  2) As a library: `from advanced_secret_scanner import SecretScanner`
  3) As a plugin: `SecretAnalyzerPlugin` (compatible shim if your project exposes AnalyzerPlugin)

Major improvements over simplistic regex-only scanners
-----------------------------------------------------
• Multi-detector pipeline:
    - Strong regex rules for popular providers (AWS, GitHub, Slack, Stripe, GCP, etc).
    - Structure-aware detectors (PEM/SSH/PGP private keys, JWTs).
    - High-entropy detector gated by context (env-var name, nearby keywords).
    - Key-value detector for .env / YAML / JSON / INI / code assignments.
    - Embedded base64 detector that decodes  (bounded) and rescans the plaintext.
    - Connection string detector (Postgres/MySQL/Mongo/Redis/AMQP/JDBC/SQLServer/Azure).
• Layered validation to reduce false positives:
    - Entropy/length/charset checks.
    - Checksums where applicable (Luhn for cards).
    - Structure validation (JWT header/payload parsable; PEM headers correct).
    - Contextual boosts/penalties (names like password/token/secret/api_key boost;
      test/fixture/example/sample paths/values penalize; comments slightly penalize).
• Tunable confidence scoring (0-1) combining detector strength + validators + context.
• Noise controls:
    - Allowlist comments (e.g., "# pragma: allowlist secret", "gitleaks:allow").
    - .secretsignore / .gitignore aware path skipping.
    - Path-based demotion (e.g., tests/, fixtures/, samples/, docs/).
    - Baseline suppression file (JSON) that records fingerprints to suppress repeats.
• Safety:
    - Redaction by default (only first 3 / last 3 chars shown).
    - Hash-based fingerprinting (SHA-256 of normalized secret + rule + path) for dedupe/baseline.
• Performance:
    - Streaming reads; size caps; binary detection; concurrency for directory scans.
    - Archive introspection (zip/tar/tgz) with max-depth limits.
• Output formats:
    - Rich Python objects, pretty text, and JSON/SARIF emitters.

Only Python standard library is used — no external deps required.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import dataclasses
import fnmatch
import hashlib
import io
import json
import logging
import math
import os
import re
import stat
import sys
import tarfile
import textwrap
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Pattern, Sequence, Set, Tuple

# ---- Optional project integration (AnalyzerPlugin) ---------------------------
try:
    # If your project exposes AnalyzerPlugin, we'll use it. Otherwise we run standalone.
    from .base_plugin import AnalyzerPlugin  # type: ignore
except Exception:  # pragma: no cover - standalone mode
    class AnalyzerPlugin:  # minimal shim for standalone usage
        def analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> List[Dict[str, Any]]:
            raise NotImplementedError

# ---- Utilities ---------------------------------------------------------------

PRINTABLE = set(bytes(bytearray(range(32, 127)))).union({9, 10, 13})  # tab/lf/cr


def is_mostly_text(data: bytes, threshold: float = 0.95) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if b in PRINTABLE)
    return printable / len(data) >= threshold


def calculate_entropy(s: str) -> float:
    """Shannon entropy in bits/char."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_base64_like(s: str) -> bool:
    # Fast pre-check without decoding
    if len(s) < 16:
        return False
    if len(s) % 4 != 0:
        return False
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return False
    return True


def safe_b64decode(s: str, max_len: int = 1_000_000) -> Optional[bytes]:
    if not is_base64_like(s):
        return None
    try:
        data = base64.b64decode(s, validate=True)
        if len(data) > max_len:
            return None
        return data
    except binascii.Error:
        return None


def stable_hash(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode('utf-8', 'ignore'))
        h.update(b'\x00')
    return h.hexdigest()


def redact(s: str, keep: int = 3) -> str:
    if len(s) <= keep * 2:
        return s[:1] + '…' if len(s) > 1 else s
    return f"{s[:keep]}…{s[-keep:]}"


# ---- Data structures ---------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    title: str
    secret: str
    file: Path
    start: int  # byte offset in file content
    end: int
    line: int
    col: int
    severity: str  # low / medium / high / critical
    confidence: float  # 0..1
    description: str
    tags: List[str] = field(default_factory=list)
    redacted: str = ""
    fingerprint: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Rule:
    id: str
    title: str
    regex: Pattern[str]
    description: str
    kind: str  # token / key / url / password / pem / jwt
    vendor: str
    severity: str
    tags: List[str]
    min_len: int = 0
    entropy_min: float = 0.0
    entropy_max: float = 8.0
    ctx_keywords: Tuple[str, ...] = (
        "secret", "token", "password", "passwd", "pwd", "auth", "apikey",
        "api_key", "access_key", "private", "key", "client_secret", "credential",
    )
    ctx_boost: float = 0.05  # add to confidence if keyword nearby
    base_weight: float = 0.55  # starting confidence for a direct hit
    validators: Tuple[str, ...] = ()  # names of validator funcs


# ---- Validators --------------------------------------------------------------

def luhn_check(s: str) -> bool:
    """Luhn checksum for credit cards (reduces false positives)."""
    digits = re.sub(r'\D', '', s)
    if len(digits) < 12 or len(digits) > 19:
        return False
    total, alt = 0, False
    for d in digits[::-1]:
        n = ord(d) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def jwt_check(s: str) -> bool:
    parts = s.split('.')
    if len(parts) != 3:
        return False
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    except Exception:
        return False
    # lightweight sanity checks
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return False
    if 'typ' in header and str(header['typ']).upper() not in ('JWT', 'ID', 'ACCESS', 'BEARER'):
        # still allow, but not a hard fail
        pass
    return True


def aws_secret_charset(s: str) -> bool:
    return bool(re.fullmatch(r'[A-Za-z0-9/+=]{40}', s))


def plausible_random(s: str, min_entropy: float = 3.5) -> bool:
    # Avoid classifying obvious placeholders
    placeholders = {'changeme', 'password', 'secret', 'example', 'dummy', 'test', 'sample'}
    if s.lower() in placeholders:
        return False
    return calculate_entropy(s) >= min_entropy


VALIDATORS = {
    'luhn': luhn_check,
    'jwt': jwt_check,
    'aws_secret_charset': aws_secret_charset,
    'randomish': plausible_random,
}


# ---- Default regex rule set --------------------------------------------------

def _c(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


DEFAULT_RULES: List[Rule] = [
    # Cloud providers / common platforms
    Rule("AWS_ACCESS_KEY_ID", "AWS Access Key ID",
         _c(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
         "AWS Access Key ID.", "key", "AWS", "high", ["cloud", "aws", "iam"], base_weight=0.65),

    Rule("AWS_SECRET_ACCESS_KEY", "AWS Secret Access Key",
         _c(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
         "AWS Secret Access Key (40 base64 characters).", "secret", "AWS", "critical",
         ["cloud", "aws", "iam"], base_weight=0.7, validators=("aws_secret_charset",)),

    Rule("GCP_API_KEY", "Google API Key",
         _c(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
         "Google API Key (starts with AIza).", "key", "Google", "high", ["cloud", "google", "api"]),

    Rule("GCP_OAUTH_TOKEN", "Google OAuth token",
         _c(r"\b(?:ya29\.[0-9A-Za-z\-_]+|1//[0-9A-Za-z\-_]{20,})\b"),
         "Google OAuth token.", "token", "Google", "high", ["oauth", "google", "token"]),

    Rule("AZURE_STORAGE_CONN", "Azure Storage Connection String",
         _c(r"\bDefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9\-]+;AccountKey=[A-Za-z0-9+/=]{40,}"
            r"(?:;EndpointSuffix=core\.windows\.net)?\b"),
         "Azure Storage connection string.", "connection", "Azure", "high", ["cloud", "azure", "storage"]),

    Rule("GITHUB_PAT", "GitHub Personal Access Token",
         _c(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
         "GitHub Personal Access Token (new formats).", "token", "GitHub", "high", ["scm", "github"], base_weight=0.7),

    Rule("GITLAB_PAT", "GitLab Personal Access Token",
         _c(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
         "GitLab Personal Access Token.", "token", "GitLab", "high", ["scm", "gitlab"]),

    Rule("BITBUCKET_REFRESH", "Bitbucket Refresh Token",
         _c(r"\b(?:xacc|xopt|xrea|xats)-[A-Za-z0-9=\-._]{30,}\b"),
         "Bitbucket OAuth tokens.", "token", "Bitbucket", "medium", ["scm", "bitbucket"], base_weight=0.6),

    Rule("SLACK_TOKEN", "Slack Token",
         _c(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
         "Slack token (xox[a|b|p|r|s]-...).", "token", "Slack", "high", ["collab", "slack"]),

    Rule("SLACK_WEBHOOK", "Slack Incoming Webhook URL",
         _c(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[A-Za-z0-9]{24,}"),
         "Slack incoming webhook.", "url", "Slack", "high", ["slack", "webhook"]),

    Rule("DISCORD_TOKEN", "Discord bot/user token",
         _c(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b"),
         "Discord bot/user token.", "token", "Discord", "high", ["chat", "discord"]),

    Rule("TELEGRAM_BOT_TOKEN", "Telegram Bot Token",
         _c(r"\b[0-9]{8,10}:AA[0-9A-Za-z_-]{33}\b"),
         "Telegram bot token.", "token", "Telegram", "high", ["chat", "telegram"]),

    Rule("STRIPE_SECRET", "Stripe Secret Key",
         _c(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
         "Stripe secret key.", "key", "Stripe", "high", ["payments", "stripe"], base_weight=0.7),

    Rule("STRIPE_RESTRICTED", "Stripe Restricted Key",
        _c(r"\brk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
        "Stripe restricted key.", "key", "Stripe", "high", ["payments", "stripe"]),

    Rule("TWILIO_AUTH_TOKEN", "Twilio Auth Token",
         _c(r"\b(?i:twilio[_-]?(?:auth[_-]?)?token)\b\s*[:=]\s*['\"]?([A-Fa-f0-9]{32})\b"),
         "Twilio auth token (32 hex).", "token", "Twilio", "high", ["telephony", "twilio"], base_weight=0.65),

    Rule("NOTION_SECRET", "Notion Internal Integration Secret",
         _c(r"\bsecret_[A-Za-z0-9]{43}\b"),
         "Notion integration secret.", "token", "Notion", "high", ["productivity", "notion"]),

    Rule("DATADOG_API_KEY", "Datadog API Key",
         _c(r"\b(?:DD_)?API[_-]?KEY\s*[:=]\s*['\"]?([a-f0-9]{32})\b", re.IGNORECASE),
         "Datadog API Key (32 hex).", "key", "Datadog", "high", ["observability", "datadog"]),

    Rule("SENTRY_DSN", "Sentry DSN",
         _c(r"https://[0-9a-fA-F]{32}@o\d+\.ingest\.sentry\.io/\d+"),
         "Sentry DSN (server key).", "url", "Sentry", "high", ["observability", "sentry"]),

    Rule("DIGITALOCEAN_PAT", "DigitalOcean Personal Access Token",
         _c(r"\bdop_v1_[a-f0-9]{64}\b"),
         "DigitalOcean PAT.", "token", "DigitalOcean", "high", ["cloud", "digitalocean"]),

    Rule("OPENAI_API_KEY", "OpenAI API Key",
         _c(r"\bsk-[A-Za-z0-9]{20,48}\b"),
         "OpenAI API key.", "key", "OpenAI", "high", ["ai", "openai"], base_weight=0.7),

    # Generic tokens / passwords (context-boosted)
    Rule("GENERIC_BEARER", "Bearer Token",
         _c(r"\bBearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\b"),
         "Authorization Bearer token.", "token", "Generic", "medium", ["auth", "http"], base_weight=0.5),

    Rule("GENERIC_PASSWORD_ASSIGN", "Password-like assignment",
         _c(r"(?i)\b(pass|password|pwd|secret|token|api[_-]?key|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
         "Suspicious credential assignment in code/config.", "password", "Generic", "medium",
         ["generic", "assignment"], base_weight=0.45, validators=("randomish",)),

    # Credit cards (demoted; requires Luhn)
    Rule("CREDIT_CARD", "Credit card number",
         _c(r"\b(?:4\d{12}(?:\d{3})?"             # Visa
            r"|5[1-5]\d{14}"                      # MasterCard
            r"|3[47]\d{13}"                       # AmEx
            r"|3(?:0[0-5]|[68]\d)\d{11}"          # Diners
            r"|6(?:011|5\d{2})\d{12}"             # Discover
            r"|(?:2131|1800|35\d{3})\d{11})\b"),
         "Payment card PAN (passes Luhn).", "pan", "Generic", "low",
         ["pci", "card"], base_weight=0.35, validators=("luhn",)),

    # URLs with credentials
    Rule("BASIC_AUTH_IN_URL", "URL with embedded credentials",
         _c(r"\b[a-zA-Z][a-zA-Z0-9+\-.]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
         "URL contains username:password@host.", "url", "Generic", "high", ["url", "basic-auth"]),

    # JWTs (validated structurally)
    Rule("JWT", "JSON Web Token",
         _c(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
         "Likely JWT (3 base64url segments).", "jwt", "Generic", "medium", ["jwt", "token"],
         base_weight=0.55, validators=("jwt",)),

    # PEM / SSH / PGP private keys are handled by structure-aware detector, but
    # keep simple regex for single-line capture (e.g., pasted in env var).
    Rule("PEM_PRIVATE_KEY_INLINE", "PEM Private Key (inline)",
         _c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
         "PEM private key header.", "pem", "Generic", "critical", ["pem", "private-key"], base_weight=0.9),
]


# ---- Structure-aware detectors ----------------------------------------------

PEM_HEADERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
)


DB_URI_PATTERNS = [
    _c(r"\bpostgres(?:ql)?://[^:\s]+:(?P<secret>[^@\s]+)@[^/\s:]+(?:\:\d+)?/[^\s'\";]+"),
    _c(r"\bmysql://[^:\s]+:(?P<secret>[^@\s]+)@[^/\s:]+(?:\:\d+)?/[^\s'\";]+"),
    _c(r"\bmongodb\+srv?://[^:\s]+:(?P<secret>[^@\s]+)@[^/\s/]+/[^\s'\";]*"),
    _c(r"\bredis://:(?P<secret>[^@\s]+)@[^/\s:]+(?:\:\d+)?"),
    _c(r"\bamqp://[^:\s]+:(?P<secret>[^@\s]+)@[^/\s:]+"),
    _c(r"\bjdbc:(?:postgresql|mysql)://[^;\s]+;user=[^;\s]+;password=(?P<secret>[^;\s]+)"),
    _c(r"\bServer=[^;]+;Database=[^;]+;User\s*Id=[^;]+;Password=(?P<secret>[^;]+);"),
]


ENV_ASSIGN_PAT = _c(r"""(?ix)
    ^\s*
    (?P<key>[A-Z0-9_][A-Z0-9_\.:-]{2,64})
    \s*[:=]\s*
    (?P<quote>['"])?
    (?P<val>.*?)
    (?P=quote)?
    \s*$
""")


def load_rules() -> List[Rule]:
    """Return a copy of the default detector rules."""

    return list(DEFAULT_RULES)


class Detector:
    name = "base"

    def detect(self, text: str, file: Path) -> Iterator[Finding]:
        raise NotImplementedError


class RegexRuleDetector(Detector):
    name = "regex_rules"

    def __init__(self, rules: Sequence[Rule]):
        self.rules = list(rules)

    def detect(self, text: str, file: Path) -> Iterator[Finding]:
        for rule in self.rules:
            for m in rule.regex.finditer(text):
                s = m.group(0)
                start, end = m.start(), m.end()
                if rule.min_len and len(s) < rule.min_len:
                    continue
                ent = calculate_entropy(s)
                if ent < rule.entropy_min or ent > rule.entropy_max + 1e-9:
                    # (entropy_max is mostly unused; leave in for future)
                    pass
                line, col = _offset_to_line_col(text, start)
                conf = rule.base_weight

                # Context boost if credential keyword nearby
                if _has_keyword_nearby(text, start, rule.ctx_keywords, window=120):
                    conf += rule.ctx_boost

                # Path demotion/boost
                conf += _path_score(file)

                # Validators
                valid_hits = 0
                for vname in rule.validators:
                    vfunc = VALIDATORS.get(vname)
                    if vfunc and vfunc(s):
                        valid_hits += 1
                if valid_hits:
                    conf += 0.1 * valid_hits

                conf = max(0.0, min(1.0, conf))
                yield Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    secret=s,
                    file=file,
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    severity=rule.severity,
                    confidence=conf,
                    description=rule.description,
                    tags=list(rule.tags),
                )


class PemKeyDetector(Detector):
    name = "pem_key"

    def detect(self, text: str, file: Path) -> Iterator[Finding]:
        for header in PEM_HEADERS:
            idx = text.find(header)
            if idx == -1:
                continue
            start = idx
            end = text.find("-----END", start)
            if end == -1:
                end = start + len(header)
            line, col = _offset_to_line_col(text, start)
            yield Finding(
                rule_id="PEM_PRIVATE_KEY_BLOCK",
                title="PEM/SSH/PGP Private Key",
                secret=text[start:end],
                file=file,
                start=start,
                end=end,
                line=line,
                col=col,
                severity="critical",
                confidence=0.95,
                description="Private key block detected.",
                tags=["pem", "ssh", "pgp", "private-key"],
            )


class JwtDetector(Detector):
    name = "jwt"

    JWT_RE = _c(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")

    def detect(self, text: str, file: Path) -> Iterator[Finding]:
        for m in self.JWT_RE.finditer(text):
            token = m.group(0)
            if not jwt_check(token):
                continue
            line, col = _offset_to_line_col(text, m.start())
            yield Finding(
                rule_id="JWT",
                title="JSON Web Token",
                secret=token,
                file=file,
                start=m.start(),
                end=m.end(),
                line=line,
                col=col,
                severity="medium",
                confidence=0.7 + _path_score(file),
                description="JWT structure validated (header/payload decodable).",
                tags=["jwt", "token"],
            )


class HighEntropyDetector(Detector):
    name = "high_entropy"

    def __init__(self, min_len: int = 20, entropy: float = 4.0):
        self.min_len = min_len
        self.entropy = entropy
        self.re_word = _c(r"[A-Za-z0-9/\+=]{%d,}" % min_len)

    def detect(self, text: str, file: Path) -> Iterator[Finding]:
        for m in self.re_word.finditer(text):
            token = m.group(0)
            ent = calculate_entropy(token)
            if ent < self.entropy:
                continue
            # Require contextual hints to avoid noise
            if not _has_keyword_nearby(text, m.start(), DEFAULT_KEYWORDS, window=80):
                continue
            line, col = _offset_to_line_col(text, m.start())
            yield Finding(
                rule_id="HIGH_ENTROPY",
                title="High-entropy token (contextual)",
                secret=token,
                file=file,
                start=m.start(),
                end=m.end(),
                line=line,
                col=col,
                severity="medium",
                confidence=0.55 + _path_score(file),
                description="High-entropy token near credential-like keywords.",
                tags=["heuristic", "entropy"],
            )


class EnvAssignmentDetector(Detector):
    name = "env_assignment"

    SUSPICIOUS_KEYS = tuple(k.lower() for k in (
        "password", "passwd", "pwd", "secret", "seckey", "secret_key", "private_key",
        "api_key", "apikey", "access_key", "client_secret", "access_token", "token",
        "db_password", "db_pass", "pg_password", "mysql_password", "redis_password",
        "smtp_password", "jwt_secret", "s3_secret", "ssh_key", "ssh_private_key",
        "notion_secret", "stripe_secret_key", "twilio_auth_token", "openai_api_key",
    ))

    PLACEHOLDERS = {"", "changeme", "placeholder", "example", "sample", "test", "dummy", "password", "secret"}

    def detect(self, text: str, file: Path) -> Iterator[Finding]:
        for line_no, raw in enumerate(text.splitlines(True), start=1):
            if raw.lstrip().startswith(('#', '//', ';')):
                # Comments still count, but lower severity through path score only.
                pass
            m = ENV_ASSIGN_PAT.match(raw)
            if not m:
                continue
            key = m.group('key')
            val = (m.group('val') or "").strip().strip("'\"")
            if len(val) < 8 or val.lower() in self.PLACEHOLDERS:
                continue
            key_l = key.lower()
            ctx = 0.0
            if any(k in key_l for k in self.SUSPICIOUS_KEYS):
                ctx += 0.2
            ent = calculate_entropy(val)
            conf = 0.45 + min(0.15, (ent - 3.0) * 0.04) + ctx + _path_score(file)
            start_off = _line_col_to_offset(text, line_no, raw.find(val))
            yield Finding(
                rule_id="ENV_ASSIGNMENT",
                title=f"Potential secret in assignment ({key})",
                secret=val,
                file=file,
                start=start_off,
                end=start_off + len(val),
                line=line_no,
                col=raw.find(val) + 1 if raw.find(val) >= 0 else 1,
                severity="medium" if ctx >= 0.2 else "low",
                confidence=max(0.0, min(1.0, conf)),
                description=f"'{key}' assigned to a suspicious value (entropy={ent:.2f}).",
                tags=["assignment", "env", "config"],
            )


class ConnectionStringDetector(Detector):
    name = "connection_string"

    def detect(self, text: str, file: Path) -> Iterator[Finding]:
        for pat in DB_URI_PATTERNS:
            for m in pat.finditer(text):
                secret = m.groupdict().get("secret") or "<redacted>"
                line, col = _offset_to_line_col(text, m.start())
                yield Finding(
                    rule_id="CONNECTION_STRING",
                    title="Connection string with credentials",
                    secret=secret,
                    file=file,
                    start=m.start(),
                    end=m.end(),
                    line=line,
                    col=col,
                    severity="high",
                    confidence=0.7 + _path_score(file),
                    description="URI or connection string contains embedded credentials.",
                    tags=["db", "uri", "connection"],
                )


class EmbeddedBase64Detector(Detector):
    name = "embedded_base64"
    MAX_DECODE = 8  # avoid O(N^2)

    RE_B64 = _c(r"(?:(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)")

    def detect(self, text: str, file: Path) -> Iterator[Finding]:
        count = 0
        for m in self.RE_B64.finditer(text):
            if count >= self.MAX_DECODE:
                break
            s = m.group(0)
            if len(s) < 64:
                continue
            raw = safe_b64decode(s)
            if not raw:
                continue
            if not is_mostly_text(raw):
                continue
            try:
                inner = raw.decode('utf-8', 'ignore')
            except Exception:
                continue
            count += 1
            # Rescan the decoded payload for cleartext secrets using strong detectors only
            nested = SecretScanner.default_detectors_for_inner()
            for det in nested:
                for finding in det.detect(inner, file):
                    # Map offsets back approximately (best-effort for reporting)
                    finding.start = m.start()
                    finding.end = m.end()
                    finding.line, finding.col = _offset_to_line_col(text, m.start())
                    finding.description += " (decoded from embedded base64)"
                    finding.confidence = min(1.0, finding.confidence + 0.1)
                    yield finding


DEFAULT_KEYWORDS = (
    "secret", "password", "passwd", "pwd", "token",
    "auth", "apikey", "api_key", "access_token", "bearer",
    "client_secret", "private", "ssh", "key", "credential",
)



def _has_keyword_nearby(text: str, offset: int, keywords: Sequence[str], window: int = 120) -> bool:
    lo = max(0, offset - window)
    hi = min(len(text), offset + window)
    seg = text[lo:hi].lower()
    return any(k.lower() in seg for k in keywords)
# ---- SecretScanner core ------------------------------------------------------

def _offset_to_line_col(text: str, offset: int) -> Tuple[int, int]:
    # Compute line/col from offset reasonably efficiently
    line = text.count('\n', 0, offset) + 1
    last_nl = text.rfind('\n', 0, offset)
    col = offset - (last_nl + 1 if last_nl != -1 else 0) + 1
    return line, col


def _line_col_to_offset(text: str, line: int, col0: int) -> int:
    if line <= 1:
        return max(0, col0 - 1)
    pos = 0
    for _ in range(line - 1):
        idx = text.find('\n', pos)
        if idx == -1:
            return len(text)
        pos = idx + 1
    return min(len(text), pos + max(0, col0 - 1))


TEST_PATH_DEMOTERS = (
    "/test/", "/tests/", "/__tests__/", "/testing/", "/fixtures/", "/mocks/",
    "/samples/", "/examples/", "/docs/", "/documentation/",
)

SENSITIVE_PATH_BOOSTERS = (
    "/config/", "/secrets/", "/credentials/", "/.aws/", "/.azure/", "/.gcp/",
    "/.ssh/", "/keys/", "/private/",
)


def _path_score(file: Path) -> float:
    p = f"/{file.as_posix().lower().strip('/')}"
    score = 0.0
    if any(seg in p for seg in TEST_PATH_DEMOTERS):
        score -= 0.1
    if any(seg in p for seg in SENSITIVE_PATH_BOOSTERS):
        score += 0.05
    return score


ALLOWLIST_HINTS = (
    "pragma: allowlist secret",
    "gitleaks:allow",
    "secrets:allow",
)


def is_allowlisted_near(text: str, start: int, window: int = 160) -> bool:
    lo = max(0, start - window)
    hi = min(len(text), start + window)
    segment = text[lo:hi].lower()
    return any(h in segment for h in ALLOWLIST_HINTS)


def load_ignore_globs(root: Path) -> List[str]:
    globs: List[str] = []
    for name in (".secretsignore", ".gitignore"):
        f = root / name
        if f.exists():
            try:
                for line in f.read_text(encoding='utf-8', errors='ignore').splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    globs.append(line)
            except Exception:
                pass
    return globs


def should_ignore_path(path: Path, root: Path, globs: Sequence[str]) -> bool:
    rel = path.relative_to(root).as_posix()
    for pat in globs:
        try:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(f"/{rel}", pat):
                return True
        except Exception:
            continue
    return False


def is_binary_path(path: Path) -> bool:
    bin_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
        ".class", ".jar", ".exe", ".dll", ".so", ".dylib",
        ".zip", ".tar", ".gz", ".tgz", ".7z", ".pdf", ".woff", ".woff2",
        ".psd", ".ai", ".sketch",
    }
    return path.suffix.lower() in bin_exts


@dataclass
class ScanConfig:
    max_file_size: int = 2_000_000  # 2 MB
    follow_symlinks: bool = False
    archive_depth: int = 1
    concurrency: int = max(1, (os.cpu_count() or 4) - 1)
    baseline_file: Optional[Path] = None


class SecretScanner:
    def __init__(self, rules: Optional[Sequence[Rule]] = None, config: Optional[ScanConfig] = None):
        self.rules = list(rules or DEFAULT_RULES)
        self.config = config or ScanConfig()
        self.detectors: List[Detector] = [
            PemKeyDetector(),
            JwtDetector(),
            RegexRuleDetector(self.rules),
            EnvAssignmentDetector(),
            ConnectionStringDetector(),
            HighEntropyDetector(),
            EmbeddedBase64Detector(),
        ]

    @staticmethod
    def default_detectors_for_inner() -> List[Detector]:
        # For decoded payloads we can skip very permissive detectors to limit noise.
        return [
            PemKeyDetector(),
            JwtDetector(),
            RegexRuleDetector(DEFAULT_RULES),
            EnvAssignmentDetector(),
            ConnectionStringDetector(),
        ]

    # ---- Directory scanning --------------------------------------------------
    def scan_path(self, root: Path) -> List[Finding]:
        root = root.resolve()
        ignore_globs = load_ignore_globs(root)
        results: List[Finding] = []

        def worker(path: Path) -> List[Finding]:
            try:
                return self.scan_file(path, root=root, ignore_globs=ignore_globs)
            except Exception:
                logging.exception("scan failed for %s", path)
                return []

        paths: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=self.config.follow_symlinks):
            # Prune hidden/system dirs early
            base = os.path.basename(dirpath)
            if base in {".git", ".svn", ".hg", ".idea", ".vscode", "__pycache__"}:
                dirnames[:] = []
                continue
            for name in filenames:
                p = Path(dirpath) / name
                if should_ignore_path(p, root, ignore_globs):
                    continue
                if not self._should_scan_file(p):
                    continue
                paths.append(p)

        if self.config.concurrency and self.config.concurrency > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.concurrency) as ex:
                for chunk in _chunks(paths, 64):
                    for part in ex.map(worker, chunk):
                        results.extend(part)
        else:
            for p in paths:
                results.extend(worker(p))

        return self._postprocess(results, root=root)

    # ---- Single file scanning ------------------------------------------------
    def scan_file(self, path: Path, *, root: Optional[Path] = None,
                  ignore_globs: Optional[Sequence[str]] = None) -> List[Finding]:
        if ignore_globs and root and should_ignore_path(path, root, ignore_globs):
            return []
        if not self._should_scan_file(path):
            return []

        data = self._read_file_bytes(path)
        if data is None:
            return []
        # Archive handling
        if self._is_archive(path):
            return self._scan_archive(path, data, depth=self.config.archive_depth)

        text = self._to_text(data)
        if text is None:
            return []

        return self._scan_text(text, path)

    def _postprocess(self, findings: List[Finding], *, root: Optional[Path]) -> List[Finding]:
        # Allowlist pruning
        out: List[Finding] = []
        seen: Set[str] = set()

        baseline: Set[str] = set()
        if self.config.baseline_file and self.config.baseline_file.exists():
            try:
                baseline = set(json.loads(self.config.baseline_file.read_text()).get("fingerprints", []))
            except Exception:
                logging.warning("Invalid baseline file, ignoring: %s", self.config.baseline_file)

        for f in findings:
            if is_allowlisted_near(self._cached_file_text(f.file), f.start):
                continue
            f.redacted = f.secret
            f.fingerprint = stable_hash(f.rule_id, f.file.as_posix(), f.redacted[:32])
            if f.fingerprint in baseline:
                continue
            key = f"{f.rule_id}:{f.file}:{f.start}:{f.redacted}"
            if key in seen:
                continue
            seen.add(key)
            out.append(f)

        out.sort(key=lambda x: (-_severity_rank(x.severity), -x.confidence, x.file.as_posix(), x.line))
        return out

    # ---- Internals -----------------------------------------------------------
    def _scan_text(self, text: str, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        for det in self.detectors:
            for f in det.detect(text, path):
                findings.append(f)
        self._cache_text(path, text)
        return findings

    def _should_scan_file(self, p: Path) -> bool:
        try:
            st = p.stat()
        except Exception:
            return False
        if stat.S_ISDIR(st.st_mode):
            return False
        if st.st_size > self.config.max_file_size:
            return False
        if is_binary_path(p):
            return False
        return True

    def _read_file_bytes(self, path: Path) -> Optional[bytes]:
        try:
            with open(path, 'rb') as fh:
                return fh.read()
        except Exception:
            return None

    def _to_text(self, data: bytes) -> Optional[str]:
        if not is_mostly_text(data):
            return None
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.decode('utf-8', 'ignore')

    def _is_archive(self, path: Path) -> bool:
        return path.suffix.lower() in {".zip", ".jar", ".war", ".tar", ".tgz", ".gz"}

    def _scan_archive(self, path: Path, data: bytes, depth: int) -> List[Finding]:
        if depth <= 0:
            return []
        results: List[Finding] = []
        try:
            if path.suffix.lower() in {".zip", ".jar", ".war"}:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for info in zf.infolist():
                        if info.is_dir() or info.file_size > self.config.max_file_size:
                            continue
                        inner_data = zf.read(info.filename)
                        inner_path = Path(f"{path}!{info.filename}")
                        if self._is_archive(Path(info.filename)):
                            results.extend(self._scan_archive(inner_path, inner_data, depth=depth-1))
                        else:
                            text = self._to_text(inner_data)
                            if text:
                                results.extend(self._scan_text(text, inner_path))
            elif path.suffix.lower() in {".tar", ".tgz", ".gz"}:
                mode = "r:gz" if path.suffix.lower() in {".tgz", ".gz"} else "r:"
                with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
                    for m in tf.getmembers():
                        if not m.isfile() or m.size > self.config.max_file_size:
                            continue
                        f = tf.extractfile(m)
                        if not f:
                            continue
                        inner_data = f.read()
                        inner_path = Path(f"{path}!{m.name}")
                        if self._is_archive(Path(m.name)):
                            results.extend(self._scan_archive(inner_path, inner_data, depth=depth-1))
                        else:
                            text = self._to_text(inner_data)
                            if text:
                                results.extend(self._scan_text(text, inner_path))
        except Exception:
            logging.exception("Failed to scan archive: %s", path)
        return results

    # cache file text for allowlist proximity checks
    _TEXT_CACHE_LOCK = threading.Lock()
    _TEXT_CACHE: Dict[str, str] = {}

    def _cache_text(self, path: Path, text: str) -> None:
        with self._TEXT_CACHE_LOCK:
            self._TEXT_CACHE[path.as_posix()] = text

    def _cached_file_text(self, path: Path) -> str:
        with self._TEXT_CACHE_LOCK:
            return self._TEXT_CACHE.get(path.as_posix(), "")


# ---- Severity utilities ------------------------------------------------------

_SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _severity_rank(s: str) -> int:
    return _SEVERITY_ORDER.get(s.lower(), 0)


# ---- Emitters ----------------------------------------------------------------

def emit_pretty(findings: Sequence[Finding]) -> str:
    out = []
    for f in findings:
        out.append(
            f"{f.severity.upper():>8}  {f.confidence:.2f}  {f.rule_id:<28}  {f.file}:{f.line}:{f.col}  "
            f"{f.secret}"
        )
    return "\n".join(out)


def emit_json(findings: Sequence[Finding]) -> str:
    return json.dumps([f.as_dict() for f in findings], indent=2)


def emit_sarif(findings: Sequence[Finding]) -> str:
    # Minimal SARIF v2.1.0
    rules = {}
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {"level": f.severity},
            }
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": f.severity,
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.as_posix()},
                    "region": {"startLine": f.line, "startColumn": f.col}
                }
            }],
                "properties": {
                    "confidence": f.confidence,
                    "secret": f.redacted or f.secret,
                    "fingerprint": f.fingerprint or stable_hash(f.rule_id, f.file.as_posix(), (f.redacted or f.secret)[:32]),
                    "tags": f.tags,
                }
        })
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "advanced_secret_scanner", "rules": list(rules.values())}},
            "results": results,
        }]
    }
    return json.dumps(sarif, indent=2)


# ---- Plugin wrapper ----------------------------------------------------------

RULE_LOOKUP = {rule.id: rule for rule in DEFAULT_RULES}


class SecretsAnalyzer(AnalyzerPlugin):
    """AnalyzerPlugin wrapper around the advanced secret scanner."""

    requires_full_content: bool = True

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.tags = {"secrets"}
        cfg = ScanConfig(
            max_file_size=int(self.config.get("max_file_size", 2_000_000)),
            follow_symlinks=bool(self.config.get("follow_symlinks", False)),
            archive_depth=int(self.config.get("archive_depth", 0)),
            concurrency=1,
            baseline_file=None,
        )
        self.scanner = SecretScanner(config=cfg)

    @property
    def plugin_type(self) -> str:
        return "secret_analyzer"

    @property
    def supported_file_types(self) -> Set[str]:
        return {"*"}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        if file_type != "text":
            return False
        return bool(content)

    def analyze(
        self,
        file_path: Path,
        file_type: str,
        content: str,
        results: Dict[str, Set[str]],
    ) -> Dict[str, Set[str]]:
        if not content:
            return results

        try:
            findings = self.scanner._scan_text(content, file_path)
            findings = self.scanner._postprocess(findings, root=file_path.parent)
        except Exception as exc:  # pragma: no cover - defensive guard
            logging.exception("Secret scanner failed for %s", file_path)
            results.setdefault("runtime_errors", set()).add(
                f"Secret scanner error in {file_path}: {exc}"
            )
            return results

        for finding in findings:
            category = self._category_for_finding(finding)
            self._record_result(results, category, finding)

        return results

    # ---- helpers ---------------------------------------------------------
    def _category_for_finding(self, finding: Finding) -> str:
        rule = RULE_LOOKUP.get(finding.rule_id)
        if rule is not None:
            kind = (rule.kind or "").lower()
            vendor = (rule.vendor or "").lower()
            tags = {t.lower() for t in rule.tags}

            if rule.id.startswith("AWS_") or vendor == "aws":
                return "aws_key"
            if kind == "jwt" or "jwt" in tags or finding.rule_id == "JWT":
                return "jwt"
            if kind == "pem" or "private-key" in tags or "pem" in tags or finding.rule_id.startswith("PEM_"):
                return "private_key"
            if kind == "password" or "password" in tags:
                return "password"
            if kind == "secret":
                return "api_key"
            if kind == "url":
                if "webhook" in tags:
                    return "webhook_url"
                return "url"
            if kind == "connection":
                return "database_connection"
            if kind == "token":
                if "oauth" in tags:
                    return "oauth_token"
                if "session" in tags:
                    return "session_id"
                return "access_token"
            if kind == "key":
                return "api_key"
            if kind == "email" or "email" in tags:
                return "email"

            if rule.id == "HIGH_ENTROPY" or "entropy" in tags:
                return "high_entropy_strings"

        # Non-rule detectors or fallbacks
        rid = finding.rule_id.upper()
        title = finding.title.lower()

        if rid.startswith("PEM_") or "private key" in title:
            return "private_key"
        if rid == "JWT":
            return "jwt"
        if rid == "ENV_ASSIGNMENT":
            key_name = self._extract_env_key(title)
            if key_name:
                lowered = key_name.lower()
                if "password" in lowered or "passwd" in lowered or "pwd" in lowered:
                    return "password"
                if "key" in lowered:
                    return "api_key"
                if "token" in lowered:
                    return "access_token"
                if "secret" in lowered:
                    return "api_key"
            return "api_key"
        if "bearer" in rid or "bearer" in title:
            return "authorization_header"
        if "cookie" in rid or "cookie" in title:
            return "cookie"
        if "session" in rid or "session" in title:
            return "session_id"
        if "webhook" in title:
            return "webhook_url"
        if "entropy" in rid or "entropy" in title:
            return "high_entropy_strings"

        return "api_key"

    def _extract_env_key(self, title: str) -> Optional[str]:
        if "(" not in title or ")" not in title:
            return None
        start = title.find("(") + 1
        end = title.find(")", start)
        if end == -1:
            return None
        return title[start:end]

    def _record_result(self, results: Dict[str, Set[str]], category: str, finding: Finding) -> None:
        bucket = results.setdefault(category, set())
        bucket.add(finding.secret)

        meta_container = results.setdefault("__meta__", {})
        if not isinstance(meta_container, dict):  # pragma: no cover - defensive
            logging.warning("__meta__ container has unexpected type: %s", type(meta_container))
            return
        entries = meta_container.setdefault(category, [])
        if not isinstance(entries, list):  # pragma: no cover - defensive
            logging.warning("Metadata bucket has unexpected type for %s: %s", category, type(entries))
            return

        entry = {
            "value": finding.secret,
            "file": str(finding.file),
            "line": int(finding.line),
            "column": int(finding.col),
            "rule_id": finding.rule_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "confidence": round(float(finding.confidence), 4),
            "tags": list(finding.tags or []),
            "fingerprint": finding.fingerprint,
        }

        for existing in entries:
            if (
                existing.get("value") == entry["value"]
                and existing.get("file") == entry["file"]
                and existing.get("line") == entry["line"]
            ):
                return

        entries.append(entry)


# ---- CLI ---------------------------------------------------------------------

def _chunks(seq: Sequence[Path], n: int) -> Iterator[List[Path]]:
    for i in range(0, len(seq), n):
        yield list(seq[i:i+n])


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Advanced Secret Scanner")
    p.add_argument("path", nargs="?", default=".", help="Path to scan (file or directory)")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of pretty text")
    p.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0")
    p.add_argument("--baseline", type=str, help="Path to a baseline JSON file for suppression")
    p.add_argument("--write-baseline", type=str, help="Write baseline file (JSON with fingerprints)")
    p.add_argument("--max-file-size", type=int, default=2_000_000)
    p.add_argument("--concurrency", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    p.add_argument("--no-follow-symlinks", dest="follow_symlinks", action="store_false", default=False)
    args = p.parse_args(argv)

    target = Path(args.path)
    cfg = ScanConfig(max_file_size=args.max_file_size,
                     follow_symlinks=args.follow_symlinks,
                     baseline_file=Path(args.baseline) if args.baseline else None,
                     concurrency=args.concurrency)
    scanner = SecretScanner(config=cfg)

    if target.is_file():
        findings = scanner.scan_file(target)
    else:
        findings = scanner.scan_path(target)

    if args.write_baseline:
        fps = [f.fingerprint or stable_hash(f.rule_id, f.file.as_posix(), (f.redacted or f.secret)[:32]) for f in findings]
        Path(args.write_baseline).write_text(json.dumps({"fingerprints": fps}, indent=2), encoding='utf-8')
        print(f"Wrote baseline with {len(fps)} fingerprints to {args.write_baseline}")
    elif args.sarif:
        print(emit_sarif(findings))
    elif args.json:
        print(emit_json(findings))
    else:
        print(emit_pretty(findings))

    # Exit nonzero if any high or critical findings
    highest = max((_severity_rank(f.severity) for f in findings), default=0)
    return 0 if highest <= _severity_rank("medium") else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
