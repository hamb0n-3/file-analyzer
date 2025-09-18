from __future__ import annotations

import base64
import binascii
import dataclasses
import fnmatch
import gzip
import io
import math
import os
import re
import tarfile
import zipfile
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Pattern, Sequence, Tuple

from .base_plugin import AnalyzerPlugin

# =============================================================================
# CONFIG (tune here)
# =============================================================================

@dataclass
class Config:
    # --- File handling --------------------------------------------------------
    include_globs: Tuple[str, ...] = (
        # Empty means "include everything not excluded".
        # Example: ("**/*.py", "**/*.js", "**/*.json", "**/*.env")
    )
    exclude_globs: Tuple[str, ...] = (
        ".git/**", ".hg/**", ".svn/**", ".idea/**", ".vscode/**",
        "node_modules/**", "vendor/**",
        "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif", "**/*.bmp", "**/*.webp",
        "**/*.pdf", "**/*.woff", "**/*.woff2", "**/*.ttf",
        "**/*.zip", "**/*.jar", "**/*.war",  # archives still scanned if explicitly passed
        "**/*.class", "**/*.exe", "**/*.dll", "**/*.so", "**/*.dylib",
    )
    max_file_size: int = 2_000_000         # 2 MB per regular file / archive member
    archive_max_depth: int = 2             # nested archives depth
    follow_symlinks: bool = False

    # --- Detection behavior ---------------------------------------------------
    # High-entropy token scanning
    enable_entropy: bool = True
    min_token_length: int = 20
    entropy_thresholds: Dict[str, float] = dataclasses.field(default_factory=lambda: {
        "base64": 4.3,     # per-char Shannon entropy
        "hex": 3.0,
        "alnum": 4.0,
    })

    # Base64 decoding & rescanning
    enable_base64_decode: bool = True
    min_base64_len: int = 64               # only consider base64 strings >= this length
    max_base64_decode_bytes: int = 500_000
    base64_rescan_recursion: int = 1       # how many nested decodes to attempt

    # Blacklist / whitelist (content-level)
    blacklist_patterns: Tuple[str, ...] = (
        r"(?i)\b(example|sample|test|dummy|fake|placeholder|changeme|notasecret)\b",
        r"^ssh-rsa [A-Za-z0-9+/=]+(?: .*)?$",  # public ssh keys
    )
    whitelist_patterns: Tuple[str, ...] = (
        # Lines containing these patterns are considered higher risk
        # (does not force a finding by itself, but boosts entropy tokens nearby).
        r"(?i)[^\n]*?(password|passwd|pwd|secret|token|apikey|api[_-]?key|bearer|private[_-]?key)\b(?:\s*(?:[:=.\-])\s*)?",
    )
    # Allowlist / blacklist (path-level)
    allowlist_path_globs: Tuple[str, ...] = (
        # If non-empty, only these paths are scanned (after exclude_globs).
    )
    blacklist_path_globs: Tuple[str, ...] = (
        # Files matching any of these globs are *skipped* even if include_globs matched.
        # e.g., "docs/**", "tests/**", "fixtures/**"
    )

    # Regex rules (id -> (pattern, severity, description, tags))
    rules: Dict[str, Tuple[str, str, str, Tuple[str, ...]]] = dataclasses.field(default_factory=lambda: {
        # Cloud & SCM
        "AWS_ACCESS_KEY_ID": (r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", "high", "AWS access key id", ("aws", "key")),
        "AWS_SECRET_ACCESS_KEY": (r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", "critical", "AWS secret access key (40 chars base64 charset)", ("aws", "secret")),
        "GITHUB_TOKEN": (r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b", "high", "GitHub token", ("github", "token")),
        "GITHUB_PAT": (r"\bgithub_pat_[A-Za-z0-9_]{80,}\b", "high", "GitHub fine-grained personal access token", ("github", "token")),
        "GITLAB_PAT": (r"\bglpat-[A-Za-z0-9\-_]{20,}\b", "high", "GitLab personal access token", ("gitlab", "token")),
        "AZURE_AD_CLIENT_SECRET": (r"\b[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{10,}\b", "high", "Azure AD client secret / JWT-like", ("azure", "jwt")),

        # APIs
        "GOOGLE_API_KEY": (r"\bAIza[0-9A-Za-z\-_]{35}\b", "high", "Google API key", ("google", "api")),
        "STRIPE_SECRET_KEY": (r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b", "high", "Stripe secret key", ("stripe", "api")),
        "SLACK_TOKEN": (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "high", "Slack token", ("slack", "api")),
        "SLACK_WEBHOOK": (r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[A-Za-z0-9]{24,}", "high", "Slack incoming webhook URL", ("slack", "webhook")),

        # Generic & URLs
        "BASIC_AUTH_URL": (r"\b[a-zA-Z][a-zA-Z0-9+\-.]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+", "high", "URL with embedded basic auth credentials", ("url",)),
        "JWT": (r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium", "JWT token", ("jwt", "token")),
        "PASSWORD_ASSIGNMENT": (r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*(['\"]?)([^'\" \n]{8,})\1", "medium", "Suspicious assignment", ("assignment",)),
    })

    # Reporting
    redact_keep: int = 3                    # keep first/last N chars when redacting
    dedupe: bool = True

    @classmethod
    def field_names(cls) -> Tuple[str, ...]:
        return tuple(field.name for field in dataclasses.fields(cls))

    @classmethod
    def from_mapping(cls, overrides: Optional[Mapping[str, Any]] = None) -> "Config":
        cfg = cls()
        if overrides:
            cfg.apply_overrides(overrides)
        return cfg

    def apply_overrides(self, overrides: Mapping[str, Any]) -> None:
        for field in dataclasses.fields(self):
            if field.name not in overrides or overrides[field.name] is None:
                continue
            try:
                setattr(self, field.name, overrides[field.name])
            except Exception:
                logging.debug("Ignoring invalid override for %s", field.name)


@dataclass
class Finding:
    rule_id: str
    title: str
    path: str
    line: Optional[int]
    col: Optional[int]
    match: str
    severity: str
    detector: str                   # "regex" | "entropy" | "pem_block" | "decoded"
    entropy: Optional[float] = None
    tags: Tuple[str, ...] = field(default_factory=tuple)
    decoded_from_base64: bool = False

    def redact(self, keep: int = 3) -> str:
        s = self.match
        if len(s) <= keep * 2:
            return "*" * len(s)
        return f"{s[:keep]}…{s[-keep:]}"

    def to_dict(self, *, redact: bool = False) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "path": self.path,
            "line": self.line,
            "col": self.col,
            "match": self.redact() if redact else self.match,
            "severity": self.severity,
            "detector": self.detector,
            "entropy": self.entropy,
            "tags": list(self.tags),
            "decoded_from_base64": self.decoded_from_base64,
        }


# =============================================================================
# Utilities
# =============================================================================

_PRINTABLE = set(bytes(bytearray(range(32, 127)))).union({9, 10, 13})  # tab/lf/cr

def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    # If >30% non-printable (excluding \t\r\n) consider binary.
    non_print = sum(b not in _PRINTABLE for b in data[:4096])
    return (non_print / min(len(data), 4096)) > 0.30

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c/len(s)) * log2(c/len(s)) for c in freq.values())

def _compile_patterns(patterns: Iterable[str]) -> Tuple[Pattern[str], ...]:
    return tuple(re.compile(p) for p in patterns)

def _offset_to_line_col(text: str, offset: int) -> Tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset - (last_nl + 1 if last_nl != -1 else 0) + 1
    return line, col

# =============================================================================
# Scanner
# =============================================================================

class SecretScanner:
    def __init__(self, config: Optional[Config | Mapping[str, Any]] = None):
        if isinstance(config, Config):
            self.config = config
        else:
            self.config = Config.from_mapping(config)
        # Pre-compile rules
        self._rules: Dict[str, Tuple[Pattern[str], str, str, Tuple[str, ...]]] = {
            rid: (re.compile(p), sev, desc, tags)
            for rid, (p, sev, desc, tags) in self.config.rules.items()
        }
        self._blacklist_content = _compile_patterns(self.config.blacklist_patterns)
        self._whitelist_content = _compile_patterns(self.config.whitelist_patterns)

        # Token patterns used for entropy checks
        self._b64_token_re = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{%d,}={0,2}(?![A-Za-z0-9+/=])" % self.config.min_base64_len)
        self._hex_token_re = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,}(?![A-Fa-f0-9])")
        self._alnum_token_re = re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{%d,}(?![A-Za-z0-9_\-])" % self.config.min_token_length)

    # ---- Public API ----------------------------------------------------------

    def scan_path(self, path: Path | str) -> List[Finding]:
        """Scan a file or directory path. Returns a list of Finding."""
        root = Path(path)
        if root.is_file():
            return self._scan_file(root)
        all_findings: List[Finding] = []
        for file_path in self._walk_files(root):
            all_findings.extend(self._scan_file(file_path))
        if self.config.dedupe:
            all_findings = self._dedupe(all_findings)
        return all_findings

    def scan_bytes(self, data: bytes, *, path_hint: str = "<memory>") -> List[Finding]:
        """Scan a bytes blob."""
        return self._scan_bytes(data, path_hint=path_hint, depth=self.config.archive_max_depth)

    # ---- Internal helpers ----------------------------------------------------

    def _walk_files(self, root: Path) -> Iterator[Path]:
        include_globs = self.config.include_globs or ("**",)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=self.config.follow_symlinks):
            rel_dir = Path(dirpath).relative_to(root)
            # Prune excluded directories
            dirnames[:] = [
                d for d in dirnames
                if not self._is_excluded(rel_dir / d)
            ]
            for name in filenames:
                full = Path(dirpath) / name
                rel_file = full.relative_to(root)
                if include_globs and not self._path_matches(rel_file, include_globs):
                    continue
                if self._is_excluded(rel_file):
                    continue
                if self.config.allowlist_path_globs and not self._is_allowlisted_path(rel_file):
                    continue
                if self._is_blacklisted_path(rel_file):
                    continue
                yield full

    def _is_excluded(self, relpath: Path) -> bool:
        return self._path_matches(relpath, self.config.exclude_globs)

    def _is_allowlisted_path(self, relpath: Path) -> bool:
        return self._path_matches(relpath, self.config.allowlist_path_globs)

    def _is_blacklisted_path(self, relpath: Path) -> bool:
        return self._path_matches(relpath, self.config.blacklist_path_globs)

    def _path_matches(self, relpath: Path, globs: Sequence[str]) -> bool:
        if not globs:
            return False
        rel = relpath.as_posix()
        for pat in globs:
            if pat == "**":
                return True
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(f"/{rel}", pat):
                return True
        return False

    def _scan_file(self, path: Path) -> List[Finding]:
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if size > self.config.max_file_size:
            return []
        try:
            with path.open("rb") as f:
                data = f.read()
        except OSError:
            return []
        return self._scan_bytes(data, path_hint=str(path), depth=self.config.archive_max_depth)

    def _scan_bytes(self, data: bytes, *, path_hint: str, depth: int) -> List[Finding]:
        # Archives
        if depth > 0 and self._looks_like_archive(path_hint, data):
            return self._scan_archive(data, path_hint=path_hint, depth=depth)
        # Otherwise treat as text if not binary
        if _looks_binary(data):
            return []
        text = self._to_text(data)
        if text is None:
            return []
        findings = list(self._scan_text(text, path_hint))
        if self.config.dedupe:
            findings = self._dedupe(findings)
        return findings

    def _scan_archive(self, data: bytes, *, path_hint: str, depth: int) -> List[Finding]:
        findings: List[Finding] = []
        # ZIP/JAR
        if self._is_zip_bytes(data):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for info in zf.infolist():
                        if info.is_dir() or info.file_size > self.config.max_file_size:
                            continue
                        try:
                            inner = zf.read(info.filename)
                        except Exception:
                            continue
                        inner_hint = f"{path_hint}!{info.filename}"
                        findings.extend(self._scan_bytes(inner, path_hint=inner_hint, depth=depth-1))
                return findings
            except Exception:
                pass
        # TAR / TGZ / GZ
        try:
            # Try tar (including gzipped/bz2/xz tar)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                for m in tf.getmembers():
                    if not m.isfile() or m.size > self.config.max_file_size:
                        continue
                    f = tf.extractfile(m)
                    if not f:
                        continue
                    inner = f.read()
                    inner_hint = f"{path_hint}!{m.name}"
                    findings.extend(self._scan_bytes(inner, path_hint=inner_hint, depth=depth-1))
                return findings
        except Exception:
            pass
        # Plain gzip of a single file
        try:
            inner = gzip.decompress(data)
            inner_hint = f"{path_hint}!<gz>"
            findings.extend(self._scan_bytes(inner, path_hint=inner_hint, depth=depth-1))
            return findings
        except Exception:
            pass
        # Not an archive after all; fallback to text
        if _looks_binary(data):
            return []
        text = self._to_text(data)
        return list(self._scan_text(text or "", path_hint))

    def _looks_like_archive(self, path_hint: str, data: bytes) -> bool:
        suffix = Path(path_hint).suffix.lower()
        if suffix in {".zip", ".jar", ".war", ".tar", ".tgz", ".gz", ".bz2", ".xz"}:
            return True
        # magic numbers quick sniff
        if self._is_zip_bytes(data):
            return True
        if data[:2] == b"\x1f\x8b":  # gzip
            return True
        if data[:4] == b"\x75\x73\x74\x61" or data[:5] == b"\x78\x61\x72\x21\x00":  # ustar/xar
            return True
        return False

    @staticmethod
    def _is_zip_bytes(data: bytes) -> bool:
        return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

    @staticmethod
    def _to_text(data: bytes) -> Optional[str]:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return data.decode("latin1")
            except UnicodeDecodeError:
                return None

    def _scan_text(self, text: str, path_hint: str) -> Iterator[Finding]:
        # PEM blocks (multi-line) — fast path
        pem_idx = text.find("-----BEGIN ")
        if pem_idx != -1 and "PRIVATE KEY-----" in text[pem_idx:pem_idx+40]:
            # Flag the header; multi-line capture increases noise & memory
            m = re.search(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----", text)
            if m:
                line, col = _offset_to_line_col(text, m.start())
                yield Finding(
                    rule_id="PEM_PRIVATE_KEY_BLOCK",
                    title="PEM/SSH Private Key",
                    path=path_hint,
                    line=line,
                    col=col,
                    match=text[m.start():m.end()],
                    severity="critical",
                    detector="pem_block",
                    tags=("pem", "private-key"),
                )

        # Regex rules
        for rid, (rx, severity, desc, tags) in self._rules.items():
            for m in rx.finditer(text):
                if self._is_line_blacklisted(text, m.start(), m.end()):
                    continue
                line, col = _offset_to_line_col(text, m.start())
                yield Finding(
                    rule_id=rid,
                    title=desc,
                    path=path_hint,
                    line=line,
                    col=col,
                    match=m.group(0),
                    severity=severity,
                    detector="regex",
                    tags=tags,
                )

        # High-entropy tokens (base64/hex/alnum)
        if self.config.enable_entropy:
            thresholds = self.config.entropy_thresholds
            # Consider whitelist keywords to boost confidence
            def keyword_boost(offset: int) -> float:
                lo = max(0, offset - 120)
                hi = min(len(text), offset + 120)
                seg = text[lo:hi].lower()
                return 0.6 if any(p.search(seg) for p in self._whitelist_content) else 0.0

            # Base64-like
            for m in self._b64_token_re.finditer(text):
                if self._is_line_blacklisted(text, m.start(), m.end()):
                    continue
                token = m.group(0)
                H = _shannon_entropy(token)
                if H >= thresholds.get("base64", 4.3):
                    line, col = _offset_to_line_col(text, m.start())
                    yield Finding(
                        rule_id="HIGH_ENTROPY_BASE64",
                        title="High‑entropy base64‑like token",
                        path=path_hint,
                        line=line,
                        col=col,
                        match=token,
                        severity="medium" if keyword_boost(m.start()) == 0 else "high",
                        detector="entropy",
                        entropy=H,
                        tags=("entropy", "base64"),
                    )
                    # Optionally decode and rescan decoded text
                    if self.config.enable_base64_decode:
                        for f in self._decode_and_rescan_base64(token, path_hint, depth=self.config.base64_rescan_recursion):
                            yield f

            # Hex-like
            for m in self._hex_token_re.finditer(text):
                if self._is_line_blacklisted(text, m.start(), m.end()):
                    continue
                token = m.group(0)
                # Ignore obvious hashes by length heuristic (sha256=64 hex)
                if len(token) in (32, 40, 64, 128):
                    # Still compute entropy; many random hashes will be high but are less risky
                    pass
                H = _shannon_entropy(token)
                if H >= thresholds.get("hex", 3.0):
                    line, col = _offset_to_line_col(text, m.start())
                    yield Finding(
                        rule_id="HIGH_ENTROPY_HEX",
                        title="High‑entropy hex‑like token",
                        path=path_hint,
                        line=line,
                        col=col,
                        match=token,
                        severity="low" if len(token) in (32, 40, 64, 128) else "medium",
                        detector="entropy",
                        entropy=H,
                        tags=("entropy", "hex"),
                    )

            # Alnum (e.g., UUID‑less long identifiers)
            for m in self._alnum_token_re.finditer(text):
                if self._is_line_blacklisted(text, m.start(), m.end()):
                    continue
                token = m.group(0)
                H = _shannon_entropy(token)
                if H >= thresholds.get("alnum", 4.0):
                    line, col = _offset_to_line_col(text, m.start())
                    sev = "medium"
                    if any(k in token.lower() for k in ("sk_", "rk_", "token", "secret", "key")):
                        sev = "high"
                    yield Finding(
                        rule_id="HIGH_ENTROPY_ALNUM",
                        title="High‑entropy identifier",
                        path=path_hint,
                        line=line,
                        col=col,
                        match=token,
                        severity=sev,
                        detector="entropy",
                        entropy=H,
                        tags=("entropy",),
                    )

# ---- Base64 decode & rescan ---------------------------------------------

    def _decode_and_rescan_base64(self, token: str, path_hint: str, *, depth: int) -> Iterator[Finding]:
        if depth <= 0 or len(token) < self.config.min_base64_len:
            return
        # Normalize padding
        pad = len(token) % 4
        if pad:
            token_p = token + ("=" * (4 - pad))
        else:
            token_p = token
        try:
            data = base64.b64decode(token_p, validate=True)
        except binascii.Error:
            return
        if not data or len(data) > self.config.max_base64_decode_bytes:
            return
        # Scan decoded content as text
        if _looks_binary(data):
            return
        text = self._to_text(data)
        if not text:
            return
        # Reuse regex/entropy scanning on decoded text
        for f in self._scan_text(text, path_hint + "#b64"):
            f.decoded_from_base64 = True
            if f.severity in ("low", "medium"):
                # Bump a notch if uncovered only after decoding
                f.severity = "high"
            yield f

    # ---- Misc ----------------------------------------------------------------

    def _is_line_blacklisted(self, text: str, start: int, end: int) -> bool:
        # If the entire line matches any blacklist pattern, skip.
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]
        return any(rx.search(line) for rx in self._blacklist_content)

    def _dedupe(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        out: List[Finding] = []
        for f in findings:
            key = (f.rule_id, f.path, f.line, f.col, f.match)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out


class SecretsAnalyzerPlugin(AnalyzerPlugin):
    """Adapter that exposes SecretScanner findings to the analyzer pipeline."""

    plugin_type = 'secret_analyzer'
    supported_file_types = {'*'}
    requires_full_content = False

    _RULE_CATEGORY_MAP: Dict[str, Tuple[str, ...]] = {
        'AWS_ACCESS_KEY_ID': ('aws_key', 'api_key'),
        'AWS_SECRET_ACCESS_KEY': ('aws_key', 'api_key', 'access_token'),
        'GITHUB_TOKEN': ('access_token', 'api_token'),
        'GITHUB_PAT': ('access_token', 'api_token'),
        'GITLAB_PAT': ('access_token', 'api_token'),
        'AZURE_AD_CLIENT_SECRET': ('client_secret', 'oauth_token'),
        'GOOGLE_API_KEY': ('api_key',),
        'STRIPE_SECRET_KEY': ('api_key',),
        'SLACK_TOKEN': ('oauth_token', 'access_token'),
        'SLACK_WEBHOOK': ('webhook_url',),
        'BASIC_AUTH_URL': ('url',),
        'JWT': ('jwt',),
        'PASSWORD_ASSIGNMENT': ('password',),
        'PEM_PRIVATE_KEY_BLOCK': ('private_key',),
        'HIGH_ENTROPY_BASE64': ('high_entropy_strings',),
        'HIGH_ENTROPY_HEX': ('high_entropy_strings',),
        'HIGH_ENTROPY_ALNUM': ('high_entropy_strings',),
    }
    _TAG_CATEGORY_MAP: Dict[str, Tuple[str, ...]] = {
        'aws': ('aws_key',),
        'token': ('access_token',),
        'secret': ('client_secret',),
        'webhook': ('webhook_url',),
        'jwt': ('jwt',),
        'key': ('api_key',),
        'api': ('api_key',),
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.tags.update({'secrets', 'security'})
        overrides = self._extract_scanner_overrides(config)
        self.scanner = SecretScanner(overrides)

    def _extract_scanner_overrides(self, config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not isinstance(config, dict):
            return {}
        if isinstance(config.get('secret_scanner'), dict):
            return config['secret_scanner']
        if isinstance(config.get('secrets_plugin'), dict):
            return config['secrets_plugin']
        valid_fields = Config.field_names()
        return {k: v for k, v in config.items() if k in valid_fields}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_type != 'binary'

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, set]) -> Dict[str, set]:
        provided_content = content or ''
        lines: Sequence[str] = ()
        full_content = False

        if provided_content:
            data = provided_content.encode('utf-8', errors='ignore')
            if not data:
                return results
            try:
                findings = self.scanner.scan_bytes(data, path_hint=str(file_path))
            except Exception as exc:
                logging.error("Secrets analyzer failure for %s: %s", file_path, exc)
                results.setdefault('runtime_errors', set()).add(f"Secrets analyzer error: {exc}")
                return results
            if not findings:
                return results
            try:
                file_size = file_path.stat().st_size
            except Exception:
                full_content = True
            else:
                full_content = len(data) >= file_size
            lines = provided_content.splitlines()
        else:
            try:
                findings = self.scanner.scan_path(file_path)
            except Exception as exc:
                logging.error("Secrets analyzer failure for %s: %s", file_path, exc)
                results.setdefault('runtime_errors', set()).add(f"Secrets analyzer error: {exc}")
                return results
            if not findings:
                return results
            try:
                text_content = file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception as exc:
                logging.debug("Secrets analyzer could not load context for %s: %s", file_path, exc)
                lines = ()
                full_content = False
            else:
                lines = text_content.splitlines()
                full_content = True

        meta_bucket = results.setdefault('__meta__', {})

        for finding in findings:
            categories = self._categories_for(finding)
            if not categories:
                continue
            for category in categories:
                values = results.setdefault(category, set())
                values.add(finding.match)

                entry = {'value': finding.match, 'file': str(file_path)}
                if full_content and isinstance(finding.line, int) and finding.line > 0:
                    entry['line_num'] = finding.line
                    if 0 < finding.line <= len(lines):
                        entry['context'] = lines[finding.line - 1].rstrip('\r\n')

                meta_list = meta_bucket.setdefault(category, [])
                if any(
                    existing.get('value') == entry['value'] and existing.get('line_num') == entry.get('line_num')
                    for existing in meta_list
                ):
                    continue
                meta_list.append(entry)

        return results

    def _categories_for(self, finding: Finding) -> Tuple[str, ...]:
        categories = set(self._RULE_CATEGORY_MAP.get(finding.rule_id, ()))
        for tag in finding.tags or ():
            categories.update(self._TAG_CATEGORY_MAP.get(tag.lower(), ()))
        if not categories and finding.detector == 'entropy':
            categories.add('high_entropy_strings')
        return tuple(categories)
