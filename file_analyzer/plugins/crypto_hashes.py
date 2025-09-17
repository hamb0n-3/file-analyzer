#!/usr/bin/env python3
# Advanced Crypto/Hash analyzer plugin
# Drop-in replacement for the existing CryptoHashesAnalyzer.
# - Greatly expanded pattern set (hash algorithms + password-hash schemes + LDAP/PHC formats)
# - Smarter candidate collection (context-aware, boundary-safe, and entropy-gated)
# - False-positive reduction (UUID/GUID, hex noise, obvious non-hash formats)
# - Structured, cache-aware identification with optional confidence scoring

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Set, Iterable, Tuple, List

# NOTE: These come from your main application. Imports are kept identical for compatibility.
from .base_plugin import AnalyzerPlugin
from ..utils.file_utils import calculate_entropy


@dataclass(frozen=True)
class PatternSpec:
    """A descriptor for a hash/password-hash identification pattern."""
    name: str                     # Human-friendly canonical type
    pattern: re.Pattern           # Compiled regex to validate a *complete* value
    fixed_length: Optional[int]   # Expected length of the raw value (if applicable)
    family: Optional[str] = None  # Algorithm family (e.g., 'SHA-2', 'PHC', 'bcrypt', 'LDAP', etc.)


class CryptoHashesAnalyzer(AnalyzerPlugin):
    """
    Detect cryptographic hashes and common password-hash formats in text files.
    Results are deduplicated and lightly annotated (type, entropy).
    """

    # --------------------------- Plugin wiring ---------------------------

    def __init__(self, config=None):
        super().__init__(config)
        # tags are used by the main program to categorize plugins
        self.tags: Set[str] = {"crypto", "security", "hash", "password"}

        # Compile candidate collectors (broad, boundary-safe)
        self._candidate_collectors: Tuple[re.Pattern, ...] = (
            # PHC strings (+ bcrypt/sha*crypt apr1)
            re.compile(r'(?P<phc>\$(?:argon2(?:id|i|d)|scrypt|pbkdf2-(?:sha1|sha256|sha512)|[1256]|apr1|2[abyxy]?)\$[^\s]{10,})'),
            # LDAP-style {SSHA},{SHA},{MD5},{SMD5},{CRYPT}
            re.compile(r'(?P<ldap>\{(?:SSHA|SSHA256|SSHA384|SSHA512|SHA|SHA256|SHA384|SHA512|MD5|SMD5|CRYPT)\}[A-Za-z0-9+/=]{10,})'),
            # Django style
            re.compile(r'(?P<django>(?:pbkdf2_(?:sha1|sha256)|argon2id|argon2i|bcrypt(?:_sha256)?)\$[^\s$]+\$[^\s$]+\$[^\s]+)'),
            # MySQL / PostgreSQL tags
            re.compile(r'(?P<db>(?:\*[0-9A-Fa-f]{40})|(?:md5[0-9A-Fa-f]{32}))'),
            # BCrypt canonical (60 chars total): $2a/$2b/$2y cost + 22-char salt + 31-char hash
            re.compile(r'(?P<bcrypt>\$2[abyxy]?\$\d{2}\$[A-Za-z0-9./]{53})'),
            # Hex digests with typical lengths; ensure proper boundaries around the token
            re.compile(r'(?P<hex>\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{56}\b|\b[A-Fa-f0-9]{64}\b|\b[A-Fa-f0-9]{96}\b|\b[A-Fa-f0-9]{128}\b)'),
            # Base64-like blocks commonly used by SSHA/PHC split forms
            re.compile(r'(?P<b64>(?:[A-Za-z0-9+/]{20,}={0,2}))'),
            # JWTs (not strictly a hash, but cryptographic token frequently confused with one)
            re.compile(r'(?P<jwt>\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)'),
        )

        # Expanded identification patterns (validation-level, not collectors)
        # Each PatternSpec *validates* a full candidate value.
        self._id_specs: Tuple[PatternSpec, ...] = tuple(self._build_id_specs())

        # Exclusion patterns to reduce false positives
        self._exclusions: Tuple[re.Pattern, ...] = (
            # UUID/GUIDs
            re.compile(r'\b[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\b'),
            # MongoDB ObjectId (24 hex) — not a cryptographic digest
            re.compile(r'\b[0-9A-Fa-f]{24}\b'),
            # Common MAC addresses, IPv6 fragments, etc.
            re.compile(r'(?:\b[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b'),
            # Hex strings inside obvious code-like prefixes (0x...): treat cautiously
            re.compile(r'\b0x[0-9A-Fa-f]{8,}\b'),
        )

        # Context keywords that increase confidence for generic hex lengths
        self._context_keywords = (
            'hash', 'digest', 'checksum', 'sha', 'sha1', 'sha2', 'sha256',
            'sha384', 'sha512', 'md5', 'bcrypt', 'argon2', 'pbkdf2', 'scrypt',
            'ntlm', 'lm', 'ldap', 'salt', 'pass', 'pwd', 'secret', 'token'
        )

        # Entropy thresholds (heuristics)
        self._entropy_min_by_type: Dict[str, float] = {
            'MD5': 3.0,
            'NTLM': 2.5,
            # Strong digests or encoded forms almost always exceed this
            'default': 3.2,
        }

    @property
    def plugin_type(self) -> str:
        return "data_analyzer"

    @property
    def supported_file_types(self) -> Set[str]:
        return {"*"}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_type == 'text'

    # --------------------------- Main analysis ---------------------------

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]):
        logging.debug(f"[CryptoHashesAnalyzer] Analyzing hashes in {file_path}")
        if not content:
            return results

        seen: Set[Tuple[int, int]] = set()
        for collector in self._candidate_collectors:
            for m in collector.finditer(content):
                start, end = m.span()
                # de-duplicate overlapping matches from different collectors
                if any(s <= start < e or s < end <= e for (s, e) in seen):
                    continue
                candidate = m.group(0)
                if self._is_excluded(candidate):
                    continue

                # Basic entropy gate (fast-fail for obvious low-entropy tokens)
                ent = calculate_entropy(candidate)
                if len(candidate) >= 32 and ent < 3.0 and not candidate.startswith('$2'):
                    # Allow well-known low-entropy NTLM/LM edge-cases later
                    # but drop generic low-entropy noise early.
                    continue

                # Identify & score
                ctype, confidence = self._identify(candidate, content, start, end, ent)

                # Special-case NTLM empty password (AAD3B435...)
                if len(candidate) == 32 and candidate.lower().startswith('aad3b435'):
                    ctype = 'NTLM (Empty Password)'
                    confidence = max(confidence, 0.95)

                if ctype == 'Unknown':
                    continue

                annotated = f"{candidate} (Type: {ctype}, Entropy: {ent:.2f}, Confidence: {confidence:.2f})"
                results.setdefault('hash', set()).add(annotated)
                seen.add((start, end))

        return results

    # --------------------------- Identification ---------------------------

    def _context_score(self, text: str, start: int, end: int) -> float:
        """Lightweight context scoring based on nearby keywords."""
        window = 64
        left = text[max(0, start - window):start].lower()
        right = text[end:min(len(text), end + window)].lower()
        ctx = f"{left} {right}"
        hits = sum(1 for k in self._context_keywords if k in ctx)
        # Clip & normalize to [0, 1]
        return min(hits / 4.0, 1.0)

    def _is_excluded(self, value: str) -> bool:
        """Screen out common non-hash artifacts to reduce false positives."""
        for ex in self._exclusions:
            if ex.search(value):
                return True
        return False

    def _entropy_ok(self, name: str, ent: float) -> bool:
        threshold = self._entropy_min_by_type.get(name, self._entropy_min_by_type['default'])
        return ent >= threshold

    @lru_cache(maxsize=2048)
    def _identify(self, value: str, context: str, start: int, end: int, ent: float) -> Tuple[str, float]:
        """
        Return (type, confidence) for a candidate value.
        Will consider multiple overlapping specs and pick the best one.
        """
        v = value.strip()

        best_name = 'Unknown'
        best_score = 0.0

        # Try strict validators first
        for spec in self._id_specs:
            if spec.fixed_length and len(v) != spec.fixed_length:
                continue
            if spec.pattern.fullmatch(v):
                # Base confidence for a positive validation
                score = 0.65
                # Entropy bonus
                if self._entropy_ok(spec.name, ent):
                    score += 0.15
                # Context bonus for generic hex lengths
                score += 0.20 * self._context_score(context, start, end)
                # Family-specific nudges
                if spec.family in ('PHC', 'bcrypt', 'crypt'):
                    score += 0.05
                if score > best_score:
                    best_name, best_score = spec.name, score

        # Generic hex length buckets: suggest algorithm families when no exact format matched
        if best_name == 'Unknown' and re.fullmatch(r'[A-Fa-f0-9]+', v or ''):
            length = len(v)
            hex_map = {
                32: ['MD5', 'NTLM/LM candidate'],
                40: ['SHA-1', 'RIPEMD-160'],
                56: ['SHA-224'],
                64: ['SHA-256', 'Keccak-256', 'BLAKE2s-256'],
                96: ['SHA-384'],
                128: ['SHA-512', 'BLAKE2b-512'],
            }
            if length in hex_map:
                # Build a joined descriptive name
                best_name = '/'.join(hex_map[length])
                # Confidence mainly from entropy + context
                best_score = 0.35 + 0.25 * self._context_score(context, start, end)
                if self._entropy_ok('default', ent):
                    best_score += 0.25

        # Clamp confidence
        best_score = max(0.0, min(1.0, best_score))
        return best_name, best_score

    # --------------------------- Pattern registry ---------------------------

    def _build_id_specs(self) -> Iterable[PatternSpec]:
        """
        Build the expanded set of identification validators.
        Keep patterns strict and anchored; collectors will feed candidates.
        """
        P = PatternSpec  # alias
        specs: List[PatternSpec] = []

        # ---- Raw hex digests (strict length checks) ----
        specs += [
            P('MD5',        re.compile(r'^[A-Fa-f0-9]{32}$'), 32, 'MD'),
            P('SHA-1',      re.compile(r'^[A-Fa-f0-9]{40}$'), 40, 'SHA-1'),
            P('RIPEMD-160', re.compile(r'^[A-Fa-f0-9]{40}$'), 40, 'RIPEMD'),
            P('SHA-224',    re.compile(r'^[A-Fa-f0-9]{56}$'), 56, 'SHA-2'),
            P('SHA-256',    re.compile(r'^[A-Fa-f0-9]{64}$'), 64, 'SHA-2'),
            P('Keccak-256', re.compile(r'^[A-Fa-f0-9]{64}$'), 64, 'Keccak'),
            P('BLAKE2s-256',re.compile(r'^[A-Fa-f0-9]{64}$'), 64, 'BLAKE2'),
            P('SHA-384',    re.compile(r'^[A-Fa-f0-9]{96}$'), 96, 'SHA-2'),
            P('SHA-512',    re.compile(r'^[A-Fa-f0-9]{128}$'), 128, 'SHA-2'),
            P('BLAKE2b-512',re.compile(r'^[A-Fa-f0-9]{128}$'), 128, 'BLAKE2'),
        ]

        # ---- bcrypt & *crypt family ----
        # bcrypt: $2a$,$2b$,$2y$ (optionally $2x$) cost(2) + 22-char salt + 31-char hash
        specs += [
            P('BCrypt', re.compile(r'^\$2[abyxy]?\$\d{2}\$[A-Za-z0-9./]{53}$'), None, 'bcrypt'),
            P('md5crypt ($1$)', re.compile(r'^\$1\$(?:[A-Za-z0-9./]{1,8})\$[A-Za-z0-9./]{22}$'), None, 'crypt'),
            P('apr1 (Apache MD5)', re.compile(r'^\$apr1\$(?:[A-Za-z0-9./]{1,8})\$[A-Za-z0-9./]{22}$'), None, 'crypt'),
            P('sha256crypt ($5$)', re.compile(r'^\$5\$(?:rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43}$'), None, 'crypt'),
            P('sha512crypt ($6$)', re.compile(r'^\$6\$(?:rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$'), None, 'crypt'),
        ]

        # ---- PHC strings ----
        specs += [
            P('Argon2id (PHC)', re.compile(r'^\$argon2id\$v=\d+\$m=\d+,t=\d+(?:,p=\d+)?\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), None, 'PHC'),
            P('Argon2i (PHC)',  re.compile(r'^\$argon2i\$v=\d+\$m=\d+,t=\d+(?:,p=\d+)?\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), None, 'PHC'),
            P('scrypt (PHC)',   re.compile(r'^\$scrypt\$N=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), None, 'PHC'),
            P('PBKDF2-SHA1 (PHC)',   re.compile(r'^\$pbkdf2-sha1\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), None, 'PHC'),
            P('PBKDF2-SHA256 (PHC)', re.compile(r'^\$pbkdf2-sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), None, 'PHC'),
            P('PBKDF2-SHA512 (PHC)', re.compile(r'^\$pbkdf2-sha512\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), None, 'PHC'),
        ]

        # ---- Django / framework formats ----
        specs += [
            P('Django PBKDF2-SHA256', re.compile(r'^pbkdf2_sha256\$\d+\$[^$\s]+\$[A-Za-z0-9/+]+=*$'), None, 'framework'),
            P('Django PBKDF2-SHA1',   re.compile(r'^pbkdf2_sha1\$\d+\$[^$\s]+\$[A-Za-z0-9/+]+=*$'), None, 'framework'),
            P('Django bcrypt',        re.compile(r'^bcrypt\$\d{2}\$[A-Za-z0-9./]{53}$'), None, 'framework'),
            P('Django bcrypt_sha256', re.compile(r'^bcrypt_sha256\$\d{2}\$[A-Za-z0-9./]{53}$'), None, 'framework'),
            P('Django argon2id',      re.compile(r'^argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[^$]+\$[^$]+$'), None, 'framework'),
        ]

        # ---- LDAP-style wrappers ----
        specs += [
            P('LDAP {SSHA}',    re.compile(r'^\{SSHA\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {SSHA256}', re.compile(r'^\{SSHA256\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {SSHA384}', re.compile(r'^\{SSHA384\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {SSHA512}', re.compile(r'^\{SSHA512\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {SHA}',     re.compile(r'^\{SHA\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {SHA256}',  re.compile(r'^\{SHA256\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {SHA384}',  re.compile(r'^\{SHA384\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {SHA512}',  re.compile(r'^\{SHA512\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {MD5}',     re.compile(r'^\{MD5\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {SMD5}',    re.compile(r'^\{SMD5\}[A-Za-z0-9+/=]+$'), None, 'LDAP'),
            P('LDAP {CRYPT}',   re.compile(r'^\{CRYPT\}[A-Za-z0-9./$]+$'), None, 'LDAP'),
        ]

        # ---- Database-specific formats ----
        specs += [
            P('MySQL 4.1+ (double SHA-1)', re.compile(r'^\*[0-9A-Fa-f]{40}$'), 41, 'DB'),  # leading '*'
            P('PostgreSQL md5',            re.compile(r'^md5[0-9A-Fa-f]{32}$'), 35, 'DB'),
        ]

        # ---- Legacy/Framework password hashes ----
        specs += [
            P('phpass ($P$/$H$)', re.compile(r'^\$(?:P|H)\$[A-Za-z0-9./]{31}$'), None, 'framework'),
            P('Drupal 7 ($S$)',   re.compile(r'^\$S\$[A-Za-z0-9./]{52}$'), None, 'framework'),
        ]

        # ---- Tokens (informational; not strictly “hashes”) ----
        specs += [
            P('JWT (JWS)', re.compile(r'^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$'), None, 'token'),
        ]

        return specs


# --------------------------- Notes for integrators ---------------------------
# - This class is a drop-in replacement for your prior CryptoHashesAnalyzer.
# - It keeps the same AnalyzerPlugin interface:
#     * plugin_type -> "data_analyzer"
#     * supported_file_types -> {"*"}
#     * can_analyze(file_path, file_type, content) -> bool (text only)
#     * analyze(file_path, file_type, content, results) -> Dict[str, Set[str]]
# - The analyzer emits entries under results['hash'] like:
#     "<raw> (Type: <inferred>, Entropy: <x.xx>, Confidence: <0.xx>)"
# - Tuning:
#     * Adjust self._entropy_min_by_type if you want to be stricter/looser.
#     * Expand _context_keywords to push confidence for particular environments.
#     * Add PatternSpec entries in _build_id_specs() to support more formats.
# - Performance:
#     * Candidate collectors are coarse; strict validators do the heavy lifting.
#     * lru_cache on _identify avoids re-evaluating duplicates.
# ---------------------------------------------------------------------------
