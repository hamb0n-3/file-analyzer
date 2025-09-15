#!/usr/bin/env python3
# Crypto/hash analyzer plugin

from __future__ import annotations

import re
import logging
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Set

from .base_plugin import AnalyzerPlugin
from ..utils.file_utils import calculate_entropy


class CryptoHashesAnalyzer(AnalyzerPlugin):
    """
    Detect likely hashes and annotate with type and entropy.
    """

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"crypto"}
        # Broad hash candidate pattern incl. bcrypt
        self.hash_candidate_re = re.compile(
            r"(?:\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53})|(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128})(?![A-Fa-f0-9])"
        )
        # Identification patterns
        self.hash_patterns: Dict[str, tuple[str, Optional[int]]] = {
            'MD5': (r'^[a-fA-F0-9]{32}$', 32),
            'SHA-1': (r'^[a-fA-F0-9]{40}$', 40),
            'SHA-256': (r'^[a-fA-F0-9]{64}$', 64),
            'SHA-512': (r'^[a-fA-F0-9]{128}$', 128),
            'NTLM': (r'^[a-fA-F0-9]{32}$', 32),
            'MySQL4': (r'^[a-fA-F0-9]{16}$', 16),
            'MySQL5': (r'^[a-fA-F0-9]{40}$', 40),
            'BCrypt': (r'^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$', None),
            'RIPEMD-160': (r'^[a-fA-F0-9]{40}$', 40)
        }

    @property
    def plugin_type(self) -> str:
        return "data_analyzer"

    @property
    def supported_file_types(self) -> Set[str]:
        return {"*"}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_type == 'text'

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]):
        logging.debug(f"Analyzing hashes in {file_path}")
        if not content:
            return results
        for m in self.hash_candidate_re.finditer(content):
            raw = m.group(0)
            htype = self._identify_hash(raw)
            ent = calculate_entropy(raw)
            annotated = f"{raw} (Type: {htype}, Entropy: {ent:.2f})"
            results.setdefault('hash', set()).add(annotated)
        return results

    @lru_cache(maxsize=1024)
    def _identify_hash(self, hash_value: str) -> str:
        hash_value = hash_value.strip()
        entropy = calculate_entropy(hash_value)
        potential = []
        for htype, (pat, length) in self.hash_patterns.items():
            if length and len(hash_value) != length:
                continue
            if re.match(pat, hash_value):
                if htype == 'MD5':
                    if entropy > 3.0:
                        potential.append(htype)
                elif htype == 'BCrypt':
                    return 'BCrypt'
                else:
                    potential.append(htype)
        if len(hash_value) == 32:
            if all(c in '0123456789abcdef' for c in hash_value.lower()):
                if hash_value.lower().startswith('aad3b435'):
                    return 'NTLM (Empty Password)'
                elif entropy < 2.5:
                    potential.append('NTLM')
        return '/'.join(potential) if potential else 'Unknown'

