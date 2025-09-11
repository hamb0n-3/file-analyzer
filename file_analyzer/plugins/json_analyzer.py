#!/usr/bin/env python3
# JSON data analyzer plugin

import json
import logging
import re
from pathlib import Path
from typing import Dict, Set, Optional, Any, Iterable

from .base_plugin import AnalyzerPlugin


class JSONAnalyzer(AnalyzerPlugin):
    """
    Analyze JSON and JSON Lines files for URLs, API endpoints, and secrets.

    - Extract URLs and possible API endpoints
    - Detect likely secrets by key names (password, token, key, secret)
    - Surface interesting metadata like service hosts
    """

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"json", "data"}
        # Simple URL and endpoint patterns reusing generic concepts
        self._url_re = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
        self._endpoint_re = re.compile(r"(?i)(?:^|/)api(?:/|$|v\d+)|graphql|webhook")

    @property
    def plugin_type(self) -> str:
        return "data_analyzer"

    @property
    def supported_file_types(self) -> Set[str]:
        return {".json", ".jsonl", ".ndjson"}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_path.suffix.lower() in {".json", ".jsonl", ".ndjson"}

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        logging.info(f"Analyzing JSON content in {file_path}")

        try:
            if file_path.suffix.lower() == ".jsonl" or file_path.suffix.lower() == ".ndjson":
                for line in content.splitlines():
                    self._analyze_json_blob(self._safe_json_loads(line), results)
            else:
                self._analyze_json_blob(self._safe_json_loads(content), results)
        except Exception as e:
            logging.warning(f"JSON analysis failed for {file_path}: {e}")
        return results

    def _safe_json_loads(self, text: str) -> Any:
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            # Try to salvage by trimming common trailing commas or BOM
            trimmed = text.lstrip("\ufeff\n\r\t ")
            try:
                return json.loads(trimmed)
            except Exception:
                return None

    def _walk(self, obj: Any) -> Iterable[tuple[Optional[str], Any]]:
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield (k, v)
                yield from self._walk(v)
        elif isinstance(obj, list):
            for v in obj:
                yield (None, v)
                yield from self._walk(v)
        else:
            yield (None, obj)

    def _analyze_json_blob(self, data: Any, results: Dict[str, Set[str]]) -> None:
        if data is None:
            return

        for key, value in self._walk(data):
            # Normalize to string for scanning when possible
            if isinstance(value, (dict, list)):
                continue

            s = str(value)

            # URLs
            for m in self._url_re.finditer(s):
                results.setdefault("url", set()).add(m.group(0))
                if self._endpoint_re.search(m.group(0)):
                    results.setdefault("api_endpoint", set()).add(m.group(0))

            # Secrets by key name heuristics
            if key is not None:
                lowered = key.lower()
                if any(t in lowered for t in ("password", "passwd", "secret", "token", "apikey", "api_key", "private", "key")):
                    if isinstance(value, str) and len(value) >= 4:
                        results.setdefault("security_smells", set()).add(
                            f"Suspicious JSON key '{key}' with value length {len(value)}"
                        )
                        # Categorize when obvious
                        if "token" in lowered:
                            results.setdefault("access_token", set()).add(value)
                        elif "apikey" in lowered or "api_key" in lowered or ("key" in lowered and len(value) > 16):
                            results.setdefault("api_key", set()).add(value)

