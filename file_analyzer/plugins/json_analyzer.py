#!/usr/bin/env python3
# JSON parser core plugin

import json
import logging
from pathlib import Path
from typing import Dict, Set, Optional, Any

from .base_plugin import AnalyzerPlugin


class JSONAnalyzer(AnalyzerPlugin):
    """
    Core JSON parser: ensures JSON/JSONL files are parsed and exposes
    lightweight metadata to aid other analyses. No security heuristics here.
    """

    # Full content is preferred for structural parsing
    requires_full_content = True

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"json", "core"}

    @property
    def plugin_type(self) -> str:
        return "core_analyzer"

    @property
    def supported_file_types(self) -> Set[str]:
        return {".json", ".jsonl", ".ndjson"}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_path.suffix.lower() in {".json", ".jsonl", ".ndjson"}

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]):
        logging.debug(f"Parsing JSON content in {file_path}")
        try:
            suffix = file_path.suffix.lower()
            if suffix in {".jsonl", ".ndjson"}:
                ok = 0
                total = 0
                top_keys: Set[str] = set()
                for line in (content or "").splitlines():
                    if not line.strip():
                        continue
                    total += 1
                    obj = self._safe_json_loads(line)
                    if isinstance(obj, dict):
                        ok += 1
                        top_keys.update([str(k) for k in obj.keys()][:50])
                results.setdefault('_jsonl_stats', set()).add(f"lines:{total}, parsed:{ok}")
                if top_keys:
                    results.setdefault('_json_top_keys', set()).update(sorted(list(top_keys))[:100])
                results['_json_valid'] = True
            else:
                obj = self._safe_json_loads(content or "")
                if isinstance(obj, dict):
                    results['_json_valid'] = True
                    # Top-level keys snapshot (limit to avoid bloat)
                    results.setdefault('_json_top_keys', set()).update(list(obj.keys())[:100])
                elif isinstance(obj, list):
                    results['_json_valid'] = True
                    results.setdefault('_json_top_keys', set()).add('[]')
                else:
                    results['_json_valid'] = False
        except Exception as e:
            logging.info(f"JSON parse aid failed for {file_path}: {e}")
        return results

    def _safe_json_loads(self, text: str) -> Any:
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            trimmed = text.lstrip("\ufeff\n\r\t ")
            try:
                return json.loads(trimmed)
            except Exception:
                return None
