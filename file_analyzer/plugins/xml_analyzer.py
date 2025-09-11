#!/usr/bin/env python3
# XML data analyzer plugin

import logging
import re
from pathlib import Path
from typing import Dict, Set, Optional

from .base_plugin import AnalyzerPlugin

try:
    import xml.etree.ElementTree as ET
except Exception:  # pragma: no cover
    ET = None


class XMLAnalyzer(AnalyzerPlugin):
    """
    Analyze XML files to extract URLs/endpoints and detect sensitive values.
    """

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"xml", "data"}
        self._url_re = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
        # This plugin relies on full content for structural parsing
        self.requires_full_content = True

    @property
    def plugin_type(self) -> str:
        return "data_analyzer"

    @property
    def supported_file_types(self) -> Set[str]:
        return {".xml"}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_path.suffix.lower() == ".xml"

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        logging.info(f"Analyzing XML content in {file_path}")

        if ET is None:
            logging.warning("xml.etree.ElementTree not available; skipping XML analysis")
            return results

        try:
            # Quick sanity check: trim BOM/whitespace and ensure it looks like XML
            trimmed = content.lstrip("\ufeff\n\r\t ")
            if not trimmed.startswith("<"):
                logging.info("File does not appear to be XML after trimming; performing text scan fallback")
                self._scan_text(trimmed, "xml_fallback", results)
                return results

            root = ET.fromstring(trimmed)
        except Exception as e:
            # Reduce noise: log at INFO and still perform a lightweight text scan
            logging.info(f"Failed to parse XML ({file_path}): {e}")
            self._scan_text(content, "xml_parse_fallback", results)
            return results

        # Traverse nodes
        for elem in root.iter():
            tag_name = (elem.tag or "").lower()

            # Text content
            if elem.text:
                self._scan_text(elem.text, tag_name, results)

            # Attributes
            for attr, val in (elem.attrib or {}).items():
                self._scan_text(str(val), f"{tag_name}@{attr.lower()}", results)

        return results

    def _scan_text(self, text: str, context: str, results: Dict[str, Set[str]]):
        # URLs and endpoints
        for m in self._url_re.finditer(text):
            url = m.group(0)
            results.setdefault("url", set()).add(url)
            if any(k in context for k in ("endpoint", "url", "webhook", "graphql", "api")):
                results.setdefault("api_endpoint", set()).add(url)

        # Heuristic secret detection
        lower_ctx = context.lower()
        if any(k in lower_ctx for k in ("password", "secret", "token", "apikey", "api_key", "private", "key")):
            if isinstance(text, str) and len(text.strip()) >= 4:
                results.setdefault("security_smells", set()).add(
                    f"Suspicious XML field '{context}' with value length {len(text.strip())}"
                )
                if "token" in lower_ctx:
                    results.setdefault("access_token", set()).add(text.strip())
                elif "apikey" in lower_ctx or "api_key" in lower_ctx or ("key" in lower_ctx and len(text.strip()) > 16):
                    results.setdefault("api_key", set()).add(text.strip())
