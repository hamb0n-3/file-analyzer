#!/usr/bin/env python3
# XML parser core plugin

import logging
from pathlib import Path
from typing import Dict, Set, Optional

from .base_plugin import AnalyzerPlugin

try:
    import xml.etree.ElementTree as ET
except Exception:  # pragma: no cover
    ET = None


class XMLAnalyzer(AnalyzerPlugin):
    """
    Core XML parser: parses XML structure and provides minimal metadata
    to assist other plugins. No security heuristics here.
    """

    requires_full_content = True

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"xml", "core"}

    @property
    def plugin_type(self) -> str:
        return "core_analyzer"

    @property
    def supported_file_types(self) -> Set[str]:
        return {".xml"}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_path.suffix.lower() == ".xml"

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]):
        if ET is None:
            logging.info("xml.etree.ElementTree not available; skipping XML parser aid")
            return results

        try:
            trimmed = (content or "").lstrip("\ufeff\n\r\t ")
            if not trimmed.startswith("<"):
                results['_xml_valid'] = False
                return results
            root = ET.fromstring(trimmed)
            results['_xml_valid'] = True
            results.setdefault('_xml_root_tag', set()).add(str(root.tag))
            # Snapshot of top-level child tags (limited)
            child_tags = set()
            for i, child in enumerate(list(root)[:50]):
                child_tags.add(str(child.tag))
            if child_tags:
                results.setdefault('_xml_top_children', set()).update(sorted(child_tags))
        except Exception as e:
            logging.info(f"XML parse aid failed for {file_path}: {e}")
        return results
