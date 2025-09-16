#!/usr/bin/env python3

from __future__ import annotations

import datetime
import json
import logging
import math
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from base_plugin import AnalyzerPlugin  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone usage
    class AnalyzerPlugin:  # type: ignore
        plugin_type: str = "semantic"
        supported_file_types: Iterable[str] = ("json",)
        name: str = "SecretsContextPlugin"

        def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
            raise NotImplementedError

        def analyze(self, file_path: Path, file_type: str, content: str, results_collector=None) -> Dict[str, Any]:
            raise NotImplementedError


class OllamaLLM:
    """Minimal wrapper around the `ollama` Python client."""

    SYSTEM_PROMPT = (
        "You are a cybersecurity assistant. Given a raw value and a short context snippet, "
        "classify whether it is a secret, whether it is a key, token, cert, hash, password, PII, or PHI. If it is not, ONLY respond with an empty json {}. If it is a secret, respond with strict JSON containing keys: "
        "{SECRET, type, username (optional), usage, reasoning, file location.}"
    )

    def __init__(self, model: str = "qwen3-4b:latest", host: Optional[str] = None) -> None:
        self.model = model
        if host:
            os.environ["OLLAMA_HOST"] = host
        try:
            import ollama  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on runtime env
            raise RuntimeError("The 'ollama' package is required for LLM classification") from exc
        self._client = ollama

    def build_messages(self, raw_secret: str, language: str, context_snippet: str) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"FILE TYPE: {language}\n"
                    f"SECRET: {raw_secret}\n"
                    f"CONTEXT:\n{context_snippet}\n"
                    "Reply with JSON only using these keys {SECRET, type, username (optional), usage, reasoning, file location}."
                ),
            },
        ]

    def classify(
        self,
        raw_secret: str,
        language: str,
        context_snippet: str,
        *,
        messages: Optional[List[Dict[str, str]]] = None,
        preview_callback: Optional[Callable[[List[Dict[str, str]], str, Optional[Dict[str, Any]]], None]] = None,
    ) -> Optional[Dict[str, Any]]:
        messages = messages or self.build_messages(raw_secret, language, context_snippet)
        try:
            response = self._client.chat(model=self.model, messages=messages)
        except Exception as exc:
            logging.warning("Ollama chat failed: %s", exc)
            return None

        content = (response or {}).get("message", {}).get("content", "")
        parsed: Optional[Dict[str, Any]] = None
        if content:
            parsed = self._parse_json_response(content)
        if preview_callback:
            try:
                preview_callback(messages, content, parsed)
            except Exception:
                logging.debug("Preview callback raised an exception", exc_info=True)
        return parsed

    @staticmethod
    def _parse_json_response(raw: str) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(raw)
        except Exception:
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if not match:
                logging.debug("Failed to locate JSON payload in LLM response")
                return None
            try:
                return json.loads(match.group(0))
            except Exception:
                logging.debug("Failed to parse JSON payload extracted from LLM response")
                return None


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def detect_language_from_ext(path: Path) -> str:
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".json": "json",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".env": "dotenv",
        ".rb": "ruby",
        ".go": "go",
        ".java": "java",
        ".cs": "csharp",
        ".php": "php",
        ".sh": "shell",
        ".ps1": "powershell",
        ".toml": "toml",
        ".ini": "ini",
        ".cfg": "ini",
        ".txt": "text",
        ".md": "markdown",
    }.get(path.suffix.lower(), "text")


def find_occurrences(text: str, needle: str) -> List[Tuple[int, int]]:
    matches: List[Tuple[int, int]] = []
    if not text or not needle:
        return matches
    for line_no, line in enumerate(text.splitlines(), start=1):
        column = line.find(needle)
        if column != -1:
            matches.append((line_no, column + 1))
    return matches


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        try:
            return path.read_text(encoding="latin-1", errors="ignore")
        except Exception:
            return ""


@dataclass
class SecretInput:
    file: str
    value: str
    hint: Optional[str] = None
    line: Optional[int] = None


@dataclass
class SecretAnalysis:
    id: str
    source_file: str
    language: str
    secret_value: str
    secret_length: int
    secret_entropy: float
    occurrences: List[Dict[str, int]]
    context_snippet: str
    var_name: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecretsContextPlugin(AnalyzerPlugin):
    """Plugin that parses a manifest JSON of discovered secrets and enriches each with code context."""

    plugin_type = "semantic"
    supported_file_types = ("json",)
    name = "SecretsContextPlugin"

    def __init__(
        self,
        model: str = "qwen3-1.7b:latest",
        use_llm: bool = True,
        ollama_host: Optional[str] = None,
        preview_count: int = 0,
    ) -> None:
        self.model = model
        self.use_llm = use_llm
        self.ollama_host = ollama_host
        self._ollama_client: Optional[OllamaLLM] = None
        self.preview_count = max(0, int(preview_count or 0))
        self._preview_shown = 0

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        if (file_type or "").lower() != "json":
            return False
        try:
            data = json.loads(content or read_text(file_path))
        except Exception:
            return False
        if isinstance(data, dict):
            container = data.get("secrets") or data.get("entries") or data.get("items")
            return isinstance(container, list)
        if isinstance(data, list):
            return True
        return False

    def analyze(self, file_path: Path, file_type: str, content: str, results_collector=None) -> Dict[str, Any]:
        manifest = self._load_manifest(file_path, content)
        analyses: List[SecretAnalysis] = []
        llm_annotations: List[Optional[Dict[str, Any]]] = []
        self._preview_shown = 0
        total_items = len(manifest)
        failures = 0
        llm_attempts = 0
        llm_successes = 0
        start_time = time.perf_counter()
        progress_bar = self._start_progress_bar(total_items)
        text_progress_active = False
        if progress_bar is None and total_items > 0 and sys.stderr.isatty():
            text_progress_active = True
            print(f"Enriching secrets: 0/{total_items}", end="", file=sys.stderr, flush=True)

        for idx, item in enumerate(manifest):
            llm_attempted = False
            try:
                analysis, llm_info, llm_attempted = self._analyze_one(item, idx)
            except Exception as exc:
                failures += 1
                logging.exception("Failed to analyze secret #%s: %s", idx, exc)
            else:
                analyses.append(analysis)
                llm_annotations.append(llm_info)
                if llm_attempted:
                    llm_attempts += 1
                    if llm_info:
                        llm_successes += 1
            finally:
                if progress_bar:
                    progress_bar.update(1)
                elif text_progress_active:
                    current = idx + 1
                    percent = (current / total_items) * 100 if total_items else 100
                    print(
                        f"\rEnriching secrets: {current}/{total_items} ({percent:5.1f}%)",
                        end="",
                        file=sys.stderr,
                        flush=True,
                    )

        if progress_bar:
            progress_bar.close()
        elif text_progress_active:
            print(file=sys.stderr)

        elapsed = time.perf_counter() - start_time
        processed = len(analyses)
        llm_failures = max(llm_attempts - llm_successes, 0)
        llm_skipped = max(processed - llm_attempts, 0)
        stats: Dict[str, Any] = {
            "total_secrets": total_items,
            "processed": processed,
            "failures": failures,
            "llm_attempts": llm_attempts,
            "llm_successes": llm_successes,
            "llm_failures": llm_failures,
            "llm_skipped": llm_skipped,
            "duration_seconds": round(elapsed, 3),
        }
        if elapsed > 0:
            stats["secrets_per_second"] = round(processed / elapsed, 3)

        stats_message = (
            "Secrets enrichment stats | total=%d | processed=%d | failures=%d | llm=%d/%d | duration=%.2fs"
            % (total_items, processed, failures, llm_successes, llm_attempts, elapsed)
        )
        logger.info(stats_message)
        if sys.stderr.isatty():
            print(stats_message, file=sys.stderr)

        result_json = self._build_output(file_path, analyses, stats)

        if results_collector and hasattr(results_collector, "add_result"):
            for analysis, llm_info in zip(analyses, llm_annotations):
                metadata = {"source": str(file_path)}
                if llm_info:
                    metadata["llm"] = llm_info
                results_collector.add_result("secret", analysis.to_dict(), metadata=metadata)

        return result_json

    def run_from_manifest_path(self, manifest_path: Path) -> Dict[str, Any]:
        content = read_text(manifest_path)
        return self.analyze(manifest_path, "json", content)

    def _load_manifest(self, path: Path, content: Optional[str]) -> List[SecretInput]:
        raw: Any = None
        if content:
            try:
                raw = json.loads(content)
            except Exception:
                raw = None
        if raw is None:
            raw = json.loads(read_text(path))

        if isinstance(raw, dict):
            container = raw.get("secrets") or raw.get("entries") or raw.get("items") or []
        elif isinstance(raw, list):
            container = raw
        else:
            container = []

        items: List[SecretInput] = []
        for obj in container:
            if not isinstance(obj, dict):
                continue
            file_value = obj.get("file") or obj.get("file_path") or obj.get("path") or obj.get("location")
            secret_value = obj.get("value") or obj.get("secret") or obj.get("token")
            hint = obj.get("hint") or obj.get("name") or obj.get("key") or obj.get("env")
            line = obj.get("line") or obj.get("lineno")
            if file_value and secret_value:
                items.append(SecretInput(file=str(file_value), value=str(secret_value), hint=hint, line=line))
        return items

    def _analyze_one(
        self, item: SecretInput, idx: int
    ) -> Tuple[SecretAnalysis, Optional[Dict[str, Any]], bool]:
        source_path = Path(item.file)
        if not str(source_path).startswith("s3://"):
            source_path = source_path.expanduser().resolve()
        text = ""
        try:
            if source_path.exists():
                text = read_text(source_path)
        except Exception:
            text = ""

        language = detect_language_from_ext(source_path if isinstance(source_path, Path) else Path(item.file))
        occurrences = find_occurrences(text, item.value)
        var_name = self._guess_var_name(item, text, occurrences)
        snippet = self._make_context_window(text, occurrences, default_line=item.line)
        entropy = shannon_entropy(item.value)

        llm_details: Optional[Dict[str, Any]] = None
        llm_attempted = False
        if self.use_llm:
            llm_attempted = True
            try:
                llm_client = self._ensure_ollama()
                preview_callback = None
                llm_messages: Optional[List[Dict[str, str]]] = None
                if self.preview_count and self._preview_shown < self.preview_count:
                    llm_messages = llm_client.build_messages(item.value, language, snippet)
                    preview_callback = self._make_preview_callback(idx, item, language)
                llm_details = llm_client.classify(
                    item.value,
                    language,
                    snippet,
                    messages=llm_messages,
                    preview_callback=preview_callback,
                )
            except Exception as exc:
                logging.warning("LLM classification unavailable: %s", exc)
                llm_details = None

        analysis = SecretAnalysis(
            id=f"secret-{idx + 1}",
            source_file=str(source_path),
            language=language,
            secret_value=item.value,
            secret_length=len(item.value),
            secret_entropy=round(entropy, 3),
            occurrences=[{"line": ln, "column": col} for (ln, col) in occurrences],
            context_snippet=snippet,
            var_name=var_name,
        )
        return analysis, llm_details, llm_attempted

    def _ensure_ollama(self) -> OllamaLLM:
        if self._ollama_client is None:
            self._ollama_client = OllamaLLM(model=self.model, host=self.ollama_host)
        return self._ollama_client

    def _make_preview_callback(
        self,
        index: int,
        item: SecretInput,
        language: str,
    ) -> Callable[[List[Dict[str, str]], str, Optional[Dict[str, Any]]], None]:
        secret_label = f"secret-{index + 1}"
        file_display = item.file

        def _preview(
            sent_messages: List[Dict[str, str]],
            raw_response: str,
            parsed_response: Optional[Dict[str, Any]],
        ) -> None:
            if self._preview_shown >= self.preview_count:
                return
            self._preview_shown += 1
            print("", file=sys.stderr)
            print(
                f"[LLM preview {self._preview_shown}/{self.preview_count}] {secret_label} | file={file_display} | language={language}",
                file=sys.stderr,
            )
            print("-- Request --", file=sys.stderr)
            for message in sent_messages:
                role = message.get("role", "?")
                content = (message.get("content") or "").rstrip()
                print(f"{role}:", file=sys.stderr)
                print(content or "<empty>", file=sys.stderr)
                print("---", file=sys.stderr)
            print("-- Raw Response --", file=sys.stderr)
            response_text = raw_response.rstrip()
            print(response_text or "<empty>", file=sys.stderr)
            if parsed_response is not None:
                print("-- Parsed JSON --", file=sys.stderr)
                print(json.dumps(parsed_response, indent=2), file=sys.stderr)
            print("=" * 40, file=sys.stderr)
            sys.stderr.flush()

        return _preview

    @staticmethod
    def _start_progress_bar(total: int) -> Optional[Any]:
        if total <= 0:
            return None
        try:
            from tqdm import tqdm  # type: ignore
        except Exception:
            return None
        return tqdm(total=total, desc="Enriching secrets", unit="secret")

    @staticmethod
    def _guess_var_name(item: SecretInput, text: str, occurrences: List[Tuple[int, int]]) -> Optional[str]:
        if item.hint:
            return str(item.hint)
        if not text:
            return None
        lines = text.splitlines()
        for line_no, _ in occurrences[:3]:
            if 0 <= line_no - 1 < len(lines):
                line = lines[line_no - 1]
            else:
                continue
            match = re.search(r"([A-Z0-9_]{3,})\s*=\s*['\"].*?['\"]", line)
            if match:
                return match.group(1)
            match = re.search(r"export\s+([A-Z0-9_]{3,})\s*=", line)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _make_context_window(text: str, occurrences: List[Tuple[int, int]], default_line: Optional[int] = None, radius: int = 4) -> str:
        lines = text.splitlines()
        if occurrences:
            center = occurrences[0][0]
        elif default_line:
            center = int(default_line)
        else:
            return ""
        start = max(1, center - radius)
        end = min(len(lines), center + radius)
        snippet_lines = []
        for line_no in range(start, end + 1):
            snippet_lines.append(f"{line_no:>5}: {lines[line_no - 1]}")
        return "\n".join(snippet_lines)

    def _build_output(
        self, manifest_path: Path, analyses: List[SecretAnalysis], stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "version": "1.0",
            "plugin": self.name,
            "generated_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "inputs": {"manifest_path": str(manifest_path)},
            "results": [analysis.to_dict() for analysis in analyses],
            "statistics": stats,
        }


# Example usage:
# plugin = SecretsContextPlugin()
# report = plugin.run_from_manifest_path(Path("manifest.json"))
# Path("secrets_report.json").write_text(json.dumps(report, indent=2))
