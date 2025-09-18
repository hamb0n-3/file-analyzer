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


PreviewCallback = Callable[
    [
        List[Dict[str, str]],
        str,
        Optional[Dict[str, Any]],
        Optional[Dict[str, Any]],
        Optional[Dict[str, Any]],
    ],
    None,
]


class OllamaLLM:
    """Thin wrapper that now routes classification through ``llama.cpp`` instead of Ollama."""

    SYSTEM_PROMPT = (
        "You classify potential security secrets. Read the value and context and decide if it is a real secret (plain text, hashed, or encrypted). Respond with JSON containing keys: secret, type, username (optional), usage, reasoning, file_location. If it is not a secret, reply with {} only."

    )

    def __init__(
        self,
        model: Optional[str] = None,
        host: Optional[str] = None,
        n_ctx: int = 0,
        n_gpu_layers: int = 0,
        **kwargs: Any,
    ) -> None:
        default_model = os.environ["LLAMA_MODEL"]
        self.model = model or default_model
        self.host = host  # preserved for API compatibility
        try:
            from llama_cpp import Llama  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on runtime env
            raise RuntimeError(
                "llama-cpp-python is required but not installed. "
                "Install with: pip install --upgrade llama-cpp-python"
            ) from exc

        # Respect explicit chat_format if caller provided, else infer from model path
        chat_format = kwargs.pop("chat_format", None)
        if not chat_format:
            chat_format = self._infer_chat_format(self.model)

        n_threads = kwargs.pop("n_threads", None)
        if not isinstance(n_threads, int) or n_threads <= 0:
            n_threads = max(1, os.cpu_count() or 1)

        self._llama = Llama(
            model_path=self.model,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            n_batch=kwargs.pop("n_batch", 1024),  # 512-1024 is a good CPU range; see notes
            n_ubatch=kwargs.pop("n_ubatch", 256),  # micro-batch to cap peak RAM
            logits_all=kwargs.pop("logits_all", False),  # leave off unless you need logprobs
            flash_attn=kwargs.pop("flash_attn", True),  # try both True/False and keep what's faster on your CPU
            n_threads=n_threads,
            offload_kqv=kwargs.pop("offload_kqv", False),  # CPU only
            chat_format=chat_format,
            verbose=False,
            **kwargs,
        )
        self.last_usage: Dict[str, Any] = {}
        self.last_timings: Dict[str, Any] = {}

    @staticmethod
    def _infer_chat_format(model_path: str) -> Optional[str]:
        """Infer llama.cpp chat format from the model path.

        - If path contains 'gemma', enforce 'gemma' format
        - If path contains 'qwen2', enforce 'qwen2'
        - Else if contains 'qwen', enforce 'qwen'
        Returns None if no specific format inferred.
        """
        mp = (model_path or "").lower()
        if "gemma" in mp:
            return "gemma"
        if "qwen2" in mp:
            return "qwen2"
        if "qwen" in mp:
            return "qwen"
        return None

    def build_messages(self, raw_secret: str, language: str, context_snippet: str) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"FILE TYPE: {language}\n"
                    f"SECRET: {raw_secret}\n"
                    f"CONTEXT:\n{context_snippet}\n"
                    "If there is a secret ONLY reply with a JSON using these keys: SECRET, type, username (optional), usage, reasoning, file location. Else reply with \{\} only."
                ),
            },
        ]

    @staticmethod
    def _parse_json_response(response_text: str) -> Optional[Dict[str, Any]]:
        content = response_text.strip()
        if not content:
            return None
        try:
            return json.loads(content)
        except Exception:
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(content[start : end + 1])
                except Exception:
                    logging.debug("Unable to parse llama.cpp JSON payload", exc_info=True)
            return None

    def classify(
        self,
        raw_secret: str,
        language: str,
        context_snippet: str,
        *,
        messages: Optional[List[Dict[str, str]]] = None,
        preview_callback: Optional[PreviewCallback] = None,
    ) -> Optional[Dict[str, Any]]:
        messages = messages or self.build_messages(raw_secret, language, context_snippet)
        self.last_usage = {}
        self.last_timings = {}
        try:
            response = self._llama.create_chat_completion(
                messages=messages,
                temperature=0.5,
                max_tokens=1000,
            )
        except Exception as exc:
            logging.warning("llama.cpp chat failed: %s", exc)
            return None

        usage_info: Optional[Dict[str, Any]] = None
        timings_info: Optional[Dict[str, Any]] = None
        if isinstance(response, dict):
            usage_info = response.get("usage")
            timings_info = response.get("timings")
            if isinstance(usage_info, dict):
                self.last_usage = usage_info
            if isinstance(timings_info, dict):
                self.last_timings = timings_info

        try:
            content = response["choices"][0]["message"]["content"]
        except Exception:
            content = ""
        parsed: Optional[Dict[str, Any]] = None
        if content:
            parsed = self._parse_json_response(content)
        if preview_callback:
            try:
                preview_callback(messages, content, parsed, usage_info, timings_info)
            except Exception:
                logging.debug("Preview callback raised an exception", exc_info=True)
        return parsed


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


def find_occurrences(
    text: str,
    needle: str,
    lines: Optional[List[str]] = None,
) -> List[Tuple[int, int]]:
    matches: List[Tuple[int, int]] = []
    if not needle:
        return matches
    search_lines = lines if lines is not None else text.splitlines()
    if not search_lines:
        return matches
    for line_no, line in enumerate(search_lines, start=1):
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
        model: str = os.environ["LLAMA_MODEL"],
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
        self._resolved_paths: Dict[str, Path] = {}
        self._path_exists_cache: Dict[str, bool] = {}
        self._file_cache: Dict[str, Tuple[str, List[str]]] = {}
        self._file_cache_hits = 0
        self._file_cache_misses = 0
        # Hints to resolve relative paths robustly
        self._search_base_dirs: List[Path] = []
        self._cwd: Path = Path.cwd()
        self._reset_llm_usage()

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
        self._resolved_paths.clear()
        self._path_exists_cache.clear()
        self._file_cache.clear()
        self._file_cache_hits = 0
        self._file_cache_misses = 0
        self._reset_llm_usage()
        # Build a list of base directories to try when resolving relative paths.
        # This makes analysis robust regardless of the current working directory.
        try:
            manifest_dir = Path(file_path).parent
            # Include manifest directory and all its ancestors (towards root)
            bases = [manifest_dir]
            bases.extend(list(manifest_dir.parents))
            # Deduplicate while preserving order
            seen: set[str] = set()
            self._search_base_dirs = []
            for b in bases:
                key = str(b)
                if key in seen:
                    continue
                seen.add(key)
                self._search_base_dirs.append(b)
        except Exception:
            self._search_base_dirs = []
        total_items = len(manifest)
        target_items = min(total_items, self.preview_count) if self.preview_count else total_items
        failures = 0
        llm_attempts = 0
        llm_successes = 0
        llm_total_latency = 0.0
        llm_max_latency = 0.0
        start_time = time.perf_counter()
        progress_bar = self._start_progress_bar(target_items)
        text_progress_active = False
        if progress_bar is None and target_items > 0 and sys.stderr.isatty():
            text_progress_active = True
            print(
                f"Enriching secrets: 0/{target_items}",
                end="",
                file=sys.stderr,
                flush=True,
            )

        items_attempted = 0
        preview_limit_reached = False

        for idx, item in enumerate(manifest):
            if target_items and items_attempted >= target_items:
                preview_limit_reached = self.preview_count > 0
                break
            items_attempted += 1
            llm_attempted = False
            try:
                analysis, llm_info, llm_attempted, llm_duration = self._analyze_one(item, idx)
            except Exception as exc:
                failures += 1
                logging.exception("Failed to analyze secret #%s: %s", idx, exc)
            else:
                analyses.append(analysis)
                llm_annotations.append(llm_info)
                if llm_attempted:
                    llm_attempts += 1
                    llm_total_latency += llm_duration
                    if llm_duration > llm_max_latency:
                        llm_max_latency = llm_duration
                    if llm_info:
                        llm_successes += 1
            finally:
                if progress_bar:
                    progress_bar.update(1)
                elif text_progress_active:
                    current = items_attempted
                    total_for_display = target_items if target_items else items_attempted
                    percent = (
                        (current / total_for_display) * 100 if total_for_display else 100
                    )
                    print(
                        f"\rEnriching secrets: {current}/{total_for_display} ({percent:5.1f}%)",
                        end="",
                        file=sys.stderr,
                        flush=True,
                    )

        if progress_bar:
            progress_bar.close()
        elif text_progress_active:
            print(file=sys.stderr)

        if preview_limit_reached:
            message = f"Preview limit reached ({target_items}); stopping early."
            logger.info(message)
            if sys.stderr.isatty():
                print(message, file=sys.stderr)

        elapsed = time.perf_counter() - start_time
        processed = len(analyses)
        llm_failures = max(llm_attempts - llm_successes, 0)
        llm_skipped = max(processed - llm_attempts, 0)
        stats: Dict[str, Any] = {
            "total_secrets": total_items,
            "target_secrets": target_items,
            "attempted": items_attempted,
            "processed": processed,
            "failures": failures,
            "llm_attempts": llm_attempts,
            "llm_successes": llm_successes,
            "llm_failures": llm_failures,
            "llm_skipped": llm_skipped,
            "duration_seconds": round(elapsed, 3),
            "llm_total_seconds": round(llm_total_latency, 3),
            "file_cache_hits": self._file_cache_hits,
            "file_cache_misses": self._file_cache_misses,
            "cached_files": len(self._file_cache),
        }
        if self.preview_count:
            stats["preview_limit"] = target_items
            stats["preview_stopped_early"] = preview_limit_reached
        if elapsed > 0:
            stats["secrets_per_second"] = round(processed / elapsed, 3)
        if llm_attempts > 0:
            stats["llm_avg_seconds"] = round(llm_total_latency / llm_attempts, 3)
            stats["llm_max_seconds"] = round(llm_max_latency, 3)

        stats["llm_usage"] = self._summarize_llm_usage()
        # Convenience roll-ups for easy display/consumption
        llm_normal = stats["llm_usage"].get("normal", {}) if isinstance(stats.get("llm_usage"), dict) else {}
        if llm_attempts > 0 and isinstance(llm_normal, dict):
            stats["llm_tokens_per_second"] = llm_normal.get("tokens_per_second", 0.0)
            stats["llm_prompt_eval_seconds"] = llm_normal.get("prompt_eval_seconds", 0.0)
            stats["llm_completion_eval_seconds"] = llm_normal.get("completion_eval_seconds", 0.0)
            stats["llm_prompt_tokens_per_second"] = llm_normal.get("prompt_tokens_per_second", 0.0)
            stats["llm_completion_tokens_per_second"] = llm_normal.get(
                "completion_tokens_per_second", 0.0
            )

        stats_message = (
            "Secrets enrichment stats | total=%d | processed=%d | failures=%d | llm=%d/%d | duration=%.2fs"
            % (total_items, processed, failures, llm_successes, llm_attempts, elapsed)
        )
        if llm_attempts > 0:
            stats_message += " | llm_time=%.2fs avg=%.2fs" % (
                llm_total_latency,
                stats["llm_avg_seconds"],
            )
            # Add token and timing rates for quick visibility
            tps = float(stats.get("llm_tokens_per_second") or 0.0)
            ptps = float(stats.get("llm_prompt_tokens_per_second") or 0.0)
            ctps = float(stats.get("llm_completion_tokens_per_second") or 0.0)
            if tps:
                stats_message += " | tok/s=%.1f" % tps
            if ptps or ctps:
                stats_message += " | prompt_tok/s=%.1f completion_tok/s=%.1f" % (ptps, ctps)
            pe = float(stats.get("llm_prompt_eval_seconds") or 0.0)
            ce = float(stats.get("llm_completion_eval_seconds") or 0.0)
            # Always show eval times even if backend didn't provide them
            stats_message += " | prompt_eval=%.2fs completion_eval=%.2fs" % (pe, ce)
        if preview_limit_reached:
            stats_message += f" | preview_limit={target_items}"
        logger.info(stats_message)
        if sys.stderr.isatty():
            print(stats_message, file=sys.stderr)

        result_json = self._build_output(file_path, analyses, llm_annotations, stats)

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

    def _load_source_material(self, raw_path: str) -> Tuple[Path, str, List[str]]:
        if self._is_remote_path(raw_path):
            return Path(raw_path), "", []
        resolved = self._resolve_local_path(raw_path)
        text, lines = self._get_cached_file_content(resolved)
        return resolved, text, lines

    @staticmethod
    def _is_remote_path(raw_path: str) -> bool:
        return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_path))

    def _resolve_local_path(self, raw_path: str) -> Path:
        """Resolve a local path robustly.

        Tries, in order:
        - As provided (relative to CWD) if it exists
        - Relative to the manifest directory
        - Relative to ancestors of the manifest directory
        Falls back to the best-effort absolute path if not found.
        """
        cached = self._resolved_paths.get(raw_path)
        if cached is not None:
            return cached

        # Expand user first
        path = Path(raw_path).expanduser()

        # If already absolute, or exists relative to CWD, prefer it
        try:
            if path.is_absolute() and path.exists():
                resolved = path
                self._resolved_paths[raw_path] = resolved
                return resolved
        except Exception:
            pass

        # Try as-is relative to current working directory
        try:
            candidate = (self._cwd / path) if not path.is_absolute() else path
            if candidate.exists():
                resolved = candidate.resolve(strict=False)
                self._resolved_paths[raw_path] = resolved
                return resolved
        except Exception:
            pass

        # Try resolving relative to manifest directory and its ancestors
        for base in self._search_base_dirs:
            try:
                candidate = (base / path) if not path.is_absolute() else path
                if candidate.exists():
                    resolved = candidate.resolve(strict=False)
                    self._resolved_paths[raw_path] = resolved
                    return resolved
            except Exception:
                continue

        # Best-effort: return an absolute version (may not exist)
        try:
            resolved = path.resolve(strict=False)
        except Exception:
            resolved = path.absolute()
        self._resolved_paths[raw_path] = resolved
        return resolved

    def _get_cached_file_content(self, path: Path) -> Tuple[str, List[str]]:
        key = str(path)
        cached = self._file_cache.get(key)
        if cached is not None:
            self._file_cache_hits += 1
            return cached

        self._file_cache_misses += 1
        exists = self._path_exists_cache.get(key)
        if exists is None:
            exists = path.exists()
            self._path_exists_cache[key] = exists

        text = ""
        if exists:
            try:
                text = read_text(path)
            except Exception:
                text = ""

        lines = text.splitlines() if text else []
        cached_value = (text, lines)
        self._file_cache[key] = cached_value
        return cached_value

    def _analyze_one(
        self, item: SecretInput, idx: int
    ) -> Tuple[SecretAnalysis, Optional[Dict[str, Any]], bool, float]:
        source_path, text, lines = self._load_source_material(item.file)

        language = detect_language_from_ext(source_path)
        occurrences = find_occurrences(text, item.value, lines)
        var_name = self._guess_var_name(item, lines, occurrences)
        snippet = self._make_context_window(lines, occurrences, default_line=item.line)
        entropy = shannon_entropy(item.value)

        llm_details: Optional[Dict[str, Any]] = None
        llm_attempted = False
        llm_duration = 0.0
        llm_usage_payload: Optional[Dict[str, Any]] = None
        llm_timings_payload: Optional[Dict[str, Any]] = None
        is_preview_call = False
        if self.use_llm:
            llm_attempted = True
            llm_start = time.perf_counter()
            bucket_key = "normal"
            llm_client: Optional[OllamaLLM] = None
            try:
                llm_client = self._ensure_ollama()
                preview_callback = None
                llm_messages: Optional[List[Dict[str, str]]] = None
                if self.preview_count and self._preview_shown < self.preview_count:
                    llm_messages = llm_client.build_messages(item.value, language, snippet)
                    preview_callback = self._make_preview_callback(idx, item, language)
                    is_preview_call = True
                    bucket_key = "preview"
                llm_details = llm_client.classify(
                    item.value,
                    language,
                    snippet,
                    messages=llm_messages,
                    preview_callback=preview_callback,
                )
                llm_usage_payload = getattr(llm_client, "last_usage", None)
                llm_timings_payload = getattr(llm_client, "last_timings", None)
            except Exception as exc:
                logging.warning("LLM classification unavailable: %s", exc)
                llm_details = None
            finally:
                llm_duration = time.perf_counter() - llm_start
                if llm_client is not None:
                    if not isinstance(llm_usage_payload, dict):
                        llm_usage_payload = getattr(llm_client, "last_usage", None)
                    if not isinstance(llm_timings_payload, dict):
                        llm_timings_payload = getattr(llm_client, "last_timings", None)
                    self._record_llm_usage(
                        "preview" if is_preview_call else bucket_key,
                        llm_duration,
                        llm_usage_payload,
                        llm_timings_payload,
                    )

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
        return analysis, llm_details, llm_attempted, llm_duration

    @staticmethod
    def _new_llm_usage_bucket() -> Dict[str, Any]:
        return {
            "calls": 0,
            "total_seconds": 0.0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "prompt_eval_seconds": 0.0,
            "prompt_eval_tokens": 0,
            "completion_eval_seconds": 0.0,
            "completion_eval_tokens": 0,
        }

    def _reset_llm_usage(self) -> None:
        self._llm_usage: Dict[str, Dict[str, Any]] = {
            "normal": self._new_llm_usage_bucket(),
            "preview": self._new_llm_usage_bucket(),
        }

    def _record_llm_usage(
        self,
        bucket: str,
        duration: float,
        usage: Optional[Dict[str, Any]],
        timings: Optional[Dict[str, Any]],
    ) -> None:
        bucket_stats = self._llm_usage.get(bucket)
        if bucket_stats is None:
            bucket_stats = self._new_llm_usage_bucket()
            self._llm_usage[bucket] = bucket_stats
        bucket_stats["calls"] += 1
        bucket_stats["total_seconds"] += max(duration, 0.0)

        if isinstance(usage, dict):
            prompt_tokens = int(usage.get("prompt_tokens") or 0)
            completion_tokens = int(usage.get("completion_tokens") or 0)
            total_tokens = int(usage.get("total_tokens") or prompt_tokens + completion_tokens)
            bucket_stats["prompt_tokens"] += prompt_tokens
            bucket_stats["completion_tokens"] += completion_tokens
            bucket_stats["total_tokens"] += total_tokens

        if isinstance(timings, dict):
            prompt_eval_ms = timings.get("prompt_eval_time") or 0.0
            prompt_eval_tokens = int(timings.get("prompt_eval_count") or 0)
            completion_eval_ms = timings.get("predicted_eval_time") or timings.get("eval_time") or 0.0
            completion_eval_tokens = int(
                timings.get("predicted_eval_count") or timings.get("eval_count") or 0
            )
            bucket_stats["prompt_eval_seconds"] += max(float(prompt_eval_ms) / 1000.0, 0.0)
            bucket_stats["prompt_eval_tokens"] += max(prompt_eval_tokens, 0)
            bucket_stats["completion_eval_seconds"] += max(float(completion_eval_ms) / 1000.0, 0.0)
            bucket_stats["completion_eval_tokens"] += max(completion_eval_tokens, 0)

    def _summarize_llm_usage(self) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        for bucket_name in ("normal", "preview"):
            bucket_stats = self._llm_usage.get(bucket_name) or self._new_llm_usage_bucket()
            summary[bucket_name] = self._summarize_llm_bucket(bucket_stats)
        return summary

    @staticmethod
    def _summarize_llm_bucket(bucket_stats: Dict[str, Any]) -> Dict[str, Any]:
        calls = int(bucket_stats.get("calls", 0))
        total_seconds = float(bucket_stats.get("total_seconds", 0.0))
        prompt_tokens = int(bucket_stats.get("prompt_tokens", 0))
        completion_tokens = int(bucket_stats.get("completion_tokens", 0))
        total_tokens = int(bucket_stats.get("total_tokens", 0))
        prompt_eval_seconds = float(bucket_stats.get("prompt_eval_seconds", 0.0))
        completion_eval_seconds = float(bucket_stats.get("completion_eval_seconds", 0.0))
        prompt_eval_tokens = int(bucket_stats.get("prompt_eval_tokens", 0))
        completion_eval_tokens = int(bucket_stats.get("completion_eval_tokens", 0))

        average_seconds = total_seconds / calls if calls else 0.0
        tokens_per_second = (
            total_tokens / total_seconds if total_tokens > 0 and total_seconds > 0 else 0.0
        )

        prompt_time_for_rate = prompt_eval_seconds if prompt_eval_seconds > 0 else total_seconds
        prompt_tokens_for_rate = prompt_eval_tokens if prompt_eval_tokens > 0 else prompt_tokens
        prompt_tokens_per_second = (
            prompt_tokens_for_rate / prompt_time_for_rate
            if prompt_tokens_for_rate > 0 and prompt_time_for_rate > 0
            else 0.0
        )

        completion_time_for_rate = (
            completion_eval_seconds if completion_eval_seconds > 0 else total_seconds
        )
        completion_tokens_for_rate = (
            completion_eval_tokens if completion_eval_tokens > 0 else completion_tokens
        )
        completion_tokens_per_second = (
            completion_tokens_for_rate / completion_time_for_rate
            if completion_tokens_for_rate > 0 and completion_time_for_rate > 0
            else 0.0
        )

        return {
            "calls": calls,
            "total_seconds": round(total_seconds, 3) if total_seconds else 0.0,
            "average_seconds": round(average_seconds, 3) if average_seconds else 0.0,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "tokens_per_second": round(tokens_per_second, 3) if tokens_per_second else 0.0,
            "prompt_eval_seconds": round(prompt_eval_seconds, 3) if prompt_eval_seconds else 0.0,
            "prompt_tokens_per_second": round(prompt_tokens_per_second, 3)
            if prompt_tokens_per_second
            else 0.0,
            "completion_eval_seconds": round(completion_eval_seconds, 3)
            if completion_eval_seconds
            else 0.0,
            "completion_tokens_per_second": round(completion_tokens_per_second, 3)
            if completion_tokens_per_second
            else 0.0,
        }

    def _ensure_ollama(self) -> OllamaLLM:
        if self._ollama_client is None:
            self._ollama_client = OllamaLLM(model=self.model, host=self.ollama_host)
        return self._ollama_client

    def _make_preview_callback(
        self,
        index: int,
        item: SecretInput,
        language: str,
    ) -> PreviewCallback:
        secret_label = f"secret-{index + 1}"
        file_display = item.file

        def _preview(
            sent_messages: List[Dict[str, str]],
            raw_response: str,
            parsed_response: Optional[Dict[str, Any]],
            usage_payload: Optional[Dict[str, Any]],
            timings_payload: Optional[Dict[str, Any]],
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
            prompt_tokens = 0
            completion_tokens = 0
            total_tokens = 0
            prompt_tokens_per_second = 0.0
            if isinstance(usage_payload, dict):
                prompt_tokens = int(usage_payload.get("prompt_tokens") or 0)
                completion_tokens = int(usage_payload.get("completion_tokens") or 0)
                total_tokens = int(
                    usage_payload.get("total_tokens")
                    or (prompt_tokens + completion_tokens)
                )
            prompt_eval_seconds = 0.0
            completion_eval_seconds = 0.0
            completion_tokens_per_second = 0.0
            if isinstance(timings_payload, dict):
                prompt_eval_ms = timings_payload.get("prompt_eval_time") or 0.0
                prompt_eval_seconds = max(float(prompt_eval_ms) / 1000.0, 0.0)
                if prompt_tokens and prompt_eval_seconds > 0:
                    prompt_tokens_per_second = prompt_tokens / prompt_eval_seconds
                # Completion timings/rate if provided by backend
                completion_eval_ms = (
                    timings_payload.get("predicted_eval_time")
                    or timings_payload.get("eval_time")
                    or 0.0
                )
                completion_eval_seconds = max(float(completion_eval_ms) / 1000.0, 0.0)
                if completion_tokens and completion_eval_seconds > 0:
                    completion_tokens_per_second = completion_tokens / completion_eval_seconds
            print("-- Token Statistics --", file=sys.stderr)
            print(
                f"prompt_tokens={prompt_tokens} | completion_tokens={completion_tokens} | total_tokens={total_tokens}",
                file=sys.stderr,
            )
            if prompt_tokens_per_second:
                print(
                    f"prompt_tokens_per_second={prompt_tokens_per_second:.3f} (over {prompt_eval_seconds:.3f}s)",
                    file=sys.stderr,
                )
            else:
                reason = "timing unavailable" if prompt_eval_seconds == 0.0 else "no prompt tokens"
                print(
                    f"prompt_tokens_per_second=N/A ({reason})",
                    file=sys.stderr,
                )
            if completion_tokens_per_second:
                print(
                    f"completion_tokens_per_second={completion_tokens_per_second:.3f} (over {completion_eval_seconds:.3f}s)",
                    file=sys.stderr,
                )
            else:
                reason = (
                    "timing unavailable" if completion_eval_seconds == 0.0 else "no completion tokens"
                )
                print(
                    f"completion_tokens_per_second=N/A ({reason})",
                    file=sys.stderr,
                )
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
    def _guess_var_name(
        item: SecretInput, lines: List[str], occurrences: List[Tuple[int, int]]
    ) -> Optional[str]:
        if item.hint:
            return str(item.hint)
        if not lines:
            return None
        for line_no, _ in occurrences[:3]:
            if not (0 <= line_no - 1 < len(lines)):
                continue
            line = lines[line_no - 1]
            match = re.search(r"([A-Z0-9_]{3,})\s*=\s*['\"].*?['\"]", line)
            if match:
                return match.group(1)
            match = re.search(r"export\s+([A-Z0-9_]{3,})\s*=", line)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _make_context_window(
        lines: List[str],
        occurrences: List[Tuple[int, int]],
        default_line: Optional[int] = None,
        radius: int = 4,
    ) -> str:
        if not lines:
            return ""
        if occurrences:
            center = occurrences[0][0]
        elif default_line:
            center = int(default_line)
        else:
            return ""
        start = max(1, center - radius)
        end = min(len(lines), center + radius)
        if start > end:
            return ""
        snippet_lines = []
        for line_no in range(start, end + 1):
            snippet_lines.append(f"{line_no:>5}: {lines[line_no - 1]}")
        return "\n".join(snippet_lines)

    def _build_output(
        self,
        manifest_path: Path,
        analyses: List[SecretAnalysis],
        llm_annotations: List[Optional[Dict[str, Any]]],
        stats: Dict[str, Any],
    ) -> Dict[str, Any]:
        generated_at = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

        def _normalize_llm_payload(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
            normalized: Dict[str, Any] = {}
            if not isinstance(raw, dict):
                return normalized
            for key, value in raw.items():
                if not isinstance(key, str):
                    continue
                spaced_key = re.sub(r"(?<!^)(?=[A-Z])", " ", key)
                normalized_key = spaced_key.replace("_", " ").strip().lower()
                normalized[normalized_key] = value
            return normalized

        results: List[Dict[str, Any]] = []
        for index, analysis in enumerate(analyses):
            llm_payload = llm_annotations[index] if index < len(llm_annotations) else None
            normalized = _normalize_llm_payload(llm_payload)
            username_value = (
                normalized.get("username")
                or normalized.get("user name")
                or normalized.get("user")
            )

            fallback_location = analysis.source_file
            if analysis.occurrences:
                first_occurrence = analysis.occurrences[0]
                line = first_occurrence.get("line")
                column = first_occurrence.get("column")
                if line is not None:
                    fallback_location = f"{fallback_location}:{line}"
                    if column is not None:
                        fallback_location = f"{fallback_location}:{column}"

            result_entry: Dict[str, Any] = {
                "secret": normalized.get("secret", analysis.secret_value),
                "type": normalized.get("type", ""),
                "usage": normalized.get("usage", ""),
                "reasoning": normalized.get("reasoning", ""),
                "file location": normalized.get("file location") or fallback_location,
            }
            if username_value:
                result_entry["username"] = username_value

            results.append(result_entry)

        runs_metadata = {
            "generated_at": generated_at,
            "plugin": self.name,
            "inputs": {"manifest_path": str(manifest_path)},
            "statistics": stats,
        }

        return {"results": results, "runs": runs_metadata}


# Example usage:
# plugin = SecretsContextPlugin()
# report = plugin.run_from_manifest_path(Path("manifest.json"))
# Path("secrets_report.json").write_text(json.dumps(report, indent=2))
