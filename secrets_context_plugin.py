#!/usr/bin/env python3
"""
Secrets Context Plugin

A drop-in, standalone plugin that:
  • Reads a manifest JSON describing discovered secrets, each with file locations and the secret value.
  • Opens the referenced files, finds the secret in-context, and extracts useful context (variable name, nearby lines, etc.).
  • (Optionally) uses a small local LLM via Ollama to classify each secret (api_key, jwt, password, etc.) and infer vendor/provider.
  • Emits a final JSON in a stable, explicit format.

It is designed to work in two modes:
  1) Standalone CLI (see run_secrets_plugin.py)
  2) As a plugin class compatible with a typical AnalyzerPlugin interface (if present).

Security notes:
  • Raw secrets are never sent to the LLM; only a redacted form (****last4) plus a short context window is used.
  • Output JSON stores only a hash and last4 of the secret (not the full value).
"""

from __future__ import annotations

import os
import json
import re
import math
import hashlib
import logging
import datetime
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple, Iterable
from pathlib import Path

# ---- Optional: integrate with an AnalyzerPlugin base if available ----
try:
    # If your project exposes a base interface, we try to import it.
    from base_plugin import AnalyzerPlugin  # local import path; adjust if your project uses packages
except Exception:
    # Fallback minimal base to keep this module self-contained.
    class AnalyzerPlugin:  # type: ignore
        plugin_type: str = "semantic"
        supported_file_types: Iterable[str] = ("json",)
        name: str = "SecretsContextPlugin"

        def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
            raise NotImplementedError

        def analyze(self, file_path: Path, file_type: str, content: str, results_collector=None) -> Dict[str, Any]:
            raise NotImplementedError

# ---- Helper: small client for Ollama ----
class OllamaLLM:
    """
    Minimal Ollama client: will prefer the 'ollama' Python package if present,
    otherwise falls back to direct HTTP calls. If neither is available, .available() is False.
    """
    def __init__(self, model: str = "llama3.2:3b", host: Optional[str] = None, request_timeout: int = 30) -> None:
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.request_timeout = request_timeout
        self._use_pkg = False
        self._ollama = None
        try:
            import ollama  # type: ignore
            self._ollama = ollama
            self._use_pkg = True
        except Exception:
            self._use_pkg = False

    def available(self) -> bool:
        if self._use_pkg and self._ollama:
            try:
                # Cheap list call
                _ = self._ollama.list()
                return True
            except Exception:
                return False
        # Try HTTP
        try:
            import urllib.request, json as _json
            req = urllib.request.Request(self.host.rstrip("/") + "/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=self.request_timeout) as resp:
                _ = _json.loads(resp.read().decode("utf-8", errors="ignore"))
            return True
        except Exception:
            return False

    def classify(self, redacted_value: str, language: str, context_snippet: str) -> Dict[str, Any]:
        """
        Ask the small LLM to classify the secret type/provider and return structured JSON.
        We instruct the model to reply in pure JSON (robust to extra text via a post-parse step).
        """
        system = (
            "You are a security assistant. "
            "Given a redacted secret value and a small code snippet, "
            "classify the likely type (api_key, oauth_token, jwt, password, private_key, client_secret, "
            "webhook_secret, database_password, ssh_key, certificate, cloud_credential, other) "
            "and the probable provider (e.g., OpenAI, Stripe, AWS, Google, GitHub, Slack, Twilio, etc.). "
            "Return strict JSON with fields: type, provider, confidence (0..1), severity (low|medium|high), "
            "is_placeholder (boolean), usage (short phrase), reasoning (<=40 words)."
        )
        user = f"""
LANGUAGE: {language}
SECRET (REDACTED): {redacted_value}
CONTEXT:
{context_snippet}
Please reply with JSON only.
""".strip()

        prompt_messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

        # Default result if LLM is unavailable or fails
        default = {
            "type": "unknown",
            "provider": "unknown",
            "confidence": 0.3,
            "severity": "medium",
            "is_placeholder": False,
            "usage": "unknown",
            "reasoning": "LLM unavailable or fallback heuristics used."
        }

        try:
            if self._use_pkg and self._ollama:
                resp = self._ollama.chat(model=self.model, messages=prompt_messages)
                text = resp.get("message", {}).get("content", "")
                return self._parse_json_response(text, default)
            else:
                import urllib.request, json as _json
                payload = _json.dumps({"model": self.model, "messages": prompt_messages}).encode("utf-8")
                req = urllib.request.Request(self.host.rstrip("/") + "/api/chat",
                                             data=payload,
                                             headers={"Content-Type": "application/json"},
                                             method="POST")
                with urllib.request.urlopen(req, timeout=self.request_timeout) as resp:
                    text = resp.read().decode("utf-8", errors="ignore")
                    # Ollama HTTP chat may stream or return JSON; handle both
                    try:
                        data = _json.loads(text)
                        msg = data.get("message", {}).get("content", "")
                        return self._parse_json_response(msg, default)
                    except Exception:
                        # If streaming-like response, try to extract trailing JSON
                        return self._parse_json_response(text, default)
        except Exception:
            return default

    @staticmethod
    def _parse_json_response(raw: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
        import json as _json
        # Try strict JSON parse first
        try:
            return _json.loads(raw)
        except Exception:
            # Try to extract JSON substring
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if not m:
                return fallback
            try:
                return _json.loads(m.group(0))
            except Exception:
                return fallback


# ---- Utility helpers ----
def shannon_entropy(s: str) -> float:
    """Compute per-character Shannon entropy."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    l = len(s)
    for count in freq.values():
        p = count / l
        ent -= p * math.log2(p)
    return ent

def mask_secret(value: str, show: int = 4) -> str:
    """Mask all but the last `show` characters."""
    if value is None:
        return ""
    n = max(0, len(value) - show)
    return "•" * n + value[-show:]

def detect_language_from_ext(path: Path) -> str:
    ext = path.suffix.lower()
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
    }.get(ext, "text")

def find_occurrences(text: str, needle: str) -> List[Tuple[int, int]]:
    """
    Return list of (line_no, col) where `needle` occurs in `text`.
    line_no is 1-based.
    """
    out = []
    if not text or not needle:
        return out
    start = 0
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        col = line.find(needle)
        if col != -1:
            out.append((i, col + 1))
    return out

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
    hint: Optional[str] = None   # variable name, env name, etc.
    line: Optional[int] = None

@dataclass
class SecretAnalysis:
    id: str
    source_file: str
    language: str
    secret_last4: str
    secret_hash: str
    secret_length: int
    secret_entropy: float
    occurrences: List[Dict[str, int]]
    context_snippet: str
    var_name: Optional[str]
    llm_type: str
    llm_provider: str
    llm_confidence: float
    llm_severity: str
    llm_is_placeholder: bool
    llm_usage: str
    llm_reasoning: str
    tags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecretsContextPlugin(AnalyzerPlugin):
    """
    Plugin that parses a manifest JSON of discovered secrets and enriches each with context,
    optionally classifying them with a small local LLM via Ollama.
    """

    plugin_type = "semantic"
    supported_file_types = ("json",)
    name = "SecretsContextPlugin"

    def __init__(self, model: str = "llama3.2:3b", use_llm: bool = True, ollama_host: Optional[str] = None) -> None:
        self.model = model
        self.use_llm = use_llm
        self.ollama = OllamaLLM(model=model, host=ollama_host)

    # ---------- AnalyzerPlugin interface ----------
    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        """
        We can analyze JSON files that look like a "secrets manifest".
        Accepted schema (flexible):
          {
            "secrets": [
                {"file": "/abs/or/relative/path", "value": "the_secret", "hint": "ENV_NAME", "line": 23},
                ...
            ]
          }
        or a bare list under "entries" / "items".
        """
        if (file_type or "").lower() not in {"json"}:
            return False

        try:
            data = json.loads(content or read_text(file_path))
        except Exception:
            return False

        if isinstance(data, dict):
            container = data.get("secrets") or data.get("entries") or data.get("items")
            return isinstance(container, list)
        elif isinstance(data, list):
            return True
        return False

    def analyze(self, file_path: Path, file_type: str, content: str, results_collector=None) -> Dict[str, Any]:
        """
        Return a normalized dict matching the "final JSON" schema defined below.
        If 'results_collector' exists and exposes add_result(...), you may hook it; otherwise we return the JSON.
        """
        manifest = self._load_manifest(file_path, content)
        analyses: List[SecretAnalysis] = []

        for idx, item in enumerate(manifest):
            try:
                analysis = self._analyze_one(item, idx)
                analyses.append(analysis)
            except Exception as e:
                logging.exception("Failed to analyze secret #%s: %s", idx, e)

        result_json = self._build_output(file_path, analyses)

        # Optional: integrate with a collector if provided by your framework
        if results_collector and hasattr(results_collector, "add_result"):
            for a in analyses:
                payload = a.to_dict()
                # category: choose something generic for secrets
                results_collector.add_result("secret", payload, metadata={"source": str(file_path)})
        return result_json

    # ---------- Standalone helpers ----------
    def run_from_manifest_path(self, manifest_path: Path) -> Dict[str, Any]:
        content = read_text(manifest_path)
        return self.analyze(manifest_path, "json", content)

    # ---------- Internals ----------
    def _load_manifest(self, path: Path, content: Optional[str]) -> List[SecretInput]:
        raw = None
        if content:
            try:
                raw = json.loads(content)
            except Exception:
                raw = None

        if raw is None:
            try:
                raw = json.loads(read_text(path))
            except Exception as e:
                raise ValueError(f"Failed to load JSON manifest: {e}") from e

        items = []
        if isinstance(raw, dict):
            container = raw.get("secrets") or raw.get("entries") or raw.get("items") or []
        elif isinstance(raw, list):
            container = raw
        else:
            container = []

        for obj in container:
            if not isinstance(obj, dict):
                continue
            file_ = obj.get("file") or obj.get("file_path") or obj.get("path") or obj.get("location")
            value = obj.get("value") or obj.get("secret") or obj.get("token")
            hint = obj.get("hint") or obj.get("name") or obj.get("key") or obj.get("env")
            line = obj.get("line") or obj.get("lineno")
            if file_ and value:
                items.append(SecretInput(file=str(file_), value=str(value), hint=hint, line=line))
        return items

    def _analyze_one(self, item: SecretInput, idx: int) -> SecretAnalysis:
        source_path = Path(item.file).expanduser().resolve() if not str(item.file).startswith("s3://") else Path(item.file)
        text = ""
        try:
            if source_path.exists():
                text = read_text(source_path)
        except Exception:
            text = ""

        language = detect_language_from_ext(source_path if isinstance(source_path, Path) else Path(item.file))
        occurrences = find_occurrences(text, item.value)
        var_name = self._guess_var_name(item, text, occurrences)

        ctx = self._make_context_window(text, occurrences, default_line=item.line)
        masked = mask_secret(item.value)
        last4 = (item.value[-4:] if item.value else "")
        digest = "sha256:" + hashlib.sha256(item.value.encode("utf-8")).hexdigest()
        entropy = shannon_entropy(item.value)

        # LLM classification (optional)
        llm = {
            "type": "unknown",
            "provider": "unknown",
            "confidence": 0.3,
            "severity": "medium",
            "is_placeholder": False,
            "usage": "unknown",
            "reasoning": "No LLM used."
        }
        if self.use_llm and self.ollama.available():
            llm = self.ollama.classify(masked, language, ctx)

        tags = self._make_tags(llm, language)

        return SecretAnalysis(
            id=f"secret-{idx+1}",
            source_file=str(source_path),
            language=language,
            secret_last4=last4,
            secret_hash=digest,
            secret_length=len(item.value),
            secret_entropy=round(entropy, 3),
            occurrences=[{"line": ln, "column": col} for (ln, col) in occurrences],
            context_snippet=ctx,
            var_name=var_name,
            llm_type=llm.get("type","unknown"),
            llm_provider=llm.get("provider","unknown"),
            llm_confidence=float(llm.get("confidence", 0.3)),
            llm_severity=llm.get("severity","medium"),
            llm_is_placeholder=bool(llm.get("is_placeholder", False)),
            llm_usage=llm.get("usage","unknown"),
            llm_reasoning=llm.get("reasoning",""),
            tags=tags,
        )

    @staticmethod
    def _make_tags(llm: Dict[str, Any], language: str) -> List[str]:
        tags = []
        t = (llm.get("type") or "unknown").lower()
        p = (llm.get("provider") or "unknown").lower()
        if t != "unknown":
            tags.append(t)
        if p != "unknown":
            tags.append(p)
        tags.append(language.lower())
        return list(dict.fromkeys([re.sub(r"[^a-z0-9_\-]+","-", x).strip("-") for x in tags if x]))

    @staticmethod
    def _guess_var_name(item: SecretInput, text: str, occurrences: List[Tuple[int,int]]) -> Optional[str]:
        """
        Try to extract a nearby variable or env name. If item.hint is present, prefer that.
        """
        if item.hint:
            return str(item.hint)

        if not text:
            return None

        # Look for a pattern like NAME = "secret" or export NAME=...
        for ln, _ in occurrences[:3]:
            line = text.splitlines()[ln-1] if ln-1 < len(text.splitlines()) else ""
            m = re.search(r'([A-Z0-9_]{3,})\s*=\s*[\'"].*?[\'"]', line)
            if m:
                return m.group(1)
            m = re.search(r'export\s+([A-Z0-9_]{3,})\s*=', line)
            if m:
                return m.group(1)

        return None

    @staticmethod
    def _make_context_window(text: str, occurrences: List[Tuple[int,int]], default_line: Optional[int] = None, radius: int = 4) -> str:
        """
        Return a small multi-line snippet around the first occurrence (or default line).
        """
        lines = text.splitlines()
        if occurrences:
            ln0 = occurrences[0][0]
        elif default_line:
            ln0 = int(default_line)
        else:
            return ""

        start = max(1, ln0 - radius)
        end = min(len(lines), ln0 + radius)
        # Prefix with line numbers for clarity
        snippet = []
        for i in range(start, end + 1):
            prefix = f"{i:>5}: "
            content = lines[i-1]
            snippet.append(prefix + content)
        return "\n".join(snippet)

    def _build_output(self, manifest_path: Path, analyses: List[SecretAnalysis]) -> Dict[str, Any]:
        """
        Final JSON style format (stable contract):
        {
          "version": "1.0",
          "plugin": "SecretsContextPlugin",
          "model": "llama3.2:3b",
          "generated_at": "2025-09-16T12:34:56Z",
          "inputs": { "manifest_path": "/abs/path.json" },
          "results": [ SecretAnalysis, ... ]
        }
        """
        return {
            "version": "1.0",
            "plugin": self.name,
            "model": self.model,
            "generated_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "inputs": {"manifest_path": str(manifest_path)},
            "results": [a.to_dict() for a in analyses],
        }


# If you import this file as a module, you can instantiate SecretsContextPlugin and call:
#   plugin = SecretsContextPlugin(model="llama3.2:3b", use_llm=True)
#   report = plugin.run_from_manifest_path(Path("manifest.json"))
#   Path("secrets_report.json").write_text(json.dumps(report, indent=2))
