# Secrets Context Plugin

This plugin ingests a **secrets manifest JSON**, opens the referenced source files to pull **context** around each secret, and (optionally) uses a **small local LLM via Ollama** to infer the secret’s type and likely provider (e.g., "api_key" / "OpenAI"). It emits a **final, stable JSON** that your pipeline can consume.

---

## Features

- **Flexible manifest schema**
  - Accepts:
    ```json
    { "secrets": [ { "file": "path", "value": "secret", "hint": "ENV_NAME", "line": 10 } ] }
    ```
    or a bare list under `entries` / `items` / root.
- **Context extraction**
  - Finds occurrences in file, records line/column, extracts a +/- N line window with line numbers.
  - Attempts to infer variable/env name near the secret.
- **Privacy-by-design**
  - LLM sees only a masked version of the secret (`••••abcd`) and a short context window.
  - Output stores `sha256` and `last4`, never the raw secret.
- **Ollama integration**
  - Works with the `ollama` Python package **or** via HTTP (`OLLAMA_HOST`, default `http://localhost:11434`).
  - Default model: `llama3.2:3b` (adjust via CLI or constructor).
- **Robust fallback**
  - If Ollama is unavailable, the plugin still produces results using heuristics.

---

## Output JSON format

Stable contract:

```json
{
  "version": "1.0",
  "plugin": "SecretsContextPlugin",
  "model": "llama3.2:3b",
  "generated_at": "2025-09-16T12:34:56Z",
  "inputs": { "manifest_path": "/abs/manifest.json" },
  "results": [
    {
      "id": "secret-1",
      "source_file": "/path/to/file.py",
      "language": "python",
      "secret_last4": "abcd",
      "secret_hash": "sha256:…",
      "secret_length": 51,
      "secret_entropy": 4.82,
      "occurrences": [ { "line": 123, "column": 18 } ],
      "context_snippet": "  121: ...\n  122: api_key = '••••abcd'\n  123: ...",
      "var_name": "OPENAI_API_KEY",
      "llm_type": "api_key",
      "llm_provider": "OpenAI",
      "llm_confidence": 0.86,
      "llm_severity": "high",
      "llm_is_placeholder": false,
      "llm_usage": "server-to-server",
      "llm_reasoning": "Short justification.",
      "tags": ["api_key","openai","python"]
    }
  ]
}
```

---

## CLI

```bash
python run_secrets_plugin.py \
  --manifest path/to/secrets_manifest.json \
  --output secrets_report.json \
  --model llama3.2:3b \
  --ollama-host http://localhost:11434
```

To disable LLM classification:

```bash
python run_secrets_plugin.py --manifest path/to/secrets_manifest.json --output out.json --no-llm
```

---

## Integration as a Plugin

If your codebase provides a `AnalyzerPlugin` base, import this module and instantiate `SecretsContextPlugin`.  
It advertises:
- `plugin_type = "semantic"`
- `supported_file_types = ("json",)`
- `name = "SecretsContextPlugin"`

It implements:
- `can_analyze(file_path, file_type, content)`
- `analyze(file_path, file_type, content, results_collector=None) -> Dict[str,Any]`  
  (Also calls `results_collector.add_result("secret", payload, ...)` if provided.)

### Registration example

```python
# plugin_registry.py
from secrets_context_plugin import SecretsContextPlugin

registry.register(SecretsContextPlugin())
```

Or, if your registry auto-discovers modules by folder, place `secrets_context_plugin.py` in your plugins dir.

---

## Manifest schema

Minimal per-item fields:
- `file` (or `file_path`, `path`, `location`) – REQUIRED
- `value` (or `secret`, `token`) – REQUIRED

Optional:
- `hint` (var/env name)
- `line` (1-based line number hint)

---

## Notes & Caveats

- The plugin reads files from disk; non-local locations (e.g., `s3://`) are not opened and will have empty context unless you extend `_analyze_one`.
- Some binary or huge files might not be fully scanned—this plugin targets source-like files.
- For best provider/type classification accuracy, choose a domain-relevant small model and keep snippets concise.

---

## License

MIT (adapt as needed).
