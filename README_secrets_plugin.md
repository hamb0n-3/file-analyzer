# Secrets Context Plugin

This plugin ingests a **secrets manifest JSON**, opens the referenced source files to pull **context** around each secret, and (optionally) uses a **small local LLM via `llama.cpp`** to infer the secret’s type and likely provider. The classification metadata stays internal so the exported JSON remains clean and focused on raw findings.

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
- **Transparent output**
  - Emits the original secret alongside entropy, occurrences, and surrounding context.
- **Local LLM integration**
  - Uses the [`llama-cpp-python`](https://github.com/abetlen/llama-cpp-python) bindings with a local `.gguf` model (configurable); classification is optional and its results are not written to the manifest JSON.

---

## Output JSON format

Stable contract:

```json
{
  "version": "1.0",
  "plugin": "SecretsContextPlugin",
  "generated_at": "2025-09-16T12:34:56Z",
  "inputs": { "manifest_path": "/abs/manifest.json" },
  "results": [
    {
      "id": "secret-1",
      "source_file": "/path/to/file.py",
      "language": "python",
      "secret_value": "sk-example",
      "secret_length": 51,
      "secret_entropy": 4.82,
      "occurrences": [ { "line": 123, "column": 18 } ],
      "context_snippet": "  121: ...\n  122: api_key = 'sk-example'\n  123: ...",
      "var_name": "OPENAI_API_KEY"
    }
  ]
}
```

---

## CLI

```bash
file-analyzer ai --input-file path/to/secrets_manifest.json --output-file secrets_report.json
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
from file_analyzer.ai_mode.ai_context_plugin import SecretsContextPlugin

registry.register(SecretsContextPlugin())
```

Or, if your registry auto-discovers modules by folder, place `file_analyzer/ai_mode/ai_context_plugin.py` in your plugins dir.

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
- LLM usage is optional; if enabled, ensure `llama-cpp-python` is installed and the configured `.gguf` model path is accessible to the analyzer process.

---

## License

MIT (adapt as needed).
