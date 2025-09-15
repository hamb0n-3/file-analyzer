# File Analyzer

A comprehensive, plugin-based file analysis tool for cybersecurity. It scans code and data files to detect security issues, extract API endpoints, identify sensitive information, and more. It’s designed to be safe, fast, and usable at scale on large directories.

## Features

- **Plugin Architecture**: Enable only what you need; easy to extend.
- **Broad Detection**: APIs, credentials, network info, crypto artifacts, code smells.
- **Language/Data Aware**: Specialized analysis for Python/JS, plus JSON/XML parsers.
- **API Correlation**: Extracts endpoints with methods, params, content types, examples.
- **Binary-Safe Scanning**: Skips noisy binary blob extraction; only scans text-like files.
- **Scalable Outputs**: Per-plugin aggregated reports for directory scans (not per-file).
- **Multiple Formats**: Console, Markdown, JSON, HTML, and CSV.
- **Performance & Safety**: Parallel workers, timeouts, memory limits, excludes/includes.

## Installation

### Basic Installation

```bash
pip install file-analyzer
```

### Installation with Extras

For specific functionality, you can install extras:

```bash
# For code analysis features
pip install "file-analyzer[code_analysis]"

# For machine learning features
pip install "file-analyzer[ml]"

# For binary analysis features
pip install "file-analyzer[binary]"

# For NLP-based analysis
pip install "file-analyzer[nlp]"

# For all features
pip install "file-analyzer[all]"
```

### Development Installation

```bash
git clone https://github.com/yourusername/file-analyzer.git
cd file-analyzer
pip install -e ".[all]"
```

## Usage

### Subcommands

- `file`: Analyze one or more files.
- `dir`: Analyze a directory (optionally recursive) and produce aggregated reports per plugin group, plus a directory summary.

### Examples

```bash
# Analyze specific files (per-file reporting)
file-analyzer file ./a.py ./b.js --plugins code,api --html results.html

# Analyze a directory non-recursively and export aggregated per-plugin reports
file-analyzer dir ./project --plugins all --html --json --csv --output-dir ./out
# Produces: out/plugin-api.html, out/plugin-endpoints.json, out/plugin-code.csv, out/plugin-secret.json, ...
# Also produces: out/summary.html and out/summary.json

# Recursive directory scan with excludes and size limit (in MB)
file-analyzer dir -r ./repo --exclude node_modules --exclude .git --max-size 50 --output-dir ./out

# Only run specific plugin groups
file-analyzer dir ./project --plugins code,endpoints --html --output-dir ./out

# Enable Markdown terminal formatting for a single file
file-analyzer file ./example.py --md

# Export a single file’s results to JSON/HTML/CSV
file-analyzer file ./example.py --json ex.json --html ex.html --csv ex.csv

# Legacy (still supported):
python -m file_analyzer ./example.py
python -m file_analyzer --dir ./project
```

### Notable Options

- `--plugins <list>`: Comma-separated plugin groups: `code, api (web), endpoints (network), json, xml, secret, crypto, ml, all`.
- `--parallel <N>`: Number of workers (0=auto).
- `--timeout <sec>`: Per-file analysis timeout.
- `--memory-limit <MB>`: Process memory safety cap.
- `--include/--exclude`: Glob patterns for directory scans.
- `--max-size <MB>`: Skip files larger than this size.
- `--output-dir <path>`: Where to write reports.
- `--quiet`, `--summary-only`: Control console output.

### Core Parsers (Always On)

The JSON and XML parsers run regardless of `--plugins` selection. They do not perform security analysis; instead they aid other plugins by parsing structure and exposing minimal metadata:

- JSON: `_json_valid`, `_json_top_keys`, and for JSONL `_jsonl_stats`.
- XML: `_xml_valid`, `_xml_root_tag`, `_xml_top_children`.

These underscore-prefixed fields may appear in JSON exports to help automation, but are not included in the human‑readable sections of HTML/text reports.

## Directory Reporting (Aggregated)

When using `dir`, the analyzer aggregates findings across all files and writes one set of reports per plugin group, avoiding an explosion of per-file reports in large trees.

Generated files (when requested via `--json/--html/--csv`):

- `plugin-api.(json|html|csv)`
- `plugin-endpoints.(json|html|csv)`
- `plugin-code.(json|html|csv)`
- `plugin-crypto.(json|html|csv)`
- `plugin-ml.(json|html|csv)`
- `plugin-secret.(json|html|csv)`
- plus `summary.html` and `summary.json` (directory overview)

Secret findings are included in the aggregated per-plugin outputs when `--plugins secret` (or `all`) is selected.

## Binary Handling

The analyzer uses a fast heuristic to detect text vs. binary content and avoids hex-dumping or scanning binary blobs that produce meaningless findings. Non-text files are skipped by the generic regex scanner; any specialized plugins that understand a non-text type can still run.

## Creating Custom Plugins

You can extend functionality by creating custom plugins:

1. Create a new Python file in the `plugins` directory
2. Create a class that inherits from `AnalyzerPlugin`
3. Implement the required methods
4. The plugin will be automatically discovered and loaded

Example plugin:

```python
from file_analyzer.plugins.base_plugin import AnalyzerPlugin

class MyCustomPlugin(AnalyzerPlugin):
    @property
    def plugin_type(self):
        return 'custom_analyzer'
        
    @property
    def supported_file_types(self):
        return {'.custom', '.ext'}
        
    def can_analyze(self, file_path, file_type, content=None):
        return file_path.suffix in self.supported_file_types
        
    def analyze(self, file_path, file_type, content, results):
        # Analyze content and update results
        results['custom_findings'] = set(['Finding 1', 'Finding 2'])
        return results
```

## Configuration

You can create a configuration file to customize behavior:

```json
{
    "log_level": "INFO",
    "log_file": "file_analyzer.log",
    "plugin_dirs": [
        "/path/to/custom/plugins"
    ],
    "analysis_settings": {
        "max_entropy_threshold": 5.0,
        "code_complexity_threshold": 15
    }
}
```

## Tips

- Use `--plugins` to restrict work to what you need (e.g., `code,api`).
- Prefer `dir` mode for projects; it creates concise, per-plugin reports and summaries.
- Tune `--exclude` (e.g., `.git`, `node_modules`, `venv`) to speed up runs.
- Set `--max-size` to avoid scanning oversized files.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
