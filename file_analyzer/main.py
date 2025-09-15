#!/usr/bin/env python3
# Main entry point for the file analyzer

import sys
import os
import argparse
import logging
import time
import traceback
from pathlib import Path
from typing import Dict, Any, Optional, List, Set

from .core.analyzer import FileAnalyzer
from .utils.dependency_checker import check_dependencies, generate_requirements_file, setup_colored_output
from .utils.output_formatter import (
    format_results,
    export_results_json,
    create_html_report,
    create_csv_report,
    format_dir_summary,
    create_dir_summary_html,
    export_dir_summary_json,
    aggregate_results_by_plugin,
)


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    # Create a colorful description for the help text
    colors = setup_colored_output()
    description = """
    File Analyzer - A comprehensive file analysis tool for cybersecurity
    
    This tool analyzes files to extract security-relevant information such as:
    - API endpoints and authentication details
    - Network information (IPs, domains, URLs)
    - Sensitive data (credentials, tokens, keys)
    - Code quality and security issues
    - And much more!
    """
    
    epilog = f"""examples:
  {colors['cyan']('Analyze one file:')}
    file-analyzer file ./example.js

  {colors['cyan']('Analyze multiple files:')}
    file-analyzer file ./a.py ./b.js ./c.xml

  {colors['cyan']('Analyze a directory (non-recursive):')}
    file-analyzer dir ./project_folder

  {colors['cyan']('Analyze a directory recursively:')}
    file-analyzer dir -r ./project_folder

  {colors['cyan']('Enable specific plugins:')}
    file-analyzer file ./example.js --plugins code,api
    file-analyzer dir ./project --plugins endpoints,secret
    file-analyzer dir ./project --plugins all

  {colors['cyan']('Available plugin groups:')}
    code, api, endpoints, json, xml, secret, all

  {colors['cyan']('Export to different formats:')}
    file-analyzer file ./example.js --json results.json --html report.html
    file-analyzer dir ./project --output-dir ./out --csv summary.csv

  {colors['cyan']('Python module usage (legacy):')}
    python -m file_analyzer example.js
    python -m file_analyzer --dir ./project_folder   {colors['yellow']('(recursive by default)')}
    """
    
    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Global options
    parser.add_argument('--skip-checks', action='store_true', help='Skip dependency checks (for advanced users)')
    parser.add_argument('--requirements', action='store_true', help='Generate requirements.txt file and exit')
    parser.add_argument('--version', action='store_true', help='Show version information and exit')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--plugin-dir', action='append', help='Additional plugin directory')
    parser.add_argument('--parallel', type=int, default=0, help='Number of parallel workers (0=auto, default: auto)')
    parser.add_argument('--timeout', type=int, default=900, help='Analysis timeout in seconds per file (default: 900)')
    parser.add_argument('--memory-limit', type=int, help='Memory limit in MB (default: auto)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='Set logging level (default: INFO)')
    parser.add_argument('--log-file', default='file_analyzer.log', help='Log file path')

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', metavar='command')

    # file subcommand
    file_p = subparsers.add_parser('file', help='Analyze one or more files')
    file_p.add_argument('paths', nargs='+', help='Path(s) to file(s) to analyze')
    file_p.add_argument('--plugins', help='Comma-separated plugin groups to enable: code, api, endpoints, json, xml, secret, all')
    file_p.add_argument('--md', action='store_true', help='Output in markdown format (wrapped in triple backticks)')
    file_p.add_argument('--json', help='Export results to JSON file')
    file_p.add_argument('--html', help='Export results to HTML report')
    file_p.add_argument('--csv', help='Export results to CSV file')
    file_p.add_argument('--output-dir', help='Directory to store all output files')
    file_p.add_argument('--quiet', action='store_true', help='Suppress terminal output')
    file_p.add_argument('--summary-only', action='store_true', help='Show only summary information')

    # dir subcommand
    dir_p = subparsers.add_parser('dir', help='Analyze files in a directory (use -r to recurse)')
    dir_p.add_argument('path', help='Directory to analyze')
    dir_p.add_argument('-r', '--recursive', action='store_true', help='Recurse into subdirectories')
    dir_p.add_argument('--plugins', help='Comma-separated plugin groups to enable: code, api, endpoints, json, xml, secret, all')
    dir_p.add_argument('--exclude', action='append', help='Exclude file pattern (glob syntax, can be used multiple times)')
    dir_p.add_argument('--include', action='append', help='Include only file pattern (glob syntax, can be used multiple times)')
    dir_p.add_argument('--max-size', type=int, default=100, help='Maximum file size to analyze in MB (default: 100)')
    dir_p.add_argument('--md', action='store_true', help='Output in markdown format (wrapped in triple backticks)')
    dir_p.add_argument('--json', help='Export results to JSON file (per-file when multiple)')
    dir_p.add_argument('--html', help='Export results to HTML report (per-file when multiple)')
    dir_p.add_argument('--csv', help='Export results to CSV file (per-file when multiple)')
    dir_p.add_argument('--output-dir', help='Directory to store all output files')
    dir_p.add_argument('--quiet', action='store_true', help='Suppress terminal output')
    dir_p.add_argument('--summary-only', action='store_true', help='Show only summary information')

    # Backward-compatible options (no subcommand): keep for existing usage
    parser.add_argument('file_paths', nargs='*', help='[Deprecated] Path(s) to the file(s) to analyze')
    parser.add_argument('--dir', help='[Deprecated] Analyze all files in directory (recursively)')
    parser.add_argument('--md', action='store_true', help='Output in markdown format (wrapped in triple backticks)')
    parser.add_argument('--json', help='Export results to JSON file')
    parser.add_argument('--html', help='Export results to HTML report')
    parser.add_argument('--csv', help='Export results to CSV file')
    parser.add_argument('--output-dir', help='Directory to store all output files')
    parser.add_argument('--quiet', action='store_true', help='Suppress terminal output')
    parser.add_argument('--summary-only', action='store_true', help='Show only summary information')

    return parser.parse_args()


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file if provided.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    config = {}
    
    if config_path:
        import json
        try:
            config_path = Path(config_path)
            if not config_path.exists():
                logging.error(f"Configuration file not found: {config_path}")
                return config
                
            with open(config_path, 'r') as f:
                config = json.load(f)
            logging.info(f"Loaded configuration from {config_path}")
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {str(e)}")
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
    
    return config


def get_files_to_analyze(args) -> List[Path]:
    """
    Get list of files to analyze based on command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        List of file paths to analyze
    """
    files_to_analyze = []
    max_size_mb = getattr(args, 'max_size', 100)
    try:
        max_size_mb = int(max_size_mb)
    except Exception:
        max_size_mb = 100
    max_size_bytes = max_size_mb * 1024 * 1024  # Convert MB to bytes
    
    # Process individual files (deprecated path)
    if getattr(args, 'file_paths', None):
        for file_path in args.file_paths:
            path = Path(file_path)
            if path.exists():
                if path.is_file():
                    if path.stat().st_size <= max_size_bytes:
                        files_to_analyze.append(path)
                    else:
                        logging.warning(f"Skipping {path}: exceeds maximum file size ({path.stat().st_size / 1024 / 1024:.2f} MB)")
                else:
                    logging.warning(f"Skipping {path}: not a file")
            else:
                logging.error(f"File not found: {path}")
    
    # Process directory (optionally recursively)
    if getattr(args, 'dir', None):
        dir_path = Path(args.dir)
        if not dir_path.exists() or not dir_path.is_dir():
            logging.error(f"Directory not found: {dir_path}")
        else:
            # Create include/exclude patterns
            include_patterns = args.include if args.include else ["*"]
            exclude_patterns = args.exclude if args.exclude else []

            # Determine recursion behavior: default recursive for legacy --dir usage
            recursive = getattr(args, 'recursive', True)

            if recursive:
                # Default directories to exclude to prevent slowdowns and hangs
                default_exclude_dirs = {
                    '.git', 'node_modules', 'venv', '.venv', '__pycache__',
                    '.mypy_cache', '.pytest_cache', 'site-packages', 'dist', 'build',
                    '.idea', '.vscode', '.tox', '.eggs'
                }
                # Walk directory recursively
                for root, dirnames, files in os.walk(dir_path):
                    # Prune heavy/irrelevant directories early
                    dirnames[:] = [d for d in dirnames if d not in default_exclude_dirs]
                    root_path = Path(root)
                    for file in files:
                        file_path = root_path / file
                        # Skip non-regular files (e.g., sockets, device files)
                        try:
                            if not file_path.is_file():
                                continue
                        except Exception:
                            continue
                        # Skip files that are too large
                        if file_path.stat().st_size > max_size_bytes:
                            logging.debug(f"Skipping {file_path}: exceeds maximum file size")
                            continue
                        # Check include/exclude patterns
                        include_match = any(file_path.match(pattern) for pattern in include_patterns)
                        exclude_match = any(file_path.match(pattern) for pattern in exclude_patterns)
                        if include_match and not exclude_match:
                            files_to_analyze.append(file_path)
            else:
                # Non-recursive: only immediate files in directory
                try:
                    for file in dir_path.iterdir():
                        file_path = file
                        if not file_path.is_file():
                            continue
                        if file_path.stat().st_size > max_size_bytes:
                            logging.debug(f"Skipping {file_path}: exceeds maximum file size")
                            continue
                        include_match = any(file_path.match(pattern) for pattern in include_patterns)
                        exclude_match = any(file_path.match(pattern) for pattern in exclude_patterns)
                        if include_match and not exclude_match:
                            files_to_analyze.append(file_path)
                except Exception as e:
                    logging.error(f"Error listing directory {dir_path}: {e}")
    
    return files_to_analyze


def analyze_files(files: List[Path], config: Dict[str, Any], args) -> Dict[str, Dict[str, set]]:
    """
    Analyze multiple files with progress tracking.
    
    Args:
        files: List of file paths to analyze
        config: Configuration dictionary
        args: Parsed command line arguments
        
    Returns:
        Dictionary mapping file paths to their analysis results
    """
    colors = setup_colored_output()
    results = {}
    total_files = len(files)
    
    # Determine number of workers for parallel processing
    num_workers = args.parallel
    if num_workers <= 0:
        import multiprocessing
        num_workers = max(1, multiprocessing.cpu_count() - 1)  # Leave one CPU free
    num_workers = min(num_workers, total_files)  # Don't use more workers than files
    
    # Suppress interactive progress when writing to output dir
    if not args.quiet and not getattr(args, 'output_dir', None):
        print(f"\n{colors['bold']('Analyzing')} {total_files} files with {num_workers} workers...")
    
    if total_files == 0:
        return results
    
    # Use progress bar if available and not in quiet mode
    try:
        if not args.quiet and not getattr(args, 'output_dir', None):
            from tqdm import tqdm
            progress_bar = tqdm(total=total_files, desc="Analyzing files", unit="file")
        else:
            progress_bar = None
            
        if num_workers > 1 and total_files > 1:
            # Process files in parallel using a persistent process pool
            from concurrent.futures import ProcessPoolExecutor, as_completed
            worker_config = dict(config)
            future_to_file = {}
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                for file_path in files:
                    future = executor.submit(_analyze_single_file, str(file_path), worker_config)
                    future_to_file[future] = file_path
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        file_results = future.result()
                        results[str(file_path)] = file_results
                    except Exception as e:
                        logging.error(f"Error analyzing {file_path}: {str(e)}")
                        results[str(file_path)] = {"error": {f"Error: {str(e)}"}}
                    if progress_bar:
                        progress_bar.update(1)
        else:
            # Process files sequentially
            for file_path in files:
                try:
                    fa = FileAnalyzer(config)
                    fa.analyze_file(str(file_path))
                    results[str(file_path)] = fa.get_results()
                except Exception as e:
                    logging.error(f"Error analyzing {file_path}: {str(e)}")
                    results[str(file_path)] = {"error": {f"Error: {str(e)}"}}
                
                # Update progress bar
                if progress_bar:
                    progress_bar.update(1)
        
        # Close progress bar
        if progress_bar:
            progress_bar.close()
            
    except ImportError:
        # If tqdm is not available, fall back to a simple single-line progress bar
        import sys as _sys
        def _draw_bar(done: int, total: int, width: int = 40):
            filled = int(width * done / max(1, total))
            bar = '#' * filled + '-' * (width - filled)
            _sys.stdout.write(f"\rAnalyzing files [{bar}] {done}/{total}")
            _sys.stdout.flush()

        if not args.quiet and not getattr(args, 'output_dir', None):
            _draw_bar(0, total_files)

        for i, file_path in enumerate(files, start=1):
            try:
                # Fallback sequential path without subprocess/isolation
                fa = FileAnalyzer(config)
                fa.analyze_file(str(file_path))
                results[str(file_path)] = fa.get_results()
            except Exception as e:
                logging.error(f"Error analyzing {file_path}: {str(e)}")
                results[str(file_path)] = {"error": {f"Error: {str(e)}"}}
            finally:
                if not args.quiet and not getattr(args, 'output_dir', None):
                    _draw_bar(i, total_files)
        if not args.quiet and not getattr(args, 'output_dir', None):
            print()
    
    return results


def _analyze_single_file(file_path, config):
    """
    Helper function for parallel file analysis.
    
    Args:
        file_path: Path to the file to analyze
        config: Configuration dictionary
        
    Returns:
        Analysis results dictionary
    """
    try:
        analyzer = FileAnalyzer(config)
        analyzer.analyze_file(str(file_path))
        return analyzer.get_results()
    except Exception as e:
        logging.error(f"Error analyzing {file_path}: {str(e)}")
        # Include traceback for debugging
        tb = traceback.format_exc()
        logging.debug(tb)
        return {"error": {f"Error: {str(e)}"}}

 


def generate_output_path(args, file_path: Path, extension: str) -> str:
    """
    Generate output file path based on input file and output directory.
    
    Args:
        args: Parsed command line arguments
        file_path: Input file path
        extension: Output file extension
        
    Returns:
        Output file path
    """
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        return str(output_dir / f"{file_path.stem}_analysis{extension}")
    else:
        return f"{file_path.stem}_analysis{extension}"


def _plugin_group_mapping() -> Dict[str, set]:
    """Return mapping of plugin groups to data types for filtering/segregation."""
    # Keep this in sync with utils.output_formatter.aggregate_results_by_plugin
    code_types = {
        'code_complexity', 'security_smells', 'code_quality', 'commented_code', 'deprecated_api'
    }
    endpoints_types = {
        'ipv4', 'ipv6', 'domain_keywords', 'url', 'va_gov_domain', 'va_gov_url', 'mac_address',
        'network_protocols', 'network_security_issues', 'network_ports',
        'network_hosts', 'network_endpoints', 'firewall_rule'
    }
    api_types = {
        'api_endpoint', 'api_method', 'content_type', 'api_version', 'api_parameter',
        'authorization_header', 'rate_limit', 'api_key_param', 'curl_command', 'webhook_url',
        'http_status_code', 'rest_resource', 'path_parameter', 'query_parameter', 'request_header',
        'request_body_json', 'form_data', 'api_request_examples', 'successful_json_request',
        'failed_json_request', 'api_framework', 'openapi_schema', 'graphql_query', 'graphql_schema',
        'soap_wsdl', 'api_auth_scheme', 'oauth_flow', 'api_security_header', 'api_doc_comment',
        'swagger_annotation', 'openapi_tag', 'webhook_event', 'pagination', 'rate_limit_header', 'caching_header',
        # Common auth/key artifacts often found alongside API usage
        'jwt', 'access_token', 'refresh_token', 'oauth_token', 'api_token', 'auth_token', 'api_key'
    }
    data_types = {
        # Encoded/serialized and PII-esque items
        'base64_encoded', 'hex_encoded', 'url_encoded', 'compressed_data', 'serialized_data',
        'email', 'phone_number', 'personal_id', 'passport_number', 'xml_response'
    }
    crypto_types = {
        'private_key', 'public_key', 'hash', 'encryption_key', 'certificate', 'signature'
    }
    ml_types = {
        'ml_credential_findings', 'ml_api_findings', 'ml_security_findings'
    }
    # Secret-focused types (subset from API, crypto, auth, and sensitive data)
    secret_types = {
        'username', 'password', 'jwt', 'access_token', 'refresh_token', 'oauth_token', 'api_token', 'auth_token',
        'api_key', 'aws_key', 'cloud_key', 'firebase_key', 'service_account', 'client_secret',
        'private_key', 'encryption_key', 'certificate', 'signature',
        'credit_card', 'social_security', 'session_id', 'cookie', 'database_connection'
    }

    return {
        'code': code_types,
        'api': api_types,
        'endpoints': endpoints_types,
        # legacy alias for backward compatibility
        'network': endpoints_types,
        'data': data_types,
        'crypto': crypto_types,
        'ml': ml_types,
        'json': {
            # JSON-centric artifacts
            'request_body_json', 'form_data', 'email', 'phone_number', 'personal_id', 'passport_number',
            'base64_encoded', 'hex_encoded', 'url_encoded', 'serialized_data', 'compressed_data'
        },
        'xml': {'xml_response', 'soap_wsdl'},
        'secret': secret_types,
    }


def _filter_results_by_plugins(all_results: Dict[str, Dict[str, set]], plugins_value: Optional[str]) -> Dict[str, Dict[str, set]]:
    """Filter results to only those belonging to the selected plugin groups.

    Keeps 'file_metadata' and 'runtime_errors'. If plugins_value is None or contains 'all',
    no filtering is applied.
    """
    if not plugins_value:
        return all_results
    try:
        req = {p.strip().lower() for p in str(plugins_value).split(',') if p and p.strip()}
    except Exception:
        req = set()
    if not req or 'all' in req:
        return all_results

    mapping = _plugin_group_mapping()
    # Union of selected types
    allowed_types: set = set()
    for group in req:
        allowed_types |= mapping.get(group, set())

    filtered: Dict[str, Dict[str, set]] = {}
    for fpath, res in all_results.items():
        new_res: Dict[str, set] = {}
        for k, v in res.items():
            if k in ('file_metadata', 'runtime_errors'):
                new_res[k] = v
            elif k in allowed_types:
                new_res[k] = v
            # else drop category not in selected plugin groups
        filtered[fpath] = new_res
    return filtered


def export_all_results(all_results: Dict[str, Dict[str, set]], args):
    """
    Export results for all analyzed files based on command line arguments.
    
    Args:
        all_results: Dictionary mapping file paths to their analysis results
        args: Parsed command line arguments
    """
    colors = setup_colored_output()
    
    # Create output directory if specified
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
    
    # If analyzing a directory, aggregate per-plugin rather than per-file
    if getattr(args, 'command', None) == 'dir' and len(all_results) > 1:
        try:
            out_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
            out_dir.mkdir(parents=True, exist_ok=True)

            plugin_buckets = aggregate_results_by_plugin(all_results)
            if not plugin_buckets:
                logging.info("No plugin-group findings to export.")
            else:
                for plugin_name, agg_results in plugin_buckets.items():
                    base = out_dir / f"plugin-{plugin_name}"
                    if args.json:
                        export_results_json(agg_results, str(base.with_suffix('.json')))
                    if args.html:
                        create_html_report(agg_results, None, str(base.with_suffix('.html')))
                    if args.csv:
                        create_csv_report(agg_results, str(base.with_suffix('.csv')))
                logging.info(
                    f"Wrote plugin-aggregated reports: {', '.join(sorted(plugin_buckets.keys()))}"
                )
        except Exception as e:
            logging.warning(f"Failed to write plugin-aggregated reports: {e}")
    else:
        # Process each file's results (single-file mode or explicit file list)
        for file_path_str, results in all_results.items():
            file_path = Path(file_path_str)

            # Generate output paths
            if args.json:
                if len(all_results) > 1:
                    json_path = generate_output_path(args, file_path, ".json")
                else:
                    json_path = args.json
                export_results_json(results, json_path)

            if args.html:
                if len(all_results) > 1:
                    html_path = generate_output_path(args, file_path, ".html")
                else:
                    html_path = args.html
                create_html_report(results, None, html_path)

            if args.csv:
                if len(all_results) > 1:
                    csv_path = generate_output_path(args, file_path, ".csv")
                else:
                    csv_path = args.csv
                create_csv_report(results, csv_path)

            # Always write a human-readable text or markdown report when output_dir is set
            if args.output_dir:
                text_ext = ".md" if args.md else ".txt"
                text_path = generate_output_path(args, file_path, text_ext)
                try:
                    formatted = format_results(results, None, args.md, setup_colored_output())
                    # Strip color codes for file output
                    import re as _re
                    ansi = _re.compile(r"\x1b\[[0-9;]*m")
                    formatted_plain = ansi.sub("", formatted)
                    Path(text_path).write_text(formatted_plain, encoding='utf-8')
                    logging.info(f"Wrote report: {text_path}")
                except Exception as e:
                    logging.warning(f"Failed to write text report for {file_path}: {e}")
    
    # If we have multiple files, create a directory summary report
    if len(all_results) > 1 and getattr(args, 'command', None) == 'dir':
        try:
            out_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
            out_dir.mkdir(parents=True, exist_ok=True)
            # JSON and HTML summaries
            export_dir_summary_json(all_results, str(out_dir / 'summary.json'), root=Path(getattr(args, 'path', args.dir)))
            create_dir_summary_html(all_results, str(out_dir / 'summary.html'), root=Path(getattr(args, 'path', args.dir)))
            logging.info("Wrote directory summaries: summary.json, summary.html")
            # Also write a plaintext/markdown summary if output_dir is set
            if args.output_dir:
                try:
                    colors = setup_colored_output()
                    summary_txt = format_dir_summary(all_results, root=Path(getattr(args, 'path', args.dir)), colors=colors)
                    # Strip color codes
                    import re as _re
                    ansi = _re.compile(r"\x1b\[[0-9;]*m")
                    summary_plain = ansi.sub("", summary_txt)
                    (out_dir / ('summary.md' if args.md else 'summary.txt')).write_text(summary_plain, encoding='utf-8')
                except Exception as e:
                    logging.warning(f"Failed to write plaintext summary: {e}")
        except Exception as e:
            logging.warning(f"Failed to write directory summary: {e}")


def main():
    """Main entry point function."""
    start_time = time.time()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Get colored output formatter
    colors = setup_colored_output()
    
    # Show version info if requested
    if args.version:
        print(f"{colors['cyan']('File Analyzer v1.0.0')}")
        print(f"{colors['green']('Author:')} Tristan Pereira")
        print(f"{colors['green']('Description:')} A comprehensive file analysis tool for cybersecurity")
        sys.exit(0)
    
    # Generate requirements file if requested
    if args.requirements:
        generate_requirements_file()
        sys.exit(0)
    
    # Check dependencies unless explicitly skipped
    if not args.skip_checks:
        if not check_dependencies():
            sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    # Apply command line configurations
    config['log_level'] = getattr(logging, args.log_level.upper())
    config['log_file'] = args.log_file
    if args.plugin_dir:
        config['plugin_dirs'] = args.plugin_dir
    if args.timeout:
        config['timeout'] = args.timeout
    if args.memory_limit:
        config['memory_limit'] = args.memory_limit * 1024 * 1024  # Convert MB to bytes
    # Plugin selection via subcommand option or legacy (None -> enable all)
    enabled_plugins = None
    if getattr(args, 'plugins', None):
        enabled_plugins = args.plugins
    config['enabled_plugins'] = enabled_plugins
    
    # Determine mode and inputs
    files_to_analyze: List[Path] = []
    mode = None
    if getattr(args, 'command', None) == 'file':
        mode = 'file'
        args.file_paths = args.paths  # bridge to existing logic
        files_to_analyze = get_files_to_analyze(args)
    elif getattr(args, 'command', None) == 'dir':
        mode = 'dir'
        # bridge: map to legacy --dir
        setattr(args, 'dir', args.path)
        files_to_analyze = get_files_to_analyze(args)
    else:
        # Backward-compatible path
        mode = 'file' if args.file_paths else ('dir' if args.dir else None)
        files_to_analyze = get_files_to_analyze(args)
    
    if not files_to_analyze:
        print(f"{colors['red']('Error: No files specified or found for analysis')}")
        print(f"Run with --help for usage information")
        sys.exit(1)
    
    # Analyze all files
    all_results = analyze_files(files_to_analyze, config, args)

    # If plugin groups are specified (and not 'all'), filter the results to segregate analyses
    all_results = _filter_results_by_plugins(all_results, getattr(args, 'plugins', None))

    # Export results if requested
    export_all_results(all_results, args)
    
    # Print results to console if not suppressed
    if not args.quiet and not getattr(args, 'output_dir', None):
        # Calculate total findings
        total_findings = sum(
            sum(len(values) for key, values in results.items() 
                if isinstance(values, set) and key not in ['file_metadata', 'runtime_errors'])
            for results in all_results.values()
        )
        
        # Print summary
        elapsed_time = time.time() - start_time
        print(f"\n{colors['bold']('Analysis Complete')}")
        print(f"{colors['green']('Files analyzed:')} {len(all_results)}")
        print(f"{colors['green']('Total findings:')} {total_findings}")
        print(f"{colors['green']('Time elapsed:')} {elapsed_time:.2f} seconds")
        
        # Directory-grouped summary for dir scans
        if getattr(args, 'command', None) == 'dir':
            root = Path(getattr(args, 'path', args.dir)) if getattr(args, 'path', None) or getattr(args, 'dir', None) else None
            print("\n" + format_dir_summary(all_results, root=root, colors=colors))

        # Print detailed results for each file
        if not args.summary_only:
            for file_path_str, results in all_results.items():
                print(f"\n{colors['bold']('='*80)}")
                print(f"{colors['cyan']('Results for:')} {file_path_str}")
                print(f"{colors['bold']('='*80)}")
                
                # Format and print results
                formatted_results = format_results(results, None, args.md, colors)
                print(formatted_results)

    
    # Return success
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
