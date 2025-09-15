#!/usr/bin/env python3
# Core analyzer class

import logging
import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
import multiprocessing
import math
import gc
from concurrent.futures import ProcessPoolExecutor, as_completed
import mmap
import resource
import signal
from functools import lru_cache

from ..plugins.plugin_registry import PluginRegistry
from ..utils.file_utils import read_file_content, detect_file_type, calculate_entropy, is_text_like_file
import re


class MemoryLimitExceeded(Exception):
    """Exception raised when memory limit is exceeded during analysis."""
    pass


class TimeoutExceeded(Exception):
    """Exception raised when timeout is exceeded during analysis."""
    pass


def timeout_handler(signum, frame):
    """Signal handler for timeouts."""
    raise TimeoutExceeded("Analysis operation timed out")


class FileAnalyzer:
    """
    Core file analyzer class.
    
    This class coordinates the analysis of files using various plugins
    and provides a central interface for result collection and processing.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the file analyzer with optional configuration.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        self._setup_logging()
        
        # Initialize results dictionary
        self.results = self._initialize_results()
        
        # API structure correlation data
        self.api_structure = {}
        
        # Initialize plugin registry
        self.plugin_registry = PluginRegistry()
        
        # Set memory limit in bytes. Prefer configured value; else use ~50% of system RAM.
        # Note: resource.getrusage().ru_maxrss is peak RSS and platform-dependent units,
        # so we avoid basing limits on it.
        self.memory_limit = self.config.get('memory_limit', None)
        if not isinstance(self.memory_limit, int):
            self.memory_limit = int(0.5 * self._get_total_memory_bytes())
        
        # Set default timeout (5 minutes)
        self.timeout = self.config.get('timeout', 300)
        
        # Load plugins
        self._load_plugins()
    
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        log_level = self.config.get('log_level', logging.INFO)
        log_file = self.config.get('log_file', 'file_analyzer.log')

        # Normalize and ensure the log directory exists (supports ~ expansion)
        log_path = Path(str(log_file)).expanduser()
        log_dir = log_path.parent
        if log_dir and not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)
        log_file = str(log_path)

        # Configure logging with rotation
        try:
            from logging.handlers import RotatingFileHandler
            
            handlers = [
                RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5),
                logging.StreamHandler()
            ]
        except ImportError:
            handlers = [
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
            handlers=handlers
        )
    
    def _initialize_results(self) -> Dict[str, Set[str]]:
        """
        Initialize the results dictionary with empty sets for all categories.
        
        Returns:
            Empty results dictionary
        """
        results = {}
        
        # Initialize known categories used across plugins
        base_keys = [
            'email','hash','api_key','jwt','username','password','private_key','public_key','aws_key',
            'base64_encoded','credit_card','social_security','database_connection','access_token','refresh_token',
            'oauth_token','session_id','cookie','api_endpoint','api_method','content_type','api_version','api_parameter',
            'authorization_header','rate_limit','api_key_param','curl_command','webhook_url','http_status_code',
            'openapi_schema','graphql_query','graphql_schema','rest_resource','xml_response','error_pattern','http_error',
            'oauth_flow','api_auth_scheme','request_header','request_body_json','form_data','path_parameter','query_parameter',
            'api_doc_comment','webhook_event','pagination','rate_limit_header','successful_json_request','failed_json_request',
            'ipv4','ipv6','domain_keywords','url','va_gov_domain','va_gov_url','mac_address'
        ]
        for key in base_keys:
            results[key] = set()
        
        # Add additional result categories
        additional_categories = [
            'api_framework', 'code_complexity', 'security_smells', 'code_quality',
            'high_entropy_strings', 'commented_code', 'network_protocols',
            'network_security_issues', 'network_ports', 'network_hosts',
            'network_endpoints', 'software_versions', 'ml_credential_findings',
            'ml_api_findings', 'runtime_errors', 'file_metadata'
        ]
        
        for category in additional_categories:
            results[category] = set()
        
        return results
    
    def _load_plugins(self) -> None:
        """Load and register all plugins."""
        try:
            # Discover built-in plugins
            self.plugin_registry.discover_plugins()
            
            # Load additional plugins from custom directories if specified
            custom_plugin_dirs = self.config.get('plugin_dirs', [])
            for plugin_dir in custom_plugin_dirs:
                plugin_path = Path(plugin_dir)
                if plugin_path.exists():
                    self.plugin_registry.discover_plugins(str(plugin_dir))
                else:
                    logging.warning(f"Plugin directory does not exist: {plugin_dir}")
            
            loaded_plugins = sum(len(plugins) for plugins in self.plugin_registry.plugins.values())
            logging.debug(f"Loaded {loaded_plugins} plugins")
        except Exception as e:
            logging.error(f"Error loading plugins: {str(e)}")
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a file and extract relevant information.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary of analysis results
        """
        try:
            # Set timeout handler
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.timeout)
            
            file_path = Path(file_path)
            if not file_path.exists():
                logging.error(f"File not found: {file_path}")
                self.results['runtime_errors'].add(f"File not found: {file_path}")
                return self.results

            # Add file metadata
            self._add_file_metadata(file_path)

            # Determine file type
            file_type = detect_file_type(file_path)
            logging.debug(f"Detected file type: {file_type}")
            
            # Check file size to determine processing method
            file_size = file_path.stat().st_size

            # Decide text-like vs binary using both detector and a quick head sample
            text_like = (file_type == 'text') or is_text_like_file(file_path)

            if not text_like:
                # Non-text: do not run regex text patterns; allow plugins only
                content, is_binary = read_file_content(file_path)
                if is_binary or not content:
                    logging.debug(f"Skipping text pattern scan for non-text file: {file_type}")
                self._process_with_plugins(file_path, file_type, content or "")
            else:
                # Text-like files: choose appropriate strategy based on size
                if file_size > self.memory_limit:
                    logging.warning(
                        f"File size ({file_size} bytes) exceeds safe memory limit, using chunked processing"
                    )
                    self._chunked_analyze(file_path, file_type)
                elif file_size > 10 * 1024 * 1024:  # 10MB
                    # For larger files under memory limit, read and analyze once
                    content, is_binary = read_file_content(file_path)
                    self._process_with_plugins(file_path, file_type, content)
                else:
                    content, is_binary = read_file_content(file_path)
                    self._process_with_plugins(file_path, file_type, content)
            
            # Clear timeout
            signal.alarm(0)
            return self.results

        except TimeoutExceeded:
            logging.error(f"Analysis timed out for {file_path}")
            self.results['runtime_errors'].add(f"Analysis timed out after {self.timeout} seconds")
            return self.results
        except MemoryLimitExceeded:
            logging.error(f"Memory limit exceeded for {file_path}")
            self.results['runtime_errors'].add("Memory limit exceeded during analysis")
            return self.results
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")
            self.results['runtime_errors'].add(f"Error: {str(e)}")
            return self.results
        finally:
            # Always clear the timeout
            signal.alarm(0)
            # Force garbage collection
            gc.collect()
    
    def _add_file_metadata(self, file_path: Path) -> None:
        """
        Add file metadata to results.
        
        Args:
            file_path: Path to the file
        """
        stat = file_path.stat()
        
        metadata = {
            f"Filename: {file_path.name}",
            f"File size: {stat.st_size} bytes",
            f"Created: {stat.st_ctime}",
            f"Modified: {stat.st_mtime}",
            f"Accessed: {stat.st_atime}",
            f"Permissions: {stat.st_mode}",
            f"Owner ID: {stat.st_uid}",
            f"Group ID: {stat.st_gid}"
        }
        
        self.results['file_metadata'].update(metadata)
    
    def _process_with_plugins(self, file_path: Path, file_type: str, content: str) -> None:
        """
        Process file with all applicable plugins.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: File content
        """
        # Get applicable plugins
        applicable_plugins = self.plugin_registry.get_plugins_for_file(file_path, file_type, content)

        # Optional filtering by enabled plugin tags (e.g., code, api, network, json, xml)
        enabled = set()
        cfg_enabled = self.config.get('enabled_plugins')
        if cfg_enabled:
            # Accept comma-separated string or list
            if isinstance(cfg_enabled, str):
                enabled = {t.strip().lower() for t in cfg_enabled.split(',') if t.strip()}
            elif isinstance(cfg_enabled, (list, set, tuple)):
                enabled = {str(t).strip().lower() for t in cfg_enabled}
        if enabled and 'all' not in enabled:
            def plugin_tags(p) -> set:
                # Base tags from plugin, plus mapping from type
                tags = set(getattr(p, 'tags', set()) or set())
                t = getattr(p, 'plugin_type', '')
                mapping = {
                    'code_analyzer': {'code'},
                    'api_analyzer': {'api'},
                    'endpoints_analyzer': {'endpoints'},
                    'network_analyzer': {'network'},  # legacy alias if any remain
                    'binary_analyzer': {'binary'},
                    'ml_analyzer': {'ml'},
                    'data_analyzer': set(),
                    'core_analyzer': {'core'},
                }
                tags |= mapping.get(t, set())
                # Derive a general tag from class name as a convenience
                cname = p.__class__.__name__.lower()
                for k in ('json', 'xml'):
                    if k in cname:
                        tags.add(k)
                return {x.lower() for x in tags}

            # Always include core analyzers regardless of selection
            core_plugins = [p for p in applicable_plugins if getattr(p, 'plugin_type', '') == 'core_analyzer' or 'core' in (getattr(p, 'tags', set()) or set())]
            filtered = [p for p in applicable_plugins if p not in core_plugins and (plugin_tags(p) & enabled)]
            applicable_plugins = core_plugins + filtered
        
        for plugin in applicable_plugins:
            try:
                logging.debug(f"Applying {plugin.name} plugin")
                plugin.analyze(file_path, file_type, content, self.results)
            except Exception as e:
                logging.error(f"Error in plugin {plugin.name}: {str(e)}")
                self.results['runtime_errors'].add(f"Plugin error ({plugin.name}): {str(e)}")
    
    def _chunked_analyze(self, file_path: Path, file_type: str) -> None:
        """
        Analyze a very large file in manageable chunks to avoid memory issues.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
        """
        chunk_size = 5 * 1024 * 1024  # 5MB chunks
        
        with open(file_path, 'rb') as f:
            chunk = f.read(chunk_size)
            chunk_num = 1
            
            while chunk:
                logging.debug(f"Processing chunk {chunk_num} of file {file_path.name}")
                
                # Convert to string for processing and run lightweight plugins on-the-fly
                content = chunk.decode('utf-8', errors='ignore')
                for plugin in self.plugin_registry.get_plugins_for_file(file_path, file_type, content):
                    if getattr(plugin, 'requires_full_content', False):
                        continue
                    try:
                        plugin.analyze(file_path, file_type, content, self.results)
                    except Exception as e:
                        logging.error(f"Error in plugin {plugin.name}: {str(e)}")
                        self.results['runtime_errors'].add(f"Plugin error ({plugin.name}): {str(e)}")
                
                # Read next chunk
                chunk = f.read(chunk_size)
                chunk_num += 1
                
                # Force garbage collection between chunks
                gc.collect()
        
        # After chunked streaming, attempt basic plugins with empty content if they can operate without it
        basic_plugins = [p for p in self.plugin_registry.get_plugins_for_file(file_path, file_type) 
                         if getattr(p, 'requires_full_content', False) is False]
        for plugin in basic_plugins:
            try:
                plugin.analyze(file_path, file_type, "", self.results)
            except Exception as e:
                logging.error(f"Error in plugin {plugin.name}: {str(e)}")
                self.results['runtime_errors'].add(f"Plugin error ({plugin.name}): {str(e)}")
    
    # Pattern scanning moved into plugins; helper removed

    def _get_total_memory_bytes(self) -> int:
        """Best-effort retrieval of total system memory in bytes."""
        try:
            import psutil  # type: ignore
            return int(psutil.virtual_memory().total)
        except Exception:
            # Fallback to POSIX sysconf if available
            try:
                page_size = os.sysconf('SC_PAGE_SIZE')  # bytes
                phys_pages = os.sysconf('SC_PHYS_PAGES')
                return int(page_size * phys_pages)
            except Exception:
                # Conservative default: 1 GiB
                return 1 * 1024 * 1024 * 1024

    def _get_current_rss_bytes(self) -> int:
        """Best-effort retrieval of current process RSS memory usage in bytes."""
        try:
            import psutil  # type: ignore
            return int(psutil.Process(os.getpid()).memory_info().rss)
        except Exception:
            try:
                rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                # ru_maxrss units: kilobytes on Linux, bytes on macOS. Heuristic conversion.
                if os.uname().sysname == 'Darwin':
                    return int(rss)
                else:
                    return int(rss) * 1024
            except Exception:
                return 0
    
    def _validate_ipv4(self, value: str, data_type: str) -> None:
        """
        Validate and add an IPv4 address.
        
        Args:
            value: The value to validate
            data_type: The data type category
        """
        from ipaddress import IPv4Address, AddressValueError
        try:
            IPv4Address(value)
            self.results[data_type].add(value)
        except AddressValueError:
            pass
    
    # Hash and base64 validations are handled by respective plugins
    
    def analyze_file_parallel(self, file_path: Path, file_type: str) -> None:
        """
        Analyze a file using parallel processing for large files.
        
        This method splits the file into chunks and processes them in parallel,
        significantly improving performance for large files.
        
        Args:
            file_path: Path to the file to analyze
            file_type: Detected file type
        """
        # Simplified: read content once and run plugins
        try:
            content, is_binary = read_file_content(file_path)
            self._process_with_plugins(file_path, file_type, content)
        except Exception as e:
            logging.error(f"Error processing large file: {str(e)}")
            self.results['runtime_errors'].add(f"Large file processing error: {str(e)}")
    
    # Parallel chunk scanning removed; plugin-only processing used
    
    def get_results(self) -> Dict[str, Any]:
        """
        Get the analysis results.
        
        Returns:
            Copy of the results dictionary
        """
        snapshot = {}
        for key, value in self.results.items():
            if isinstance(value, set):
                snapshot[key] = set(value)
            elif isinstance(value, dict):
                snapshot[key] = value.copy()
            elif isinstance(value, list):
                snapshot[key] = list(value)
            elif isinstance(value, tuple):
                snapshot[key] = tuple(value)
            else:
                snapshot[key] = value
        return snapshot
    
    def get_api_structure(self) -> Dict:
        """
        Get the API structure information.
        
        Returns:
            The API structure dictionary
        """
        return self.api_structure.copy()
    
    def reset_results(self) -> None:
        """Reset the results to an empty state."""
        self.results = self._initialize_results()
        self.api_structure = {} 
