#!/usr/bin/env python3
# API analyzer plugin (flattened)

import re
import logging
from pathlib import Path
from typing import Dict, Set, Optional, Any

from .base_plugin import AnalyzerPlugin
from ..core.patterns import get_patterns


class APIAnalyzer(AnalyzerPlugin):
    """
    Plugin for analyzing API endpoints, patterns, and related information.
    """

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"api"}
        all_patterns = get_patterns()
        self.api_patterns = {k: v for k, v in all_patterns.items() if any(
            keyword in k for keyword in ['api', 'endpoint', 'webhook', 'graphql', 'rest']
        )}
        self.api_patterns['successful_json_request'] = all_patterns['successful_json_request']
        self.api_patterns['failed_json_request'] = all_patterns['failed_json_request']
        self.api_structure: Dict[str, Dict[str, Any]] = {}

    @property
    def plugin_type(self) -> str:
        return 'api_analyzer'

    @property
    def supported_file_types(self) -> Set[str]:
        return {'*'}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_type == 'text' or file_path.suffix.lower() in {
            '.json', '.js', '.py', '.java', '.php', '.ts', '.html', '.xml',
            '.yaml', '.yml', '.md', '.txt', '.log'
        }

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        logging.info(f"Analyzing API information in {file_path}")
        self.extract_api_structure(content, results)
        self.detect_api_frameworks(content, results)
        self.extract_api_responses(content, results)
        self.extract_complete_api_requests(content, results)
        results['_api_structure'] = self.api_structure
        return results

    def extract_api_structure(self, content: str, results: Dict[str, Set[str]]) -> None:
        openapi_match = re.search(r'(?i)"swagger"\s*:\s*"([^"]+)"|"openapi"\s*:\s*"([^"]+)"', content)
        if openapi_match:
            version = openapi_match.group(1) or openapi_match.group(2)
            results['openapi_schema'].add(f"OpenAPI/Swagger detected: {version}")

        endpoints: Dict[str, Dict[str, Set[str]]] = {}
        endpoint_matches = re.finditer(self.api_patterns['api_endpoint'], content)
        for match in endpoint_matches:
            endpoint = match.group(0)
            context_window = content[max(0, match.start() - 100):min(len(content), match.end() + 100)]
            method_matches = re.finditer(self.api_patterns['api_method'], context_window)
            methods = set(m.group(0).strip('"\'') for m in method_matches)
            params = set()
            param_matches = re.finditer(self.api_patterns['api_parameter'], context_window)
            params.update(p.group(0) for p in param_matches)
            if 'path_parameter' in self.api_patterns:
                path_param_matches = re.finditer(self.api_patterns['path_parameter'], endpoint)
                params.update(p.group(0) for p in path_param_matches)
            content_types = set()
            if 'content_type' in self.api_patterns:
                content_type_matches = re.finditer(self.api_patterns['content_type'], context_window)
                content_types.update(ct.group(0) for ct in content_type_matches)
            if endpoint not in endpoints:
                endpoints[endpoint] = {'methods': methods, 'parameters': params, 'content_types': content_types}
            else:
                endpoints[endpoint]['methods'].update(methods)
                endpoints[endpoint]['parameters'].update(params)
                endpoints[endpoint]['content_types'].update(content_types)
        self.api_structure = endpoints

    def detect_api_frameworks(self, content: str, results: Dict[str, Set[str]]) -> None:
        frameworks = []
        if re.search(r'(?i)rest[ful]?[\s_-]?api', content):
            frameworks.append('REST API')
        if re.search(r'(?i)(?:graphql|query\s+\{|mutation\s+\{)', content):
            frameworks.append('GraphQL')
        if re.search(r'(?i)(?:<soap:|</soap:|soap:Envelope)', content):
            frameworks.append('SOAP')
        if re.search(r'(?i)(?:grpc\.|\bproto3\b)', content):
            frameworks.append('gRPC')
        if re.search(r'(?i)(?:"swagger":|"openapi":)', content):
            frameworks.append('OpenAPI/Swagger')
        for framework in frameworks:
            results['api_framework'].add(framework)

    def extract_api_responses(self, content: str, results: Dict[str, Set[str]]) -> None:
        success_matches = re.finditer(self.api_patterns['successful_json_request'], content)
        for match in success_matches:
            start_pos = match.start()
            while start_pos < len(content) and content[start_pos] != '{':
                start_pos += 1
            brace_count = 0
            end_pos = start_pos
            for i in range(start_pos, min(start_pos + 500, len(content))):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            json_sample = content[start_pos:end_pos]
            if len(json_sample) > 200:
                json_sample = json_sample[:197] + '...'
            results['successful_json_request'].add(json_sample)

        error_matches = re.finditer(self.api_patterns['failed_json_request'], content)
        for match in error_matches:
            start_pos = match.start()
            while start_pos < len(content) and content[start_pos] != '{':
                start_pos += 1
            brace_count = 0
            end_pos = start_pos
            for i in range(start_pos, min(start_pos + 500, len(content))):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            json_sample = content[start_pos:end_pos]
            if len(json_sample) > 200:
                json_sample = json_sample[:197] + '...'
            results['failed_json_request'].add(json_sample)

    def extract_complete_api_requests(self, content: str, results: Dict[str, Set[str]]) -> None:
        if 'api_request_examples' not in results:
            results['api_request_examples'] = set()
        request_patterns = [
            r'(?i)curl\s+(?:-X\s+)?(?P<method>GET|POST|PUT|DELETE|PATCH)\s+["\']?(?P<url>https?://[^\s"\']+)["\']?(?P<options>(?:\s+-H\s+["\'][^"\']+["\']|\s+--header\s+["\'][^"\']+["\']|\s+-d\s+["\'].*?["\']|\s+--data\s+["\'].*?["\']|\s+--data-raw\s+["\'](.+?)["\']|\s+-F\s+["\'].*?["\'])*)',
            r'(?i)(?:fetch|axios)(?:\.[a-zA-Z]+)?\(\s*["\'](?P<url>https?://[^\s"\']+)["\'](?:\s*,\s*\{(?P<options>.*?)\})?\s*\)',
            r'(?i)requests\.(?P<method>get|post|put|delete|patch)\(\s*["\'](?P<url>https?://[^\s"\']+)["\'](?:\s*,\s*(?P<options>.*?))?\s*\)',
            r'(?i)(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<url>https?://[^\s"\']+)[\s\n]+(?P<headers>(?:[A-Za-z0-9-]+:\s*[^\n]+[\n])+)(?:[\n\s]*(?P<body>\{.*?\}))?',
        ]
        success_indicators = [
            r'(?i)(?:status(?:_code)?|code)\s*(?::|=|==)\s*(?:200|201|202|204|2\d{2})',
            r'(?i)(?:\"status\"\s*:\s*(?:200|201|\"success\"|\"ok\"))',
            r'(?i)(?:\"success\"\s*:\s*(?:true|1))',
            r'(?i)(?:\"ok\"\s*:\s*(?:true|1))',
            r'(?i)(?:\"message\"\s*:\s*\"[^\"]*(?:success|succeeded)[^\"]*\")',
            r'(?i)(?:\/\/\s*success|#\s*success|console\.log\("[^\"]*success[^\"]*"\))',
            r'(?i)(?:\"data\"\s*:\s*\{[^}]+\})(?![^}]*\"error\")',
            r'(?i)(?:assert(?:Equal)?\([^)]*(?:200|201|(?:true|success))[^)]*\))',
        ]
        for pattern in request_patterns:
            matches = re.finditer(pattern, content, re.DOTALL)
            for match in matches:
                try:
                    context_window = content[match.start():min(len(content), match.end() + 500)]
                    if not any(re.search(ind, context_window) for ind in success_indicators):
                        continue
                    method = match.group('method').upper() if 'method' in match.groupdict() and match.group('method') else "GET"
                    url = match.group('url')
                    example = f"{method} {url}"
                    if 'options' in match.groupdict() and match.group('options'):
                        options = match.group('options')
                        headers = []
                        header_matches = re.finditer(r'-H\s+["\']([^"\']+)["\']|--header\s+["\']([^"\']+)["\']', options)
                        for h_match in header_matches:
                            header = h_match.group(1) or h_match.group(2)
                            headers.append(header)
                        if headers:
                            example += "\nHeaders:"
                            for header in headers:
                                example += f"\n  {header}"
                        body_match = re.search(r'-d\s+["\'](.+?)["\']|--data\s+["\'](.+?)["\']|--data-raw\s+["\'](.+?)["\']|body\s*:\s*(\{.+?\})|data\s*:\s*(\{.+?\})', options, re.DOTALL)
                        if body_match:
                            body = next((g for g in body_match.groups() if g), "")
                            if body:
                                if len(body) > 300:
                                    body = body[:297] + "..."
                                example += f"\nBody:\n  {body}"
                    if 'headers' in match.groupdict() and match.group('headers'):
                        headers = match.group('headers').strip().split('\n')
                        example += "\nHeaders:"
                        for header in headers:
                            if header.strip():
                                example += f"\n  {header.strip()}"
                    if 'body' in match.groupdict() and match.group('body'):
                        body = match.group('body')
                        if len(body) > 300:
                            body = body[:297] + "..."
                        example += f"\nBody:\n  {body}"
                    example += "\nStatus: SUCCESSFUL REQUEST"
                    results['api_request_examples'].add(example)
                except Exception as e:
                    logging.warning(f"Error processing API request example: {str(e)}")
