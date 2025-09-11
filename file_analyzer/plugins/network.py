#!/usr/bin/env python3
# Network analyzer plugin (flattened)

import re
import logging
from pathlib import Path
from typing import Dict, Set, Optional

from .base_plugin import AnalyzerPlugin
from ..core.patterns import get_network_patterns


class NetworkAnalyzer(AnalyzerPlugin):
    """Analyze network-related information in files."""

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"network"}
        self.network_patterns = get_network_patterns()

    @property
    def plugin_type(self) -> str:
        return 'network_analyzer'

    @property
    def supported_file_types(self) -> Set[str]:
        return {'*'}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_type == 'text' or file_path.suffix.lower() in {
            '.json', '.js', '.py', '.java', '.php', '.ts', '.ini', '.conf', '.yaml', '.yml',
            '.xml', '.log', '.txt', '.html', '.md', '.sh', '.bash', 'Dockerfile'
        }

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        logging.info(f"Analyzing network information in {file_path}")
        self._analyze_network_protocols(content, results)
        self._analyze_network_security_issues(content, results)
        self._extract_network_configuration(content, results)
        self._correlate_network_endpoints(content, results)
        return results

    def _analyze_network_protocols(self, content: str, results: Dict[str, Set[str]]) -> None:
        for protocol, pattern in self.network_patterns.get('protocols', {}).items():
            if re.search(pattern, content):
                results.setdefault('network_protocols', set()).add(protocol)

    def _analyze_network_security_issues(self, content: str, results: Dict[str, Set[str]]) -> None:
        for issue, pattern in self.network_patterns.get('security_issues', {}).items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                context = content[max(0, match.start() - 20):min(len(content), match.end() + 20)].strip()
                results.setdefault('network_security_issues', set()).add(f"{issue} (line {line_no}): {context}")

    def _extract_network_configuration(self, content: str, results: Dict[str, Set[str]]) -> None:
        if 'port' in self.network_patterns.get('configuration', {}):
            port_pattern = self.network_patterns['configuration']['port']
            for match in re.finditer(port_pattern, content):
                port = match.group(1)
                try:
                    port_number = int(port)
                    if 0 <= port_number <= 65535:
                        results.setdefault('network_ports', set()).add(port)
                        sensitive_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 27017}
                        if port_number in sensitive_ports:
                            service = self._get_port_service(port_number)
                            results.setdefault('network_security_issues', set()).add(
                                f"Potentially sensitive port used: {port} (common for {service})"
                            )
                except ValueError:
                    continue
        if 'host' in self.network_patterns.get('configuration', {}):
            host_pattern = self.network_patterns['configuration']['host']
            for match in re.finditer(host_pattern, content):
                host = match.group(1)
                results.setdefault('network_hosts', set()).add(host)
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) and not host.startswith(('127.', '192.168.', '10.')):
                    results.setdefault('network_security_issues', set()).add(f"Hardcoded non-local IP address: {host}")

    def _correlate_network_endpoints(self, content: str, results: Dict[str, Set[str]]) -> None:
        hosts = results.get('network_hosts', set())
        ports = results.get('network_ports', set())
        if hosts and ports:
            for host in hosts:
                for port in ports:
                    if re.search(rf'{re.escape(host)}.*?{port}|{port}.*?{re.escape(host)}', content, re.DOTALL):
                        results.setdefault('network_endpoints', set()).add(f"{host}:{port}")

    def _get_port_service(self, port: int) -> str:
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alternate",
            27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown Service")

