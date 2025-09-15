#!/usr/bin/env python3
# Endpoints analyzer plugin (formerly Network analyzer)

import re
import logging
from pathlib import Path
from typing import Dict, Set, Optional

from .base_plugin import AnalyzerPlugin


class EndpointsAnalyzer(AnalyzerPlugin):
    """Analyze endpoints, hosts, IPs, URLs, and related network configs."""

    def __init__(self, config=None):
        super().__init__(config)
        # Support both new and legacy group names for selection
        self.tags = {"endpoints", "network"}
        # Inline network protocol/security patterns (migrated from core.patterns)
        self.network_patterns = {
            'protocols': {
                'HTTP': r'(?i)(?:http\.(?:get|post|put|delete)|fetch\(|XMLHttpRequest|axios)',
                'HTTPS': r'(?i)https:\/\/',
                'FTP': r'(?i)(?:ftp:\/\/|ftps:\/\/|\bftp\s+(?:open|get|put))',
                'SSH': r'(?i)(?:ssh\s+|ssh2_connect|new\s+SSH|JSch)',
                'SMTP': r'(?i)(?:smtp\s+|mail\s+send|createTransport|sendmail|new\s+SmtpClient)',
                'DNS': r'(?i)(?:dns\s+lookup|resolv|nslookup|dig\s+)',
                'MQTT': r'(?i)(?:mqtt\s+|MQTTClient|mqtt\.connect)',
                'WebSocket': r'(?i)(?:new\s+WebSocket|createWebSocketClient|websocket\.connect)',
                'gRPC': r'(?i)(?:grpc\.(?:Server|Client)|new\s+ServerBuilder)',
                'GraphQL': r'(?i)(?:graphql\s+|ApolloClient|gql`)',
                'TCP/IP': r'(?i)(?:socket\.|Socket\(|createServer|listen\(\d+|bind\(\d+|connect\(\d+)',
                'UDP': r'(?i)(?:dgram\.|DatagramSocket|UdpClient)',
                'ICMP': r'(?i)(?:ping\s+|ICMP|IcmpClient)',
                'SNMP': r'(?i)(?:snmp\s+|SnmpClient|createSnmpSession)',
                'LDAP': r'(?i)(?:ldap\s+|LdapClient|createLdapConnection)',
                # JavaScript-specific
                'Fetch API': r'(?i)(?:fetch\s*\(|\.then\s*\(|\.json\s*\(\s*\)|\.blob\s*\(\s*\))',
                'Axios': r'(?i)(?:axios\.(?:get|post|put|delete|patch)|axios\s*\(\s*\{)',
                'jQuery AJAX': r'(?i)(?:\$\.(?:ajax|get|post|getJSON)|jQuery\.(?:ajax|get|post))',
                'XMLHttpRequest': r'(?i)(?:new\s+XMLHttpRequest\(|\.open\s*\(|\.send\s*\(|\.onreadystatechange)',
                'NodeJS HTTP': r'(?i)(?:require\s*\(\s*[\'\"]http[\'\"]|http\.createServer|http\.request|http\.get)',
                'NodeJS HTTPS': r'(?i)(?:require\s*\(\s*[\'\"]https[\'\"]|https\.createServer|https\.request|https\.get)',
                'WebRTC': r'(?i)(?:RTCPeerConnection|getUserMedia|createDataChannel|onicecandidate)',
                'Server-Sent Events': r'(?i)(?:new\s+EventSource\s*\(|\.addEventListener\s*\(\s*[\'\"]message[\'\"])',
                'Service Workers': r'(?i)(?:navigator\.serviceWorker|ServiceWorkerRegistration|new\s+Cache\()',
                'Firebase': r'(?i)(?:firebase\.database\(\)|ref\(\)|child\(\)|set\(\)|push\(\)|update\(\)|remove\(\))',
                'Socket.IO': r'(?i)(?:io\s*\(\s*|\.on\s*\(\s*[\'\"]connect[\'\"]\s*|socket\.emit\s*\()',
                'Cross-Domain': r'(?i)(?:\.postMessage\s*\(|JSONP|document\.domain\s*=)',
            },
            'security_issues': {
                'Clear Text Credentials': r'(?i)(?:auth=|user:pass@|username=\w+&password=)',
                'Insecure Protocol': r'(?i)(?:ftp:\/\/|telnet:\/\/|http:\/\/(?!localhost|127\.0\.0\.1))',
                'Hardcoded IP': r"\b(?:PUBLIC_IP|SERVER_ADDR|API_HOST)\s*=\s*['\"](?:\d{1,3}\.){3}\d{1,3}['\"]",
                'Open Port': r'(?i)(?:listen\(\s*\d+|port\s*=\s*\d+|\.connect\(\s*(?:["\']\w+["\']\s*,\s*)?\d+\))',
                'Weak TLS': r'(?i)(?:SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|\bRC4\b|\bDES\b|MD5WithRSA|allowAllHostnames)',
                'Certificate Validation Disabled': r'(?i)(?:verify=False|CERT_NONE|InsecureRequestWarning|rejectUnauthorized:\s*false|trustAllCerts)',
                'Proxy Settings': r'(?i)(?:proxy\s*=|http_proxy|https_proxy|\.setProxy|\.proxy\()',
                'CORS Misconfiguration': r'(?i)(?:Access-Control-Allow-Origin:\s*\*|cors\({.*?origin:\s*[\'\"]?\*[\'\"]?)',
                'Unencrypted Socket': r'(?i)(?:new\s+Socket|socket\.|createServer)(?![^\n]*SSL|[^\n]*TLS)',
                'Server-Side Request Forgery': r'(?i)(?:\.open\([\'\"]GET[\'\"],\s*(?:url|req|request))',
                'DNS Rebinding': r'(?i)(?:allowLocal\s*:|allowAny\s*:|\*\.localhost)',
                'WebSockets Insecure': r'(?i)(?:ws:\/\/|new\s+WebSocket\([\'\"]ws:\/\/)',
            },
            'configuration': {
                'port': r'(?:^|\s)(?:PORT|port)\s*(?:=|:)\s*(\d+)',
                'host': r'(?:^|\s)(?:HOST|host|SERVER|server)\s*(?:=|:)\s*[\'\"]([\w\.\-]+)[\'\"]',
            }
        }
        # Inline endpoint patterns
        self.endpoint_patterns = {
            'ipv4': r'(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain_keywords': r'\b(?:(?=[\w.-]*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b',
            'url': r'https?://[A-Za-z0-9\-._~%]+(?::\d{1,5})?(?:/[^\s\"\'<>]*)?',
            'va_gov_domain': r'(?i)\b(?:[A-Za-z0-9-]+\.)*va\.gov\b',
            'va_gov_url': r'(?i)\bhttps?://(?:[A-Za-z0-9-]+\.)*va\.gov(?:/[^\s\"\'<>]*)?',
        }

    @property
    def plugin_type(self) -> str:
        return 'endpoints_analyzer'

    @property
    def supported_file_types(self) -> Set[str]:
        return {'*'}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_type == 'text' or file_path.suffix.lower() in {
            '.json', '.js', '.py', '.java', '.php', '.ts', '.ini', '.conf', '.yaml', '.yml',
            '.xml', '.log', '.txt', '.html', '.md', '.sh', '.bash', 'Dockerfile'
        }

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        logging.debug(f"Analyzing endpoints information in {file_path}")
        self._extract_ips_domains_urls(content, results)
        self._analyze_network_protocols(content, results)
        self._analyze_network_security_issues(content, results)
        self._extract_network_configuration(content, results)
        self._correlate_network_endpoints(content, results)
        return results

    def _extract_ips_domains_urls(self, content: str, results: Dict[str, Set[str]]) -> None:
        # IPv4/IPv6
        ipv4_re = self.endpoint_patterns.get('ipv4')
        if ipv4_re:
            for m in re.finditer(ipv4_re, content):
                results.setdefault('ipv4', set()).add(m.group(0))
        ipv6_re = self.endpoint_patterns.get('ipv6')
        if ipv6_re:
            for m in re.finditer(ipv6_re, content):
                results.setdefault('ipv6', set()).add(m.group(0))
        # Domain keywords
        dom_re = self.endpoint_patterns.get('domain_keywords')
        if dom_re:
            for m in re.finditer(dom_re, content):
                results.setdefault('domain_keywords', set()).add(m.group(0))
        # URLs
        url_re = self.endpoint_patterns.get('url')
        if url_re:
            for m in re.finditer(url_re, content):
                results.setdefault('url', set()).add(m.group(0))
        # VA.gov specifics
        va_dom = self.endpoint_patterns.get('va_gov_domain')
        if va_dom:
            for m in re.finditer(va_dom, content):
                results.setdefault('va_gov_domain', set()).add(m.group(0))
        va_url = self.endpoint_patterns.get('va_gov_url')
        if va_url:
            for m in re.finditer(va_url, content):
                results.setdefault('va_gov_url', set()).add(m.group(0))
        # MAC addresses
        mac_re = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
        for m in re.finditer(mac_re, content):
            results.setdefault('mac_address', set()).add(m.group(0))

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
        hosts = list(results.get('network_hosts', set()) or [])
        ports = list(results.get('network_ports', set()) or [])
        if not hosts or not ports:
            return

        # Fast-path: literal 'host:port' detection (cheap substring search)
        endpoints = results.setdefault('network_endpoints', set())
        max_pairs = 1000  # cap work to avoid O(N*M) blowups
        pairs_checked = 0

        for host in hosts:
            for port in ports:
                if pairs_checked >= max_pairs:
                    return
                pairs_checked += 1
                if f"{host}:{port}" in content:
                    endpoints.add(f"{host}:{port}")
                # Only fall back to regex when content is reasonably small
                elif len(content) <= 200_000:
                    try:
                        if re.search(rf'{re.escape(host)}.*?{port}|{port}.*?{re.escape(host)}', content, re.DOTALL):
                            endpoints.add(f"{host}:{port}")
                    except re.error:
                        # Ignore malformed host/port patterns in regex context
                        pass

    def _get_port_service(self, port: int) -> str:
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alternate",
            27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown Service")
