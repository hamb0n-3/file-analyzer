#!/usr/bin/env python3
# Endpoints analyzer plugin (formerly Network analyzer)

import re
import logging
import ipaddress
from bisect import bisect_right
from urllib.parse import urlparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Match, Optional, Pattern, Set, Tuple

from .base_plugin import AnalyzerPlugin


@dataclass(frozen=True)
class EndpointPattern:
    """Compiled regex describing a network endpoint or URL."""

    name: str
    pattern: Pattern[str]
    result_key: str
    description: str = ""
    value_group: int = 0


def _compile_endpoint_patterns() -> list[EndpointPattern]:
    """Return curated endpoint patterns used by the analyzer."""

    return [
        EndpointPattern(
            "IPv4 Address",
            re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)"),
            "ipv4",
            "Possible IPv4 address.",
        ),
        EndpointPattern(
            "IPv6 Address",
            re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
            "ipv6",
            "Possible IPv6 address.",
        ),
        EndpointPattern(
            "Domain Name",
            re.compile(r"\b(?:(?=[\w.-]*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"),
            "domain_keywords",
            "Domain-like hostname.",
        ),
        EndpointPattern(
            "HTTP URL",
            re.compile(r"https?://[A-Za-z0-9\-._~%]+(?::\d{1,5})?(?:/[^\s\"\'<>]*)?"),
            "url",
            "HTTP(S) URL.",
        ),
        EndpointPattern(
            "VA.gov Domain",
            re.compile(r"(?i)\b(?:[A-Za-z0-9-]+\.)*va\.gov\b"),
            "va_gov_domain",
            "Veterans Affairs domain.",
        ),
        EndpointPattern(
            "VA.gov URL",
            re.compile(r"(?i)\bhttps?://(?:[A-Za-z0-9-]+\.)*va\.gov(?:/[^\s\"\'<>]*)?"),
            "va_gov_url",
            "Veterans Affairs URL.",
        ),
        EndpointPattern(
            "Cloud Provider Endpoint",
            re.compile(
                r"(?i)\bhttps?://(?:[^/\s]+\.)?(?:amazonaws|azurewebsites|windows|cloudfront|googleapis|appspot|firebaseio|digitaloceanspaces|herokuapp|supabase|vercel|render)\.[^\s\"\'<>]+"
            ),
            "cloud_endpoint",
            "Likely cloud-hosted endpoint.",
        ),
        EndpointPattern(
            "Firebase Realtime Database URL",
            re.compile(r"https://[A-Za-z0-9-]+\.firebaseio\.com/[^\s\"\'<>]+"),
            "firebase_url",
            "Firebase Realtime Database endpoint.",
        ),
        EndpointPattern(
            "Supabase Project URL",
            re.compile(r"https://[a-z]{15,}\.supabase\.co\b"),
            "supabase_url",
            "Supabase project endpoint.",
        ),
    ]


DEFAULT_ENDPOINT_PATTERNS: list[EndpointPattern] = _compile_endpoint_patterns()


def iter_endpoint_matches(
    text: str, patterns: Iterable[EndpointPattern] | None = None
) -> Iterator[tuple[EndpointPattern, Match[str]]]:
    """Yield endpoint pattern matches for provided text."""

    active_patterns = patterns or DEFAULT_ENDPOINT_PATTERNS
    for endpoint_pattern in active_patterns:
        try:
            for match in endpoint_pattern.pattern.finditer(text):
                yield endpoint_pattern, match
        except re.error:
            continue


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
        # share endpoint regexes defined alongside Starlette endpoints
        self.endpoint_patterns: list[EndpointPattern] = list(DEFAULT_ENDPOINT_PATTERNS)

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
        line_starts, lines = self._prepare_line_index(content)
        self._extract_ips_domains_urls(content, results, file_path, line_starts, lines)
        self._analyze_network_protocols(content, results, file_path, line_starts, lines)
        self._analyze_network_security_issues(content, results, file_path, line_starts, lines)
        self._extract_network_configuration(content, results, file_path, line_starts, lines)
        self._correlate_network_endpoints(content, results, file_path, line_starts, lines)
        return results

    def _extract_ips_domains_urls(
        self,
        content: str,
        results: Dict[str, Set[str]],
        file_path: Path,
        line_starts: List[int],
        lines: List[str],
    ) -> None:
        for pattern, match in iter_endpoint_matches(content, self.endpoint_patterns):
            try:
                value = match.group(pattern.value_group)
                start_pos = match.start(pattern.value_group)
            except IndexError:
                value = match.group(0)
                start_pos = match.start()
            if pattern.result_key == 'ipv4' and self._skip_ipv4_candidate(value):
                continue
            if pattern.result_key == 'domain_keywords' and self._skip_domain_candidate(value):
                continue
            if pattern.result_key == 'url' and self._skip_url_candidate(value):
                continue
            self._record_detection(
                results,
                pattern.result_key,
                value,
                file_path=file_path,
                line_starts=line_starts,
                lines=lines,
                position=start_pos,
            )
        # MAC addresses
        mac_re = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
        for m in re.finditer(mac_re, content):
            mac = m.group(0)
            if self._skip_mac_candidate(mac):
                continue
            self._record_detection(
                results,
                'mac_address',
                mac,
                file_path=file_path,
                line_starts=line_starts,
                lines=lines,
                position=m.start(),
            )

    def _analyze_network_protocols(
        self,
        content: str,
        results: Dict[str, Set[str]],
        file_path: Path,
        line_starts: List[int],
        lines: List[str],
    ) -> None:
        for protocol, pattern in self.network_patterns.get('protocols', {}).items():
            match = next(re.finditer(pattern, content), None)
            if not match:
                continue
            self._record_detection(
                results,
                'network_protocols',
                protocol,
                file_path=file_path,
                line_starts=line_starts,
                lines=lines,
                position=match.start(),
            )

    def _analyze_network_security_issues(
        self,
        content: str,
        results: Dict[str, Set[str]],
        file_path: Path,
        line_starts: List[int],
        lines: List[str],
    ) -> None:
        for issue, pattern in self.network_patterns.get('security_issues', {}).items():
            for match in re.finditer(pattern, content):
                line_no = self._line_from_position(match.start(), line_starts)
                context_line = self._line_text(line_no, lines)
                value = f"{issue} (line {line_no}): {content[max(0, match.start() - 20):min(len(content), match.end() + 20)].strip()}"
                self._record_detection(
                    results,
                    'network_security_issues',
                    value,
                    file_path=file_path,
                    line_starts=line_starts,
                    lines=lines,
                    line_num=line_no,
                    context=context_line,
                )

    def _extract_network_configuration(
        self,
        content: str,
        results: Dict[str, Set[str]],
        file_path: Path,
        line_starts: List[int],
        lines: List[str],
    ) -> None:
        if 'port' in self.network_patterns.get('configuration', {}):
            port_pattern = self.network_patterns['configuration']['port']
            for match in re.finditer(port_pattern, content):
                port = match.group(1)
                try:
                    port_number = int(port)
                    if 0 <= port_number <= 65535:
                        self._record_detection(
                            results,
                            'network_ports',
                            port,
                            file_path=file_path,
                            line_starts=line_starts,
                            lines=lines,
                            position=match.start(1),
                        )
                        sensitive_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 27017}
                        if port_number in sensitive_ports:
                            service = self._get_port_service(port_number)
                            issue_value = f"Potentially sensitive port used: {port} (common for {service})"
                            line_no = self._line_from_position(match.start(1), line_starts)
                            context_line = self._line_text(line_no, lines)
                            self._record_detection(
                                results,
                                'network_security_issues',
                                issue_value,
                                file_path=file_path,
                                line_starts=line_starts,
                                lines=lines,
                                line_num=line_no,
                                context=context_line,
                            )
                except ValueError:
                    continue
        if 'host' in self.network_patterns.get('configuration', {}):
            host_pattern = self.network_patterns['configuration']['host']
            for match in re.finditer(host_pattern, content):
                host = match.group(1)
                self._record_detection(
                    results,
                    'network_hosts',
                    host,
                    file_path=file_path,
                    line_starts=line_starts,
                    lines=lines,
                    position=match.start(1),
                )
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) and not host.startswith(('127.', '192.168.', '10.')):
                    line_no = self._line_from_position(match.start(1), line_starts)
                    context_line = self._line_text(line_no, lines)
                    issue_value = f"Hardcoded non-local IP address: {host}"
                    self._record_detection(
                        results,
                        'network_security_issues',
                        issue_value,
                        file_path=file_path,
                        line_starts=line_starts,
                        lines=lines,
                        line_num=line_no,
                        context=context_line,
                    )

    def _correlate_network_endpoints(
        self,
        content: str,
        results: Dict[str, Set[str]],
        file_path: Path,
        line_starts: List[int],
        lines: List[str],
    ) -> None:
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
                endpoint = f"{host}:{port}"
                position = content.find(endpoint)
                if position != -1:
                    endpoints.add(endpoint)
                    line_no = self._line_from_position(position, line_starts)
                    context_line = self._line_text(line_no, lines)
                    self._record_detection(
                        results,
                        'network_endpoints',
                        endpoint,
                        file_path=file_path,
                        line_starts=line_starts,
                        lines=lines,
                        line_num=line_no,
                        context=context_line,
                    )
                    continue
                # Only fall back to regex when content is reasonably small
                elif len(content) <= 200_000:
                    try:
                        match = re.search(
                            rf'{re.escape(host)}.*?{port}|{port}.*?{re.escape(host)}',
                            content,
                            re.DOTALL,
                        )
                        if match:
                            endpoints.add(endpoint)
                            line_no = self._line_from_position(match.start(), line_starts)
                            context_line = self._line_text(line_no, lines)
                            self._record_detection(
                                results,
                                'network_endpoints',
                                endpoint,
                                file_path=file_path,
                                line_starts=line_starts,
                                lines=lines,
                                line_num=line_no,
                                context=context_line,
                            )
                    except re.error:
                        # Ignore malformed host/port patterns in regex context
                        pass

    def _skip_ipv4_candidate(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return True
        if not isinstance(ip, ipaddress.IPv4Address):
            return True
        return (
            ip.is_loopback
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
            or getattr(ip, 'is_link_local', False)
        )

    def _skip_domain_candidate(self, domain: str) -> bool:
        lowered = domain.lower()
        noise_domains = {
            'example.com', 'example.org', 'example.net', 'localhost', 'localdomain',
            'test.com', 'test.org', 'test.net'
        }
        if lowered in noise_domains:
            return True
        if lowered.endswith('.example.com') or lowered.endswith('.example.org'):
            return True
        return False

    def _skip_url_candidate(self, url_value: str) -> bool:
        try:
            parsed = urlparse(url_value)
        except Exception:
            return True
        host = parsed.hostname or ""
        if not host:
            return True
        if self._skip_domain_candidate(host):
            return True
        if parsed.scheme not in {'http', 'https'}:
            return True
        return False

    def _skip_mac_candidate(self, mac: str) -> bool:
        cleaned = mac.replace('-', ':').lower()
        if cleaned == '00:00:00:00:00:00' or cleaned.startswith('ff:ff:ff'):
            return True
        return False

    def _get_port_service(self, port: int) -> str:
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alternate",
            27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown Service")

    def _prepare_line_index(self, content: str) -> Tuple[List[int], List[str]]:
        line_starts: List[int] = []
        lines: List[str] = []
        offset = 0
        for raw_line in content.splitlines(True):
            line_starts.append(offset)
            lines.append(raw_line.rstrip('\r\n'))
            offset += len(raw_line)
        if not line_starts:
            line_starts = [0]
        if not lines and content:
            lines.append(content.rstrip('\r\n'))
        return line_starts, lines

    def _line_from_position(self, position: int, line_starts: List[int]) -> int:
        index = bisect_right(line_starts, position) - 1
        if index < 0:
            index = 0
        return index + 1

    def _line_text(self, line_num: int, lines: List[str]) -> Optional[str]:
        if line_num <= 0:
            return None
        idx = line_num - 1
        if 0 <= idx < len(lines):
            return lines[idx]
        return None

    def _record_detection(
        self,
        results: Dict[str, Set[str]],
        dtype: str,
        value: str,
        *,
        file_path: Path,
        line_starts: List[int],
        lines: List[str],
        position: Optional[int] = None,
        line_num: Optional[int] = None,
        context: Optional[str] = None,
    ) -> None:
        bucket = results.setdefault(dtype, set())
        bucket.add(value)

        if line_num is None and position is not None:
            line_num = self._line_from_position(position, line_starts)
        if context is None and line_num is not None:
            context = self._line_text(line_num, lines)

        meta_container = results.setdefault('__meta__', {})
        if not isinstance(meta_container, dict):
            logging.warning("__meta__ container has unexpected type for endpoints plugin: %s", type(meta_container))
            return
        entries = meta_container.setdefault(dtype, [])
        if not isinstance(entries, list):
            logging.warning("Metadata bucket has unexpected type for %s: %s", dtype, type(entries))
            return

        record: Dict[str, Any] = {
            'value': value,
            'file': str(file_path),
        }
        if line_num is not None:
            record['line_num'] = line_num
        if context is not None:
            record['context'] = context

        for existing in entries:
            if (
                existing.get('value') == record['value']
                and existing.get('file') == record['file']
                and existing.get('line_num') == record.get('line_num')
            ):
                if context is not None and not existing.get('context'):
                    existing['context'] = context
                return

        entries.append(record)
