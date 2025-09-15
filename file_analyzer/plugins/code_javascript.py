#!/usr/bin/env python3
# JavaScript code analyzer plugin (flattened)

import re
import json
import logging
from pathlib import Path
from typing import Dict, Set, Optional

from .base_plugin import AnalyzerPlugin


class JavaScriptCodeAnalyzer(AnalyzerPlugin):
    """Analyze JavaScript/TypeScript code for security issues and complexity."""

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"code", "javascript"}
        # Inline JavaScript security patterns (migrated from core.patterns)
        self.security_patterns = {
            'Eval Usage': r"\beval\s*\(",
            'Document Write': r"document\.write\s*\(",
            'innerHtml Assignment': r"\.innerHTML\s*=",
            'DOM-based XSS': r"(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer))",
            'DOM Storage Usage': r"(?:localStorage|sessionStorage)\.",
            'Hardcoded JWT': r"['\"]eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+=]*['\"]",
            'Protocol-relative URL': r"['\"]\/\/\w+",
            'HTTP Without TLS': r"http:\/\/(?!localhost|127\.0\.0\.1)",
            'Dangerous Function Creation': r"(?:new\s+Function|setTimeout\s*\(\s*['\"`][^'\"`]*['\"`]\s*\)|setInterval\s*\(\s*['\"`][^'\"`]*['\"`]\s*\))",
            'Prototype Pollution': r"(?:Object\.assign|Object\.prototype\.|__proto__|constructor\.prototype)",
            # Common DOM XSS sinks: property assignment and HTML injection APIs
            'XSS Sinks': r"(?:\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|\.write(?:ln)?\s*\(|\.createContextualFragment\s*\()",
            'Insecure Randomness': r"(?:Math\.random\s*\(\))",
            'JWT Verification Issues': r"(?:\.verify\s*\(\s*token\s*,\s*['\"`][^'\"]+['\"`]\s*[,\)]|{algorithms:\s*\[\s*['\"`]none['\"`]\s*\]})",
            'Client Storage of Sensitive Data': r"(?:localStorage\.setItem\s*\(\s*['\"`][^'\"]+['\"`]\s*,\s*(?:password|token|key|secret|credentials))",
            'Insecure Client-Side Validation': r"(?:\.validate\s*\(\s*\)|\.isValid\s*\(\s*\))",
            'Weak Cryptography': r"(?:\bMD5\b|\bSHA1\b|\.createHash\s*\(\s*['\"`]md5['\"`]\s*\))",
            'Postmessage Vulnerabilities': r"(?:window\.addEventListener\s*\(\s*['\"`]message['\"`]|\.postMessage\s*\(\s*[^,]+,\s*['\"]\*['\"])",
            'CSRF Issues': r"(?:withCredentials\s*:\s*true|xhrFields\s*:\s*{\s*withCredentials\s*:\s*true\s*})",
            'Content Security Issues': r"(?:unsafe-eval|unsafe-inline)",
            'Hardcoded Credentials': r"(?:username\s*[:=]\s*['\"`][^'\"]+['\"`]|password\s*[:=]\s*['\"`][^'\"]+['\"`]|apiKey\s*[:=]\s*['\"`][^'\"]+['\"`]|token\s*[:=]\s*['\"`][^'\"]+['\"`])",
            'Insecure Communication': r"(?:ws:\/\/(?!localhost|127\.0\.0\.1))",
            'NoSQL Injection': r"(?:\.find\s*\(\s*{\s*\$where\s*:\s*|\.find\s*\(\s*{\s*['\"`][^'\"]+['\"`]\s*:\s*\$\w+)",
            'Regular Expression DOS': r"(?:[^\\][.+*]\{\d+,\}|\(\.\*\)\+)",
            'Insecure Cross-Origin Resource Sharing': r"(?:Access-Control-Allow-Origin\s*:\s*\*|cors\(\s*\{origin\s*:\s*['\"`]\*['\"`])",
            'Insecure Third-Party Scripts': r"(?:<script\s+src\s*=\s*['\"`]http:\/\/|\.src\s*=\s*['\"`]http:\/\/)",
            'Server-Side Request Forgery': r"(?:\.open\s*\(\s*['\"`]GET['\"`]\s*,\s*(?:url|req|request))",
            'Insecure File Upload': r"(?:\.upload\s*\(\s*|\.uploadFile\s*\(\s*|createReadStream\s*\(\s*)",
            'Insecure Iframe': r"(?:<iframe\s+src\s*=\s*['\"`]http:\/\/|\.src\s*=\s*['\"`]http:\/\/)",
            'JSON Injection': r"(?:JSON\.parse\s*\(\s*.*(?:req|request|input|data)\s*)",
            'Path Traversal': r"(?:fs\.readFileSync\s*\(\s*.*\.\.\/|fs\.readFile\s*\(\s*.*\.\.\/)",
            'Command Injection': r"(?:(?:child_process|exec|spawn|execSync)\s*\(\s*.*(?:\+|\$\{))",
        }
        self.additional_security_patterns = {
            'Dangerous Eval': r'(?:\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*[\'"`][^\'"`]*[\'"`]\s*\)|\bsetInterval\s*\(\s*[\'"`][^\'"`]*[\'"`]\s*\))',
            'Prototype Pollution': r'(?:Object\.assign|Object\.prototype\.|__proto__|constructor\.prototype)',
            'DOM XSS': r'(?:\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|\.write(?:ln)?\s*\()',
            'Insecure Randomness': r'(?:Math\.random\s*\(\))',
            'JWT Verification': r'(?:\.verify\s*\(\s*token\s*,\s*[\'"`][^\'"]+[\'"`]\s*[,\)])',
            'Sensitive Info Exposure': r'(?:localStorage\.setItem\s*\(\s*[\'"`][^\'"]+[\'"`]\s*,\s*(?:password|token|key|secret))',
            'Client-Side Validation': r'(?:\.validate\s*\(\s*\)|\.isValid\s*\(\s*\))',
            'Insecure Hashing': r'(?:\bMD5\b|\bSHA1\b)',
            'Event Listeners on Window': r'(?:window\.addEventListener\s*\(\s*[\'"`]message[\'"`])',
            'PostMessage Vulnerability': r'(?:\.postMessage\s*\(\s*[^,]+,\s*[\'"]\*[\'"])',
            'CSRF Vulnerability': r'(?:withCredentials\s*:\s*true)',
            'Content Security Policy': r'(?:unsafe-eval|unsafe-inline)',
            'Hardcoded Credentials': r'(?:username\s*[:=]\s*[\'"`][^\'"]+[\'"`]|password\s*[:=]\s*[\'"`][^\'"]+[\'"`]|apiKey\s*[:=]\s*[\'"`][^\'"]+[\'"`])',
            'Unsanitized Inputs': r'(?:\.param\s*\(\s*[\'"`][^\'"]+[\'"`]\s*\)|req\.query|req\.body)',
            'Regex DOS': r'(?:[^\\][.+*]\{\d+,\}|\(\.\*\)\+)',
        }
        self.security_patterns.update(self.additional_security_patterns)

        self.framework_patterns = {
            'React': r'(?:React\.|ReactDOM\.|import\s+React|from\s+[\'\"]react[\'\"]|extends\s+React\.Component)',
            'Angular': r'(?:@Component|@NgModule|@Injectable|angular\.module|import\s+{\s*[^}]*Component[^}]*\s*}\s+from\s+[\'\"]@angular/core[\'\"])',
            'Vue': r'(?:new\s+Vue|Vue\.component|createApp|import\s+Vue|from\s+[\'\"]vue[\'\"])',
            'jQuery': r'(?:\$\(|jQuery\(|import\s+\$|from\s+[\'\"]jquery[\'\"])',
            'Express': r'(?:express\(\)|app\.get\s*\(|app\.post\s*\(|app\.use\s*\(|router\.get\s*\(|import\s+express|from\s+[\'\"]express[\'\"])',
            'Axios': r'(?:axios\.|axios\(|import\s+axios|from\s+[\'\"]axios[\'\"])',
            'Lodash': r'(?:_\.|import\s+_|from\s+[\'\"]lodash[\'\"])',
            'Moment': r'(?:moment\.|import\s+moment|from\s+[\'\"]moment[\'\"])',
            'D3': r'(?:d3\.|import\s+\*\s+as\s+d3|from\s+[\'\"]d3[\'\"])',
            'Ember': r'(?:Ember\.|import\s+Ember|from\s+[\'\"]ember[\'\"])',
            'Next.js': r'(?:import\s+\{\s*[^}]*useRouter[^}]*\s*\}\s+from\s+[\'\"]next/router[\'\"]|NextPage|GetStaticProps)',
            'Nuxt.js': r'(?:import\s+\{\s*[^}]*useNuxt[^}]*\s*\}\s+from\s+[\'\"]nuxt[\'\"])',
            'GraphQL': r'(?:gql`|ApolloClient|import\s+\{\s*[^}]*gql[^}]*\s*\}\s+from|useQuery\()',
            'Redux': r'(?:createStore|useSelector|useDispatch|import\s+\{\s*[^}]*createStore[^}]*\s*\}\s+from\s+[\'\"]redux[\'\"])',
            'Webpack': r'(?:webpack\.|module\.exports|import\s+webpack)',
            'Jest': r'(?:describe\(|it\(|test\(|expect\(|jest\.|import\s+\{\s*[^}]*(jest|expect)[^}]*\s*\}\s+from)',
            'Cypress': r'(?:\bcy\.|\bCypress\.)',
            'Firebase': r'(?:firebase\.|initializeApp\(|import\s+\{\s*[^}]*initializeApp[^}]*\s*\}\s+from\s+[\'\"]firebase[\'\"])',
            'TypeScript': r'(?:implements\s+|interface\s+[\w_]+\s*\{|type\s+[\w_]+\s*=|as\s+[\w_]+)',
        }

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
                'host': r"(?:^|\s)(?:HOST|host|SERVER|server)\s*(?:=|:)\s*['\"]([\w\.\-]+)['\"]",
            }
        }

        self.complexity_patterns = {
            'complex_function': r'function\s+[\w_]+\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}',
            'nested_callbacks': r'\.then\s*\(\s*(?:function|\([^)]*\)\s*=>).*\.then\s*\(\s*(?:function|\([^)]*\)\s*=>)',
            'deep_nesting': r'(?:\{[^{}]*){5,}',
            'long_line': r'.{120,}',
            'large_object': r'(?:\{[^\}]*(?:(?:\{[^\}]*\})[^\}]*){5,})',
            'multiple_returns': r'(?:return[^;]*;.*){4,}',
            'large_array': r'(?:\[[^\]]*(?:(?:\[[^\]]*\])[^\]]*){5,})',
            'many_parameters': r'function\s+[\w_]+\s*\([^)]{80,}\)',
            'complex_regex': r'\/(?:\\.|[^\/]){40,}\/',
            'complex_ternary': r'\?[^:?]*(?:\?[^:?]*:[^:?]*)+:',
        }

        self.complexity_thresholds = {
            'max_function_length': self.config.get('max_function_length', 100),
            'max_nesting_depth': self.config.get('max_nesting_depth', 4),
            'max_file_size': self.config.get('max_file_size', 1000),
            'max_line_length': self.config.get('max_line_length', 120),
            'max_params': self.config.get('max_params', 5),
        }

    @property
    def plugin_type(self) -> str:
        return 'code_analyzer'

    @property
    def supported_file_types(self) -> Set[str]:
        return {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        if file_path.suffix.lower() in self.supported_file_types:
            return True
        if content and file_path.suffix.lower() not in self.supported_file_types:
            js_signatures = [
                'function ', 'var ', 'let ', 'const ', 'import ', 'export ',
                'class ', '() =>', 'window.', 'document.', 'module.exports',
                'require(', 'async function', 'new Promise'
            ]
            for sig in js_signatures:
                if sig in content:
                    return True
        return False

    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        logging.debug(f"Analyzing JavaScript code in {file_path}")
        try:
            self._check_security_patterns(content, results)
            self._detect_frameworks(content, results)
            self._detect_commented_code(content, results)
            self._analyze_code_complexity(content, results)
            self._detect_api_usage(content, results)
            self._detect_network_features(content, results)
            if file_path.name == 'package.json':
                self._analyze_package_json(content, results)
            return results
        except Exception as e:
            logging.error(f"Error analyzing JavaScript code: {str(e)}")
            results.setdefault('code_quality', set()).add(f"Error analyzing file: {str(e)}")
            return results

    def _check_security_patterns(self, content: str, results: Dict[str, Set[str]]) -> None:
        for smell_name, pattern in self.security_patterns.items():
            try:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    line_no = content[:match.start()].count('\n') + 1
                    context = self._get_context(content, match.start(), 20)
                    finding = f"{smell_name} (line {line_no}): {context.strip()}"
                    results.setdefault('security_smells', set()).add(finding)
            except re.error as e:
                logging.warning(f"Skipping invalid security regex '{smell_name}': {e}")

    def _detect_frameworks(self, content: str, results: Dict[str, Set[str]]) -> None:
        for framework, pattern in self.framework_patterns.items():
            try:
                if re.search(pattern, content, re.MULTILINE):
                    results.setdefault('api_framework', set()).add(f"JavaScript framework: {framework}")
            except re.error as e:
                logging.warning(f"Skipping invalid framework regex for {framework}: {e}")

    def _detect_commented_code(self, content: str, results: Dict[str, Set[str]]) -> None:
        single_line_pattern = r'\/\/.*(?:function|var|let|const|if|for|while|switch|return|=|\{|\})'
        multi_line_pattern = r'\/\*[\s\S]*?(?:function|var|let|const|if|for|while|switch|return|=|\{|\})[\s\S]*?\*\/'
        for pattern in [single_line_pattern, multi_line_pattern]:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                comment = match.group(0)
                if '/**' in comment and '*/' in comment and ('@param' in comment or '@return' in comment):
                    continue
                results.setdefault('commented_code', set()).add(f"Commented code at line {line_no}")

    def _analyze_code_complexity(self, content: str, results: Dict[str, Set[str]]) -> None:
        for complexity_type, pattern in self.complexity_patterns.items():
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                if complexity_type == 'complex_function':
                    function_code = match.group(0)
                    lines = function_code.count('\n') + 1
                    if lines > self.complexity_thresholds['max_function_length']:
                        results.setdefault('code_complexity', set()).add(f"Long function with {lines} lines at line {line_no}")
                elif complexity_type == 'nested_callbacks':
                    results.setdefault('code_complexity', set()).add(f"Nested callbacks (promise chain) at line {line_no}")
                elif complexity_type == 'deep_nesting':
                    results.setdefault('code_complexity', set()).add(f"Deep nesting detected at line {line_no}")
                elif complexity_type == 'long_line':
                    results.setdefault('code_complexity', set()).add(f"Long line ({len(match.group(0))} chars) at line {line_no}")
                elif complexity_type == 'large_object':
                    results.setdefault('code_complexity', set()).add(f"Complex object literal at line {line_no}")
                elif complexity_type == 'multiple_returns':
                    results.setdefault('code_complexity', set()).add(f"Multiple return statements in function at line {line_no}")
                elif complexity_type == 'many_parameters':
                    params = match.group(0)
                    param_count = params.count(',') + 1
                    if param_count > self.complexity_thresholds['max_params']:
                        results.setdefault('code_complexity', set()).add(f"Function with {param_count} parameters at line {line_no}")
                elif complexity_type == 'complex_regex':
                    results.setdefault('code_complexity', set()).add(f"Complex regex pattern at line {line_no}")
                elif complexity_type == 'complex_ternary':
                    results.setdefault('code_complexity', set()).add(f"Complex nested ternary expression at line {line_no}")

    def _detect_api_usage(self, content: str, results: Dict[str, Set[str]]) -> None:
        api_usage_patterns = {
            'Fetch API': r'fetch\s*\(\s*(?P<url>[\'\"][^\'\"]+[\'\"])',
            'Axios': r'axios\.(?:get|post|put|delete|patch)\s*\(\s*(?P<url>[\'\"][^\'\"]+[\'\"])',
            'XMLHttpRequest': r'new\s+XMLHttpRequest\(\)'
        }
        for client, pattern in api_usage_patterns.items():
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                url = match.group('url') if 'url' in match.groupdict() else "unknown"
                if not re.match(r'^https?://', url) and not url.startswith('/api/'):
                    continue
                results.setdefault('api_endpoint', set()).add(f"API endpoint ({client}): {url}")

    def _detect_network_features(self, content: str, results: Dict[str, Set[str]]) -> None:
        for protocol, pattern in self.network_patterns['protocols'].items():
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                results.setdefault('network_protocols', set()).add(f"Network protocol: {protocol}")
        for issue, pattern in self.network_patterns['security_issues'].items():
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                context = self._get_context(content, match.start(), 20)
                results.setdefault('network_security_issues', set()).add(f"{issue} at line {line_no}: {context.strip()}")

    def _analyze_package_json(self, content: str, results: Dict[str, Set[str]]) -> None:
        try:
            package_data = json.loads(content)
            dependencies = {}
            if 'dependencies' in package_data:
                dependencies.update(package_data['dependencies'])
            if 'devDependencies' in package_data:
                dependencies.update(package_data['devDependencies'])
            for package, version in dependencies.items():
                results.setdefault('dependency', set()).add(f"JavaScript package: {package} ({version})")
                if (version.startswith('^0.') or version.startswith('~0.') or version == '*' or version.startswith('>=') or version.startswith('>')):
                    results.setdefault('security_smells', set()).add(f"Potentially insecure dependency version: {package} {version}")
            if 'name' in package_data:
                results.setdefault('software_versions', set()).add(f"Package name: {package_data['name']}")
            if 'version' in package_data:
                results.setdefault('software_versions', set()).add(f"Package version: {package_data['version']}")
            if 'license' in package_data:
                results.setdefault('software_versions', set()).add(f"Package license: {package_data['license']}")
        except json.JSONDecodeError:
            results.setdefault('code_quality', set()).add("Invalid JSON in package.json file")
        except Exception as e:
            logging.error(f"Error analyzing package.json: {str(e)}")

    def _get_context(self, content: str, position: int, context_size: int = 20) -> str:
        start = max(0, position - context_size)
        end = min(len(content), position + context_size)
        line_start = content.rfind('\n', 0, position)
        if line_start == -1:
            line_start = 0
        else:
            line_start += 1
        line_end = content.find('\n', position)
        if line_end == -1:
            line_end = len(content)
        return content[line_start:line_end].strip()
