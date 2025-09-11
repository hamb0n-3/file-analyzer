#!/usr/bin/env python3
# JavaScript code analyzer plugin (flattened)

import re
import json
import logging
from pathlib import Path
from typing import Dict, Set, Optional

from ..core.patterns import get_language_security_patterns, get_network_patterns
from .base_plugin import AnalyzerPlugin


class JavaScriptCodeAnalyzer(AnalyzerPlugin):
    """Analyze JavaScript/TypeScript code for security issues and complexity."""

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"code", "javascript"}
        self.security_patterns = get_language_security_patterns().get('javascript', {})
        self.additional_security_patterns = {
            'Dangerous Eval': r'(?:\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*[\'"`][^\'"`]*[\'"`]\s*\)|\bsetInterval\s*\(\s*[\'"`][^\'"`]*[\'"`]\s*\))',
            'Prototype Pollution': r'(?:Object\.assign|Object\.prototype\.|__proto__|constructor\.prototype)',
            'DOM XSS': r'(?:\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML|\.write\s*\(|\.writeln\s*\()',
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

        self.network_patterns = get_network_patterns()

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
        logging.info(f"Analyzing JavaScript code in {file_path}")
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

