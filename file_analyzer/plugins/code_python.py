#!/usr/bin/env python3
# Python code analyzer plugin (flattened)

import re
import logging
import ast
from pathlib import Path
from typing import Dict, Set, Optional, Tuple

_PRINT_REFACTOR_TOOL = None

from .base_plugin import AnalyzerPlugin


class PythonCodeAnalyzer(AnalyzerPlugin):
    """Analyze Python code for security issues and complexity."""

    def __init__(self, config=None):
        super().__init__(config)
        self.tags = {"code", "python"}
        # Inline Python security patterns (migrated from core.patterns)
        self.security_patterns = {
            'Hardcoded Secret': r"(?:password|secret|key|token)\s*=\s*['\"][^'\"]+['\"]",
            'Shell Injection': r"(?:os\.system|subprocess\.call|subprocess\.Popen|eval|exec)\s*\(",
            'SQL Injection': r"(?:execute|executemany)\s*\(\s*[f'\"]",
            'Pickle Usage': r"pickle\.(?:load|loads)",
            'Temp File': r"(?:tempfile\.mk(?:stemp|temp)|open\s*\(\s*['\"]\/tmp\/)",
            'Assert Usage': r"\bassert\b",
            'HTTP Without TLS': r"http:\/\/(?!localhost|127\.0\.0\.1)",
        }
        # Needs full source for AST/metrics
        self.requires_full_content = True

    @property
    def plugin_type(self) -> str:
        return 'code_analyzer'

    @property
    def supported_file_types(self) -> Set[str]:
        return {'.py', '.pyw'}

    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        return file_path.suffix.lower() in {'.py', '.pyw'}

    def analyze(self, file_path: Path, file_type: str, content: str,
                results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        logging.debug(f"Analyzing Python code in {file_path}")

        # Always run regex-based checks, even if AST parsing fails later
        self._check_security_patterns(content, results)

        # Heuristic: if shebang indicates Python 2, avoid AST parse noise
        head = content[:128]
        if "python2" in head or "python 2" in head:
            logging.info("Detected Python 2 shebang or marker; skipping AST checks")
            results.setdefault('code_quality', set()).add(
                "Detected Python 2.x source; AST-based checks skipped"
            )
            return results

        try:
            tree, analysis_source = self._parse_python_content(content, file_path, results)
            if tree is None:
                return results
            self._check_code_complexity(analysis_source, results)
            self._analyze_ast_security(tree, analysis_source, results)
            return results
        except Exception as exc:
            logging.error(f"Error analyzing Python code: {str(exc)}")
            return results

    def _check_security_patterns(self, content: str, results: Dict[str, Set[str]]) -> None:
        for smell_name, pattern in self.security_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                context = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                finding = f"{smell_name} (line {line_no}): {context.strip()}"
                results.setdefault('security_smells', set()).add(finding)

    def _check_code_complexity(self, content: str, results: Dict[str, Set[str]]) -> None:
        try:
            from radon.complexity import cc_visit
            from radon.metrics import mi_visit

            # Cyclomatic complexity
            complexities = cc_visit(content)
            for item in complexities:
                if item.complexity > 10:
                    results.setdefault('code_complexity', set()).add(
                        f"High complexity ({item.complexity}) in {item.name} at line {item.lineno}"
                    )

            # Maintainability Index (0-100)
            mi_score = mi_visit(content, multi=False)
            try:
                mi_value = float(mi_score)
            except Exception:
                # If radon returns a non-float (older versions), skip gracefully
                mi_value = None
            if mi_value is not None and mi_value < 65:
                results.setdefault('code_quality', set()).add(
                    f"Low maintainability index: {mi_value:.2f}/100"
                )
        except ImportError:
            logging.info("Radon not available, skipping complexity analysis")
        except Exception as e:
            logging.warning(f"Error calculating code metrics: {str(e)}")

    def _parse_python_content(self, content: str, file_path: Path,
                               results: Dict[str, Set[str]]) -> Tuple[Optional[ast.AST], str]:
        """Parse Python content and attempt to recover from Python 2 print syntax."""
        try:
            return ast.parse(content), content
        except SyntaxError as exc:
            line_no = getattr(exc, 'lineno', '?')
            msg = str(exc)

            if self._is_python2_print_error(msg):
                converted = self._convert_python2_prints(content)
                if converted and converted != content:
                    try:
                        tree = ast.parse(converted)
                        results.setdefault('code_quality', set()).add(
                            f"Detected Python 2 print statements; auto-converted for analysis (line {line_no})"
                        )
                        logging.info(f"Auto-converted Python 2 print statements in {file_path}: {msg}")
                        return tree, converted
                    except SyntaxError as retry_err:
                        logging.info(f"Python 2-style print in {file_path}: {msg}")
                        logging.debug(f"Conversion parse failed for {file_path}: {retry_err}")
                else:
                    logging.info(f"Python 2-style print in {file_path}: {msg}")
                results.setdefault('code_quality', set()).add(
                    f"Likely Python 2 print syntax (line {line_no})"
                )
                return None, content

            results.setdefault('code_quality', set()).add(
                f"Python syntax error at line {line_no}: {msg}"
            )
            logging.info(f"Syntax error in {file_path}: {msg}")
            return None, content

    @staticmethod
    def _is_python2_print_error(message: str) -> bool:
        return 'Missing parentheses in call to' in message and 'print' in message

    def _convert_python2_prints(self, content: str) -> Optional[str]:
        """Best-effort conversion of Python 2 print statements using lib2to3."""
        try:
            global _PRINT_REFACTOR_TOOL
            if _PRINT_REFACTOR_TOOL is None:
                from lib2to3.refactor import RefactoringTool
                _PRINT_REFACTOR_TOOL = RefactoringTool(['lib2to3.fixes.fix_print'])
                _PRINT_REFACTOR_TOOL.log.setLevel(logging.ERROR)
            return str(_PRINT_REFACTOR_TOOL.refactor_string(content, 'pycode'))
        except Exception as exc:
            logging.debug(f"Failed to convert Python 2 print statements: {exc}")
            return None

    def _analyze_ast_security(self, tree: ast.AST, content: str, results: Dict[str, Set[str]]) -> None:
        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, file_content, results_dict):
                self.file_content = file_content
                self.lines = file_content.splitlines()
                self.results = results_dict

            def visit_Import(self, node):
                dangerous_modules = ['pickle', 'marshal', 'shelve', 'dill']
                for name in node.names:
                    if name.name in dangerous_modules:
                        self.results.setdefault('security_smells', set()).add(
                            f"Dangerous module import: {name.name} (line {node.lineno})"
                        )
                self.generic_visit(node)

            def visit_Call(self, node):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec']:
                        self.results.setdefault('security_smells', set()).add(
                            f"Dangerous function call: {node.func.id} (line {node.lineno})"
                        )
                    if node.func.id == 'open':
                        if len(node.args) > 0 and isinstance(node.args[0], ast.Str):
                            path = node.args[0].s
                            if any(keyword in path.lower() for keyword in ['secret', 'password', 'key', 'credential', 'token']):
                                self.results.setdefault('security_smells', set()).add(
                                    f"Sensitive file operation: open('{path}') at line {node.lineno}"
                                )
                            if len(node.args) > 1 and isinstance(node.args[1], ast.Str):
                                mode = node.args[1].s
                                if 'w' in mode and path.startswith('/'):
                                    self.results.setdefault('security_smells', set()).add(
                                        f"Potentially insecure file write: open('{path}', '{mode}') at line {node.lineno}"
                                    )
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                        for keyword in node.keywords:
                            if getattr(keyword, 'arg', None) == 'shell' and getattr(keyword, 'value', None) and getattr(keyword.value, 'value', None) is True:
                                self.results.setdefault('security_smells', set()).add(
                                    f"Shell injection risk: subprocess call with shell=True at line {node.lineno}"
                                )
                self.generic_visit(node)

            def visit_BinOp(self, node):
                line_content = self.lines[node.lineno-1] if 0 < node.lineno <= len(self.lines) else ""
                if isinstance(node.op, ast.Mod) and any(s in line_content.upper() for s in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'EXEC']):
                    self.results.setdefault('security_smells', set()).add(
                        f"Potential SQL injection with string formatting (line {node.lineno}): {line_content.strip()}"
                    )
                if isinstance(node.op, ast.Add) and any(s in line_content.lower() for s in ['os.system', 'subprocess', 'popen', 'exec']):
                    self.results.setdefault('security_smells', set()).add(
                        f"Potential command injection with string concatenation (line {node.lineno}): {line_content.strip()}"
                    )
                self.generic_visit(node)

            def visit_Assign(self, node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(keyword in var_name for keyword in ['password', 'secret', 'key', 'token', 'apikey']):
                            if isinstance(node.value, ast.Str) and len(node.value.s) > 3:
                                self.results.setdefault('security_smells', set()).add(
                                    f"Hardcoded sensitive value in variable '{target.id}' at line {node.lineno}"
                                )
                self.generic_visit(node)

            def visit_FunctionDef(self, node):
                for arg in node.args.args:
                    if hasattr(arg, 'arg') and arg.arg.lower() in ['password', 'secret', 'token', 'key']:
                        if not hasattr(arg, 'annotation') or arg.annotation is None:
                            self.results.setdefault('security_smells', set()).add(
                                f"Function '{node.name}' receives sensitive parameter '{arg.arg}' without type annotation at line {node.lineno}"
                            )
                self.generic_visit(node)

        SecurityVisitor(content, results).visit(tree)
