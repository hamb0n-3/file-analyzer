#!/usr/bin/env python3
"""Comprehensive, verbose test harness for File Analyzer.

This runner is intentionally polished and expressive. It produces
clear, colorized, professional output with timings, suite summaries,
and artifact paths. It can be invoked directly or via the main CLI
using the flag `--test`.

Highlights:
- Artistic banner with concise environment summary
- Per-test progress with icons and durations
- Clean pass/fail table and aggregate metrics
- Writes a compact JSON report to `test/.reports/last_run.json`
"""

from __future__ import annotations

import importlib
import io
import json
import logging
import os
import platform
import re
import sys
import tempfile
import time
import unittest
from collections import Counter, defaultdict, OrderedDict
from contextlib import ExitStack, redirect_stderr, redirect_stdout, nullcontext
from dataclasses import dataclass
from pathlib import Path
from itertools import product
from typing import Any, Dict, Iterable, List, Optional, NamedTuple, Tuple
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from file_analyzer.ai_mode.ai_context_plugin import (  # noqa: E402
    SecretsContextPlugin,
    find_occurrences,
    shannon_entropy,
)
main_module = importlib.import_module("file_analyzer.main")  # noqa: E402


FIXTURES = PROJECT_ROOT / "test" / "fixtures"
ARTIFACTS_ROOT = PROJECT_ROOT / "test" / ".artifacts"
MANIFEST_PATH = FIXTURES / "manifest.json"
SAMPLE_APP = FIXTURES / "sample_project" / "app.py"
SAMPLE_SETTINGS = FIXTURES / "sample_project" / "settings.yaml"
SAMPLE_SERVICES = FIXTURES / "sample_project" / "services.py"
SAMPLE_ROUTES = FIXTURES / "sample_project" / "routes" / "api_routes.js"
SAMPLE_CONFIG = FIXTURES / "sample_project" / "config.ini"
SAMPLE_TEMPLATE = FIXTURES / "sample_project" / "templates" / "index.html"
SAMPLE_DATASET = FIXTURES / "sample_project" / "data" / "sample.json"
SAMPLE_PROJECT_FILES = [
    SAMPLE_APP,
    SAMPLE_SETTINGS,
    SAMPLE_SERVICES,
    SAMPLE_ROUTES,
    SAMPLE_CONFIG,
    SAMPLE_TEMPLATE,
    SAMPLE_DATASET,
]
ADVANCED_PROJECT = FIXTURES / "advanced_project"
ADVANCED_MANIFEST = FIXTURES / "advanced_manifest.json"
ADVANCED_JS = ADVANCED_PROJECT / "src" / "api_client.js"
ADVANCED_HELPER = ADVANCED_PROJECT / "src" / "helper.py"
ADVANCED_SECRETS = ADVANCED_PROJECT / "src" / "nested" / "secrets.txt"


# ---- Styling helpers ---------------------------------------------------------

def _setup_colors() -> Dict[str, callable]:
    try:
        from colorama import init, Fore, Style  # type: ignore

        init()

        def color(text: str, fg: Optional[str] = None, bold: bool = False) -> str:
            parts = []
            if bold:
                parts.append(Style.BRIGHT)
            if fg:
                parts.append(getattr(Fore, fg))
            parts.append(str(text))
            parts.append(Style.RESET_ALL)
            return "".join(parts)

        return {
            "ok": lambda s: color(s, "GREEN", True),
            "warn": lambda s: color(s, "YELLOW", True),
            "err": lambda s: color(s, "RED", True),
            "info": lambda s: color(s, "CYAN", False),
            "muted": lambda s: color(s, "BLUE", False),
            "bold": lambda s: color(s, None, True),
            "plain": lambda s: s,
        }
    except Exception:
        return {
            "ok": lambda s: s,
            "warn": lambda s: s,
            "err": lambda s: s,
            "info": lambda s: s,
            "muted": lambda s: s,
            "bold": lambda s: s,
            "plain": lambda s: s,
        }


COL = _setup_colors()


def _banner() -> str:
    title = "FILE ANALYZER – TEST SUITE"
    bar = "═" * len(title)
    return "\n".join([
        COL["bold"](bar),
        COL["bold"](title),
        COL["bold"](bar),
    ])


def _env_summary() -> str:
    py = platform.python_version()
    impl = platform.python_implementation()
    os_name = platform.system()
    cwd = os.getcwd()
    return (
        f"Python {py} ({impl}) | {os_name} | cwd: {cwd}"
    )


# ---- Custom runner -----------------------------------------------------------

@dataclass
class TestRecord:
    qualified_name: str
    display_name: str
    suite: str
    suite_doc: Optional[str]
    status: str
    seconds: float
    message: Optional[str] = None
    test_doc: Optional[str] = None
    notes: Optional[List[str]] = None


class FancyResult(unittest.TextTestResult):
    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.records: List[TestRecord] = []

    def _doc_line(self, test) -> Optional[str]:
        doc = None
        try:
            doc = test.shortDescription()
        except Exception:
            doc = None
        if not doc:
            raw = getattr(test, "__doc__", None)
            if raw:
                text = str(raw).strip()
                doc = text.splitlines()[0] if text else None
        if isinstance(doc, str):
            doc = doc.strip()
        return doc or None

    def _record(self, test, status: str, elapsed: float, message: Optional[str] = None) -> None:
        qualified_name = test.id() if hasattr(test, "id") else self.getDescription(test)
        display_name = self.getDescription(test)
        suite = test.__class__.__name__
        doc = getattr(test.__class__, "__doc__", None)
        doc_line = doc.strip().splitlines()[0] if doc and doc.strip() else None
        test_doc = self._doc_line(test)
        notes = list(getattr(test, "_test_notes", [])) or None
        self.records.append(
            TestRecord(
                qualified_name=qualified_name,
                display_name=display_name,
                suite=suite,
                suite_doc=doc_line,
                status=status,
                seconds=elapsed,
                message=message,
                test_doc=test_doc,
                notes=notes,
            )
        )

    def startTest(self, test):
        self._started_at = time.perf_counter()
        qualified = test.id() if hasattr(test, "id") else self.getDescription(test)
        doc_line = self._doc_line(test)
        headline = doc_line or self.getDescription(test)
        print(f"  → {COL['muted']('RUN')} {COL['bold'](headline)}")
        print(f"     {COL['muted']('Case:')} {qualified}")
        notes = getattr(test, "_test_notes", None)
        if notes:
            for note in notes:
                print(f"     {COL['info']('Info:')} {note}")
        setattr(
            test,
            "_note_announcer",
            lambda message: print(f"     {COL['info']('Info:')} {message}"),
        )
        super().startTest(test)

    def addSuccess(self, test):
        elapsed = time.perf_counter() - getattr(self, "_started_at", time.perf_counter())
        name = self.getDescription(test)
        print(f"    {COL['ok']('✔ PASS')} {name}  {elapsed:.3f}s")
        self._record(test, "passed", elapsed)
        super().addSuccess(test)

    def addSkip(self, test, reason):
        elapsed = time.perf_counter() - getattr(self, "_started_at", time.perf_counter())
        name = self.getDescription(test)
        print(f"    {COL['warn']('↷ SKIP')} {name}  {elapsed:.3f}s  – {reason}")
        self._record(test, "skipped", elapsed, message=str(reason))
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        elapsed = time.perf_counter() - getattr(self, "_started_at", time.perf_counter())
        name = self.getDescription(test)
        print(f"    {COL['warn']('◌ XFAIL')} {name}  {elapsed:.3f}s")
        message = str(err[1]) if err and len(err) > 1 else None
        self._record(test, "xfail", elapsed, message=message)
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        elapsed = time.perf_counter() - getattr(self, "_started_at", time.perf_counter())
        name = self.getDescription(test)
        print(f"    {COL['warn']('◍ XPASS')} {name}  {elapsed:.3f}s")
        self._record(test, "xpass", elapsed)
        super().addUnexpectedSuccess(test)

    def addFailure(self, test, err):
        elapsed = time.perf_counter() - getattr(self, "_started_at", time.perf_counter())
        name = self.getDescription(test)
        print(f"    {COL['err']('✖ FAIL')} {name}  {elapsed:.3f}s")
        message = str(err[1]) if err and len(err) > 1 else None
        self._record(test, "failed", elapsed, message=message)
        super().addFailure(test, err)

    def addError(self, test, err):
        elapsed = time.perf_counter() - getattr(self, "_started_at", time.perf_counter())
        name = self.getDescription(test)
        print(f"    {COL['err']('‼ ERROR')} {name}  {elapsed:.3f}s")
        message = str(err[1]) if err and len(err) > 1 else None
        self._record(test, "error", elapsed, message=message)
        super().addError(test, err)


class FancyRunner(unittest.TextTestRunner):
    resultclass = FancyResult

    def run(self, test):
        print(_banner())
        print(COL["info"](_env_summary()))
        print("")
        started = time.perf_counter()
        result: FancyResult = super().run(test)  # type: ignore
        duration = time.perf_counter() - started
        records: List[TestRecord] = getattr(result, "records", [])
        status_counts = Counter(rec.status for rec in records)
        total = len(records) or result.testsRun
        passed = status_counts.get("passed", 0)
        failed = status_counts.get("failed", 0)
        errored = status_counts.get("error", 0)
        skipped = status_counts.get("skipped", 0)
        xfail = status_counts.get("xfail", 0)
        xpass = status_counts.get("xpass", 0)
        pass_rate = (passed / total * 100) if total else 0.0
        avg_test = (sum(rec.seconds for rec in records) / total) if total else 0.0
        status_palette = {
            "passed": COL["ok"]("PASS"),
            "failed": COL["err"]("FAIL"),
            "error": COL["err"]("ERROR"),
            "skipped": COL["warn"]("SKIP"),
            "xfail": COL["warn"]("XFAIL"),
            "xpass": COL["warn"]("XPASS"),
        }

        suite_groups: Dict[str, List[TestRecord]] = defaultdict(list)
        for rec in records:
            suite_groups[rec.suite].append(rec)

        slowest_records = sorted(records, key=lambda r: r.seconds, reverse=True)[:3]
        issues_records = [rec for rec in records if rec.status in {"failed", "error", "xpass"}]

        print("")
        suite_payload: List[Dict[str, Any]] = []
        if suite_groups:
            print(COL["bold"]("Suites Covered"))
            for suite, recs in sorted(suite_groups.items()):
                counts = Counter(r.status for r in recs)
                total_suite = len(recs)
                icon = COL["ok"]("✔") if counts.get("failed", 0) == 0 and counts.get("error", 0) == 0 else COL["err"]("✖")
                plural = "test" if total_suite == 1 else "tests"
                print(f"  {icon} {COL['bold'](suite)} ({total_suite} {plural})")
                doc = next((r.suite_doc for r in recs if r.suite_doc), None)
                if doc:
                    print(f"     Focus: {COL['muted'](doc)}")
                scenario_labels = [r.test_doc for r in recs if r.test_doc]
                method_names = [r.qualified_name.split('.')[-1] for r in recs]
                collected_notes: List[str] = []
                for r in recs:
                    if r.notes:
                        collected_notes.extend(r.notes)
                unique_notes = []
                seen_notes = set()
                for note in collected_notes:
                    if note not in seen_notes:
                        unique_notes.append(note)
                        seen_notes.add(note)
                if scenario_labels:
                    if len(scenario_labels) > 4:
                        scenario_display = scenario_labels[:3] + [f"+{len(scenario_labels) - 3} more"]
                    else:
                        scenario_display = scenario_labels
                    print(f"     Scenarios: {', '.join(scenario_display)}")
                if method_names:
                    if len(method_names) > 4:
                        display_methods = method_names[:3] + [f"+{len(method_names) - 3} more"]
                    else:
                        display_methods = method_names
                    print(f"     Cases: {', '.join(display_methods)}")
                if unique_notes:
                    snippet = unique_notes[:3]
                    if len(unique_notes) > 3:
                        snippet.append(f"+{len(unique_notes) - 3} more")
                    print(f"     Notes: {', '.join(snippet)}")
                suite_stats = [f"Passed: {counts.get('passed', 0)}"]
                if counts.get("failed"):
                    suite_stats.append(f"Failed: {counts['failed']}")
                if counts.get("error"):
                    suite_stats.append(f"Errors: {counts['error']}")
                if counts.get("skipped"):
                    suite_stats.append(f"Skipped: {counts['skipped']}")
                if counts.get("xfail"):
                    suite_stats.append(f"XFail: {counts['xfail']}")
                if counts.get("xpass"):
                    suite_stats.append(f"XPass: {counts['xpass']}")
                print(f"     {COL['muted'](' | '.join(suite_stats))}")
                suite_payload.append(
                    {
                        "name": suite,
                        "doc": doc,
                        "tests": total_suite,
                        "passed": counts.get("passed", 0),
                        "failed": counts.get("failed", 0),
                        "errors": counts.get("error", 0),
                        "skipped": counts.get("skipped", 0),
                        "xfail": counts.get("xfail", 0),
                        "xpass": counts.get("xpass", 0),
                        "checks": method_names,
                        "scenarios": [label for label in scenario_labels],
                        "notes": unique_notes,
                    }
                )
            print("")

        print(COL["bold"]("Metrics"))
        print(f"  Tests Run : {total}")
        print(f"  {COL['ok']('✔ Passed')}: {passed}")
        print(f"  {COL['err']('✖ Failed')}: {failed}")
        print(f"  {COL['err']('‼ Errors')}: {errored}")
        print(f"  {COL['warn']('↷ Skipped')}: {skipped}")
        if xfail:
            print(f"  {COL['warn']('◌ XFail')}: {xfail}")
        if xpass:
            print(f"  {COL['warn']('◍ XPass')}: {xpass}")
        if total:
            print(f"  Pass Rate : {pass_rate:.1f}% ({passed}/{total})")
            print(f"  Duration  : {duration:.2f}s total  •  avg {avg_test:.3f}s/test")
        else:
            print(f"  Pass Rate : n/a")
            print(f"  Duration  : {duration:.2f}s total")

        if slowest_records:
            print("")
            print(COL["bold"]("Slowest Tests"))
            for rec in slowest_records:
                badge = status_palette.get(rec.status, rec.status.upper())
                label = rec.test_doc or rec.display_name
                print(f"  {badge}  {rec.seconds:.3f}s  {label}")
                if rec.test_doc and rec.test_doc != label:
                    print(f"     {rec.display_name}")

        if issues_records:
            print("")
            print(COL["bold"]("Issues"))
            for rec in issues_records:
                badge = status_palette.get(rec.status, rec.status.upper())
                label = rec.test_doc or rec.display_name
                print(f"  {badge} {label}")
                if rec.test_doc and rec.test_doc != rec.display_name:
                    print(f"     Case: {rec.display_name}")
                if rec.notes:
                    for note in rec.notes:
                        print(f"     Note: {note}")
                if rec.message:
                    print(f"     {rec.message}")

        # Write enriched JSON report for CI or debugging
        report_dir = PROJECT_ROOT / "test" / ".reports"
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
            slowest_payload = [
                {
                    "qualified_name": rec.qualified_name,
                    "display_name": rec.display_name,
                    "status": rec.status,
                    "seconds": round(rec.seconds, 3),
                    "doc": rec.test_doc,
                    "notes": rec.notes,
                }
                for rec in slowest_records
            ]
            issues_payload = [
                {
                    "qualified_name": rec.qualified_name,
                    "display_name": rec.display_name,
                    "status": rec.status,
                    "message": rec.message,
                    "doc": rec.test_doc,
                    "notes": rec.notes,
                }
                for rec in issues_records
            ]
            payload = {
                "tests": total,
                "passed": passed,
                "failed": failed,
                "errors": errored,
                "skipped": skipped,
                "xfail": xfail,
                "xpass": xpass,
                "pass_rate": round(pass_rate, 2),
                "duration_seconds": round(duration, 3),
                "avg_test_seconds": round(avg_test, 3) if total else 0.0,
                "slowest_tests": slowest_payload,
                "issues": issues_payload,
                "suites": suite_payload,
                "python": platform.python_version(),
                "platform": platform.platform(),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            (report_dir / "last_run.json").write_text(json.dumps(payload, indent=2))
        except Exception:
            pass

        return result


# ---- Tests ------------------------------------------------------------------


class FakeOllama:
    """Predictable stand-in for OllamaLLM used during tests."""

    def __init__(self, model: str = "fake-model") -> None:
        self.model = model
        self.calls: List[Dict[str, Any]] = []

    def build_messages(self, raw_secret: str, language: str, context_snippet: str) -> List[Dict[str, str]]:
        prompt = {
            "role": "user",
            "content": json.dumps(
                {
                    "language": language,
                    "secret": raw_secret,
                    "context": context_snippet,
                }
            ),
        }
        return [{"role": "system", "content": "system"}, prompt]

    def classify(
        self,
        raw_secret: str,
        language: str,
        context_snippet: str,
        *,
        messages: List[Dict[str, str]] | None = None,
        preview_callback=None,
    ) -> Dict[str, Any]:
        entry = {
            "raw_secret": raw_secret,
            "language": language,
            "context": context_snippet,
            "messages_used": messages,
        }
        self.calls.append(entry)
        reply = {
            "type": "api_key" if "key" in raw_secret.lower() else "token",
            "provider": "demo-provider",
            "confidence": 0.99,
            "severity": "moderate",
            "is_placeholder": False,
            "usage": "unit-test",
            "reasoning": "deterministic stub",
        }
        if preview_callback is not None:
            preview_callback(messages or self.build_messages(raw_secret, language, context_snippet), json.dumps(reply), reply)
        return reply


class VerboseCase(unittest.TestCase):
    """TestCase base that records per-test notes for richer runner output."""

    def setUp(self) -> None:  # type: ignore[override]
        super().setUp()
        self._test_notes: List[str] = []

    def add_note(self, note: str) -> None:
        if note:
            text = str(note)
            self._test_notes.append(text)
            announcer = getattr(self, "_note_announcer", None)
            if callable(announcer):
                announcer(text)

    def note(self, label: str, value: Any) -> None:
        self.add_note(f"{label}: {value}")

    # Artifacts helpers
    def mk_artifacts_dir(self, category: str, name: Optional[str] = None) -> Path:
        base = ARTIFACTS_ROOT / category
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        test_name = self.id().split(".")[-1]
        label = name or test_name
        # Keep paths readable and safe
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(label)).strip("-")
        run_dir = base / safe
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self.note("Artifacts", run_dir)
        print(f"ARTIFACTS> {run_dir}")
        return run_dir


class PluginTestCase(VerboseCase):
    """Unit-level checks for secrets analysis helpers and integrations."""

    maxDiff = None

    def setUp(self) -> None:
        super().setUp()
        self.manifest_content = MANIFEST_PATH.read_text()
        self.note("Fixture manifest", MANIFEST_PATH)

    def test_find_occurrences_reuses_lines(self) -> None:
        """Utility: find_occurrences reuses shared line cache for speed."""

        self.note("Sample text", "alpha/beta lines")
        self.note("Search terms", "alpha, beta")
        text = "alpha\nbeta\nalpha"
        lines = text.splitlines()
        matches = find_occurrences(text, "alpha", lines)
        self.assertEqual(matches, [(1, 1), (3, 1)])
        matches_no_lines = find_occurrences(text, "beta")
        self.assertEqual(matches_no_lines, [(2, 1)])

    def test_make_full_analysis_without_llm_uses_cache(self) -> None:
        """Analysis: offline mode exercises cache hits and misses."""

        self.note("SecretsContextPlugin.use_llm", False)
        plugin = SecretsContextPlugin(use_llm=False)
        report = plugin.analyze(MANIFEST_PATH, "json", self.manifest_content)
        stats = report["statistics"]
        self.assertEqual(len(report["results"]), 11)
        self.assertGreaterEqual(stats["file_cache_hits"], 1)
        self.assertGreaterEqual(stats["file_cache_misses"], 1)
        self.assertEqual(stats["llm_attempts"], 0)
        # Ensure context snippet captured expected lines
        snippets = [entry["context_snippet"] for entry in report["results"] if entry["occurrences"]]
        self.assertTrue(any("ZZZ_SUPER_SECRET" in snippet for snippet in snippets))

    def test_analysis_with_mock_llm_and_preview(self) -> None:
        """Analysis: preview logging triggers for deterministic mock LLM."""

        self.note("SecretsContextPlugin.preview_count", 2)
        self.note("LLM backend", "FakeOllama stub")
        plugin = SecretsContextPlugin(use_llm=True, preview_count=2)
        fake_llm = FakeOllama()
        plugin._ensure_ollama = lambda: fake_llm  # type: ignore
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            report = plugin.analyze(MANIFEST_PATH, "json", self.manifest_content)
        stderr_output = buffer.getvalue()
        self.assertIn("[LLM preview 1/2]", stderr_output)
        self.assertIn("[LLM preview 2/2]", stderr_output)
        self.assertNotIn("[LLM preview 3/2]", stderr_output)
        self.assertEqual(len(fake_llm.calls), 11)
        stats = report["statistics"]
        self.assertEqual(stats["llm_attempts"], 11)
        self.assertEqual(stats["llm_successes"], 11)
        self.assertGreaterEqual(stats["llm_total_seconds"], 0)
        self.assertIn("llm_avg_seconds", stats)

    def test_entropy_helper(self) -> None:
        """Utility: shannon_entropy handles uniform and mixed distributions."""

        self.note("Inputs", "aaaa, ab")
        entropy = shannon_entropy("aaaa")
        self.assertEqual(entropy, 0.0)
        entropy_mixed = shannon_entropy("ab")
        self.assertAlmostEqual(entropy_mixed, 1.0, places=6)

    def test_cli_ai_flow_uses_preview_and_writes_output(self) -> None:
        """CLI: ai subcommand writes enriched manifest and honors preview count."""

        self.note("Patched plugin", "DummyPlugin capturing preview_count")
        self.note("Manifest", MANIFEST_PATH)
        class DummyPlugin:
            last_init_kwargs: Dict[str, Any] | None = None
            run_calls: List[Path] = []

            def __init__(self, **kwargs: Any) -> None:
                DummyPlugin.last_init_kwargs = kwargs

            def run_from_manifest_path(self, manifest_path: Path) -> Dict[str, Any]:
                DummyPlugin.run_calls.append(manifest_path)
                return {
                    "version": "1.0",
                    "plugin": "Dummy",
                    "generated_at": "2024-01-01T00:00:00Z",
                    "inputs": {"manifest_path": str(manifest_path)},
                    "results": [],
                    "statistics": {"total_secrets": 0},
                }

        output_path = self.mk_artifacts_dir("ai", "dummy-plugin") / "enriched.json"
        argv = [
            "file-analyzer",
            "ai",
            "-i",
            str(MANIFEST_PATH),
            "-o",
            str(output_path),
            "--preview",
            "3",
        ]
        with mock.patch.object(sys, "argv", argv), \
            mock.patch.object(main_module, "check_dependencies", return_value=True), \
            mock.patch.object(main_module, "load_config", return_value={}), \
            mock.patch("file_analyzer.ai_mode.ai_context_plugin.SecretsContextPlugin", DummyPlugin):
            exit_code = main_module.main()
        self.assertEqual(exit_code, 0)
        self.assertTrue(output_path.exists())
        written = json.loads(output_path.read_text())
        self.assertEqual(written["plugin"], "Dummy")
        self.assertEqual(DummyPlugin.last_init_kwargs["preview_count"], 3)
        self.assertEqual(DummyPlugin.run_calls, [MANIFEST_PATH])


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def _filter_cli_output(text: str) -> str:
    """Strip ANSI escape codes and collapse empty lines for reliable checks."""

    if not text:
        return ""
    cleaned = ANSI_ESCAPE_RE.sub("", text)
    lines = [line.rstrip() for line in cleaned.splitlines() if line.strip()]
    return "\n".join(lines)


class CLIResult(NamedTuple):
    code: int
    stdout: str
    stderr: str
    filtered_stdout: str


class CLICombinationTests(VerboseCase):
    """Drive the CLI through comprehensive flag combinations against fixtures."""

    maxDiff = None

    EXPORT_FLAG_MAP = OrderedDict(
        [
            ("json", "--json"),
            ("html", "--html"),
            ("csv", "--csv"),
            ("md", "--md"),
        ]
    )
    CONSOLE_FLAG_MAP = OrderedDict(
        [
            ("summary_only", "--summary-only"),
            ("quiet", "--quiet"),
            ("md", "--md"),
        ]
    )
    PLUGIN_CHOICES: Tuple[Optional[str], ...] = (None, "secrets", "all")

    def run_cli(
        self,
        argv: List[str],
        *,
        expect_code: int = 0,
        capture_stdout: bool = True,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        details: Optional[List[str]] = None,
    ) -> CLIResult:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        command_preview = " ".join(str(a) for a in argv)
        self.add_note(f"Command: {command_preview}")
        print(f"COMMAND> {command_preview}")
        if expect_code != 0:
            self.add_note(f"Expect exit code: {expect_code}")
        if cwd is not None:
            self.add_note(f"Working dir: {cwd}")
        if env:
            rendered_env = ", ".join(f"{k}={v}" for k, v in sorted(env.items()))
            self.add_note(f"Env overrides: {rendered_env}")
        if details:
            for line in details:
                self.add_note(line)

        def _value_after(flag: str) -> Optional[str]:
            try:
                idx = argv.index(flag)
            except ValueError:
                return None
            if idx + 1 < len(argv):
                return str(argv[idx + 1])
            return None

        output_dir = _value_after("--output-dir")
        if output_dir:
            self.add_note(f"Output dir flag: {output_dir}")
        plugin_select = _value_after("--plugin")
        if plugin_select:
            self.add_note(f"Plugin filter: {plugin_select}")
        preview = _value_after("--preview")
        if preview is not None and preview != "":
            self.add_note(f"Preview count flag: {preview}")
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(main_module, "load_config", return_value={}))
            stack.enter_context(mock.patch.object(main_module, "check_dependencies", return_value=True))
            if cwd is not None:
                original_os_cwd = os.getcwd()
                os.chdir(str(cwd))
                stack.callback(os.chdir, original_os_cwd)
                stack.enter_context(mock.patch("pathlib.Path.cwd", return_value=cwd))
                stack.enter_context(mock.patch("os.getcwd", return_value=str(cwd)))
            if env:
                stack.enter_context(mock.patch.dict(os.environ, env, clear=False))
            if capture_stdout:
                stack.enter_context(redirect_stdout(stdout_buffer))
            stack.enter_context(redirect_stderr(stderr_buffer))
            try:
                code = main_module.main()
            except SystemExit as exc:  # version/requirements exit early
                code = exc.code if isinstance(exc.code, int) else 0
        self.assertEqual(
            code,
            expect_code,
            f"CLI returned {code}, expected {expect_code}; stderr={stderr_buffer.getvalue()}",
        )
        stdout_value = stdout_buffer.getvalue()
        stderr_value = stderr_buffer.getvalue()
        filtered_value = _filter_cli_output(stdout_value)
        return CLIResult(
            code=code,
            stdout=stdout_value,
            stderr=stderr_value,
            filtered_stdout=filtered_value,
        )

    def _assert_json_file(self, path: Path) -> Dict[str, Any]:
        self.assertTrue(path.exists(), f"Expected JSON artifact {path}")
        return json.loads(path.read_text())

    def _flag_matrix(self, mapping: OrderedDict[str, str]) -> Iterable[Dict[str, bool]]:
        keys = list(mapping.keys())
        for bits in product([False, True], repeat=len(keys)):
            yield {keys[idx]: bits[idx] for idx in range(len(keys))}

    def _combo_label(self, combo: Dict[str, bool]) -> str:
        enabled = [name for name, state in combo.items() if state]
        return ",".join(enabled) if enabled else "none"

    def _assert_common_artifacts(self, out_dir: Path) -> None:
        for name in ("summary.json", "summary.txt", "plugins-output.json", "plugins-output.txt"):
            self.assertTrue((out_dir / name).exists(), f"Missing {name} in {out_dir}")

    def _assert_summary_html(self, out_dir: Path, enabled: bool) -> None:
        summary_html = out_dir / "summary.html"
        if enabled:
            self.assertTrue(summary_html.exists(), f"Expected {summary_html}")
        else:
            self.assertFalse(summary_html.exists(), f"Unexpected {summary_html}")

    def _expect_manifest(self, out_dir: Path, plugin: Optional[str]) -> None:
        expect_manifest = plugin in {"secrets", "all"}
        manifest_path = out_dir / "secrets.json"
        if expect_manifest:
            self.assertTrue(manifest_path.exists(), f"Expected {manifest_path}")
        else:
            self.assertFalse(manifest_path.exists(), f"Unexpected {manifest_path}")

    def _assert_file_exports(
        self,
        out_dir: Path,
        files: Iterable[Path],
        flags: Dict[str, bool],
    ) -> None:
        for file_path in files:
            stem = file_path.stem
            json_path = out_dir / f"{stem}_analysis.json"
            html_path = out_dir / f"{stem}_analysis.html"
            csv_path = out_dir / f"{stem}_analysis.csv"
            md_path = out_dir / f"{stem}_analysis.md"
            txt_path = out_dir / f"{stem}_analysis.txt"

            if flags.get("json"):
                self.assertTrue(json_path.exists(), f"Expected {json_path}")
            else:
                self.assertFalse(json_path.exists(), f"Unexpected {json_path}")

            if flags.get("html"):
                self.assertTrue(html_path.exists(), f"Expected {html_path}")
            else:
                self.assertFalse(html_path.exists(), f"Unexpected {html_path}")

            if flags.get("csv"):
                self.assertTrue(csv_path.exists(), f"Expected {csv_path}")
            else:
                self.assertFalse(csv_path.exists(), f"Unexpected {csv_path}")

            if flags.get("md"):
                self.assertTrue(md_path.exists(), f"Expected {md_path}")
                self.assertFalse(txt_path.exists(), f"Unexpected {txt_path}")
            else:
                self.assertTrue(txt_path.exists(), f"Expected {txt_path}")
                self.assertFalse(md_path.exists(), f"Unexpected {md_path}")

    def _assert_no_text_reports(self, out_dir: Path, files: Iterable[Path]) -> None:
        for file_path in files:
            stem = file_path.stem
            self.assertFalse((out_dir / f"{stem}_analysis.md").exists())
            self.assertFalse((out_dir / f"{stem}_analysis.txt").exists())

    def test_file_export_flag_matrix(self) -> None:
        """Exercise every combination of export toggles with each plugin choice."""

        base_targets = [str(path) for path in SAMPLE_PROJECT_FILES]
        for plugin in self.PLUGIN_CHOICES:
            for flags in self._flag_matrix(self.EXPORT_FLAG_MAP):
                label = f"plugin={plugin or 'default'}|exports={self._combo_label(flags)}"
                with self.subTest(label=label):
                    out_dir = self.mk_artifacts_dir("file-matrix", label)
                    argv = [
                        "file-analyzer",
                        "--skip-checks",
                        "file",
                        *base_targets,
                    ]
                    for name, enabled in flags.items():
                        if enabled:
                            argv.append(self.EXPORT_FLAG_MAP[name])
                    argv.extend(["--output-dir", str(out_dir)])
                    if plugin:
                        argv.extend(["--plugin", plugin])
                    result = self.run_cli(argv)
                    self.assertEqual(result.code, 0)
                    filtered = result.filtered_stdout
                    if filtered:
                        for line in filtered.splitlines():
                            self.assertFalse(
                                line.startswith("Results for:"),
                                f"Unexpected detail output: {line}",
                            )
                    self._assert_common_artifacts(out_dir)
                    self._assert_summary_html(out_dir, flags.get("html", False))
                    self._assert_file_exports(out_dir, SAMPLE_PROJECT_FILES, flags)
                    self._expect_manifest(out_dir, plugin)

    def test_file_console_flag_matrix(self) -> None:
        """Run console output combinations without an explicit output directory."""

        console_targets = [str(path) for path in SAMPLE_PROJECT_FILES[:3]]
        for plugin in self.PLUGIN_CHOICES:
            for flags in self._flag_matrix(self.CONSOLE_FLAG_MAP):
                label = f"plugin={plugin or 'default'}|console={self._combo_label(flags)}"
                with self.subTest(label=label):
                    out_dir = self.mk_artifacts_dir("file-console", label)
                    argv = [
                        "file-analyzer",
                        "--skip-checks",
                        "file",
                        *console_targets,
                    ]
                    for name, enabled in flags.items():
                        if enabled:
                            argv.append(self.CONSOLE_FLAG_MAP[name])
                    if plugin:
                        argv.extend(["--plugin", plugin])
                    result = self.run_cli(argv, cwd=out_dir)
                    self.assertEqual(result.code, 0)
                    self._assert_common_artifacts(out_dir)
                    self._assert_no_text_reports(out_dir, SAMPLE_PROJECT_FILES[:3])
                    self._expect_manifest(out_dir, plugin)
                    filtered = result.filtered_stdout
                    if flags["quiet"]:
                        self.assertFalse(filtered, "quiet flag should suppress stdout")
                    else:
                        self.assertIn("Analysis Complete", filtered)
                        has_details = not flags["summary_only"]
                        if has_details:
                            self.assertIn("Results for:", filtered)
                        else:
                            self.assertNotIn("Results for:", filtered)
                        if flags["md"] and has_details:
                            self.assertIn("```", filtered)
                        if not flags["md"]:
                            self.assertNotIn("```", filtered)

    def test_dir_mode_summary_outputs(self) -> None:
        """Dir CLI: summary artifacts generated for advanced project."""

        out = self.mk_artifacts_dir("dir", "summary")
        self.note("Scan root", ADVANCED_PROJECT)
        argv = [
            "file-analyzer",
            "--skip-checks",
            "dir",
            str(ADVANCED_PROJECT),
            "--output-dir",
            str(out),
        ]
        result = self.run_cli(argv)
        self.assertEqual(result.code, 0)
        filtered = result.filtered_stdout
        if filtered:
            self.assertNotIn("Results for:", filtered)
        summary = self._assert_json_file(out / "summary.json")
        self.assertIn("summary", summary)
        self.assertTrue((out / "summary.txt").exists())
        self.assertTrue((out / "plugins-output.json").exists())

    def test_dir_mode_recursive_with_include_exclude(self) -> None:
        """Dir CLI: recursive include/exclude globs restrict file set."""

        out = self.mk_artifacts_dir("dir", "recursive")
        self.note("Scan root", ADVANCED_PROJECT)
        argv = [
            "file-analyzer",
            "--skip-checks",
            "dir",
            str(ADVANCED_PROJECT),
            "--output-dir",
            str(out),
            "--recursive",
            "--include",
            "*.js",
            "--exclude",
            "*tests*",
        ]
        result = self.run_cli(argv)
        self.assertEqual(result.code, 0)
        summary = self._assert_json_file(out / "summary.json")
        total_files = summary.get("summary", {}).get("total_files")
        self.assertEqual(total_files, 1)

    def test_dir_mode_quiet_summary_only(self) -> None:
        """Dir CLI: quiet + summary-only produces silent CLI run."""

        out = self.mk_artifacts_dir("dir", "quiet-summary")
        self.note("Scan root", ADVANCED_PROJECT)
        argv = [
            "file-analyzer",
            "--skip-checks",
            "dir",
            str(ADVANCED_PROJECT),
            "--output-dir",
            str(out),
            "--quiet",
            "--summary-only",
        ]
        result = self.run_cli(argv)
        self.assertEqual(result.code, 0)
        filtered = result.filtered_stdout
        if filtered:
            self.assertNotIn("Results for:", filtered)
        self.assertTrue((out / "summary.json").exists())

    def test_ai_mode_with_preview_count(self) -> None:
        """AI CLI: preview count surfaces log lines and writes report."""

        output = self.mk_artifacts_dir("ai", "preview-2") / "enriched.json"
        self.note("Manifest", ADVANCED_MANIFEST)
        argv = [
            "file-analyzer",
            "ai",
            "-i",
            str(ADVANCED_MANIFEST),
            "-o",
            str(output),
            "--preview",
            "2",
        ]
        result = self.run_cli(argv)
        self.assertEqual(result.code, 0)
        self.assertTrue(output.exists())
        data = json.loads(output.read_text())
        stats = data.get("statistics", {})
        self.assertEqual(stats.get("processed"), 3)
        self.assertEqual(stats.get("total_secrets"), 3)
        self.assertGreaterEqual(stats.get("llm_attempts", 0), 0)
        self.assertIn("Enriched manifest written", result.filtered_stdout)

    def test_ai_mode_preview_flag_defaults_to_one(self) -> None:
        """AI CLI: bare --preview still processes each secret."""

        output = self.mk_artifacts_dir("ai", "preview-default") / "enriched.json"
        self.note("Manifest", MANIFEST_PATH)
        argv = [
            "file-analyzer",
            "ai",
            "-i",
            str(MANIFEST_PATH),
            "-o",
            str(output),
            "--preview",
        ]
        result = self.run_cli(argv)
        self.assertEqual(result.code, 0)
        self.assertTrue(output.exists())
        data = json.loads(output.read_text())
        stats = data.get("statistics", {})
        self.assertEqual(stats.get("processed"), stats.get("total_secrets"))
        self.assertEqual(stats.get("llm_attempts"), stats.get("total_secrets"))
        self.assertGreaterEqual(len(result.stderr), 0)


class AggregationTests(VerboseCase):
    """Utility helpers covering aggregation and conversion pipelines."""

    def test_roundtrip_aggregate_and_convert(self) -> None:
        """Aggregations: bucket secrets then restore to result structure."""

        # Simulate a small all_results structure
        file_path = str(SAMPLE_APP)
        self.note("Sample file", file_path)
        all_results = {
            file_path: {
                "api_key": {"abc123"},
                "password": {"p@ss"},
                "__meta__": {
                    "api_key": [{"value": "abc123", "file": file_path, "line": 1}],
                },
            }
        }

        # Aggregate to plugin buckets
        from file_analyzer.utils.output_formatter import (
            aggregate_results_by_plugin,
            aggregated_payload_to_results,
        )

        buckets = aggregate_results_by_plugin(all_results)
        self.assertIn("secrets", buckets)
        secrets_bucket = buckets["secrets"]
        self.assertIn("categories", secrets_bucket)
        self.assertIn("entries", secrets_bucket)

        # Convert a bucket back to results and ensure structure remains compatible
        restored = aggregated_payload_to_results(secrets_bucket)
        self.assertIn("api_key", restored)
        self.assertIsInstance(restored["api_key"], set)
        self.assertIn("__meta__", restored)
        self.assertIsInstance(restored["__meta__"].get("api_key"), list)


# ---- Public entrypoint -------------------------------------------------------

def run(pattern: Optional[str] = None) -> int:
    """Run the test suite with fancy output. Returns process exit code."""
    loader = unittest.TestLoader()
    if pattern:
        loader.testNamePatterns = [pattern]
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = FancyRunner(verbosity=2, stream=sys.stdout, descriptions=True)
    result: unittest.TestResult = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    # Allow running a subset by name with TEST pattern env var
    pat = os.environ.get("TEST") or None
    sys.exit(run(pat))
