#!/usr/bin/env python3
"""
CLI Flag Matrix Runner — Subprocess-based, articulate & professional.

Purpose
-------
Run the project's main CLI in a **subprocess** across a curated matrix of
CLI flag combinations, verify outputs, and produce a clean human-readable
report plus a machine-readable JSON artifact. This is designed to be easy
to read, easy to extend, and safe to run repeatedly in CI or locally.

What you get per test case
--------------------------
- The exact command that was executed
- A concise description of the scenario being exercised
- What was verified and **how** it was verified (exit code, artifacts, content sanity)
- Duration, pass/fail status, and pointers to any artifacts

What you get in the total summary
---------------------------------
- Totals and pass rate
- Timing stats (min / median / mean / p95 / max)
- Heuristics:
  - flags most associated with failures
  - candidate incompatible flag pairs (via simple lift)
  - flags correlated with slower runs

Usage (examples)
----------------
$ python run_all_tests.py
$ python run_all_tests.py --max-cases 100
$ python run_all_tests.py --target ./test/fixtures/sample_project
$ python run_all_tests.py --entry "python -m file_analyzer.main"
$ python run_all_tests.py --only-formats json,md
$ python run_all_tests.py --no-color

Assumptions & detection
-----------------------
- By default we try to invoke the CLI via:  python -m file_analyzer.main
  You can override with --entry "<command...>".
- Target directory is auto-detected from a few common fixture paths, else '.'.

This script is **standalone**. It intentionally avoids importing the product
code so that every run exercises the real command-line entry point.
"""

from __future__ import annotations

import argparse
import dataclasses as dc
import itertools
import json
import math
import os
import re
import shlex
import statistics
import subprocess
import sys
import textwrap
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# ------------------------------- Console UX -------------------------------- #

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR", "0") not in {"1", "true", "TRUE"}


class Palette:
    try:
        from colorama import Fore, Style, init as _colorama_init  # type: ignore
        _colorama_init()  # safe if already initialized
        COK = Fore.GREEN + "✔" + Style.RESET_ALL
        CFAIL = Fore.RED + "✖" + Style.RESET_ALL
        CWARN = Fore.YELLOW + "▲" + Style.RESET_ALL
        BLUE = Fore.CYAN
        GREY = Fore.LIGHTBLACK_EX
        BOLD = Style.BRIGHT
        RESET = Style.RESET_ALL
        GREEN = Fore.GREEN
        RED = Fore.RED
        YELLOW = Fore.YELLOW
    except Exception:
        # Fallback to plain text if colorama isn't available
        COK = "✔"
        CFAIL = "✖"
        CWARN = "▲"
        BLUE = ""
        GREY = ""
        BOLD = ""
        RESET = ""
        GREEN = ""
        RED = ""
        YELLOW = ""


def c(text_: str, color: str) -> str:
    if not _supports_color():
        return text_
    return f"{color}{text_}{Palette.RESET}"


def banner(title: str) -> str:
    return c("═" * 78, Palette.GREY) + "\n" + c(f" {title} ", Palette.BOLD) + "\n" + c("─" * 78, Palette.GREY)


def indent(s: str, n: int = 2) -> str:
    pad = " " * n
    return "\n".join(pad + line if line.strip() else line for line in s.splitlines())


# ------------------------------- Data Models -------------------------------- #

@dc.dataclass(frozen=True)
class Case:
    """A single CLI invocation scenario."""

    mode: str  # "file" or "dir"
    fmt: str  # one of: json, csv, html, md
    quiet: bool
    skip_checks: bool
    summary_only: bool
    recursive: bool = False
    include: Optional[str] = None
    exclude: Optional[str] = None
    plugin: Optional[str] = None  # kept for future extension

    def describe(self) -> str:
        bits = [f"mode={self.mode}", f"format={self.fmt}"]
        for flag, value in [
            ("recursive", self.recursive),
            ("quiet", self.quiet),
            ("skip_checks", self.skip_checks),
            ("summary_only", self.summary_only),
        ]:
            if value:
                bits.append(flag)
        if self.include:
            bits.append(f"include={self.include!r}")
        if self.exclude:
            bits.append(f"exclude={self.exclude!r}")
        if self.plugin:
            bits.append(f"plugin={self.plugin!r}")
        return ", ".join(bits)

    def global_flags(self) -> List[str]:
        flags: List[str] = []
        if self.skip_checks:
            flags.append("--skip-checks")
        return flags

    def subcommand_args(self, output_dir: Path, targets: "Targets") -> List[str]:
        args: List[str] = [self.mode, f"--{self.fmt}", "--output-dir", str(output_dir)]
        if self.mode == "dir":
            if self.recursive:
                args.append("--recursive")
            if self.include:
                args.extend(["--include", self.include])
            if self.exclude:
                args.extend(["--exclude", self.exclude])
        if self.quiet:
            args.append("--quiet")
        if self.summary_only:
            args.append("--summary-only")
        if self.plugin:
            args.extend(["--plugin", self.plugin])

        target_arg = str(targets.directory if self.mode == "dir" else targets.file)
        args.append(target_arg)
        return args

    def as_key(self) -> Tuple[str, ...]:
        """Normalized immutable identity used for mapping stats per-flag."""
        keys = [f"mode={self.mode}", f"--{self.fmt}"]
        if self.recursive and self.mode == "dir":
            keys.append("--recursive")
        if self.quiet:
            keys.append("--quiet")
        if self.skip_checks:
            keys.append("--skip-checks")
        if self.summary_only:
            keys.append("--summary-only")
        if self.include:
            keys.append(f"--include={self.include}")
        if self.exclude:
            keys.append(f"--exclude={self.exclude}")
        if self.plugin:
            keys.append(f"--plugin={self.plugin}")
        return tuple(sorted(keys))


@dc.dataclass(frozen=True)
class Targets:
    """Resolved default targets for file and directory test cases."""

    directory: Path
    file: Path


@dc.dataclass
class Verification:
    label: str
    how: str
    ok: bool
    detail: Optional[str] = None


@dc.dataclass
class Result:
    case: Case
    cmd: List[str]
    started_at: float
    ended_at: float
    returncode: int
    stdout: str
    stderr: str
    artifacts: List[Path]
    verifications: List[Verification]

    @property
    def duration_s(self) -> float:
        return max(0.0, self.ended_at - self.started_at)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and all(v.ok for v in self.verifications)


# ------------------------------- Utilities ---------------------------------- #

def find_target_dir(user_target: Optional[str]) -> Path:
    """Choose a directory to analyze; prefer fixtures if present."""
    if user_target:
        p = Path(user_target)
        if p.exists():
            if p.is_dir():
                return p.resolve()
            if p.is_file():
                return p.parent.resolve()
        print(c(f"[warn] --target path not found: {user_target}", Palette.YELLOW))
    candidates = [
        Path("test/fixtures/sample_project"),
        Path("tests/fixtures/sample_project"),
        Path("tests/fixtures"),
        Path("test/fixtures"),
        Path("example"),
        Path("examples"),
        Path("."),
    ]
    for p in candidates:
        if p.exists():
            return p.resolve()
    return Path(".").resolve()


def find_target_file(user_files: Sequence[str], fallback_dir: Path, *, fallback_file: Optional[Path] = None) -> Path:
    """Pick a representative file for file-mode test cases."""

    for candidate in user_files:
        p = Path(candidate)
        if p.exists() and p.is_file():
            return p.resolve()
        print(c(f"[warn] --file-target path not found or not a file: {candidate}", Palette.YELLOW))

    if fallback_file and fallback_file.exists() and fallback_file.is_file():
        return fallback_file.resolve()

    search_patterns = [
        "*.py",
        "*.js",
        "*.json",
        "*.txt",
        "*.md",
    ]

    def _first_match(iterable: Iterable[Path]) -> Optional[Path]:
        for item in iterable:
            if item.is_file():
                return item.resolve()
        return None

    # Try shallow search first.
    for pattern in search_patterns:
        match = _first_match(sorted(fallback_dir.glob(pattern)))
        if match:
            return match

    # Fall back to a recursive search with the same pattern ordering.
    for pattern in search_patterns:
        match = _first_match(sorted(fallback_dir.rglob(pattern)))
        if match:
            return match

    # As a last resort, pick the first regular file anywhere under the directory.
    match = _first_match(sorted(fallback_dir.rglob("*")))
    if match:
        return match

    raise FileNotFoundError(f"No files found under {fallback_dir}")


def resolve_targets(user_target: Optional[str], file_targets: Sequence[str]) -> Targets:
    """Resolve the directory and representative file targets for the run."""

    explicit_file: Optional[Path] = None
    if user_target:
        p = Path(user_target)
        if p.exists() and p.is_file():
            explicit_file = p.resolve()

    directory = find_target_dir(user_target)
    file_path = find_target_file(file_targets, directory, fallback_file=explicit_file)
    return Targets(directory=directory, file=file_path)


def detect_entry(cmd_override: Optional[str]) -> List[str]:
    """Return the command vector used to invoke the product CLI."""
    if cmd_override:
        return shlex.split(cmd_override)
    # Default: Python module entry
    return [sys.executable, "-m", "file_analyzer.main"]


def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def now_ms() -> int:
    return int(time.time() * 1000)


def human_dur(seconds: float) -> str:
    ms = int(seconds * 1000)
    if ms < 1000:
        return f"{ms} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    m, s = divmod(seconds, 60)
    return f"{int(m)}m {s:04.1f}s"


def quote_cmd(cmd: Sequence[str]) -> str:
    return " ".join(shlex.quote(x) for x in cmd)


def plural(n: int, word: str, suffix: str = "s") -> str:
    return f"{n} {word if n == 1 else word + suffix}"


# ------------------------------ Case Generator ------------------------------ #

def default_flag_matrix(include_patterns: Iterable[str], exclude_patterns: Iterable[str]) -> List[Case]:
    """Curated but thorough combinatorial set for file and directory scans."""

    include_list = [None] + list(include_patterns)
    exclude_list = [None] + list(exclude_patterns)
    common_flags = {
        "quiet": [False, True],
        "skip_checks": [False, True],
        "summary_only": [False, True],
    }

    cases: List[Case] = []

    # File-mode cases exercise per-file export surfaces where format flags apply.
    for fmt in ["json", "csv", "html", "md"]:
        for quiet, skip_checks, summary_only in itertools.product(
            common_flags["quiet"],
            common_flags["skip_checks"],
            common_flags["summary_only"],
        ):
            cases.append(
                Case(
                    mode="file",
                    fmt=fmt,
                    quiet=quiet,
                    skip_checks=skip_checks,
                    summary_only=summary_only,
                )
            )

    # Directory-mode cases focus on recursive and include/exclude behaviour; only json
    # export produces a dedicated artifact in the current CLI implementation.
    for fmt in ["json"]:
        for quiet, skip_checks, summary_only, recursive in itertools.product(
            common_flags["quiet"],
            common_flags["skip_checks"],
            common_flags["summary_only"],
            [False, True],
        ):
            for inc in include_list:
                for exc in exclude_list:
                    cases.append(
                        Case(
                            mode="dir",
                            fmt=fmt,
                            quiet=quiet,
                            skip_checks=skip_checks,
                            summary_only=summary_only,
                            recursive=recursive,
                            include=inc,
                            exclude=exc,
                        )
                    )

    return cases


def limit_cases(cases: List[Case], limit: Optional[int]) -> List[Case]:
    if limit is None or limit <= 0 or limit >= len(cases):
        return cases
    # Take a deterministic spread over the space
    step = max(1, len(cases) // limit)
    return [cases[i] for i in range(0, len(cases), step)][:limit]


# ----------------------------- Running & Checks ----------------------------- #


def _select_relevant_artifacts(case: Case, artifacts: Iterable[Path]) -> Tuple[List[Path], str]:
    if case.mode == "file":
        ext_map = {"json": ".json", "csv": ".csv", "html": ".html", "md": ".md"}
        expected_ext = ext_map.get(case.fmt)
        if not expected_ext:
            return [], f"*_analysis{expected_ext or ''}"
        expected_pattern = f"*_analysis{expected_ext}"
        relevant = [
            p
            for p in artifacts
            if p.suffix.lower() == expected_ext and p.stem.endswith("_analysis")
        ]
        return relevant, expected_pattern

    dir_expected = {"json": ["summary.json"]}
    expected_names = dir_expected.get(case.fmt, [])
    relevant = [p for p in artifacts if p.name in expected_names]
    if expected_names:
        return relevant, " or ".join(expected_names)
    return relevant, "known summary artifact"


def run_one(entry_cmd: List[str], base_out_dir: Path, targets: Targets, case: Case, timeout_s: int) -> Result:
    start = time.time()
    stamp = f"{int(start)}-{os.getpid()}-{abs(hash(case.as_key())) % (10**8)}"
    run_out_dir = ensure_dir(base_out_dir / stamp)
    argv = entry_cmd + case.global_flags() + case.subcommand_args(run_out_dir, targets)
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_s,
        cwd=os.getcwd(),
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    end = time.time()

    artifacts: List[Path] = []
    if run_out_dir.exists():
        for p in run_out_dir.rglob("*"):
            if p.is_file():
                artifacts.append(p)

    verifs: List[Verification] = []
    verifs.append(Verification(
        label="Exit code is 0",
        how="Subprocess return code is checked",
        ok=(proc.returncode == 0),
        detail=f"returncode={proc.returncode}"
    ))

    relevant_artifacts, expected_desc = _select_relevant_artifacts(case, artifacts)
    artifact_kind = "artifact" if case.mode == "file" else "summary artifact"
    verifs.append(Verification(
        label=f"Produced {expected_desc} {artifact_kind}",
        how=f"Scan {run_out_dir} for {expected_desc}",
        ok=bool(relevant_artifacts),
        detail=f"found={len(relevant_artifacts)}"
    ))

    if relevant_artifacts:
        candidate = max(relevant_artifacts, key=lambda x: x.stat().st_mtime)
        try:
            if case.mode == "dir" and case.fmt == "json":
                data = json.loads(candidate.read_text(encoding="utf-8"))
                ok = isinstance(data, dict) and "summary" in data
                verifs.append(Verification(
                    label="Directory summary parses as JSON",
                    how="json.loads() + dict with 'summary'",
                    ok=ok,
                    detail=f"type={type(data).__name__}"
                ))
            elif case.fmt == "json":
                data = json.loads(candidate.read_text(encoding="utf-8"))
                ok = isinstance(data, (dict, list))
                verifs.append(Verification(
                    label="JSON parses and has plausible shape",
                    how="json.loads() + isinstance(dict|list)",
                    ok=ok,
                    detail=f"type={type(data).__name__}"
                ))
            elif case.fmt == "csv":
                text = candidate.read_text(encoding="utf-8", errors="replace")
                lines = [ln for ln in text.splitlines() if ln.strip()]
                ok = len(lines) >= 2 and "," in lines[0]
                verifs.append(Verification(
                    label="CSV has header and at least one row",
                    how="Read file; check ≥2 non-empty lines and comma in header",
                    ok=ok,
                    detail=f"lines={len(lines)}"
                ))
            elif case.fmt == "html":
                text = candidate.read_text(encoding="utf-8", errors="replace")
                ok = "<html" in text.lower() or "<!doctype" in text.lower()
                verifs.append(Verification(
                    label="HTML contains a root <html> or <!DOCTYPE>",
                    how="Substring search in file for '<html' or '<!doctype'",
                    ok=ok
                ))
            elif case.fmt == "md":
                text = candidate.read_text(encoding="utf-8", errors="replace")
                ok = bool(re.search(r"^#\\s+.+", text, re.M)) or "##" in text
                verifs.append(Verification(
                    label="Markdown has at least one heading",
                    how="Regex ^#\\s+ or presence of '##'",
                    ok=ok
                ))
        except Exception as exc:
            verifs.append(Verification(
                label="Artifact content sanity check",
                how="Read/parse failed with exception",
                ok=False,
                detail=str(exc)
            ))
    else:
        verifs.append(Verification(
            label="Artifact content sanity check",
            how="Skipped because no artifact was found",
            ok=False,
            detail="No artifact available"
        ))

    return Result(
        case=case,
        cmd=argv,
        started_at=start,
        ended_at=end,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        artifacts=artifacts,
        verifications=verifs,
    )


# ------------------------------ Reporting ----------------------------------- #

def print_case_result(i: int, n: int, result: Result) -> None:
    print()
    header = f"[{i}/{n}] " + ("PASS" if result.ok else "FAIL")
    color = Palette.GREEN if result.ok else Palette.RED
    print(c(header, color), c(f"({human_dur(result.duration_s)})", Palette.GREY))
    print(indent(c("Command:", Palette.BOLD) + " " + quote_cmd(result.cmd)))
    print(indent(c("Scenario:", Palette.BOLD) + " " + result.case.describe()))
    # What was verified & how
    print(indent(c("Verified:", Palette.BOLD)))
    for v in result.verifications:
        icon = Palette.COK if v.ok else Palette.CFAIL
        line = f"{icon} {v.label} — {v.how}"
        if v.detail:
            line += c(f" [{v.detail}]", Palette.GREY)
        print(indent(line, 4))
    # Artifacts
    if result.artifacts:
        print(indent(c("Artifacts:", Palette.BOLD)))
        for p in sorted(result.artifacts)[:5]:
            print(indent(f"• {p}", 4))
        extra = len(result.artifacts) - min(5, len(result.artifacts))
        if extra > 0:
            print(indent(c(f"... and {extra} more file(s)", Palette.GREY), 6))
    # Stderr (only on failure or when not quiet)
    if (not result.ok) or (not result.case.quiet and result.stderr.strip()):
        print(indent(c("stderr:", Palette.BOLD)))
        snippet = result.stderr.strip()
        if snippet:
            snippet = snippet[-2000:]  # tail
            print(indent(snippet, 4))
    if (not result.case.quiet) and result.stdout.strip():
        print(indent(c("stdout (last 30 lines):", Palette.BOLD)))
        lines = result.stdout.rstrip().splitlines()
        tail = lines[-30:]
        print(indent("\n".join(tail), 4))


def summarize(results: List[Result]) -> Dict[str, object]:
    total = len(results)
    passed = sum(1 for r in results if r.ok)
    failed = total - passed
    durations = [r.duration_s for r in results]
    dmin = min(durations) if durations else 0.0
    dmax = max(durations) if durations else 0.0
    dmed = statistics.median(durations) if durations else 0.0
    dmean = statistics.mean(durations) if durations else 0.0
    dp95 = (statistics.quantiles(durations, n=20)[18] if len(durations) >= 20 else dmax)

    # Per-flag failure and slowness heuristics
    flag_counts = Counter()
    flag_failures = Counter()
    flag_durations: Dict[str, List[float]] = defaultdict(list)
    for r in results:
        keys = r.case.as_key()
        for k in keys:
            flag_counts[k] += 1
            flag_durations[k].append(r.duration_s)
            if not r.ok:
                flag_failures[k] += 1

    flag_failure_rates = [
        (k, flag_failures[k] / flag_counts[k], flag_counts[k])
        for k in sorted(flag_counts)
        if flag_counts[k] >= 3
    ]
    flag_failure_rates.sort(key=lambda x: x[1], reverse=True)

    flag_slow_deltas = []
    for k, dur_list in flag_durations.items():
        with_flag = statistics.mean(dur_list)
        without_list = [r.duration_s for r in results if k not in r.case.as_key()]
        if without_list:
            without_flag = statistics.mean(without_list)
            delta = with_flag - without_flag
            flag_slow_deltas.append((k, delta, len(dur_list)))
    flag_slow_deltas.sort(key=lambda x: x[1], reverse=True)

    # Candidate incompatible pairs (lift of joint failure over independent)
    pair_fail_lift: List[Tuple[str, str, float, int]] = []
    # Build lookup case->ok
    for a, b in itertools.combinations(sorted(flag_counts.keys()), 2):
        # Only consider real flags; ignore format flags conflicting with each other
        if a in {"--json", "--csv", "--html", "--md"} and b in {"--json", "--csv", "--html", "--md"}:
            continue
        with_a = [r for r in results if a in r.case.as_key()]
        with_b = [r for r in results if b in r.case.as_key()]
        with_both = [r for r in results if a in r.case.as_key() and b in r.case.as_key()]
        if len(with_both) < 3:
            continue
        p_fail_a = 1 - (sum(1 for r in with_a if r.ok) / len(with_a))
        p_fail_b = 1 - (sum(1 for r in with_b if r.ok) / len(with_b))
        p_fail_expected = p_fail_a * p_fail_b
        p_fail_both = 1 - (sum(1 for r in with_both if r.ok) / len(with_both))
        lift = (p_fail_both / (p_fail_expected + 1e-9)) if p_fail_expected > 0 else (p_fail_both if p_fail_both > 0 else 0.0)
        pair_fail_lift.append((a, b, lift, len(with_both)))
    pair_fail_lift.sort(key=lambda x: x[2], reverse=True)

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": (passed / total) if total else 0.0,
        "duration": {
            "min_s": dmin,
            "median_s": dmed,
            "mean_s": dmean,
            "p95_s": dp95,
            "max_s": dmax,
        },
        "flag_failure_rates": flag_failure_rates[:10],
        "flag_slow_deltas": flag_slow_deltas[:10],
        "pair_failure_lift": pair_fail_lift[:10],
    }


def print_summary(summary: Dict[str, object]) -> None:
    print()
    print(banner("Total Summary"))
    total = summary["total"]
    passed = summary["passed"]
    failed = summary["failed"]
    rate = summary["pass_rate"]
    dur = summary["duration"]
    print(f"{Palette.BOLD}Results:{Palette.RESET} {passed}/{total} passed "
          f"({rate:.1%}), {failed} failed")

    print()
    print(c("Durations:", Palette.BOLD))
    print(indent(f"min={human_dur(dur['min_s'])}, median={human_dur(dur['median_s'])}, "
                 f"mean={human_dur(dur['mean_s'])}, p95={human_dur(dur['p95_s'])}, "
                 f"max={human_dur(dur['max_s'])}"))

    # Heuristics
    print()
    print(c("Heuristics — flags associated with failures:", Palette.BOLD))
    ff = summary["flag_failure_rates"]
    if not ff:
        print(indent("No signal yet."))
    else:
        for k, rate, count in ff:
            print(indent(f"• {k}: failure rate {rate:.1%} over {count} case(s)"))

    print()
    print(c("Heuristics — flags associated with slower runs:", Palette.BOLD))
    sd = summary["flag_slow_deltas"]
    if not sd:
        print(indent("No signal yet."))
    else:
        for k, delta, count in sd:
            sign = "+" if delta >= 0 else ""
            print(indent(f"• {k}: {sign}{delta:.3f}s average delta over {count} case(s)"))

    print()
    print(c("Heuristics — candidate incompatible flag pairs:", Palette.BOLD))
    pf = summary["pair_failure_lift"]
    if not pf:
        print(indent("No signal yet."))
    else:
        for a, b, lift, n in pf:
            print(indent(f"• {a} + {b}: failure 'lift' {lift:.2f} across {n} case(s)"))


def write_report_json(path: Path, results: List[Result], summary: Dict[str, object]) -> None:
    ensure_dir(path.parent)
    serializable = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": [
            {
                "case": dc.asdict(r.case),
                "cmd": r.cmd,
                "started_at": r.started_at,
                "ended_at": r.ended_at,
                "duration_s": r.duration_s,
                "returncode": r.returncode,
                "ok": r.ok,
                "verifications": [dc.asdict(v) for v in r.verifications],
                "artifacts": [str(p) for p in r.artifacts],
                "stdout_tail": r.stdout.splitlines()[-30:],
                "stderr_tail": r.stderr.splitlines()[-30:],
            }
            for r in results
        ],
        "summary": summary,
    }
    path.write_text(json.dumps(serializable, indent=2))


# --------------------------------- Main ------------------------------------- #

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run the main CLI across a matrix of flag combinations (subprocess).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--entry", help="Command to invoke the product CLI", default=None)
    p.add_argument("--target", help="Directory (or file) to analyze (default: auto-detected)", default=None)
    p.add_argument("--file-target", action="append", default=[], help="Specific file path(s) for file-mode cases; can be repeated.")
    p.add_argument("--only-formats", help="Comma-separated subset of formats to test (json,csv,html,md)", default=None)
    p.add_argument("--max-cases", type=int, default=0, help="If >0, cap the number of generated cases.")
    p.add_argument("--timeout", type=int, default=120, help="Per-case timeout in seconds.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p.add_argument("--include", action="append", default=[], help="Additional include pattern(s) to test.")
    p.add_argument("--exclude", action="append", default=[], help="Additional exclude pattern(s) to test.")
    p.add_argument("--out-root", default="test/.artifacts/cli_matrix", help="Where to place run artifacts.")
    p.add_argument("--report-json", default="test/.reports/cli_matrix.last.json", help="Path to write the JSON report.")
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    entry_cmd = detect_entry(args.entry)
    try:
        targets = resolve_targets(args.target, args.file_target)
    except FileNotFoundError as exc:
        print(c(f"[error] {exc}", Palette.RED))
        return 2
    out_root = ensure_dir(Path(args.out_root))
    report_json = Path(args.report_json)

    include_patterns = args.include or ["*.py", "*.js"]
    exclude_patterns = args.exclude or ["*/node_modules/*", "*/.venv/*", "*/.git/*"]

    cases = default_flag_matrix(include_patterns, exclude_patterns)

    if args.only_formats:
        subset = {f.strip().lower() for f in args.only_formats.split(",")}
        cases = [c for c in cases if c.fmt in subset]

    cases = limit_cases(cases, args.max_cases)

    print(banner("CLI Flag Matrix Runner"))
    print(f"{Palette.BOLD}Entry:{Palette.RESET} {quote_cmd(entry_cmd)}")
    print(f"{Palette.BOLD}Target dir:{Palette.RESET} {targets.directory}")
    print(f"{Palette.BOLD}Target file:{Palette.RESET} {targets.file}")
    print(f"{Palette.BOLD}Output root:{Palette.RESET} {out_root}")
    print(f"{Palette.BOLD}Planned cases:{Palette.RESET} {len(cases)}")

    results: List[Result] = []
    for i, case in enumerate(cases, 1):
        res = run_one(entry_cmd, out_root, targets, case, timeout_s=args.timeout)
        print_case_result(i, len(cases), res)
        results.append(res)

    summary = summarize(results)
    print_summary(summary)
    write_report_json(report_json, results, summary)
    print()
    print(c(f"JSON report written to {report_json}", Palette.BLUE))
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
