
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..plugins.sensitive import Rule, load_rules
from .helpers import (
    TEXT_EXTENSIONS, DEFAULT_EXCLUDES, is_probably_text, shannon_entropy,
    mask_secret, rel_to, fingerprint, should_skip
)

@dataclass
class Finding:
    id: int
    rule_id: str
    rule_name: str
    provider: Optional[str]
    category: str
    severity: str
    confidence: float
    file_path: str
    line: int
    column_start: int
    column_end: int
    match: str
    redacted: str
    secret_hash: str
    entropy: Optional[float]
    context: str
    tags: List[str]

def _compile_rules(rules: List[Rule]) -> List[Rule]:
    # Already compiled in loader, but return as list for clarity
    return rules

def _score(rule: Rule, value: str, context: str) -> float:
    # Simple confidence heuristic
    score = 0.7 if rule.severity in ("high","critical") else 0.5
    if len(value) >= 32:
        score += 0.1
    ent = shannon_entropy(value)
    if ent >= 3.5:
        score += 0.1
    if "password" in context.lower() or "secret" in context.lower() or "token" in context.lower():
        score += 0.05
    return min(score, 0.99)

def _iter_files(root: Path, include_exts: Optional[List[str]], excludes: set[str], follow_symlinks: bool, exclude_globs: Optional[List[str]] = None):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # Prune excluded dirs in-place for performance
        dirnames[:] = [d for d in dirnames if d not in excludes]
        for fn in filenames:
            p = Path(dirpath) / fn
            if should_skip(p, excludes, follow_symlinks):
                continue
            # glob-based excludes on relative path
            if exclude_globs:
                from fnmatch import fnmatch
                rel = os.path.relpath(str(p), str(root))
                if any(fnmatch(rel, pat) for pat in exclude_globs):
                    continue
                continue
            if include_exts:
                if p.suffix.lower() not in include_exts:
                    # still allow obvious text files w/out extensions
                    if not is_probably_text(p):
                        continue
            yield p

def _scan_file(p: Path, rules: List[Rule], root: Path, redact: bool, max_file_bytes: int) -> Tuple[List[Finding], Optional[str]]:
    findings: List[Finding] = []
    if p.stat().st_size > max_file_bytes:
        return findings, None
    try:
        # Read as text with utf-8 fallback
        with open(p, "rb") as f:
            raw = f.read()
        # Detect binary
        if b"\x00" in raw[:2048] and not is_probably_text(p):
            return findings, None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except Exception:
                return findings, None

        rel = rel_to(root, p)
        fid = 0
        # Line-by-line scanning for line-local patterns
        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            for rule in rules:
                for m in rule.pattern.finditer(line):
                    full = m.group(0)
                    # For assignment style patterns, capture the last group if present
                    candidate = m.group(m.lastindex) if m.lastindex else full
                    ent = shannon_entropy(candidate) if candidate else None
                    conf = _score(rule, candidate, line)
                    red = mask_secret(candidate) if redact else candidate
                    findings.append(Finding(
                        id=0,  # temporary; will set later
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        provider=rule.provider,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=round(conf, 2),
                        file_path=rel,
                        line=i,
                        column_start=m.start()+1,
                        column_end=m.end()+1,
                        match=candidate,
                        redacted=red,
                        secret_hash=fingerprint(candidate),
                        entropy=round(ent,2) if ent is not None else None,
                        context=line,
                        tags=rule.tags or []
                    ))
        # Multi-line patterns (e.g., PEM blocks) – search in whole text
        for rule in rules:
            if "PRIVATE KEY" in rule.name or "CERTIFICATE" in rule.name or rule.rule_id in {"JWT"}:
                for m in rule.pattern.finditer(text):
                    start_line = text.count("\n", 0, m.start()) + 1
                    end_line = text.count("\n", 0, m.end()) + 1
                    snippet = text[m.start():m.start()+200]
                    candidate = m.group(0)
                    ent = shannon_entropy(candidate[:2000])
                    conf = _score(rule, candidate, snippet)
                    red = mask_secret(candidate, keep=8) if redact else candidate
                    findings.append(Finding(
                        id=0,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        provider=rule.provider,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=round(conf,2),
                        file_path=rel,
                        line=start_line,
                        column_start=1,
                        column_end=1,
                        match=candidate,
                        redacted=red,
                        secret_hash=fingerprint(candidate),
                        entropy=round(ent,2),
                        context=snippet,
                        tags=rule.tags or []
                    ))
        return findings, None
    except Exception as e:
        return findings, f"{rel_to(root, p)}: {e}"

def scan_directory(
    root: Path,
    include_exts: Optional[List[str]] = None,
    excludes: Optional[List[str]] = None,
    threads: int = 8,
    redact: bool = False,
    max_file_bytes: int = 2_000_000
) -> Dict:
    start = time.time()
    root = root.resolve()
    rules = _compile_rules(load_rules())
    include_exts = [e.lower() if e.startswith(".") else "."+e.lower() for e in (include_exts or [])]
    excludes_set = set(DEFAULT_EXCLUDES)
    if excludes:
        excludes_set.update(excludes)

    findings_all: List[Finding] = []
    errors: List[str] = []

    # Load ignore files if present (.faignore takes precedence; basic glob patterns supported)
    exclude_globs: List[str] = []
    faignore = root / ".faignore"
    gitignore = root / ".gitignore"
    for ign in [faignore, gitignore]:
        if ign.exists():
            for line in ign.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                exclude_globs.append(line)
    files = list(_iter_files(root, include_exts, excludes_set, follow_symlinks=False, exclude_globs=exclude_globs))
    with cf.ThreadPoolExecutor(max_workers=max(2, threads)) as ex:
        futs = [ex.submit(_scan_file, p, rules, root, redact, max_file_bytes) for p in files]
        for fut in cf.as_completed(futs):
            fnds, err = fut.result()
            findings_all.extend(fnds)
            if err:
                errors.append(err)

    # Deduplicate by (file_path, line, rule_id, secret_hash)
    uniq = {}
    for f in findings_all:
        key = (f.file_path, f.line, f.rule_id, f.secret_hash)
        if key not in uniq:
            uniq[key] = f
    findings = list(uniq.values())
    # Assign ids
    for i, f in enumerate(findings, start=1):
        f.id = i

    # Summaries
    by_rule: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    result = {
        "version": "1.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "root_path": str(root),
        "totals": {"files_scanned": len(files), "findings": len(findings)},
        "summary_by_severity": by_sev,
        "summary_by_rule": by_rule,
        "findings": [asdict(f) for f in findings],
        "errors": errors,
        "rules_loaded": [r.rule_id for r in rules]
    }
    return result

def _write_json(data: Dict, out: Optional[Path]) -> None:
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2))
        print(f"Wrote JSON to {out}")
    else:
        print(json.dumps(data, indent=2))

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="file-analyzer dirscan",
        description="Scan a directory for secrets, passwords, URLs, keys, certs, and other sensitive info."
    )
    p.add_argument("path", help="Directory to scan")
    p.add_argument("--ext", action="append", default=None, help="Only include files with these extensions (e.g., --ext .py --ext .env)")
    p.add_argument("--exclude", action="append", default=None, help="Exclude directory or name (exact match, can be repeated)")
    p.add_argument("--threads", type=int, default=8, help="Concurrency (default: 8)")
    p.add_argument("--no-redact", action="store_true", help="Do not redact matched values in JSON (unsafe)")
    p.add_argument("--max-bytes", type=int, default=2_000_000, help="Skip files larger than this size")
    p.add_argument("--json-out", type=str, default=None, help="Write JSON to this path instead of stdout")
    p.add_argument("--sarif-out", type=str, default=None, help="Also write a SARIF v2.1.0 report to this path")
    p.add_argument("--exit-on-high", action="store_true", help="Exit with code 2 if any high/critical findings (CI-friendly)")
    p.add_argument("--use-ignore-files", action="store_true", help="Respect .faignore and .gitignore glob patterns (on by default)")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    root = Path(args.path)
    if not root.exists() or not root.is_dir():
        print(f"Path not found or not a directory: {root}", file=sys.stderr)
        return 1
    data = scan_directory(
        root=root,
        include_exts=args.ext,
        excludes=args.exclude,
        threads=max(2, args.threads),
        redact=not args.no_redact,
        max_file_bytes=args.max_bytes
    )
    _write_json(data, Path(args.json_out) if args.json_out else None)
    if args.sarif_out:
        from .sarif import write_sarif
        write_sarif(data, Path(args.sarif_out))
        print(f"Wrote SARIF to {args.sarif_out}")
    if args.exit_on_high and (data.get("summary_by_severity", {}).get("high", 0) or data.get("summary_by_severity", {}).get("critical", 0)):
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
