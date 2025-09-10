
#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

def to_sarif(report: Dict) -> Dict:
    # Very small SARIF v2.1.0 mapping
    rules = {}
    for r in report.get("rules_loaded", []):
        rules[r["rule_id"]] = r

    results = []
    for f in report.get("findings", []):
        rule_id = f["rule_id"]
        level = {"critical":"error","high":"error","medium":"warning","low":"note"}.get(f["severity"], "warning")
        message = f'{f["rule_name"]} in {f["file_path"]}:{f["line"]}'
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file_path"]},
                    "region": {"startLine": f["line"], "startColumn": f["column_start"]}
                }
            }],
            "properties": {
                "provider": f.get("provider"),
                "category": f.get("category"),
                "entropy": f.get("entropy"),
                "confidence": f.get("confidence"),
                "secretHash": f.get("secret_hash"),
                "redacted": f.get("redacted"),
                "tags": f.get("tags", []),
            }
        })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "file-analyzer dirscan",
                    "rules": [{
                        "id": rid,
                        "name": info.get("name"),
                        "shortDescription": {"text": info.get("description","")},
                        "properties": {"severity": info.get("severity")}
                    } for rid, info in rules.items()]
                }
            },
            "results": results
        }]
    }

def write_sarif(report: Dict, out_path: Path) -> None:
    data = to_sarif(report)
    out_path.write_text(json.dumps(data, indent=2))
