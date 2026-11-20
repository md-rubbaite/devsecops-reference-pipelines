"""Text and SARIF 2.1.0 output. SARIF uploads to GitHub code scanning, so findings appear in the Security tab."""

from __future__ import annotations

import json
from collections.abc import Sequence

from . import __version__
from .model import Finding, Severity
from .rules import ALL_RULES

_SARIF_LEVEL = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.NOTE: "note"}


def to_text(findings: Sequence[Finding]) -> str:
    if not findings:
        return "pipeguard: no findings\n"
    lines = [
        f"{f.path}:{f.line}: {f.rule.severity.name.lower()} {f.rule.id} {f.rule.title}: {f.message}\n"
        f"    fix: {f.rule.remediation}"
        for f in findings
    ]
    counts = {s: sum(1 for f in findings if f.rule.severity == s) for s in Severity}
    summary = ", ".join(f"{n} {s.name.lower()}" for s, n in sorted(counts.items(), reverse=True) if n)
    return "\n".join(lines) + f"\n\npipeguard: {summary}\n"


def to_sarif(findings: Sequence[Finding]) -> str:
    rules = [
        {
            "id": r.id,
            "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "help": {"text": r.remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
        }
        for r in ALL_RULES
    ]
    results = [
        {
            "ruleId": f.rule.id,
            "level": _SARIF_LEVEL[f.rule.severity],
            "message": {"text": f"{f.message} Fix: {f.rule.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        for f in findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "pipeguard", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
