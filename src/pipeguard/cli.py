"""``pipeguard scan PATH... [--format text|sarif] [--output FILE] [--fail-on error|warning|note]``.

Exit codes: 0 = nothing at or above the fail-on level, 1 = findings at or above it, 2 = invalid input.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .model import Severity, load_workflow
from .report import to_sarif, to_text
from .rules import scan


def _workflow_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files += sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
        elif p.is_file():
            files.append(p)
        else:
            raise ValueError(f"{p}: no such file or directory")
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pipeguard", description="Security checks for GitHub Actions workflows.")
    sub = parser.add_subparsers(dest="command", required=True)
    p_scan = sub.add_parser("scan", help="scan workflow files or directories")
    p_scan.add_argument("paths", nargs="+", type=Path)
    p_scan.add_argument("--format", choices=["text", "sarif"], default="text")
    p_scan.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    p_scan.add_argument("--fail-on", default="error", help="lowest severity that fails the run")
    args = parser.parse_args(argv)

    try:
        threshold = Severity.parse(args.fail_on)
        findings = [f for path in _workflow_files(args.paths) for f in scan(load_workflow(path))]
    except (OSError, ValueError) as exc:
        print(f"pipeguard: error: {exc}", file=sys.stderr)
        return 2

    report = to_sarif(findings) if args.format == "sarif" else to_text(findings)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(to_text(findings), end="")
    else:
        print(report, end="")
    return 1 if any(f.rule.severity >= threshold for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
