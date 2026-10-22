"""Command-line entry points.

    siglint scan <logfile>... -r <rules>
    siglint validate <rules>
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .engine import Finding, run_rules
from .parsers import parse_file
from .rules import SEVERITY_ORDER, load_rules, validate_rules
from .sarif import to_sarif

_LEVEL_TAG = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "informational": "INFO",
}


def _duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def _print_table(findings: List[Finding], logfiles: List[str]) -> None:
    label = logfiles[0] if len(logfiles) == 1 else f"{len(logfiles)} files"
    if not findings:
        print(f"No findings in {label}.")
        return
    print(f"{len(findings)} finding(s) in {label}:\n")
    width = max(len("RULE"), *(len(f.rule.id) for f in findings))
    print(f"{'LEVEL':5}  {'RULE':{width}}  {'COUNT':>5}  WHERE / LINE")
    print("-" * (width + 40))
    for f in findings:
        if f.group not in (None, "*"):
            where = str(f.group)
            if f.span is not None:
                where += f"  (within {_duration(f.span)})"
        elif len(logfiles) > 1:
            where = f"{f.event.get('_source')}:{f.event.get('_line', '?')}"
        else:
            where = f"line {f.event.get('_line', '?')}"
        tag = _LEVEL_TAG.get(f.rule.level, "MED ")
        print(f"{tag:5}  {f.rule.id:{width}}  {f.count:>5}  {where}")


def _scan(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as exc:
        print(f"error loading rules: {exc}", file=sys.stderr)
        print(f"run `siglint validate {args.rules}` to see every problem", file=sys.stderr)
        return 2
    if not rules:
        print(f"No rules found at {args.rules!r}.", file=sys.stderr)
        return 2

    events = []
    for logfile in args.logfile:
        try:
            for event in parse_file(logfile, args.format):
                event["_source"] = logfile
                events.append(event)
        except OSError as exc:
            print(f"error reading {logfile}: {exc.strerror}", file=sys.stderr)
            return 2

    findings = run_rules(rules, events)

    if args.sarif_file:
        with open(args.sarif_file, "w", encoding="utf-8") as handle:
            json.dump(to_sarif(findings, version=__version__), handle, indent=2)

    if args.output == "sarif":
        print(json.dumps(to_sarif(findings, version=__version__), indent=2))
    elif args.output == "json":
        print(
            json.dumps(
                [
                    {
                        "rule": f.rule.id,
                        "level": f.rule.level,
                        "count": f.count,
                        "group": f.group,
                        "file": f.event.get("_source"),
                        "line": f.event.get("_line"),
                        "span_seconds": f.span,
                    }
                    for f in findings
                ],
                indent=2,
            )
        )
    else:
        _print_table(findings, args.logfile)

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(f.rule.severity_rank >= threshold for f in findings):
            return 1
    return 0


def _validate(args: argparse.Namespace) -> int:
    rules, errors = validate_rules(args.rules)
    for path, message in errors:
        print(f"FAIL  {path}: {message}")
    print(f"{len(rules)} rule(s) OK, {len(errors)} error(s).")
    return 1 if errors or not rules else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siglint",
        description="Scan logs against Sigma-style detection rules.",
    )
    parser.add_argument("--version", action="version", version=f"siglint {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan a log file against rules")
    scan.add_argument("logfile", nargs="+", help="one or more log files")
    scan.add_argument(
        "-r", "--rules", default="rules", help="rule file or directory (default: rules)"
    )
    scan.add_argument(
        "-f", "--format", default="auto", choices=["auto", "syslog", "json"]
    )
    scan.add_argument(
        "-o", "--output", default="table", choices=["table", "sarif", "json"]
    )
    scan.add_argument("--sarif-file", help="also write SARIF to this path")
    scan.add_argument(
        "--fail-on",
        default="none",
        choices=["none", "low", "medium", "high", "critical"],
        help="exit 1 if a finding at or above this level is present",
    )
    scan.set_defaults(func=_scan)

    validate = sub.add_parser("validate", help="check rules for errors without scanning")
    validate.add_argument("rules", nargs="?", default="rules", help="rule file or directory")
    validate.set_defaults(func=_validate)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
