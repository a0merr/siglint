"""Command-line entry point: `siglint scan <logfile> -r <rules>`."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .engine import Finding, run_rules
from .parsers import parse_file
from .rules import SEVERITY_ORDER, load_rules
from .sarif import to_sarif

_LEVEL_TAG = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "informational": "INFO",
}


def _print_table(findings: List[Finding], logfile: str) -> None:
    if not findings:
        print(f"No findings in {logfile}.")
        return
    print(f"{len(findings)} finding(s) in {logfile}:\n")
    print(f"{'LEVEL':5}  {'RULE':24}  {'COUNT':>5}  WHERE / LINE")
    print("-" * 70)
    for f in findings:
        where = f.group if f.group not in (None, "*") else f"line {f.event.get('_line', '?')}"
        tag = _LEVEL_TAG.get(f.rule.level, "MED ")
        print(f"{tag:5}  {f.rule.id[:24]:24}  {f.count:>5}  {where}")


def _scan(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    if not rules:
        print(f"No rules found at {args.rules!r}.", file=sys.stderr)
        return 2

    events = list(parse_file(args.logfile, args.format))
    for event in events:
        event["_source"] = args.logfile

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
                        "line": f.event.get("_line"),
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siglint",
        description="Scan logs against Sigma-style detection rules.",
    )
    parser.add_argument("--version", action="version", version=f"siglint {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan a log file against rules")
    scan.add_argument("logfile", help="path to the log file")
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
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
