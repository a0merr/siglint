"""Render findings as SARIF 2.1.0 so they appear in GitHub's Security tab."""

from __future__ import annotations

import json
from typing import Iterable, List

from .engine import Finding

# Sigma severity -> SARIF result level.
_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}

TOOL_URI = "https://github.com/a0merr/siglint"


def to_sarif(findings: Iterable[Finding], version: str = "0.1.0") -> dict:
    findings = list(findings)
    rules_index: dict = {}
    results: List[dict] = []

    for finding in findings:
        rule = finding.rule
        if rule.id not in rules_index:
            rules_index[rule.id] = {
                "id": rule.id,
                "name": rule.title,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description or rule.title},
                "defaultConfiguration": {
                    "level": _LEVEL_MAP.get(rule.level, "warning")
                },
            }

        where = finding.group if finding.group not in (None, "*") else None
        text = f"{rule.title} — {finding.count} event(s)"
        if where:
            text += f" from {where}"

        results.append(
            {
                "ruleId": rule.id,
                "level": _LEVEL_MAP.get(rule.level, "warning"),
                "message": {"text": text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.event.get("_source", "log")
                            },
                            "region": {
                                "startLine": finding.event.get("_line", 1),
                                "snippet": {
                                    "text": str(finding.event.get("raw", ""))[:300]
                                },
                            },
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "siglint",
                        "version": version,
                        "informationUri": TOOL_URI,
                        "rules": list(rules_index.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def dumps_sarif(findings: Iterable[Finding], **kwargs) -> str:
    return json.dumps(to_sarif(findings, **kwargs), indent=2)
