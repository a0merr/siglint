"""Load Sigma-style detection rules from YAML.

A rule looks like:

    title: SSH Brute Force
    id: ssh_brute_force
    level: high
    logsource: auth
    detection:
      selection:
        message|contains: "Failed password"
      threshold:
        count: 5
        group_by: src_ip
      condition: selection

Any key under `detection` other than `condition`, `threshold` and `timeframe`
is a named search, so full Sigma conditions work:

    detection:
      selection:
        process|startswith: sudo
      filter_ci:
        user: [jenkins, gitlab-runner]
      condition: selection and not filter_ci
"""

from __future__ import annotations

import glob
import os
import re
from typing import Dict, List, Optional, Tuple

import yaml

from .condition import parse_condition

# Keys under `detection` that are not searches.
_RESERVED = {"condition", "threshold", "timeframe"}

MODIFIERS = {
    "equals", "contains", "startswith", "endswith",
    "re", "regex", "gt", "gte", "lt", "lte", "cidr",
    "all", "cased", "windash", "i", "m", "s",
}


def _check_search(rule_id: str, name: str, body) -> None:
    maps = [body] if isinstance(body, dict) else [b for b in body if isinstance(b, dict)]
    for mapping in maps:
        for key, value in mapping.items():
            field, *mods = str(key).split("|")
            bad = [m for m in mods if m.lower() not in MODIFIERS]
            if not field or bad:
                raise ValueError(f"rule {rule_id!r}: bad field key {key!r} in {name!r}")
            if {"re", "regex"} & {m.lower() for m in mods}:
                for pattern in value if isinstance(value, list) else [value]:
                    try:
                        re.compile(str(pattern))
                    except re.error as exc:
                        raise ValueError(
                            f"rule {rule_id!r}: invalid regex {pattern!r} ({exc})"
                        ) from None

SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Rule:
    def __init__(self, data: dict, source: Optional[str] = None):
        self.source = source
        self.id = data.get("id") or data.get("title") or "unnamed_rule"
        self.title = data.get("title", self.id)
        self.level = str(data.get("level", "medium")).lower()
        self.description = data.get("description", "")
        self.logsource = data.get("logsource", "")
        if self.level not in SEVERITY_ORDER:
            raise ValueError(f"rule {self.id!r} has unknown level {self.level!r}")
        detection = data.get("detection", {}) or {}
        if not isinstance(detection, dict):
            raise ValueError(f"rule {self.id!r}: detection must be a mapping")
        self.searches: Dict[str, object] = {
            name: body for name, body in detection.items() if name not in _RESERVED
        }
        if not self.searches:
            raise ValueError(f"rule {self.id!r} has no detection searches")
        for name, body in self.searches.items():
            if not body or not isinstance(body, (dict, list)):
                raise ValueError(f"rule {self.id!r}: search {name!r} is empty or not a map/list")
            _check_search(self.id, name, body)
        self.selection = self.searches.get("selection", {})
        self.threshold = detection.get("threshold")

        condition = detection.get("condition")
        if condition is None:
            if len(self.searches) != 1:
                raise ValueError(f"rule {self.id!r} has several searches but no condition")
            condition = next(iter(self.searches))
        if isinstance(condition, list):  # Sigma: a list of conditions is OR-ed
            condition = " or ".join(f"({c})" for c in condition)
        self.condition = str(condition)
        try:
            self.condition_ast = parse_condition(self.condition, list(self.searches))
        except ValueError as exc:
            raise ValueError(f"rule {self.id!r}: {exc}") from None

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.level, 2)

    def __repr__(self) -> str:
        return f"<Rule {self.id} level={self.level}>"


def rule_files(path: str) -> List[str]:
    """A single rule file, or every *.yml/*.yaml under a directory (recursive)."""
    if not os.path.isdir(path):
        return [path]
    return sorted(
        glob.glob(os.path.join(path, "**", "*.yml"), recursive=True)
        + glob.glob(os.path.join(path, "**", "*.yaml"), recursive=True)
    )


def _load_file(filepath: str) -> Optional[Rule]:
    with open(filepath, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not data:
        return None
    if not isinstance(data, dict):
        raise ValueError("top level must be a mapping")
    return Rule(data, source=filepath)


def load_rules(path: str) -> List[Rule]:
    """Load a single rule file or every *.yml/*.yaml in a directory."""
    rules: List[Rule] = []
    for filepath in rule_files(path):
        rule = _load_file(filepath)
        if rule:
            rules.append(rule)
    return rules


def validate_rules(path: str) -> Tuple[List[Rule], List[Tuple[str, str]]]:
    """Load every rule, collecting (file, error) pairs instead of raising."""
    rules: List[Rule] = []
    errors: List[Tuple[str, str]] = []
    seen: Dict[str, str] = {}
    for filepath in rule_files(path):
        try:
            rule = _load_file(filepath)
        except (ValueError, yaml.YAMLError) as exc:
            errors.append((filepath, str(exc).splitlines()[0]))
            continue
        if rule is None:
            continue
        if rule.id in seen:
            errors.append((filepath, f"duplicate id {rule.id!r} (also in {seen[rule.id]})"))
            continue
        seen[rule.id] = filepath
        rules.append(rule)
    return rules, errors
