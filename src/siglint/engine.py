"""Match events against rules.

Field keys may carry an operator after a pipe, Sigma-style:
    message|contains, process|equals, raw|regex, user|endswith ...
Default operator is equals. A rule with a `threshold` fires once per group
(e.g. per src_ip) when the match count reaches `count`.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, List

from .rules import Rule


def _match_field(event: dict, key: str, expected) -> bool:
    field, _, op = key.partition("|")
    op = op or "equals"
    value = event.get(field)
    if value is None:
        return False
    value = str(value)

    candidates = expected if isinstance(expected, list) else [expected]
    for raw in candidates:
        exp = str(raw)
        if op == "equals" and value == exp:
            return True
        if op == "contains" and exp in value:
            return True
        if op == "startswith" and value.startswith(exp):
            return True
        if op == "endswith" and value.endswith(exp):
            return True
        if op == "regex" and re.search(exp, value):
            return True
    return False


def selection_matches(event: dict, selection: dict) -> bool:
    """A selection matches when every field condition matches (logical AND)."""
    return all(_match_field(event, key, val) for key, val in selection.items())


class Finding:
    def __init__(self, rule: Rule, event: dict, count: int = 1, group=None):
        self.rule = rule
        self.event = event  # representative event (last match for thresholds)
        self.count = count
        self.group = group

    def __repr__(self) -> str:
        return f"<Finding {self.rule.id} count={self.count} group={self.group}>"


def run_rule(rule: Rule, events: List[dict]) -> List[Finding]:
    matched = [ev for ev in events if selection_matches(ev, rule.selection)]
    if not matched:
        return []

    if not rule.threshold:
        return [Finding(rule, ev) for ev in matched]

    count_needed = int(rule.threshold.get("count", 1))
    group_by = rule.threshold.get("group_by")

    buckets = defaultdict(list)
    for ev in matched:
        key = ev.get(group_by, "<none>") if group_by else "*"
        buckets[key].append(ev)

    findings = []
    for key, bucket in buckets.items():
        if len(bucket) >= count_needed:
            findings.append(Finding(rule, bucket[-1], count=len(bucket), group=key))
    return findings


def run_rules(rules: Iterable[Rule], events: Iterable[dict]) -> List[Finding]:
    events = list(events)
    findings: List[Finding] = []
    for rule in rules:
        findings.extend(run_rule(rule, events))
    # Most severe first.
    findings.sort(key=lambda f: f.rule.severity_rank, reverse=True)
    return findings
