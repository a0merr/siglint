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
"""

from __future__ import annotations

import glob
import os
from typing import List, Optional

import yaml

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
        detection = data.get("detection", {}) or {}
        self.selection = detection.get("selection", {}) or {}
        self.threshold = detection.get("threshold")
        self.condition = detection.get("condition", "selection")
        if not self.selection:
            raise ValueError(f"rule {self.id!r} has no detection.selection")

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.level, 2)

    def __repr__(self) -> str:
        return f"<Rule {self.id} level={self.level}>"


def load_rules(path: str) -> List[Rule]:
    """Load a single rule file or every *.yml/*.yaml in a directory."""
    if os.path.isdir(path):
        files = sorted(
            glob.glob(os.path.join(path, "*.yml"))
            + glob.glob(os.path.join(path, "*.yaml"))
        )
    else:
        files = [path]

    rules: List[Rule] = []
    for filepath in files:
        with open(filepath, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if data:
            rules.append(Rule(data, source=filepath))
    return rules
