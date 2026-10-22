"""Match events against rules.

Field keys carry Sigma modifiers after pipes:
    message|contains, process|startswith, raw|re, cmdline|contains|all ...

- Plain string matching is case-insensitive, as in Sigma; add `|cased` to
  make it exact. `*` and `?` are wildcards (escape with a backslash).
- `re` / `regex` use Python regex and stay case-sensitive; add `|i`, `|m`,
  `|s` for ignore-case, multiline and dot-all.
- `gt` / `gte` / `lt` / `lte` compare numerically; `cidr` tests IP ranges.
- `windash` also matches `-flag` written as `/flag` or with unicode dashes.
- A list of values is OR; add `|all` to require every value.
- A `null` value matches when the field is missing or empty.

A search that is a mapping ANDs its fields; a list of mappings ORs them; a
list of plain strings is a keyword search over the raw line. The rule's
`condition` combines searches. A rule with a `threshold` fires once per group
(e.g. per src_ip) when the match count reaches `count`.
"""

from __future__ import annotations

import ipaddress
import operator
import re
from collections import defaultdict
from functools import lru_cache
from typing import Iterable, List

from .condition import evaluate
from .rules import MODIFIERS, Rule

_REGEX_OPS = {"re", "regex"}
_NUMERIC_OPS = {"gt": operator.gt, "gte": operator.ge, "lt": operator.lt, "lte": operator.le}
_FLAGS = {"all", "cased", "windash", "i", "m", "s"}
_RE_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
# A dash or slash that starts a command-line flag, e.g. "-enc" or "/c".
_FLAG_DASH = re.compile(r"(?<![\w-])[-/](?=\w)")
_DASHES = ("-", "/", "–", "—", "―")  # en, em, horizontal bar


@lru_cache(maxsize=4096)
def _wildcard_regex(value: str, op: str, cased: bool) -> "re.Pattern[str]":
    """Compile a Sigma string value (with * ? wildcards) for `op`."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    body = "".join(out)
    if op in ("contains", "endswith"):
        body = ".*" + body
    if op in ("contains", "startswith"):
        body += ".*"
    return re.compile(body, re.DOTALL if cased else re.DOTALL | re.IGNORECASE)


@lru_cache(maxsize=1024)
def _compiled(pattern: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(pattern, flags)


def _windash_variants(value: str) -> List[str]:
    return list(dict.fromkeys(_FLAG_DASH.sub(dash, value) for dash in _DASHES))


def _in_cidr(value, network) -> bool:
    try:
        return ipaddress.ip_address(str(value).strip()) in ipaddress.ip_network(
            str(network), strict=False
        )
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def _parse_key(key: str):
    field, *mods = key.split("|")
    op, flags = "equals", set()
    for mod in mods:
        mod = mod.lower()
        if mod in _FLAGS:
            flags.add(mod)
        elif mod in MODIFIERS:
            op = mod
        else:
            raise ValueError(f"unsupported modifier {mod!r} in {key!r}")
    return field, op, frozenset(flags)


def _match_value(value, op: str, exp, flags: frozenset) -> bool:
    if op == "cidr":
        return _in_cidr(value, exp)
    if op in _NUMERIC_OPS:
        try:
            return _NUMERIC_OPS[op](float(value), float(exp))
        except (TypeError, ValueError):
            return False
    if op in _REGEX_OPS:
        re_flags = 0
        for flag in flags & _RE_FLAGS.keys():
            re_flags |= _RE_FLAGS[flag]
        return _compiled(str(exp), re_flags).search(str(value)) is not None
    if isinstance(exp, bool) or isinstance(value, bool):
        return str(value).lower() == str(exp).lower()
    return _wildcard_regex(str(exp), op, "cased" in flags).fullmatch(str(value)) is not None


def _match_field(event: dict, key: str, expected) -> bool:
    field, op, flags = _parse_key(key)
    value = event.get(field)
    candidates = expected if isinstance(expected, list) else [expected]

    if None in candidates and (value is None or value == ""):
        return True
    if value is None:
        return False

    values = value if isinstance(value, list) else [value]

    def hit(exp) -> bool:
        if exp is None:
            return False
        variants = _windash_variants(str(exp)) if "windash" in flags else [exp]
        return any(_match_value(v, op, e, flags) for v in values for e in variants)

    check = all if "all" in flags else any
    return check(hit(exp) for exp in candidates)


def selection_matches(event: dict, selection: dict) -> bool:
    """A selection matches when every field condition matches (logical AND)."""
    return all(_match_field(event, key, val) for key, val in selection.items())


def search_matches(event: dict, search) -> bool:
    """Evaluate one named search: map = AND, list of maps = OR, strings = keywords."""
    if isinstance(search, dict):
        return selection_matches(event, search)
    if all(isinstance(item, dict) for item in search):
        return any(selection_matches(event, item) for item in search)
    haystack = {"raw": event.get("raw", event.get("message", ""))}
    return _match_field(haystack, "raw|contains", [str(k) for k in search])


def rule_matches(rule: Rule, event: dict) -> bool:
    cache: dict = {}

    def hit(name: str) -> bool:
        if name not in cache:
            cache[name] = search_matches(event, rule.searches[name])
        return cache[name]

    return evaluate(rule.condition_ast, hit)


class Finding:
    def __init__(self, rule: Rule, event: dict, count: int = 1, group=None):
        self.rule = rule
        self.event = event  # representative event (last match for thresholds)
        self.count = count
        self.group = group

    def __repr__(self) -> str:
        return f"<Finding {self.rule.id} count={self.count} group={self.group}>"


def run_rule(rule: Rule, events: List[dict]) -> List[Finding]:
    matched = [ev for ev in events if rule_matches(rule, ev)]
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
