"""Parse and evaluate Sigma `condition` expressions.

Supported grammar (precedence: not > and > or):

    expr     := or_expr
    or_expr  := and_expr ("or" and_expr)*
    and_expr := not_expr ("and" not_expr)*
    not_expr := "not" not_expr | atom
    atom     := "(" expr ")"
              | ("1" | "any" | "all") "of" (pattern | "them")
              | identifier

`pattern` may end in `*` to match every search name with that prefix
(e.g. `1 of selection_*`). The legacy pipe aggregations (`| count() > 5`)
are not supported — use a rule's `threshold` block instead.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Callable, List, Sequence, Tuple

_TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")
_KEYWORDS = {"and", "or", "not", "of", "them"}

# AST nodes are plain tuples:
#   ("name", str) | ("not", node) | ("and", [nodes]) | ("or", [nodes])
#   ("of", "any"|"all", [names])
Node = Tuple


class ConditionError(ValueError):
    pass


def _tokenize(text: str) -> List[str]:
    text = text.strip()
    tokens, pos = [], 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize condition at {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: List[str], names: Sequence[str]):
        self.tokens = tokens
        self.pos = 0
        self.names = list(names)

    def peek(self):
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, want: str) -> None:
        if self.peek() != want:
            got = self.tokens[self.pos] if self.pos < len(self.tokens) else "end of condition"
            raise ConditionError(f"expected {want!r}, got {got!r}")
        self.pos += 1

    def parse(self) -> Node:
        if not self.tokens:
            raise ConditionError("empty condition")
        if "|" in self.tokens:
            raise ConditionError(
                "pipe aggregations (`| count() ...`) are not supported; use `threshold`"
            )
        node = self.or_expr()
        if self.pos != len(self.tokens):
            raise ConditionError(f"unexpected token {self.tokens[self.pos]!r}")
        return node

    def or_expr(self) -> Node:
        parts = [self.and_expr()]
        while self.peek() == "or":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_expr(self) -> Node:
        parts = [self.not_expr()]
        while self.peek() == "and":
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def not_expr(self) -> Node:
        if self.peek() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.atom()

    def atom(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ConditionError("condition ended unexpectedly")
        if tok == "(":
            self.take()
            node = self.or_expr()
            self.expect(")")
            return node
        if tok in ("1", "any", "all") and self.pos + 1 < len(self.tokens) \
                and self.tokens[self.pos + 1].lower() == "of":
            quant = "all" if self.take().lower() == "all" else "any"
            self.take()  # "of"
            if self.peek() is None:
                raise ConditionError(f"'{quant} of' needs a search name or 'them'")
            target = self.take()
            return ("of", quant, self._expand(target))
        if tok in _KEYWORDS or tok == ")":
            raise ConditionError(f"unexpected {self.tokens[self.pos]!r}")
        name = self.take()
        if name not in self.names:
            raise ConditionError(f"condition references unknown search {name!r}")
        return ("name", name)

    def _expand(self, target: str) -> List[str]:
        if target.lower() == "them":
            matched = list(self.names)
        else:
            matched = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
        if not matched:
            raise ConditionError(f"{target!r} matches no search in this rule")
        return matched


def parse_condition(text: str, names: Sequence[str]) -> Node:
    """Parse `text` into an AST, checking every reference against `names`."""
    return _Parser(_tokenize(str(text)), names).parse()


def evaluate(node: Node, hit: Callable[[str], bool]) -> bool:
    """Evaluate an AST. `hit(name)` reports whether that search matched."""
    kind = node[0]
    if kind == "name":
        return hit(node[1])
    if kind == "not":
        return not evaluate(node[1], hit)
    if kind == "and":
        return all(evaluate(child, hit) for child in node[1])
    if kind == "or":
        return any(evaluate(child, hit) for child in node[1])
    if kind == "of":
        check = all if node[1] == "all" else any
        return check(hit(name) for name in node[2])
    raise ConditionError(f"bad condition node {node!r}")
