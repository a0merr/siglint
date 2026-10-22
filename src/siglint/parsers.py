"""Turn raw log lines into field dictionaries.

Supports syslog/auth.log lines and JSON-per-line logs. A few common fields
(src_ip, user) are extracted from free-text messages so rules can match on
them regardless of the source format.
"""

from __future__ import annotations

import json
import re
from typing import Iterator, Optional

# Classic syslog: "Mar 10 13:58:01 host sshd[1234]: message"
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

_IP_RE = re.compile(r"(?:from|rhost=)\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_USER_RE = re.compile(r"(?:invalid user |user[= ]|for )(?P<user>[\w.$-]+)")


def _enrich(event: dict) -> dict:
    """Pull src_ip / user out of the message if not already present."""
    message = str(event.get("message", event.get("raw", "")))
    if "src_ip" not in event:
        m = _IP_RE.search(message)
        if m:
            event["src_ip"] = m.group("ip")
    if "user" not in event:
        m = _USER_RE.search(message)
        if m:
            event["user"] = m.group("user")
    return event


def parse_line(line: str, fmt: str = "auto") -> Optional[dict]:
    """Parse one line into a field dict, or None for blank/unparseable JSON."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    if fmt in ("json", "auto") and line.lstrip().startswith("{"):
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                data.setdefault("raw", line)
                return _enrich(data)
        except json.JSONDecodeError:
            if fmt == "json":
                return None

    if fmt in ("syslog", "auto"):
        m = SYSLOG_RE.match(line)
        if m:
            event = {k: v for k, v in m.groupdict().items() if v is not None}
            event["raw"] = line
            return _enrich(event)

    # Fallback: expose the whole line as the message.
    return {"raw": line, "message": line}


def parse_file(path: str, fmt: str = "auto") -> Iterator[dict]:
    """Yield one enriched event dict per log line, tagged with its line number."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, start=1):
            event = parse_line(line, fmt)
            if event is not None:
                event["_line"] = lineno
                yield event
