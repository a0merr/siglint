"""Turn raw log lines into field dictionaries.

Supports syslog/auth.log lines and JSON-per-line logs. A few common fields
(src_ip, user) are extracted from free-text messages so rules can match on
them regardless of the source format.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Iterator, Optional, Tuple

# Classic syslog: "Mar 10 13:58:01 host sshd[1234]: message"
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Keys that commonly hold an event's time, in priority order.
_TIME_KEYS = (
    "@timestamp", "timestamp", "ts", "time", "TimeCreated", "UtcTime",
    "EventTime", "SystemTime", "date",
)
_ISO_PREFIX_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_APACHE_TIME_RE = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]")
_DOTNET_DATE_RE = re.compile(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/")
# Syslog lines carry no year. Parsing them into a leap year keeps "Feb 29" valid;
# only the spacing between events matters for timeframes, not the absolute date.
_SYSLOG_YEAR = 2000

_IP_RE = re.compile(r"(?:from|rhost=)\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_USER_RE = re.compile(r"(?:invalid user |user[= ]|for )(?P<user>[\w.$-]+)")


def _enrich(event: dict) -> dict:
    """Normalize common fields and pull src_ip / user out of the message.

    Also maps Windows event JSON (e.g. `Get-WinEvent | ConvertTo-Json` or an
    evtx export) onto the common keys `message`, `event_id`, and `provider`.
    """
    # Windows event JSON uses PascalCase keys.
    if "message" not in event and "Message" in event:
        event["message"] = event["Message"]
    if "event_id" not in event:
        if "Id" in event:
            event["event_id"] = event["Id"]
        elif "EventID" in event:
            event["event_id"] = event["EventID"]
    if "provider" not in event and "ProviderName" in event:
        event["provider"] = event["ProviderName"]

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


def _epoch(dt: datetime) -> float:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # naive times are taken as UTC
    return dt.timestamp()


def _parse_time_value(value) -> Optional[float]:
    """Epoch seconds from an ISO string, a .NET /Date(ms)/ string, or an epoch number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        # Heuristic: anything past ~2286 in seconds is really milliseconds.
        return value / 1000.0 if value > 1e10 else float(value)
    if not isinstance(value, str):
        return None
    m = _DOTNET_DATE_RE.search(value)
    if m:
        return int(m.group(1)) / 1000.0
    m = _ISO_PREFIX_RE.match(value.strip())
    if m:
        text = m.group(1).replace("Z", "+00:00")
        try:
            return _epoch(datetime.fromisoformat(text))
        except ValueError:
            return None
    return None


def _time_of(event: dict) -> Tuple[Optional[float], bool]:
    """(epoch seconds or None, whether the time came from a year-less syslog stamp)."""
    for key in _TIME_KEYS:
        if key in event:
            ts = _parse_time_value(event[key])
            if ts is not None:
                return ts, False
    stamp = event.get("timestamp")
    if isinstance(stamp, str):
        try:
            when = datetime.strptime(f"{_SYSLOG_YEAR} {stamp}", "%Y %b %d %H:%M:%S")
            return _epoch(when), True
        except ValueError:
            pass
    raw = str(event.get("raw", ""))
    m = _APACHE_TIME_RE.search(raw)
    if m:
        try:
            when = datetime.strptime(" ".join(m.groups()), "%d/%b/%Y:%H:%M:%S %z")
            return when.timestamp(), False
        except ValueError:
            return None, False
    return _parse_time_value(raw), False


def event_time(event: dict) -> Optional[float]:
    """Best-effort epoch seconds for an event, or None when it carries no usable time.

    Syslog stamps have no year and parse into a fixed one, so their absolute value
    is meaningless; the spacing between events — all a timeframe needs — is exact.
    """
    return _time_of(event)[0]


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
    """Yield one enriched event dict per log line, tagged with its line number.

    Each event also gets `_ts` (epoch seconds) when a time can be read from it.
    Year-less syslog stamps borrow the year of the first fully dated event in the
    file, so mixed syslog / JSON / access logs line up; a jump back of more than
    half a year between syslog lines is read as a December -> January rollover.
    """
    events, yearless = [], []
    anchor_year: Optional[int] = None
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, start=1):
            event = parse_line(line, fmt)
            if event is None:
                continue
            event["_line"] = lineno
            ts, is_yearless = _time_of(event)
            if ts is not None:
                event["_ts"] = ts
                if is_yearless:
                    yearless.append(event)
                elif anchor_year is None:
                    anchor_year = datetime.fromtimestamp(ts, timezone.utc).year
            events.append(event)

    if yearless and anchor_year is not None:
        for event in yearless:
            try:
                when = datetime.strptime(
                    f"{anchor_year} {event['timestamp']}", "%Y %b %d %H:%M:%S"
                )
                event["_ts"] = _epoch(when)
            except ValueError:  # Feb 29 outside a leap year: keep the placeholder
                pass
    offset, last = 0.0, None
    for event in yearless:
        event["_ts"] += offset
        if last is not None and event["_ts"] < last - 183 * 86400:
            offset += 365 * 86400
            event["_ts"] += 365 * 86400
        last = event["_ts"]

    yield from events
