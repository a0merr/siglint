import pytest

from siglint.engine import run_rules
from siglint.parsers import event_time, parse_file, parse_line
from siglint.rules import Rule, parse_timeframe

FAIL = "Mar 10 13:58:{:02d} web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2"


def _rule(count=3, timeframe="1m", group_by="src_ip"):
    return Rule({
        "id": "bf", "level": "high",
        "detection": {
            "selection": {"message|contains": "Failed password"},
            "threshold": {"count": count, "group_by": group_by},
            "timeframe": timeframe,
            "condition": "selection",
        },
    })


def _events(seconds):
    """Failed-login events at the given second offsets (minutes roll over past 59)."""
    out = []
    for i, sec in enumerate(seconds):
        line = (
            f"Mar 10 {13 + (58 * 60 + sec) // 3600:02d}:{(58 + sec // 60) % 60:02d}:{sec % 60:02d}"
            " web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2"
        )
        ev = parse_line(line)
        ev["_ts"] = event_time(ev)
        ev["_line"] = i + 1
        out.append(ev)
    return out


# -- time extraction ----------------------------------------------------------

@pytest.mark.parametrize(
    "event, expected",
    [
        ({"@timestamp": "2026-03-10T09:00:00Z"}, 1773133200.0),
        ({"TimeCreated": "2026-03-10T09:00:00+00:00"}, 1773133200.0),
        ({"TimeCreated": "2026-03-10T10:00:00+01:00"}, 1773133200.0),
        ({"TimeCreated": "/Date(1773133200000)/"}, 1773133200.0),  # PowerShell ConvertTo-Json
        ({"ts": 1773133200}, 1773133200.0),
        ({"ts": 1773133200000}, 1773133200.0),  # epoch milliseconds
        ({"raw": '1.2.3.4 - - [10/Mar/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 1'}, 1773133200.0),
        ({"raw": "2026-03-10T09:00:00 host app: hello"}, 1773133200.0),
        ({"raw": "no time here"}, None),
        ({"ts": "yesterday"}, None),
    ],
)
def test_event_time_formats(event, expected):
    assert event_time(event) == expected


def test_syslog_spacing_is_exact():
    a, b = (event_time(parse_line(FAIL.format(s))) for s in (1, 31))
    assert b - a == 30


def test_syslog_borrows_the_files_year_and_rolls_over(tmp_path):
    log = tmp_path / "x.log"
    log.write_text(
        '{"ts": "2025-12-31T23:59:00Z", "message": "anchor"}\n'
        "Dec 31 23:59:30 h p[1]: before midnight\n"
        "Jan  1 00:00:10 h p[1]: after midnight\n"
    )
    anchor, before, after = (e["_ts"] for e in parse_file(str(log)))
    assert before - anchor == 30
    assert after - before == 40  # not -364 days


# -- timeframe parsing / validation -------------------------------------------

@pytest.mark.parametrize("text, seconds", [("30s", 30), ("5m", 300), ("1h", 3600), ("2d", 172800)])
def test_parse_timeframe(text, seconds):
    assert parse_timeframe(text) == seconds


@pytest.mark.parametrize("bad", ["5", "0m", "1w", "soon"])
def test_bad_timeframe_rejected(bad):
    with pytest.raises(ValueError, match="bad timeframe"):
        _rule(timeframe=bad)


def test_timeframe_without_threshold_rejected():
    with pytest.raises(ValueError, match="needs a threshold"):
        Rule({"id": "x", "detection": {"sel": {"a": 1}, "timeframe": "5m"}})


# -- sliding window -----------------------------------------------------------

def test_burst_inside_window_fires():
    (f,) = run_rules([_rule(count=3)], _events([0, 10, 20]))
    assert f.count == 3 and f.span == 20 and f.group == "203.0.113.9"


def test_slow_attack_does_not_fire():
    # Same three failures, but spread over three minutes: not a burst.
    assert run_rules([_rule(count=3)], _events([0, 90, 180])) == []


def test_reports_the_densest_window():
    # 2 early, then 4 tightly packed, then 1 late: best window holds 4.
    (f,) = run_rules([_rule(count=3)], _events([0, 30, 200, 205, 210, 215, 400]))
    assert f.count == 4
    assert f.span == 15
    assert f.event["_line"] == 6  # last event of the densest window


def test_window_edge_is_inclusive():
    (f,) = run_rules([_rule(count=2, timeframe="30s")], _events([0, 30]))
    assert f.count == 2


def test_events_without_time_are_skipped_not_counted():
    events = _events([0, 10])
    events.append({"message": "Failed password", "src_ip": "203.0.113.9", "_line": 99})
    assert run_rules([_rule(count=3)], events) == []


def test_groups_are_windowed_independently():
    a = _events([0, 5, 10])
    b = _events([0, 100, 200])
    for ev in b:
        ev["src_ip"] = "198.51.100.7"
    (f,) = run_rules([_rule(count=3)], a + b)
    assert f.group == "203.0.113.9"


def test_without_timeframe_count_is_over_the_whole_file():
    rule = Rule({
        "id": "bf", "level": "high",
        "detection": {
            "selection": {"message|contains": "Failed password"},
            "threshold": {"count": 3, "group_by": "src_ip"},
        },
    })
    (f,) = run_rules([rule], _events([0, 900, 1800]))
    assert f.count == 3 and f.span is None
