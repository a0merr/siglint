import os

import pytest

from siglint.cli import main
from siglint.condition import ConditionError, evaluate, parse_condition
from siglint.engine import rule_matches, search_matches, selection_matches
from siglint.rules import Rule, validate_rules

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
NAMES = ["selection", "selection_a", "selection_b", "filter"]


def _eval(text, hits):
    return evaluate(parse_condition(text, NAMES), lambda name: name in hits)


def _rule(detection, level="high"):
    return Rule({"id": "t", "title": "t", "level": level, "detection": detection})


# --- condition grammar -------------------------------------------------------

def test_and_or_not_precedence():
    # not > and > or:  selection or (selection_a and not filter)
    expr = "selection or selection_a and not filter"
    assert _eval(expr, {"selection"})
    assert _eval(expr, {"selection_a"})
    assert not _eval(expr, {"selection_a", "filter"})


def test_parentheses_override_precedence():
    assert not _eval("(selection or selection_a) and not filter", {"selection", "filter"})
    assert _eval("(selection or selection_a) and not filter", {"selection_a"})


def test_of_quantifiers():
    assert _eval("1 of selection_*", {"selection_b"})
    assert not _eval("all of selection_*", {"selection_a"})
    assert _eval("all of selection_*", {"selection_a", "selection_b"})
    assert _eval("1 of them", {"filter"})
    assert not _eval("all of them", {"selection", "selection_a", "selection_b"})


def test_keywords_are_case_insensitive():
    assert _eval("selection AND NOT filter", {"selection"})
    assert _eval("1 OF selection_*", {"selection_a"})


@pytest.mark.parametrize(
    "bad",
    ["", "selection and", "nope", "(selection", "selection filter",
     "1 of missing_*", "selection | count() > 5", "not"],
)
def test_bad_conditions_raise(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad, NAMES)


# --- field modifiers ---------------------------------------------------------

EV = {"cmd": "C:\\Windows\\System32\\cmd.exe /c whoami", "user": "Admin",
      "port": "4444", "tags": ["a", "b"], "empty": ""}


def test_matching_is_case_insensitive_by_default():
    assert selection_matches(EV, {"user": "admin"})
    assert not selection_matches(EV, {"user|cased": "admin"})
    assert selection_matches(EV, {"user|cased": "Admin"})


def test_wildcards():
    assert selection_matches(EV, {"cmd": "*\\cmd.exe *"})
    assert selection_matches(EV, {"user": "Adm?n"})
    assert not selection_matches(EV, {"user": "Adm?"})
    assert not selection_matches({"v": "abc"}, {"v": "a\\*c"})
    assert selection_matches({"v": "a*c"}, {"v": "a\\*c"})


def test_all_modifier():
    assert selection_matches(EV, {"cmd|contains|all": ["cmd.exe", "whoami"]})
    assert not selection_matches(EV, {"cmd|contains|all": ["cmd.exe", "net user"]})
    assert selection_matches(EV, {"cmd|contains": ["cmd.exe", "net user"]})


def test_regex_alias_and_case():
    assert selection_matches(EV, {"cmd|re": r"System32\\cmd"})
    assert not selection_matches(EV, {"cmd|re": r"system32"})


def test_numeric_comparisons():
    assert selection_matches(EV, {"port|gte": 1024})
    assert not selection_matches(EV, {"port|lt": 1024})
    assert not selection_matches(EV, {"user|gt": 1})


def test_regex_flag_modifiers():
    assert selection_matches(EV, {"cmd|re|i": r"system32"})
    assert selection_matches({"v": "a\nb"}, {"v|re|s": "a.b"})


def test_windash():
    for cmd in ("powershell -enc AAAA", "powershell /enc AAAA", "powershell –enc AAAA"):
        assert selection_matches({"cmd": cmd}, {"cmd|windash|contains": " -enc "})
    assert not selection_matches({"cmd": "powershell -enc"}, {"cmd|contains": " /enc"})


def test_cidr():
    assert selection_matches({"src_ip": "10.1.2.3"}, {"src_ip|cidr": ["192.168.0.0/16", "10.0.0.0/8"]})
    assert not selection_matches({"src_ip": "203.0.113.9"}, {"src_ip|cidr": "10.0.0.0/8"})
    assert not selection_matches({"src_ip": "not-an-ip"}, {"src_ip|cidr": "10.0.0.0/8"})


def test_null_matches_missing_or_empty():
    assert selection_matches(EV, {"missing": None})
    assert selection_matches(EV, {"empty": None})
    assert not selection_matches(EV, {"user": None})
    assert selection_matches(EV, {"missing": [None, "x"]})
    assert selection_matches(EV, {"user": [None, "admin"]})


def test_list_valued_fields():
    assert selection_matches(EV, {"tags": "b"})


# --- search shapes and full rules --------------------------------------------

def test_list_of_maps_is_or():
    search = [{"user": "root"}, {"port": "4444"}]
    assert search_matches(EV, search)
    assert not search_matches(EV, [{"user": "root"}, {"port": "22"}])


def test_keyword_search_hits_raw_line():
    ev = {"raw": "Mar 10 bash: unset HISTFILE; history -c"}
    assert search_matches(ev, ["HISTORY -C"])
    assert not search_matches(ev, ["shred"])


def test_selection_with_filter():
    rule = _rule({
        "selection": {"message|contains": "authentication failure"},
        "filter_ci": {"user": ["jenkins", "ansible"]},
        "condition": "selection and not filter_ci",
    })
    assert rule_matches(rule, {"message": "authentication failure", "user": "deploy"})
    assert not rule_matches(rule, {"message": "authentication failure", "user": "Jenkins"})


def test_sigmahq_shaped_rule():
    # Same shape as SigmaHQ's regedit-import rule: list-OR selection,
    # `all of` / `not all of` over wildcard names, windash and re filters.
    rule = _rule({
        "selection_img": [{"Image|endswith": "\\regedit.exe"}, {"OriginalFileName": "REGEDIT.EXE"}],
        "selection_cli": {"CommandLine|contains": [" /i ", " /s ", ".reg"]},
        "filter_1": {"CommandLine|contains|windash": [" -e ", " -a ", " -c "]},
        "filter_2": {"CommandLine|re": r":[^ \\]"},
        "condition": "all of selection_* and not all of filter_*",
    })
    img = "C:\\Windows\\regedit.exe"
    assert rule_matches(rule, {"Image": img, "CommandLine": "regedit.exe /s C:\\evil.reg"})
    assert rule_matches(rule, {"OriginalFileName": "regedit.exe", "CommandLine": "r /i x.reg"})
    assert not rule_matches(rule, {"Image": "C:\\notepad.exe", "CommandLine": "n /s x.reg"})
    # both filters hit (en-dash flag + ADS-style path) -> suppressed
    assert not rule_matches(rule, {"Image": img, "CommandLine": "regedit.exe \u2013e C:out.reg"})


def test_condition_list_is_or():
    rule = _rule({"a": {"x": "1"}, "b": {"y": "2"}, "condition": ["a", "b"]})
    assert rule_matches(rule, {"y": "2"})


def test_single_search_needs_no_condition():
    assert rule_matches(_rule({"sel": {"x": "1"}}), {"x": "1"})


@pytest.mark.parametrize(
    "detection, level, msg",
    [
        ({"selection": {"x": "1"}}, "severe", "unknown level"),
        ({"a": {"x": "1"}, "b": {"x": "2"}}, "high", "no condition"),
        ({"selection": {"x|bogus": "1"}, "condition": "selection"}, "high", "bad field key"),
        ({"selection": {"x|re": "("}, "condition": "selection"}, "high", "invalid regex"),
        ({"selection": {"x": "1"}, "condition": "selection and filter"}, "high", "unknown search"),
        ({"condition": "selection"}, "high", "no detection searches"),
    ],
)
def test_rule_validation_errors(detection, level, msg):
    with pytest.raises(ValueError, match=msg):
        _rule(detection, level=level)


# --- validate + CLI ----------------------------------------------------------

def test_validate_collects_errors_and_duplicates(tmp_path):
    good = "id: dup\nlevel: low\ndetection:\n  selection:\n    x: 1\n"
    (tmp_path / "a.yml").write_text(good)
    (tmp_path / "b.yml").write_text(good)
    (tmp_path / "c.yml").write_text("id: c\ndetection:\n  selection:\n    x|nope: 1\n")
    rules, errors = validate_rules(str(tmp_path))
    assert [r.id for r in rules] == ["dup"]
    messages = " ".join(msg for _, msg in errors)
    assert "duplicate id" in messages and "bad field key" in messages


def test_cli_validate_shipped_rules(capsys):
    assert main(["validate", os.path.join(ROOT, "rules")]) == 0
    assert "0 error(s)" in capsys.readouterr().out


def test_cli_scan_multiple_files_and_fail_on(capsys):
    logs = [os.path.join(ROOT, "examples", n) for n in ("auth.log", "process_web.log")]
    code = main(["scan", *logs, "-r", os.path.join(ROOT, "rules"), "--fail-on", "critical"])
    out = capsys.readouterr().out
    assert code == 1
    assert "in 2 files" in out
    assert "log_tampering" in out and "uid0_account_created" in out


def test_cli_scan_bad_rules_exits_2(tmp_path, capsys):
    (tmp_path / "bad.yml").write_text("id: bad\ndetection:\n  selection:\n    x|re: '('\n")
    log = tmp_path / "x.log"
    log.write_text("hello\n")
    assert main(["scan", str(log), "-r", str(tmp_path)]) == 2
    assert "invalid regex" in capsys.readouterr().err
