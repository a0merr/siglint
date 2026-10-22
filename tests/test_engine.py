import os

from siglint.engine import run_rules, selection_matches
from siglint.parsers import parse_file
from siglint.rules import Rule, load_rules

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
RULES_DIR = os.path.join(ROOT, "rules")
SAMPLE_LOG = os.path.join(ROOT, "examples", "auth.log")
PROCESS_LOG = os.path.join(ROOT, "examples", "process_web.log")


def test_operators():
    ev = {"message": "Failed password for root", "process": "sshd", "user": "root"}
    assert selection_matches(ev, {"message|contains": "Failed password"})
    assert selection_matches(ev, {"process|startswith": "ssh"})
    assert selection_matches(ev, {"user|equals": "root"})
    assert not selection_matches(ev, {"user|equals": "deploy"})


def test_threshold_groups_by_ip():
    rule = Rule(
        {
            "title": "bf",
            "id": "bf",
            "level": "high",
            "detection": {
                "selection": {"message|contains": "Failed password"},
                "threshold": {"count": 5, "group_by": "src_ip"},
            },
        }
    )
    events = list(parse_file(SAMPLE_LOG))
    findings = run_rules([rule], events)
    assert len(findings) == 1
    assert findings[0].group == "203.0.113.9"
    assert findings[0].count == 6


def test_sample_log_against_all_rules():
    rules = load_rules(RULES_DIR)
    findings = run_rules(rules, parse_file(SAMPLE_LOG))
    fired = {f.rule.id for f in findings}
    assert "ssh_brute_force" in fired
    assert "sudo_auth_failure" in fired
    assert "new_user_created" in fired
    assert "accepted_root_login" in fired
    assert "suspicious_download_pipe_shell" in fired


def test_process_web_rules_fire():
    rules = load_rules(RULES_DIR)
    findings = run_rules(rules, parse_file(PROCESS_LOG))
    fired = {f.rule.id for f in findings}
    assert "reverse_shell_devtcp" in fired
    assert "powershell_encoded_command" in fired  # matches plain + JSON line
    assert "web_sql_injection" in fired
    assert "web_path_traversal" in fired
    assert "user_added_privileged_group" in fired


def test_findings_sorted_by_severity():
    rules = load_rules(RULES_DIR)
    findings = run_rules(rules, parse_file(SAMPLE_LOG))
    ranks = [f.rule.severity_rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)
