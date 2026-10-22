from siglint.parsers import parse_line


def test_syslog_fields():
    line = "Mar 10 13:58:01 web01 sshd[2041]: Failed password for root from 203.0.113.9 port 51022 ssh2"
    ev = parse_line(line)
    assert ev["host"] == "web01"
    assert ev["process"] == "sshd"
    assert ev["src_ip"] == "203.0.113.9"
    assert ev["user"] == "root"
    assert "Failed password" in ev["message"]


def test_json_line():
    ev = parse_line('{"process": "sudo", "message": "authentication failure", "user": "deploy"}')
    assert ev["process"] == "sudo"
    assert ev["user"] == "deploy"


def test_blank_line_is_none():
    assert parse_line("   ") is None


def test_unparseable_falls_back_to_message():
    ev = parse_line("totally freeform text")
    assert ev["message"] == "totally freeform text"
