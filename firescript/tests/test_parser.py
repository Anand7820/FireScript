from firescript import parse_rules


def test_valid_rule_is_parsed():
    r = parse_rules("allow tcp from 10.0.0.0/24 to any port 80")
    assert r.ok and len(r.rules) == 1
    rule = r.rules[0]
    assert (rule.action, rule.protocol) == ("allow", "tcp")
    assert str(rule.src) == "10.0.0.0/24" and str(rule.dst) == "0.0.0.0/0"
    assert (rule.port_start, rule.port_end) == (80, 80)


def test_any_means_full_range():
    rule = parse_rules("deny any from any to any port any").rules[0]
    assert rule.protocol == "any"
    assert (rule.port_start, rule.port_end) == (1, 65535)


def test_port_range():
    rule = parse_rules("allow tcp from any to any port 8000-9000").rules[0]
    assert (rule.port_start, rule.port_end) == (8000, 9000)


def test_comments_blank_lines_and_case():
    r = parse_rules("# note\n\nALLOW TCP FROM any TO any PORT 80  # web\n")
    assert r.ok and len(r.rules) == 1 and r.rules[0].line == 3


def test_missing_keyword_gives_line_number():
    r = parse_rules("allow tcp from any to any 80")
    assert len(r.errors) == 1 and r.errors[0].line == 1
    assert "Syntax error" in r.errors[0].message


def test_unknown_action():
    assert parse_rules("permit tcp from any to any port 80").errors


def test_bad_ip_octet():
    r = parse_rules("allow tcp from 300.1.1.1 to any port 80")
    assert "Invalid address" in r.errors[0].message


def test_host_bits_set():
    r = parse_rules("allow tcp from 10.0.0.5/24 to any port 80")
    assert "host bits set" in r.errors[0].message


def test_bad_prefix_length():
    assert parse_rules("allow tcp from 10.0.0.0/40 to any port 80").errors


def test_port_out_of_range():
    assert "valid range" in parse_rules("allow tcp from any to any port 70000").errors[0].message


def test_backwards_port_range():
    assert "backwards" in parse_rules("allow tcp from any to any port 900-800").errors[0].message


def test_bad_line_does_not_hide_good_lines():
    r = parse_rules("allow tcp from any to any port 80\nbad line here\ndeny tcp from any to any port 22")
    assert len(r.rules) == 2 and len(r.errors) == 1 and r.errors[0].line == 2
