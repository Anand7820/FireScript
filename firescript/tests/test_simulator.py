"""Tests for firescript/simulator.py (Stage 3).

All tests build rules via parse_rules() so the real parser is always exercised.

Coverage:
  1.  Basic allow match
  2.  Basic deny match
  3.  Default deny (no rules match)
  4.  First-match wins (allow before deny → allow)
  5.  First-match wins (deny before allow → deny)
  6.  Also-matched list is populated correctly
  7.  'any' protocol matches tcp packet
  8.  'any' protocol matches udp packet
  9.  'any' src matches any source IP
  10. 'any' dst matches any destination IP
  11. Port at the exact lower boundary of a range
  12. Port at the exact upper boundary of a range
  13. Port just below the range → no match
  14. Port just above the range → no match
  15. Src IP not in subnet → no match, dst matches
  16. Invalid source IP raises PacketError
  17. Invalid destination IP raises PacketError
  18. Port out of range (0) raises PacketError
  19. Port out of range (65536) raises PacketError
  20. Non-integer port raises PacketError
  21. Invalid protocol raises PacketError
  22. Empty rule list → default deny
  23. PacketResult.__str__ includes action, line, reason
  24. Hidden rules listed in also_matched and in __str__
  25. Three rules, first two match: first wins, second in also_matched
"""

import pytest
from firescript import parse_rules, test_packet, PacketError


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _rules(src: str):
    """Parse source and return Rule list; assert no parse errors."""
    result = parse_rules(src)
    assert result.ok, f"Parse errors: {result.errors}"
    return result.rules


# ===========================================================================
# 1. Basic allow match
# ===========================================================================

def test_basic_allow():
    rules = _rules("allow tcp from 10.0.0.0/24 to any port 80")
    r = test_packet(rules, "tcp", "10.0.0.5", "1.2.3.4", 80)
    assert r.action == "allow"
    assert r.matched_rule is not None
    assert r.matched_rule.line == 1


# ===========================================================================
# 2. Basic deny match
# ===========================================================================

def test_basic_deny():
    rules = _rules("deny tcp from any to any port 22")
    r = test_packet(rules, "tcp", "5.5.5.5", "6.6.6.6", 22)
    assert r.action == "deny"
    assert r.matched_rule.line == 1


# ===========================================================================
# 3. Default deny when nothing matches
# ===========================================================================

def test_default_deny():
    rules = _rules("allow tcp from any to any port 80")
    r = test_packet(rules, "udp", "1.1.1.1", "2.2.2.2", 53)
    assert r.action == "deny"
    assert r.matched_rule is None
    assert "default" in r.reason.lower()


# ===========================================================================
# 4. First-match wins: allow before deny → allow
# ===========================================================================

def test_first_match_allow_before_deny():
    rules = _rules(
        "allow tcp from any to any port 443\n"
        "deny  tcp from any to any port 443"
    )
    r = test_packet(rules, "tcp", "10.0.0.1", "10.0.0.2", 443)
    assert r.action == "allow"
    assert r.matched_rule.line == 1


# ===========================================================================
# 5. First-match wins: deny before allow → deny
# ===========================================================================

def test_first_match_deny_before_allow():
    rules = _rules(
        "deny  tcp from any to any port 443\n"
        "allow tcp from any to any port 443"
    )
    r = test_packet(rules, "tcp", "10.0.0.1", "10.0.0.2", 443)
    assert r.action == "deny"
    assert r.matched_rule.line == 1


# ===========================================================================
# 6. also_matched is populated when later rules would have matched
# ===========================================================================

def test_also_matched_populated():
    rules = _rules(
        "allow tcp from any to any port 80\n"
        "deny  tcp from any to any port 80\n"
        "allow tcp from 10.0.0.0/8 to any port 80"
    )
    r = test_packet(rules, "tcp", "10.1.2.3", "5.5.5.5", 80)
    assert r.action == "allow"
    assert r.matched_rule.line == 1
    # Both line 2 and line 3 also match; they appear in also_matched
    hidden_lines = [rule.line for rule in r.also_matched]
    assert 2 in hidden_lines
    assert 3 in hidden_lines


# ===========================================================================
# 7. 'any' protocol matches a tcp packet
# ===========================================================================

def test_any_protocol_matches_tcp():
    rules = _rules("deny any from any to any port any")
    r = test_packet(rules, "tcp", "1.2.3.4", "5.6.7.8", 8080)
    assert r.action == "deny"
    assert r.matched_rule.line == 1


# ===========================================================================
# 8. 'any' protocol matches a udp packet
# ===========================================================================

def test_any_protocol_matches_udp():
    rules = _rules("allow any from any to any port any")
    r = test_packet(rules, "udp", "9.9.9.9", "8.8.8.8", 53)
    assert r.action == "allow"


# ===========================================================================
# 9. 'any' src matches an arbitrary source IP
# ===========================================================================

def test_any_src_matches():
    rules = _rules("deny tcp from any to any port 23")
    r = test_packet(rules, "tcp", "203.0.113.42", "10.0.0.1", 23)
    assert r.action == "deny"


# ===========================================================================
# 10. 'any' dst matches an arbitrary destination IP
# ===========================================================================

def test_any_dst_matches():
    rules = _rules("allow tcp from 10.0.0.0/8 to any port 443")
    r = test_packet(rules, "tcp", "10.20.30.40", "172.217.14.206", 443)
    assert r.action == "allow"


# ===========================================================================
# 11. Port at the exact lower boundary of a range
# ===========================================================================

def test_port_at_lower_boundary():
    rules = _rules("allow tcp from any to any port 1000-2000")
    r = test_packet(rules, "tcp", "1.1.1.1", "2.2.2.2", 1000)
    assert r.action == "allow"
    assert r.matched_rule is not None


# ===========================================================================
# 12. Port at the exact upper boundary of a range
# ===========================================================================

def test_port_at_upper_boundary():
    rules = _rules("allow tcp from any to any port 1000-2000")
    r = test_packet(rules, "tcp", "1.1.1.1", "2.2.2.2", 2000)
    assert r.action == "allow"
    assert r.matched_rule is not None


# ===========================================================================
# 13. Port just below the range → no match → default deny
# ===========================================================================

def test_port_just_below_range():
    rules = _rules("allow tcp from any to any port 1000-2000")
    r = test_packet(rules, "tcp", "1.1.1.1", "2.2.2.2", 999)
    assert r.action == "deny"
    assert r.matched_rule is None


# ===========================================================================
# 14. Port just above the range → no match → default deny
# ===========================================================================

def test_port_just_above_range():
    rules = _rules("allow tcp from any to any port 1000-2000")
    r = test_packet(rules, "tcp", "1.1.1.1", "2.2.2.2", 2001)
    assert r.action == "deny"
    assert r.matched_rule is None


# ===========================================================================
# 15. Src IP not in subnet → no match (even though dst and port match)
# ===========================================================================

def test_src_not_in_subnet_no_match():
    rules = _rules("allow tcp from 10.0.0.0/24 to any port 80")
    r = test_packet(rules, "tcp", "192.168.1.5", "1.2.3.4", 80)
    assert r.action == "deny"
    assert r.matched_rule is None


# ===========================================================================
# 16–21. Input validation errors
# ===========================================================================

def test_invalid_src_ip_raises():
    rules = _rules("allow tcp from any to any port 80")
    with pytest.raises(PacketError, match="source"):
        test_packet(rules, "tcp", "not.an.ip", "1.2.3.4", 80)


def test_invalid_dst_ip_raises():
    rules = _rules("allow tcp from any to any port 80")
    with pytest.raises(PacketError, match="destination"):
        test_packet(rules, "tcp", "1.2.3.4", "999.999.999.999", 80)


def test_port_zero_raises():
    rules = _rules("allow tcp from any to any port 80")
    with pytest.raises(PacketError, match="out of range"):
        test_packet(rules, "tcp", "1.2.3.4", "5.6.7.8", 0)


def test_port_too_large_raises():
    rules = _rules("allow tcp from any to any port 80")
    with pytest.raises(PacketError, match="out of range"):
        test_packet(rules, "tcp", "1.2.3.4", "5.6.7.8", 65536)


def test_non_integer_port_raises():
    rules = _rules("allow tcp from any to any port 80")
    with pytest.raises(PacketError, match="integer"):
        test_packet(rules, "tcp", "1.2.3.4", "5.6.7.8", "80")  # type: ignore[arg-type]


def test_invalid_protocol_raises():
    rules = _rules("allow tcp from any to any port 80")
    with pytest.raises(PacketError, match="not supported"):
        test_packet(rules, "ftp", "1.2.3.4", "5.6.7.8", 21)


# ===========================================================================
# 22. Empty rule list → default deny
# ===========================================================================

def test_empty_rules_default_deny():
    r = test_packet([], "tcp", "1.2.3.4", "5.6.7.8", 443)
    assert r.action == "deny"
    assert r.matched_rule is None
    assert "default" in r.reason.lower()


# ===========================================================================
# 23. PacketResult.__str__ contains key fields
# ===========================================================================

def test_packet_result_str_content():
    rules = _rules("allow tcp from any to any port 80")
    r = test_packet(rules, "tcp", "10.0.0.1", "20.0.0.1", 80)
    text = str(r)
    assert "ALLOW" in text
    assert "line 1" in text
    assert "Reason" in text


# ===========================================================================
# 24. also_matched entries appear in __str__ output
# ===========================================================================

def test_also_matched_in_str():
    rules = _rules(
        "allow tcp from any to any port 443\n"
        "deny  tcp from any to any port 443"
    )
    r = test_packet(rules, "tcp", "1.2.3.4", "5.6.7.8", 443)
    assert len(r.also_matched) == 1
    assert r.also_matched[0].line == 2
    text = str(r)
    assert "Hidden" in text
    assert "line 2" in text


# ===========================================================================
# 25. Three-rule scenario: first two match, second in also_matched
# ===========================================================================

def test_three_rules_first_two_match():
    rules = _rules(
        "deny  tcp from 10.0.0.0/8 to any port 22\n"   # line 1 — matches
        "allow tcp from 10.0.0.0/8 to any port 22\n"   # line 2 — also matches (hidden)
        "allow udp from any to any port 53"             # line 3 — different proto
    )
    r = test_packet(rules, "tcp", "10.5.5.5", "8.8.8.8", 22)
    assert r.action == "deny"
    assert r.matched_rule.line == 1
    # Line 2 is hidden; line 3 doesn't match (udp vs tcp)
    assert len(r.also_matched) == 1
    assert r.also_matched[0].line == 2
