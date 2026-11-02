"""Edge-case tests that probe boundary conditions and improved error messages.

These complement the existing test_parser.py, test_analyzer.py, and
test_simulator.py.  Each test targets a specific tricky scenario that
arose during review:

Parser edge cases:
  - Bare host IP in rules (now auto-promoted to /32)
  - host-bits-set now gives a "did you mean …?" message
  - Port 0 and port 65536 in rules
  - Empty source (all whitespace / only comments)

Analyzer edge cases:
  - Two identical rules (same action, same everything) → REDUNDANT only once
  - /32 host vs /24 subnet it belongs to
  - 'any' protocol cover in both directions
  - GENERALIZATION is not also reported as SHADOWED for the same pair
  - Rule that both overlaps and covers at the same time

Simulator edge cases:
  - Subnet CIDR as src_ip raises a clear PacketError
  - IPv6 address raises a clear PacketError
  - Protocol matching is case-insensitive ('TCP' → 'tcp')
  - Packet that matches no rule in a non-empty rule set → default deny
  - Port as float raises PacketError
  - Port as bool raises PacketError (bool is a subclass of int in Python)
"""

import pytest
from firescript import (
    parse_rules,
    analyze,
    test_packet,
    PacketError,
    import_iptables,
)


# ============================================================
# Helpers
# ============================================================

def _rules(src: str):
    result = parse_rules(src)
    assert result.ok, f"Unexpected parse errors: {result.errors}"
    return result.rules


def _kinds(findings):
    return [f.kind for f in findings]


# ============================================================
# PARSER EDGE CASES
# ============================================================

class TestParserEdgeCases:

    def test_bare_host_ip_accepted_as_slash32(self):
        """A plain IP without a prefix (10.0.0.5) is now valid and becomes /32."""
        result = parse_rules("allow tcp from 10.0.0.5 to 8.8.8.8 port 80")
        assert result.ok, result.errors
        rule = result.rules[0]
        assert str(rule.src) == "10.0.0.5/32"
        assert str(rule.dst) == "8.8.8.8/32"

    def test_host_bits_set_gives_helpful_suggestion(self):
        """10.0.0.5/24 should mention the two valid alternatives in the error."""
        result = parse_rules("allow tcp from 10.0.0.5/24 to any port 80")
        assert result.errors
        msg = result.errors[0].message
        # Should mention the corrected network
        assert "10.0.0.0/24" in msg or "host bits" in msg.lower()

    def test_port_zero_in_rule_gives_clear_error(self):
        """Port 0 is not in 1-65535 and should give a range error."""
        result = parse_rules("allow tcp from any to any port 0")
        assert result.errors
        assert "range" in result.errors[0].message.lower()

    def test_port_65536_in_rule_gives_clear_error(self):
        """Port 65536 exceeds the maximum and should give a range error."""
        result = parse_rules("deny tcp from any to any port 65536")
        assert result.errors
        assert "range" in result.errors[0].message.lower()

    def test_only_comments_produces_no_rules_and_no_errors(self):
        """A file that is nothing but comments should parse cleanly with 0 rules."""
        result = parse_rules("# this is a comment\n# another comment\n")
        assert result.ok
        assert result.rules == []

    def test_all_whitespace_produces_no_rules(self):
        """Blank lines and spaces only — no rules, no errors."""
        result = parse_rules("   \n\n\t\n   ")
        assert result.ok
        assert result.rules == []

    def test_error_on_one_line_does_not_block_others(self):
        """A bad line produces an error but still yields the surrounding good rules."""
        src = (
            "allow tcp from any to any port 80\n"
            "this is garbage\n"
            "deny tcp from any to any port 22\n"
        )
        result = parse_rules(src)
        assert len(result.rules) == 2
        assert len(result.errors) == 1
        assert result.errors[0].line == 2

    def test_port_65535_is_valid_upper_bound(self):
        """Port 65535 is the last legal port and must parse without errors."""
        result = parse_rules("allow tcp from any to any port 65535")
        assert result.ok
        assert result.rules[0].port_end == 65535

    def test_port_1_is_valid_lower_bound(self):
        """Port 1 is the first legal port."""
        result = parse_rules("deny udp from any to any port 1")
        assert result.ok
        assert result.rules[0].port_start == 1


# ============================================================
# ANALYZER EDGE CASES
# ============================================================

class TestAnalyzerEdgeCases:

    def test_identical_rules_produce_single_redundant(self):
        """Two completely identical rules → exactly one REDUNDANT finding."""
        rules = _rules(
            "allow tcp from 10.0.0.0/24 to any port 80\n"
            "allow tcp from 10.0.0.0/24 to any port 80"
        )
        findings = analyze(rules)
        assert len(findings) == 1
        assert findings[0].kind == "REDUNDANT"

    def test_host_slash32_in_slash24_is_shadowed(self):
        """A /32 host rule that falls inside an earlier /24 rule is shadowed."""
        rules = _rules(
            "deny tcp from 10.0.0.0/24 to any port 22\n"
            "allow tcp from 10.0.0.5/32 to any port 22"
        )
        findings = analyze(rules)
        assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)

    def test_generalization_not_also_reported_as_shadowed(self):
        """When B covers A (GENERALIZATION), it must NOT also be reported as SHADOWED."""
        rules = _rules(
            "deny tcp from 10.0.0.16/28 to any port 80\n"  # A – specific
            "allow tcp from 10.0.0.0/24 to any port 80"    # B – broader
        )
        findings = analyze(rules)
        kinds = _kinds(findings)
        assert "GENERALIZATION" in kinds
        assert "SHADOWED" not in kinds

    def test_no_self_comparison(self):
        """A single rule must never produce a finding against itself."""
        rules = _rules("deny any from any to any port any")
        assert analyze(rules) == []

    def test_same_action_overlap_is_not_contradiction(self):
        """Overlapping port ranges with the same action are REDUNDANT, not CONTRADICTION."""
        rules = _rules(
            "allow tcp from any to any port 80-200\n"
            "allow tcp from any to any port 100-300"
        )
        findings = analyze(rules)
        assert all(f.kind != "CONTRADICTION" for f in findings)

    def test_any_covers_any_same_action(self):
        """'any any any any' followed by a specific rule with same action → REDUNDANT."""
        rules = _rules(
            "allow any from any to any port any\n"
            "allow tcp from 10.0.0.0/24 to any port 443"
        )
        findings = analyze(rules)
        assert any(f.kind == "REDUNDANT" for f in findings)

    def test_any_covers_any_different_action(self):
        """'deny any…' followed by a specific 'allow' → SHADOWED."""
        rules = _rules(
            "deny any from any to any port any\n"
            "allow tcp from 10.0.0.0/24 to any port 443"
        )
        findings = analyze(rules)
        assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)

    def test_disjoint_port_ranges_no_finding(self):
        """Non-overlapping port ranges never interact."""
        rules = _rules(
            "allow tcp from any to any port 1-1023\n"
            "deny tcp from any to any port 1024-65535"
        )
        assert analyze(rules) == []

    def test_findings_sorted_by_rule_line(self):
        """analyze() must return findings sorted by rule_line ascending."""
        rules = _rules(
            "deny tcp from any to any port any\n"  # catch-all
            "allow tcp from any to any port 80\n"
            "allow tcp from any to any port 443\n"
            "allow tcp from any to any port 8080"
        )
        findings = analyze(rules)
        lines = [f.rule_line for f in findings]
        assert lines == sorted(lines)


# ============================================================
# SIMULATOR EDGE CASES
# ============================================================

class TestSimulatorEdgeCases:

    def test_cidr_as_src_ip_gives_clear_error(self):
        """Passing a subnet (10.0.0.0/24) as src_ip must raise PacketError."""
        rules = _rules("allow tcp from any to any port 80")
        with pytest.raises(PacketError, match="network range"):
            test_packet(rules, "tcp", "10.0.0.0/24", "1.2.3.4", 80)

    def test_cidr_as_dst_ip_gives_clear_error(self):
        """Passing a subnet as dst_ip must raise PacketError."""
        rules = _rules("allow tcp from any to any port 80")
        with pytest.raises(PacketError, match="network range"):
            test_packet(rules, "tcp", "1.2.3.4", "192.168.0.0/16", 80)

    def test_ipv6_src_raises_error(self):
        """An IPv6 address as src_ip should raise PacketError explaining IPv4-only."""
        rules = _rules("allow tcp from any to any port 80")
        with pytest.raises(PacketError, match="IPv6"):
            test_packet(rules, "tcp", "::1", "1.2.3.4", 80)

    def test_protocol_case_insensitive(self):
        """Protocol 'TCP' (uppercase) should be accepted and normalised."""
        rules = _rules("allow tcp from any to any port 80")
        result = test_packet(rules, "TCP", "1.2.3.4", "5.6.7.8", 80)
        assert result.action == "allow"

    def test_no_match_in_non_empty_ruleset_default_deny(self):
        """When rules exist but none match, the result is the default deny."""
        rules = _rules("allow tcp from 10.0.0.0/24 to any port 80")
        result = test_packet(rules, "udp", "10.0.0.5", "8.8.8.8", 53)
        assert result.action == "deny"
        assert result.matched_rule is None

    def test_float_port_raises_packet_error(self):
        """A float port (80.0) must raise PacketError, not pass silently."""
        rules = _rules("allow tcp from any to any port 80")
        with pytest.raises(PacketError, match="integer"):
            test_packet(rules, "tcp", "1.2.3.4", "5.6.7.8", 80.0)  # type: ignore

    def test_bool_port_raises_packet_error(self):
        """True (bool) is a subclass of int in Python; it must still be rejected."""
        rules = _rules("allow tcp from any to any port 80")
        with pytest.raises(PacketError, match="integer"):
            test_packet(rules, "tcp", "1.2.3.4", "5.6.7.8", True)  # type: ignore

    def test_also_matched_is_empty_when_only_one_match(self):
        """When exactly one rule matches, also_matched must be an empty list."""
        rules = _rules(
            "allow tcp from 10.0.0.0/24 to any port 80\n"
            "deny udp from any to any port 53"  # different proto — no match
        )
        result = test_packet(rules, "tcp", "10.0.0.1", "1.2.3.4", 80)
        assert result.also_matched == []

    def test_unknown_protocol_error_lists_valid_options(self):
        """PacketError for unknown protocol must name the allowed values."""
        rules = _rules("allow tcp from any to any port 80")
        with pytest.raises(PacketError) as exc_info:
            test_packet(rules, "ftp", "1.2.3.4", "5.6.7.8", 21)
        msg = str(exc_info.value)
        # Must name the three valid protocols
        assert "tcp" in msg and "udp" in msg and "icmp" in msg


# ============================================================
# IPTABLES IMPORT EDGE CASES
# ============================================================

class TestIptablesIntegrationEdgeCases:

    def test_import_and_analyze_finds_shadowed_and_redundant(self):
        """Converting an iptables snippet with duplicates and shadow rules yields findings."""
        ipt_raw = (
            "-P INPUT DROP\n"
            "-A INPUT -s 10.0.0.0/24 -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 22 -j DROP\n"
            "-A INPUT -s 10.0.0.5/32 -p tcp --dport 22 -j ACCEPT\n"
        )
        res = import_iptables(ipt_raw, chain="INPUT")
        assert res.converted == 3
        parsed = parse_rules(res.text)
        assert parsed.ok
        findings = analyze(parsed.rules)
        kinds = _kinds(findings)
        assert "SHADOWED" in kinds or "REDUNDANT" in kinds

    def test_import_empty_text_returns_clean_result(self):
        """Empty input text yields 0 converted rules and appropriate warning."""
        res = import_iptables("", chain="INPUT")
        assert res.converted == 0
        assert res.skipped == 0
        assert any("No rules found" in w for w in res.warnings)

    def test_import_custom_chain_filter(self):
        """Only rules matching the selected chain are imported."""
        ipt_raw = (
            "-A CUSTOM -p tcp --dport 8080 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
        )
        res = import_iptables(ipt_raw, chain="CUSTOM")
        assert res.converted == 1
        assert "port 8080" in res.text
        assert "port 80  " not in res.text

    def test_import_warnings_contain_skipped_reasons(self):
        """Unsupported iptables lines (conntrack, interface) produce descriptive warnings."""
        ipt_raw = (
            "-A INPUT -i eth0 -j ACCEPT\n"
            "-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT\n"
            "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
        )
        res = import_iptables(ipt_raw, chain="INPUT")
        assert res.converted == 1
        assert res.skipped == 2
        assert len(res.warnings) >= 2
        assert any("-i" in w for w in res.warnings)
        assert any("conntrack" in w for w in res.warnings)

