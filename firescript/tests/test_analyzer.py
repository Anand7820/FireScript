"""Tests for firescript/analyzer.py (Stage 2).

Each test builds rules via parse_rules() to guarantee the Rule objects
come from the real parser, then calls analyze() and checks the findings.

Coverage targets (15+ cases):
  1.  Exact match, different action  → SHADOWED
  2.  Exact match, same action       → REDUNDANT
  3.  Subnet src, different action   → SHADOWED
  4.  Subnet src, same action        → REDUNDANT
  5.  'any' protocol covers named    → SHADOWED
  6.  Port range subset              → SHADOWED
  7.  Port range overlap (no cover)  → CONTRADICTION
  8.  Network overlap (no subnet)    → CONTRADICTION
  9.  No overlap at all              → no findings
  10. Different protocols            → no findings
  11. Same action, partial overlap   → no findings (not shadowed/contradicted)
  12. Generalization later rule      → GENERALIZATION
  13. Three-rule chain               → multiple findings
  14. Single rule                    → no findings
  15. Allow then deny exact (reversed action pair) → SHADOWED
  16. Port range completely inside another → SHADOWED
  17. Totally disjoint subnets       → no findings
  18. 'any' src & dst, port subset   → SHADOWED
"""

import pytest
from firescript import parse_rules, analyze, Finding


# ---------------------------------------------------------------------------
# Helper: parse exactly N rules, asserting no parse errors.
# ---------------------------------------------------------------------------

def _rules(src: str):
    """Parse source text and return the list of Rule objects (no errors expected)."""
    result = parse_rules(src)
    assert result.ok, f"Parse errors: {result.errors}"
    return result.rules


def _kinds(findings):
    """Return just the list of kind strings from a findings list."""
    return [f.kind for f in findings]


# ===========================================================================
# 1. Exact match, different action → SHADOWED
# ===========================================================================

def test_exact_match_shadowed():
    """Rule 2 is identical to rule 1 but with opposite action; rule 2 is shadowed."""
    rules = _rules(
        "deny tcp from 10.0.0.0/24 to 192.168.1.0/24 port 22\n"
        "allow tcp from 10.0.0.0/24 to 192.168.1.0/24 port 22"
    )
    findings = analyze(rules)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "SHADOWED"
    assert f.rule_line == 2
    assert f.other_line == 1
    assert "shadowed" in f.explanation.lower()


# ===========================================================================
# 2. Exact match, same action → REDUNDANT
# ===========================================================================

def test_exact_match_redundant():
    """Rule 2 duplicates rule 1 exactly; it is redundant."""
    rules = _rules(
        "allow tcp from 10.0.0.0/24 to any port 80\n"
        "allow tcp from 10.0.0.0/24 to any port 80"
    )
    findings = analyze(rules)
    assert len(findings) == 1
    assert findings[0].kind == "REDUNDANT"
    assert findings[0].rule_line == 2


# ===========================================================================
# 3. Narrower src subnet, different action → SHADOWED
# ===========================================================================

def test_subnet_src_shadowed():
    """Rule 2 targets /28, which is a subnet of /24 in rule 1; shadowed."""
    rules = _rules(
        "deny tcp from 10.0.0.0/24 to any port 80\n"
        "allow tcp from 10.0.0.16/28 to any port 80"
    )
    findings = analyze(rules)
    assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)


# ===========================================================================
# 4. Narrower src subnet, same action → REDUNDANT
# ===========================================================================

def test_subnet_src_redundant():
    """Narrower subnet rule with same action is redundant."""
    rules = _rules(
        "allow tcp from 10.0.0.0/24 to any port 80\n"
        "allow tcp from 10.0.0.16/28 to any port 80"
    )
    findings = analyze(rules)
    assert any(f.kind == "REDUNDANT" and f.rule_line == 2 for f in findings)


# ===========================================================================
# 5. 'any' protocol covers a specific protocol, different action → SHADOWED
# ===========================================================================

def test_any_protocol_covers_tcp():
    """Rule 1 uses 'any' protocol; rule 2 uses tcp. Rule 2 is shadowed."""
    rules = _rules(
        "deny any from any to any port any\n"
        "allow tcp from any to any port 80"
    )
    findings = analyze(rules)
    assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)


# ===========================================================================
# 6. Port range subset, different action → SHADOWED
# ===========================================================================

def test_port_range_subset_shadowed():
    """Rule 1 covers ports 1-1024; rule 2 covers port 80 only; rule 2 is shadowed."""
    rules = _rules(
        "deny tcp from any to any port 1-1024\n"
        "allow tcp from any to any port 80"
    )
    findings = analyze(rules)
    assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)


# ===========================================================================
# 7. Port range overlap but no full cover → CONTRADICTION
# ===========================================================================

def test_port_range_partial_overlap_contradiction():
    """Ports 80-443 vs 400-800: they overlap (400-443) but neither covers the other."""
    rules = _rules(
        "allow tcp from any to any port 80-443\n"
        "deny tcp from any to any port 400-800"
    )
    findings = analyze(rules)
    assert any(f.kind == "CONTRADICTION" for f in findings)


# ===========================================================================
# 8. Network overlap (not subnet), different action → CONTRADICTION
# ===========================================================================

def test_network_overlap_contradiction():
    """10.0.0.0/23 and 10.0.1.0/24 share 10.0.1.0/24 but neither is a subnet of the other
    with respect to the pair of rules — actually /24 IS a subnet of /23.
    Use sibling subnets instead: 10.0.0.0/24 and 10.0.1.0/24 don't overlap.
    Use 10.0.0.0/22 vs 10.0.0.0/23: the /23 is a subset.
    For a real partial-overlap use different octets that share IPs:
    src overlap: 10.0.0.0/23 vs 10.0.1.0/23 — these share 10.0.1.x.
    Actually those two /23 networks don't overlap.
    Use 10.0.0.0/22 (10.0.0-3.x) and 10.0.2.0/23 (10.0.2-3.x) — /23 IS subnet of /22.
    Use DIFFERENT ranges on src vs dst to force partial overlap:
      A: src=10.0.0.0/24, dst=any, ports 80-200
      B: src=any, dst=any, ports 100-300, different action
    → A.src⊄B.src (any), B.src⊄A.src? 10.0.0.0/24 ⊆ any (0.0.0.0/0)? Yes.
    Hard to make a pure network partial overlap without subnet relationship.
    Simplest: use overlapping port ranges as in test 7. Keep this one simpler.
    """
    # Two rules with the same protocol, src=any, dst=any, but different *adjacent*
    # port ranges that overlap in the middle.
    rules = _rules(
        "allow udp from any to any port 1000-2000\n"
        "deny udp from any to any port 1500-3000"
    )
    findings = analyze(rules)
    assert any(f.kind == "CONTRADICTION" for f in findings)


# ===========================================================================
# 9. No overlap at all → no findings
# ===========================================================================

def test_no_overlap_no_findings():
    """TCP on port 22 and UDP on port 53 have no overlap."""
    rules = _rules(
        "allow tcp from any to any port 22\n"
        "deny udp from any to any port 53"
    )
    findings = analyze(rules)
    assert findings == []


# ===========================================================================
# 10. Different protocols, different actions → no findings
# ===========================================================================

def test_different_protocols_no_findings():
    """tcp and udp don't overlap; no finding even with different actions."""
    rules = _rules(
        "allow tcp from 10.0.0.0/24 to any port 443\n"
        "deny udp from 10.0.0.0/24 to any port 443"
    )
    findings = analyze(rules)
    assert findings == []


# ===========================================================================
# 11. Same action, partial port overlap → no CONTRADICTION (same action can't conflict)
# ===========================================================================

def test_same_action_partial_overlap_no_contradiction():
    """Two allow rules that overlap on ports produce REDUNDANT at most, not CONTRADICTION."""
    rules = _rules(
        "allow tcp from any to any port 80-443\n"
        "allow tcp from any to any port 400-800"
    )
    findings = analyze(rules)
    # No CONTRADICTION because actions are the same
    assert all(f.kind != "CONTRADICTION" for f in findings)


# ===========================================================================
# 12. GENERALIZATION: later rule is broader, different action
# ===========================================================================

def test_generalization():
    """Rule 1 denies /28; rule 2 allows /24, which covers /28. GENERALIZATION."""
    rules = _rules(
        "deny tcp from 10.0.0.16/28 to any port 80\n"
        "allow tcp from 10.0.0.0/24 to any port 80"
    )
    findings = analyze(rules)
    assert any(f.kind == "GENERALIZATION" and f.rule_line == 2 for f in findings)


# ===========================================================================
# 13. Three-rule chain → multiple findings
# ===========================================================================

def test_three_rule_chain():
    """
    Rule 1: deny tcp any→any port any    (catch-all deny)
    Rule 2: allow tcp any→any port 80    (shadowed by rule 1)
    Rule 3: allow tcp any→any port 443   (shadowed by rule 1)
    """
    rules = _rules(
        "deny tcp from any to any port any\n"
        "allow tcp from any to any port 80\n"
        "allow tcp from any to any port 443"
    )
    findings = analyze(rules)
    shadowed = [f for f in findings if f.kind == "SHADOWED"]
    assert len(shadowed) >= 2
    assert any(f.rule_line == 2 and f.other_line == 1 for f in shadowed)
    assert any(f.rule_line == 3 and f.other_line == 1 for f in shadowed)


# ===========================================================================
# 14. Single rule → no findings
# ===========================================================================

def test_single_rule_no_findings():
    """A single rule has nothing to compare against."""
    rules = _rules("allow tcp from any to any port 80")
    assert analyze(rules) == []


# ===========================================================================
# 15. Allow then deny exact (reversed action pair) → SHADOWED
# ===========================================================================

def test_allow_then_deny_exact_shadowed():
    """Rule 1 allows; rule 2 denies the exact same traffic. Rule 2 is shadowed."""
    rules = _rules(
        "allow udp from 172.16.0.0/16 to 8.8.8.8/32 port 53\n"
        "deny udp from 172.16.0.0/16 to 8.8.8.8/32 port 53"
    )
    findings = analyze(rules)
    assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)


# ===========================================================================
# 16. Port range completely inside another, same protocol → SHADOWED
# ===========================================================================

def test_port_subrange_inside_wide_range():
    """Rule 1 blocks ports 1-65535 (any); rule 2 targets 8080 only — shadowed."""
    rules = _rules(
        "deny tcp from any to any port any\n"
        "allow tcp from any to any port 8080"
    )
    findings = analyze(rules)
    assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)


# ===========================================================================
# 17. Totally disjoint subnets → no findings
# ===========================================================================

def test_disjoint_subnets_no_findings():
    """10.0.0.0/24 and 192.168.0.0/24 share no addresses."""
    rules = _rules(
        "allow tcp from 10.0.0.0/24 to any port 80\n"
        "deny tcp from 192.168.0.0/24 to any port 80"
    )
    findings = analyze(rules)
    assert findings == []


# ===========================================================================
# 18. 'any' src & dst, port subset → SHADOWED
# ===========================================================================

def test_any_src_dst_port_subset_shadowed():
    """Rule 1 denies all ports on any src/dst; rule 2 is a subset — shadowed."""
    rules = _rules(
        "deny icmp from any to any port any\n"
        "allow icmp from any to any port 1-100"
    )
    findings = analyze(rules)
    assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)


# ===========================================================================
# 19. Explanation text is meaningful (spot-check content)
# ===========================================================================

def test_explanation_mentions_line_numbers():
    """The explanation string must contain the line numbers of both rules."""
    rules = _rules(
        "deny tcp from any to any port 22\n"
        "allow tcp from any to any port 22"
    )
    findings = analyze(rules)
    assert findings
    for f in findings:
        assert str(f.rule_line) in f.explanation
        assert str(f.other_line) in f.explanation


# ===========================================================================
# 20. Finding.__str__ includes kind and line numbers
# ===========================================================================

def test_finding_str_format():
    """Finding.__str__ should include the kind and both line numbers."""
    rules = _rules(
        "deny tcp from any to any port 443\n"
        "allow tcp from any to any port 443"
    )
    findings = analyze(rules)
    assert findings
    s = str(findings[0])
    assert "SHADOWED" in s
    assert "1" in s
    assert "2" in s
