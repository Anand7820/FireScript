"""Tests for firescript/can_analyzer.py.

Covers all four finding kinds for CAN gateway rules:
  - SHADOWED: Earlier rule covers later rule with different action.
  - REDUNDANT: Earlier rule covers later rule with same action.
  - CONTRADICTION: Two rules overlap, neither covers the other, actions differ.
  - GENERALIZATION: Later rule covers earlier rule with different action (info).
  - Disjoint buses and disjoint ID ranges produce no findings.
"""

from firescript.can_rules import parse_can_rules
from firescript.can_analyzer import analyze_can, CanFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _can_rules(src: str):
    """Parse CAN rules text and assert no parse errors occurred."""
    result = parse_can_rules(src)
    assert result.ok, f"Parse errors: {result.errors}"
    return result.rules


def _kinds(findings):
    return [f.kind for f in findings]


# ---------------------------------------------------------------------------
# Analyzer tests
# ---------------------------------------------------------------------------

def test_exact_match_different_action_shadowed():
    """Identical bus and ID range with opposite actions produces SHADOWED."""
    rules = _can_rules(
        "deny  can from bus infotainment to bus powertrain id 0x100-0x1FF\n"
        "allow can from bus infotainment to bus powertrain id 0x100-0x1FF\n"
    )
    findings = analyze_can(rules)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "SHADOWED"
    assert f.rule_line == 2
    assert f.other_line == 1
    assert "shadowed" in f.explanation.lower()


def test_exact_match_same_action_redundant():
    """Identical bus and ID range with same action produces REDUNDANT."""
    rules = _can_rules(
        "allow can from bus infotainment to bus display id 0x120\n"
        "allow can from bus infotainment to bus display id 0x120\n"
    )
    findings = analyze_can(rules)
    assert len(findings) == 1
    assert findings[0].kind == "REDUNDANT"
    assert findings[0].rule_line == 2


def test_id_subrange_shadowed():
    """A narrower ID range covered by an earlier broader rule is SHADOWED."""
    rules = _can_rules(
        "deny  can from bus infotainment to bus powertrain id 0x100-0x200\n"
        "allow can from bus infotainment to bus powertrain id 0x150\n"
    )
    findings = analyze_can(rules)
    assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)


def test_id_subrange_redundant():
    """A narrower ID range with the same action is REDUNDANT."""
    rules = _can_rules(
        "allow can from bus any to bus any id 0x100-0x200\n"
        "allow can from bus infotainment to bus display id 0x150\n"
    )
    findings = analyze_can(rules)
    assert any(f.kind == "REDUNDANT" and f.rule_line == 2 for f in findings)


def test_any_bus_covers_named_bus():
    """'any' bus covers any specific bus name."""
    rules = _can_rules(
        "deny  can from bus any to bus any id any\n"
        "allow can from bus infotainment to bus powertrain id 0x100\n"
    )
    findings = analyze_can(rules)
    assert any(f.kind == "SHADOWED" and f.rule_line == 2 for f in findings)


def test_partial_id_overlap_contradiction():
    """Overlapping ID ranges (0x100-0x200 vs 0x180-0x280) with different actions."""
    rules = _can_rules(
        "allow can from bus infotainment to bus powertrain id 0x100-0x200\n"
        "deny  can from bus infotainment to bus powertrain id 0x180-0x280\n"
    )
    findings = analyze_can(rules)
    assert any(f.kind == "CONTRADICTION" for f in findings)


def test_same_action_partial_overlap_not_contradiction():
    """Overlapping ranges with the same action do not contradict."""
    rules = _can_rules(
        "allow can from bus infotainment to bus powertrain id 0x100-0x200\n"
        "allow can from bus infotainment to bus powertrain id 0x180-0x280\n"
    )
    findings = analyze_can(rules)
    assert all(f.kind != "CONTRADICTION" for f in findings)


def test_generalization_pattern():
    """Specific filter followed by broad allow is recognized as GENERALIZATION."""
    rules = _can_rules(
        "deny  can from bus infotainment to bus powertrain id 0x120\n"
        "allow can from bus any to bus any id any\n"
    )
    findings = analyze_can(rules)
    assert any(f.kind == "GENERALIZATION" and f.rule_line == 2 for f in findings)
    assert all(f.kind != "SHADOWED" for f in findings)


def test_disjoint_buses_no_interaction():
    """Rules targeting completely different bus pairs never interact."""
    rules = _can_rules(
        "allow can from bus infotainment to bus display id 0x120\n"
        "deny  can from bus body to bus chassis id 0x120\n"
    )
    findings = analyze_can(rules)
    assert findings == []


def test_disjoint_id_ranges_no_interaction():
    """Rules with separate non-overlapping ID ranges do not interact."""
    rules = _can_rules(
        "allow can from bus infotainment to bus powertrain id 0x100-0x150\n"
        "deny  can from bus infotainment to bus powertrain id 0x200-0x250\n"
    )
    findings = analyze_can(rules)
    assert findings == []


def test_three_rule_chain():
    """Catch-all deny shadows multiple subsequent specific allows."""
    rules = _can_rules(
        "deny  can from bus any to bus any id any\n"
        "allow can from bus infotainment to bus display id 0x200\n"
        "allow can from bus body to bus chassis id 0x300\n"
    )
    findings = analyze_can(rules)
    shadowed = [f for f in findings if f.kind == "SHADOWED"]
    assert len(shadowed) >= 2
    assert any(f.rule_line == 2 and f.other_line == 1 for f in shadowed)
    assert any(f.rule_line == 3 and f.other_line == 1 for f in shadowed)


def test_single_rule_no_findings():
    """A solitary rule produces no findings."""
    rules = _can_rules("allow can from bus infotainment to bus display id 0x120")
    assert analyze_can(rules) == []


def test_findings_sorted_by_rule_line():
    """analyze_can returns findings sorted by rule_line ascending."""
    rules = _can_rules(
        "deny  can from bus any to bus any id any\n"
        "allow can from bus bus1 to bus bus2 id 0x100\n"
        "allow can from bus bus3 to bus bus4 id 0x200\n"
    )
    findings = analyze_can(rules)
    lines = [f.rule_line for f in findings]
    assert lines == sorted(lines)


def test_finding_string_representation():
    """CanFinding.__str__ includes kind, line numbers, and explanation."""
    rules = _can_rules(
        "deny  can from bus any to bus any id 0x100\n"
        "allow can from bus any to bus any id 0x100\n"
    )
    findings = analyze_can(rules)
    assert len(findings) == 1
    s = str(findings[0])
    assert "SHADOWED" in s
    assert "2" in s
    assert "1" in s
