"""Tests for firescript/can_rules.py.

Covers:
  - Parsing single hex IDs, ranges, and 'any'
  - Case-insensitivity, comments, blank lines
  - Semantic validation errors (bad bus names, IDs > 0x7FF, reversed ranges)
  - Syntax error reporting with line numbers
  - Message simulator (first-match, default deny, hidden rules, boundary IDs, input validation)
"""

import pytest
from firescript.can_rules import (
    parse_can_rules,
    test_message,
    CanRule,
    CanMessageError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _can_rules(src: str):
    """Parse CAN rules text and assert no parse errors occurred."""
    result = parse_can_rules(src)
    assert result.ok, f"Parse errors: {result.errors}"
    return result.rules


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_parse_single_hex_id():
    """A single hex ID parses into identical start and end values."""
    rules = _can_rules("allow can from bus infotainment to bus display id 0x120")
    assert len(rules) == 1
    r = rules[0]
    assert r.line == 1
    assert r.action == "allow"
    assert r.from_bus == "infotainment"
    assert r.to_bus == "display"
    assert r.id_start == 0x120
    assert r.id_end == 0x120
    assert r.tuple == ("allow", "infotainment", "display", 0x120, 0x120)


def test_parse_hex_range():
    """A range 0x100-0x1FF sets id_start and id_end correctly."""
    rules = _can_rules("deny can from bus infotainment to bus powertrain id 0x100-0x1FF")
    assert len(rules) == 1
    r = rules[0]
    assert r.action == "deny"
    assert r.id_start == 0x100
    assert r.id_end == 0x1FF


def test_parse_any_bus_and_any_id():
    """'any' bus means every bus; 'any' id means 0x000-0x7FF."""
    rules = _can_rules("allow can from bus any to bus any id any")
    assert len(rules) == 1
    r = rules[0]
    assert r.from_bus == "any"
    assert r.to_bus == "any"
    assert r.id_start == 0x000
    assert r.id_end == 0x7FF


def test_parse_comments_and_case_insensitivity():
    """Rules ignore comments, leading spaces, and are case-insensitive."""
    src = (
        "# Gateway security policy\n\n"
        "  DENY CAN FROM BUS INFOTAINMENT TO BUS POWERTRAIN ID 0X250  # block untrusted\n"
    )
    result = parse_can_rules(src)
    assert result.ok and len(result.rules) == 1
    r = result.rules[0]
    assert r.line == 3
    assert r.action == "deny"
    assert r.from_bus == "infotainment"
    assert r.to_bus == "powertrain"
    assert r.id_start == 0x250


def test_bad_bus_name_starting_with_digit():
    """Bus name starting with a digit produces a line-numbered error."""
    result = parse_can_rules("allow can from bus 123bus to bus powertrain id 0x100")
    assert len(result.errors) == 1
    assert result.errors[0].line == 1
    assert "Invalid bus name" in result.errors[0].message


def test_bad_bus_name_with_punctuation():
    """Bus name with illegal symbols produces a line-numbered error."""
    result = parse_can_rules("deny can from bus @infotainment to bus powertrain id 0x100")
    assert len(result.errors) == 1
    assert "Invalid bus name" in result.errors[0].message


def test_can_id_out_of_range():
    """Standard 11-bit CAN ID cannot exceed 0x7FF (2047)."""
    result = parse_can_rules("allow can from bus body to bus powertrain id 0x800")
    assert len(result.errors) == 1
    assert "out of range" in result.errors[0].message.lower()


def test_can_id_invalid_token():
    """Non-hex string in ID position produces a line-numbered error."""
    result = parse_can_rules("allow can from bus body to bus powertrain id 0xZZZ")
    assert len(result.errors) == 1
    assert "Invalid CAN ID" in result.errors[0].message


def test_reversed_id_range():
    """A range where start > end produces a line-numbered error."""
    result = parse_can_rules("deny can from bus body to bus powertrain id 0x200-0x100")
    assert len(result.errors) == 1
    assert "reversed" in result.errors[0].message.lower()


def test_bad_line_does_not_block_good_lines():
    """One erroneous rule does not prevent other valid rules from parsing."""
    src = (
        "allow can from bus body to bus chassis id 0x100\n"
        "bad can rule syntax here\n"
        "deny can from bus any to bus any id any\n"
    )
    result = parse_can_rules(src)
    assert len(result.rules) == 2
    assert len(result.errors) == 1
    assert result.errors[0].line == 2


def test_syntax_error_missing_bus_keyword():
    """Omitting 'bus' triggers a friendly syntax error message."""
    result = parse_can_rules("allow can from infotainment to bus powertrain id 0x100")
    assert len(result.errors) == 1
    assert "Syntax error" in result.errors[0].message


# ---------------------------------------------------------------------------
# Simulator tests (test_message)
# ---------------------------------------------------------------------------

def test_simulator_basic_allow():
    rules = _can_rules("allow can from bus infotainment to bus display id 0x120")
    res = test_message(rules, "infotainment", "display", 0x120)
    assert res.action == "allow"
    assert res.matched_rule is not None
    assert res.matched_rule.line == 1


def test_simulator_basic_deny():
    rules = _can_rules("deny can from bus infotainment to bus powertrain id 0x100-0x1FF")
    res = test_message(rules, "infotainment", "powertrain", 0x150)
    assert res.action == "deny"
    assert res.matched_rule.line == 1


def test_simulator_default_deny():
    rules = _can_rules("allow can from bus infotainment to bus display id 0x120")
    res = test_message(rules, "body", "chassis", 0x300)
    assert res.action == "deny"
    assert res.matched_rule is None
    assert "default" in res.reason.lower()


def test_simulator_first_match_precedence():
    """First matching rule wins over later conflicting rules."""
    rules = _can_rules(
        "allow can from bus any to bus any id 0x100\n"
        "deny  can from bus any to bus any id 0x100\n"
    )
    res = test_message(rules, "diag", "powertrain", 0x100)
    assert res.action == "allow"
    assert res.matched_rule.line == 1
    assert len(res.also_matched) == 1
    assert res.also_matched[0].line == 2


def test_simulator_hex_string_input_and_boundaries():
    """Boundary IDs 0x000 and 0x7FF can be passed as hex strings or ints."""
    rules = _can_rules(
        "allow can from bus any to bus any id 0x000\n"
        "allow can from bus any to bus any id 0x7FF\n"
    )
    r1 = test_message(rules, "can0", "can1", "0x000")
    assert r1.action == "allow" and r1.matched_rule.line == 1

    r2 = test_message(rules, "can0", "can1", 0x7FF)
    assert r2.action == "allow" and r2.matched_rule.line == 2


def test_simulator_invalid_inputs_raise_error():
    """Empty bus names and out-of-range IDs raise CanMessageError."""
    rules = _can_rules("allow can from bus any to bus any id any")
    with pytest.raises(CanMessageError, match="Source bus"):
        test_message(rules, "", "powertrain", 0x100)
    with pytest.raises(CanMessageError, match="out of range"):
        test_message(rules, "infotainment", "powertrain", 0x800)
    with pytest.raises(CanMessageError, match="boolean"):
        test_message(rules, "infotainment", "powertrain", True)


def test_simulator_result_string_representation():
    """CanMessageResult string includes verdict, line number, and reason."""
    rules = _can_rules(
        "allow can from bus any to bus any id 0x100\n"
        "deny  can from bus any to bus any id 0x100\n"
    )
    res = test_message(rules, "diag", "powertrain", 0x100)
    s = str(res)
    assert "ALLOW" in s
    assert "line 1" in s
    assert "Hidden" in s
    assert "line 2" in s
