"""CAN gateway rules: parsing, AST data model, and message simulator.

This module models firewall/gateway rules for vehicle Controller Area Network (CAN)
buses. Rules govern message routing between CAN buses based on standard 11-bit
CAN identifiers (0x000 to 0x7FF).

Rule format (one per line, '#' starts a comment):
    allow can from bus <name> to bus <name> id <hex|a-b|any>
    deny  can from bus <name> to bus <name> id <hex|a-b|any>

Example:
    deny can from bus infotainment to bus powertrain id 0x100-0x1FF

DISCLAIMER:
This is an educational simulation for static analysis and software-based
verification. It is NOT connected to or deployed on real vehicles.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Union

from lark import Lark, Transformer, Token
from lark.exceptions import UnexpectedInput


# ---------------------------------------------------------------------------
# Grammar
# ---------------------------------------------------------------------------

CAN_GRAMMAR = r"""
start: ACTION "can" "from" "bus" endpoint "to" "bus" endpoint "id" id_spec

endpoint: ANY -> any_bus
        | BUS_TOKEN -> bus_name

id_spec: ANY -> any_ids
       | ID_TOKEN "-" ID_TOKEN -> id_range
       | ID_TOKEN -> single_id

ACTION: "allow" | "deny"
ANY: "any"
BUS_TOKEN: /[^\s]+/
ID_TOKEN: /[^\s-]+/

%import common.WS_INLINE
%ignore WS_INLINE
"""

_can_parser = Lark(CAN_GRAMMAR, parser="lalr", start="start")


# ---------------------------------------------------------------------------
# Data Models and Error Types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CanRule:
    """Represents a parsed CAN gateway filter rule."""
    line: int          # 1-indexed line number in source text
    action: str        # "allow" or "deny"
    from_bus: str      # source bus name or "any"
    to_bus: str        # destination bus name or "any"
    id_start: int      # first 11-bit CAN ID in range (0x000 - 0x7FF)
    id_end: int        # last 11-bit CAN ID in range (0x000 - 0x7FF)
    text: str          # original rule text

    @property
    def tuple(self) -> tuple[str, str, str, int, int]:
        """Return the tuple representation (action, from_bus, to_bus, id_start, id_end)."""
        return (self.action, self.from_bus, self.to_bus, self.id_start, self.id_end)

    def __str__(self) -> str:
        return f"Line {self.line}: {self.text}"


@dataclass
class CanParseError:
    """A parse or validation error with an exact line number."""
    line: int
    message: str

    def __str__(self) -> str:
        return f"Line {self.line}: {self.message}"


@dataclass
class CanParseResult:
    """Outcome of parsing CAN rule text: valid rules and any errors."""
    rules: List[CanRule] = field(default_factory=list)
    errors: List[CanParseError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class CanRuleError(ValueError):
    """Raised when a rule is syntactically structured but semantically invalid."""


class CanMessageError(ValueError):
    """Raised when a simulated CAN message has invalid parameters."""


# ---------------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------------

_BUS_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")


def _validate_bus_name(name: str) -> str:
    """Validate a bus name identifier.

    Bus names must start with an ASCII letter and contain only alphanumeric
    characters, underscores, or hyphens (e.g. 'powertrain', 'infotainment', 'can_0').
    """
    cleaned = name.strip()
    if cleaned.lower() == "any":
        return "any"
    if not _BUS_NAME_PATTERN.match(cleaned):
        raise CanRuleError(
            f"Invalid bus name '{name}'. Bus names must start with a letter and "
            "contain only letters, numbers, underscores, or hyphens."
        )
    return cleaned.lower()


def _parse_can_id(text: str) -> int:
    """Convert a hex string (0x100) or integer to an 11-bit CAN ID (0x000-0x7FF)."""
    cleaned = text.strip()
    try:
        if cleaned.lower().startswith("0x"):
            val = int(cleaned, 16)
        else:
            val = int(cleaned, 10)
    except ValueError:
        raise CanRuleError(
            f"Invalid CAN ID '{text}'. Must be a hexadecimal value (e.g. 0x100) or integer."
        )
    if not 0x000 <= val <= 0x7FF:
        raise CanRuleError(
            f"CAN ID {text} ({hex(val)}) is out of range. "
            "Standard 11-bit CAN IDs must be between 0x000 and 0x7FF (0-2047)."
        )
    return val


# ---------------------------------------------------------------------------
# Lark Transformer
# ---------------------------------------------------------------------------

class _CanRuleBuilder(Transformer):
    """Transforms Lark parse tree nodes into CanRule instances."""

    def __init__(self, line_no: int, text: str):
        super().__init__()
        self.line_no = line_no
        self.text = text

    def any_bus(self, _items):
        return "any"

    def bus_name(self, items):
        return _validate_bus_name(str(items[0]))

    def any_ids(self, _items):
        return (0x000, 0x7FF)

    def single_id(self, items):
        id_val = _parse_can_id(str(items[0]))
        return (id_val, id_val)

    def id_range(self, items):
        first = _parse_can_id(str(items[0]))
        last = _parse_can_id(str(items[1]))
        if first > last:
            raise CanRuleError(
                f"CAN ID range {hex(first)}-{hex(last)} is reversed (start must be <= end)."
            )
        return (first, last)

    def start(self, items):
        action, from_bus, to_bus, (id_start, id_end) = items
        return CanRule(
            line=self.line_no,
            action=str(action).lower(),
            from_bus=from_bus,
            to_bus=to_bus,
            id_start=id_start,
            id_end=id_end,
            text=self.text,
        )


def _friendly_can_syntax_error(exc: UnexpectedInput, line: str) -> str:
    """Format a Lark syntax error into an admin-readable sentence."""
    column = getattr(exc, "column", 0)
    token = getattr(exc, "token", None)
    if isinstance(token, Token) and token.type != "$END":
        found = f"unexpected '{token}' at column {column}"
    elif token is not None and getattr(token, "type", "") == "$END":
        found = "the rule ends too early"
    else:
        found = f"unexpected character '{line[column - 1:column]}' at column {column}"
    return (
        f"Syntax error: {found}. "
        "Expected format: <allow|deny> can from bus <name|any> to bus <name|any> id <hex|a-b|any>"
    )


# ---------------------------------------------------------------------------
# Parser API
# ---------------------------------------------------------------------------

def parse_can_rules(source: str) -> CanParseResult:
    """Parse text containing CAN gateway rules line-by-line.

    Errors on one line do not prevent remaining lines from being parsed.
    """
    result = CanParseResult()
    for line_no, raw in enumerate(source.splitlines(), start=1):
        text = raw.split("#", 1)[0].strip()
        if not text:
            continue
        lowered = text.lower()
        try:
            tree = _can_parser.parse(lowered)
            rule = _CanRuleBuilder(line_no, text).transform(tree)
            result.rules.append(rule)
        except UnexpectedInput as exc:
            result.errors.append(CanParseError(line_no, _friendly_can_syntax_error(exc, lowered)))
        except Exception as exc:
            cause = getattr(exc, "orig_exc", exc)
            result.errors.append(CanParseError(line_no, str(cause)))
    return result


# ---------------------------------------------------------------------------
# Simulator Data Model & Function
# ---------------------------------------------------------------------------

@dataclass
class CanMessageResult:
    """Outcome of testing a CAN message through the gateway rules."""
    action: str                           # "allow" or "deny"
    matched_rule: Optional[CanRule]       # first matching rule, or None if default deny
    reason: str                           # plain-English explanation
    also_matched: List[CanRule] = field(default_factory=list)

    def __str__(self) -> str:
        parts = [f"Action : {self.action.upper()}"]
        if self.matched_rule:
            parts.append(f"Matched: line {self.matched_rule.line} — {self.matched_rule.text}")
        else:
            parts.append("Matched: <default policy>")
        parts.append(f"Reason : {self.reason}")
        if self.also_matched:
            hidden = ", ".join(f"line {r.line}" for r in self.also_matched)
            parts.append(f"Hidden : {hidden} would also have matched")
        return "\n".join(parts)


def test_message(
    rules: List[CanRule],
    from_bus: str,
    to_bus: str,
    can_id: Union[int, str],
) -> CanMessageResult:
    """Test a CAN frame through the gateway rule set.

    Checks rules top-to-bottom and returns the FIRST matching rule.
    If no rule matches, returns 'deny' under default policy.
    Also tracks all subsequent rules that would have matched.

    Parameters:
      rules    : List of CanRule objects
      from_bus : source bus name (e.g. 'infotainment')
      to_bus   : destination bus name (e.g. 'powertrain')
      can_id   : CAN ID as integer (e.g. 0x120) or hex string ('0x120')
    """
    # Validate buses
    if not isinstance(from_bus, str) or not from_bus.strip():
        raise CanMessageError("Source bus name must be a non-empty string.")
    if not isinstance(to_bus, str) or not to_bus.strip():
        raise CanMessageError("Destination bus name must be a non-empty string.")

    cleaned_from = from_bus.strip().lower()
    cleaned_to = to_bus.strip().lower()

    # Validate CAN ID
    if isinstance(can_id, bool):
        raise CanMessageError("CAN ID cannot be a boolean.")
    if isinstance(can_id, float):
        raise CanMessageError(f"CAN ID must be an integer, got float {can_id}.")

    if isinstance(can_id, str):
        can_id_int = _parse_can_id(can_id)
    elif isinstance(can_id, int):
        if not 0x000 <= can_id <= 0x7FF:
            raise CanMessageError(
                f"CAN ID {hex(can_id)} is out of range. "
                "Standard 11-bit CAN IDs must be between 0x000 and 0x7FF (0-2047)."
            )
        can_id_int = can_id
    else:
        raise CanMessageError(f"Unsupported CAN ID type: {type(can_id).__name__}.")

    first_match: Optional[CanRule] = None
    also_matched: List[CanRule] = []

    for rule in rules:
        from_ok = (rule.from_bus == "any") or (rule.from_bus == cleaned_from)
        to_ok = (rule.to_bus == "any") or (rule.to_bus == cleaned_to)
        id_ok = rule.id_start <= can_id_int <= rule.id_end

        if from_ok and to_ok and id_ok:
            if first_match is None:
                first_match = rule
            else:
                also_matched.append(rule)

    if first_match is None:
        return CanMessageResult(
            action="deny",
            matched_rule=None,
            reason=(
                f"No rule matched CAN message {hex(can_id_int)} from bus '{from_bus}' to '{to_bus}'. "
                "Default policy is deny."
            ),
            also_matched=[],
        )

    hidden_note = ""
    if also_matched:
        lines = ", ".join(f"line {r.line}" for r in also_matched)
        hidden_note = f" Rules on {lines} would also have matched but were not reached."

    reason = (
        f"Matched rule on line {first_match.line} ({first_match.text}). "
        f"Message: {hex(can_id_int)} from bus '{from_bus}' to '{to_bus}'.{hidden_note}"
    )

    return CanMessageResult(
        action=first_match.action,
        matched_rule=first_match,
        reason=reason,
        also_matched=also_matched,
    )


# Tell pytest not to collect test_message as a test function
test_message.__test__ = False  # type: ignore[attr-defined]
