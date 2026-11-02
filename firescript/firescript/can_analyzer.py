"""CAN gateway rule analyzer: detects SHADOWED, REDUNDANT, CONTRADICTION, and GENERALIZATION.

This module reuses the verification logic from the FireScript IP rule analyzer,
adapted to automotive CAN bus topologies and 11-bit identifier ranges.

Definitions:
  - Rule A "covers" rule B when every message matching B also matches A:
      A.from_bus is 'any' or equal to B.from_bus,
      A.to_bus is 'any' or equal to B.to_bus,
      and B's ID range lies entirely inside A's ID range.
  - Two rules "overlap" when at least one message could match both rules.

Finding kinds:
  1. SHADOWED      – an earlier rule covers B and has a DIFFERENT action; B never fires.
  2. REDUNDANT     – an earlier rule covers B and has the SAME action; B is duplicate.
  3. CONTRADICTION – two rules overlap, have different actions, neither covers the other;
                     the outcome depends on rule order.
  4. GENERALIZATION – a later rule covers an earlier rule with a different action
                     (info level; often intentional exception-then-default pattern).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .can_rules import CanRule


# ---------------------------------------------------------------------------
# Finding Dataclass
# ---------------------------------------------------------------------------

@dataclass
class CanFinding:
    """One reported conflict or advisory between two CAN gateway rules."""
    kind: str        # "SHADOWED", "REDUNDANT", "CONTRADICTION", "GENERALIZATION"
    rule_line: int   # line number of rule B being examined
    other_line: int  # line number of rule A it interacts with
    explanation: str # plain-English explanation

    def __str__(self) -> str:
        return f"[{self.kind}] lines {self.rule_line} & {self.other_line}: {self.explanation}"


# Alias for compatibility with IP analyzer naming conventions
Finding = CanFinding


# ---------------------------------------------------------------------------
# Relation Helpers
# ---------------------------------------------------------------------------

def _can_covers(a: CanRule, b: CanRule) -> bool:
    """Return True when every message matching rule B also matches rule A.

    Conditions (all must hold):
      - A's from_bus is 'any' OR matches B's from_bus.
      - A's to_bus is 'any' OR matches B's to_bus.
      - B's CAN ID range is completely contained within A's ID range.
    """
    from_ok = (a.from_bus == "any") or (a.from_bus == b.from_bus)
    to_ok = (a.to_bus == "any") or (a.to_bus == b.to_bus)
    id_ok = (a.id_start <= b.id_start) and (b.id_end <= a.id_end)
    return from_ok and to_ok and id_ok


def _can_overlaps(a: CanRule, b: CanRule) -> bool:
    """Return True when at least one CAN message could match both rules."""
    from_ok = (a.from_bus == "any") or (b.from_bus == "any") or (a.from_bus == b.from_bus)
    to_ok = (a.to_bus == "any") or (b.to_bus == "any") or (a.to_bus == b.to_bus)
    id_ok = (a.id_start <= b.id_end) and (b.id_start <= a.id_end)
    return from_ok and to_ok and id_ok


# ---------------------------------------------------------------------------
# Analyzer API
# ---------------------------------------------------------------------------

def analyze_can(rules: List[CanRule]) -> List[CanFinding]:
    """Compare each CAN gateway rule against earlier rules and return findings.

    Pass 1:
      Examines rule B against all earlier rules A. Reports SHADOWED, REDUNDANT,
      or CONTRADICTION if rules interact.

    Pass 2:
      Detects GENERALIZATION where a later rule B covers an earlier rule A with
      an opposite action (e.g. specific deny followed by catch-all allow).
    """
    findings: List[CanFinding] = []
    reported_pairs: set[tuple[int, int]] = set()

    # Pass 1: backward look from each rule
    for i, b in enumerate(rules):
        for j in range(i):
            a = rules[j]
            pair = (b.line, a.line)

            if not _can_overlaps(a, b):
                continue

            a_covers_b = _can_covers(a, b)
            b_covers_a = _can_covers(b, a)
            different_action = (a.action != b.action)

            if a_covers_b:
                if different_action:
                    kind = "SHADOWED"
                    msg = (
                        f"Rule on line {b.line} is shadowed by line {a.line}. "
                        f"Line {a.line} already {a.action}s CAN traffic "
                        f"from bus '{a.from_bus}' to '{a.to_bus}' "
                        f"for IDs {hex(a.id_start)}-{hex(a.id_end)}, "
                        f"so line {b.line} will never be reached."
                    )
                else:
                    kind = "REDUNDANT"
                    msg = (
                        f"Rule on line {b.line} is redundant because line {a.line} "
                        f"already {a.action}s the same CAN traffic "
                        f"(from bus '{a.from_bus}' to '{a.to_bus}' "
                        f"IDs {hex(a.id_start)}-{hex(a.id_end)})."
                    )
            elif not b_covers_a and different_action:
                kind = "CONTRADICTION"
                msg = (
                    f"Rules on lines {a.line} and {b.line} overlap but neither covers "
                    f"the other, and they have different actions ({a.action} vs {b.action}). "
                    f"CAN messages in the overlapping ID range are handled by whichever rule "
                    f"appears first (line {a.line})."
                )
            else:
                continue

            reported_pairs.add(pair)
            findings.append(CanFinding(kind=kind, rule_line=b.line, other_line=a.line, explanation=msg))

    # Pass 2: generalization check (later rule covers earlier rule with different action)
    for i, b in enumerate(rules):
        for j in range(i):
            a = rules[j]
            pair = (b.line, a.line)
            if pair in reported_pairs:
                continue

            if _can_covers(b, a) and a.action != b.action:
                msg = (
                    f"Rule on line {b.line} generalizes line {a.line} with a different action. "
                    f"Line {a.line} {a.action}s specific CAN traffic "
                    f"(from bus '{a.from_bus}' to '{a.to_bus}' IDs {hex(a.id_start)}-{hex(a.id_end)}), "
                    f"and line {b.line} {b.action}s a broader set that includes it. "
                    f"This is often intentional (specific exception followed by general rule)."
                )
                reported_pairs.add(pair)
                findings.append(CanFinding(kind="GENERALIZATION", rule_line=b.line, other_line=a.line, explanation=msg))

    findings.sort(key=lambda f: (f.rule_line, f.other_line))
    return findings


# Convenience alias matching the IP analyzer function name
analyze = analyze_can
