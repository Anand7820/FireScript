"""Stage 2: analyze a list of Rule objects and report conflicts.

Four kinds of findings:
  SHADOWED      – an earlier rule covers this one with a DIFFERENT action,
                  so this rule can never be reached.
  REDUNDANT     – an earlier rule covers this one with the SAME action,
                  so this rule does useful work but is already implied.
  CONTRADICTION – two rules overlap but neither covers the other and they
                  have different actions; the winner depends on rule order.
  GENERALIZATION – a LATER rule covers an EARLIER rule with a different action
                  (info level, usually intentional: specific deny then broad allow).
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import List

from .models import Rule


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One reported issue between two rules."""
    kind: str        # "SHADOWED", "REDUNDANT", "CONTRADICTION", "GENERALIZATION"
    rule_line: int   # the rule being examined (B)
    other_line: int  # the rule it interacts with (A)
    explanation: str # plain-English description

    def __str__(self) -> str:
        return f"[{self.kind}] lines {self.rule_line} & {self.other_line}: {self.explanation}"


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _protocols_overlap(proto_a: str, proto_b: str) -> bool:
    """Return True when the two protocol values can match the same packet.

    'any' matches everything; two named protocols overlap only if equal.
    """
    return proto_a == "any" or proto_b == "any" or proto_a == proto_b


def _nets_overlap(net_a: IPv4Network, net_b: IPv4Network) -> bool:
    """Return True when the two networks share at least one address."""
    return net_a.overlaps(net_b)


def _ports_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """Return True when the two port ranges share at least one port number."""
    return a_start <= b_end and b_start <= a_end


def _rules_overlap(a: Rule, b: Rule) -> bool:
    """Return True when at least one packet could match both rules."""
    return (
        _protocols_overlap(a.protocol, b.protocol)
        and _nets_overlap(a.src, b.src)
        and _nets_overlap(a.dst, b.dst)
        and _ports_overlap(a.port_start, a.port_end, b.port_start, b.port_end)
    )


def _covers(a: Rule, b: Rule) -> bool:
    """Return True when every packet that matches B also matches A.

    Conditions (all must hold):
      - A's protocol is 'any', OR A and B share the same protocol.
      - B's src network is a subnet of (or equal to) A's src.
      - B's dst network is a subnet of (or equal to) A's dst.
      - B's port range lies entirely inside A's port range.
    """
    # Protocol check
    proto_ok = (a.protocol == "any") or (a.protocol == b.protocol)
    if not proto_ok:
        return False

    # Subnet check (b.src ⊆ a.src)
    src_ok = b.src.subnet_of(a.src)
    if not src_ok:
        return False

    # Subnet check (b.dst ⊆ a.dst)
    dst_ok = b.dst.subnet_of(a.dst)
    if not dst_ok:
        return False

    # Port range check: b's range must sit inside a's range
    port_ok = (a.port_start <= b.port_start) and (b.port_end <= a.port_end)
    return port_ok


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(rules: List[Rule]) -> List[Finding]:
    """Compare every rule with every earlier rule and return a Finding list.

    The function works in two passes:
      Pass 1 – for each rule B (index i), scan all earlier rules A (index < i):
                classify as SHADOWED, REDUNDANT, or CONTRADICTION.
      Pass 2 – for each rule A (index i), scan all later rules B (index > i):
                classify as GENERALIZATION when B covers A with a different action.

    A single pair may produce at most one Finding (the most severe one).
    """
    findings: List[Finding] = []
    reported_pairs: set[tuple[int, int]] = set()  # (rule_line_b, rule_line_a)

    # ------------------------------------------------------------------
    # Pass 1: look backward from each rule
    # ------------------------------------------------------------------
    for i, b in enumerate(rules):
        for j in range(i):
            a = rules[j]
            pair = (b.line, a.line)

            if not _rules_overlap(a, b):
                continue  # no interaction at all

            a_covers_b = _covers(a, b)
            b_covers_a = _covers(b, a)
            different_action = a.action != b.action

            if a_covers_b:
                if different_action:
                    # A fires first and blocks B entirely.
                    kind = "SHADOWED"
                    msg = (
                        f"Rule on line {b.line} is shadowed by line {a.line}. "
                        f"Line {a.line} already {a.action}s "
                        f"{a.protocol} traffic "
                        f"from {a.src} to {a.dst} "
                        f"on ports {a.port_start}-{a.port_end}, "
                        f"so line {b.line} will never be reached."
                    )
                else:
                    # Same action; B is implied by A.
                    kind = "REDUNDANT"
                    msg = (
                        f"Rule on line {b.line} is redundant because line {a.line} "
                        f"already {a.action}s the same traffic "
                        f"({a.protocol} from {a.src} to {a.dst} "
                        f"ports {a.port_start}-{a.port_end})."
                    )
            elif not b_covers_a and different_action:
                # Partial overlap with conflicting actions.
                kind = "CONTRADICTION"
                msg = (
                    f"Rules on lines {a.line} and {b.line} overlap but neither covers "
                    f"the other, and they have different actions ({a.action} vs {b.action}). "
                    f"Packets in the overlapping region are handled by whichever rule "
                    f"appears first (line {a.line})."
                )
            else:
                # Same-action partial overlap or b covers a (handled in pass 2).
                continue

            reported_pairs.add(pair)
            findings.append(Finding(kind=kind, rule_line=b.line, other_line=a.line, explanation=msg))

    # ------------------------------------------------------------------
    # Pass 2: GENERALIZATION – a later rule covers an earlier rule
    #         with a different action (info-level, usually intentional).
    # ------------------------------------------------------------------
    for i, b in enumerate(rules):
        for j in range(i):
            a = rules[j]
            pair = (b.line, a.line)

            # Skip if we already reported something for this pair.
            if pair in reported_pairs:
                continue

            if _covers(b, a) and a.action != b.action:
                msg = (
                    f"Rule on line {b.line} generalizes line {a.line} with a different "
                    f"action. Line {a.line} {a.action}s a specific range "
                    f"({a.protocol} from {a.src} to {a.dst} ports {a.port_start}-{a.port_end}), "
                    f"and line {b.line} {b.action}s a broader set that includes it. "
                    f"This is often intentional (specific exception followed by general rule)."
                )
                reported_pairs.add(pair)
                findings.append(
                    Finding(kind="GENERALIZATION", rule_line=b.line, other_line=a.line, explanation=msg)
                )

    # Return findings sorted by the line number of the rule being reported.
    findings.sort(key=lambda f: (f.rule_line, f.other_line))
    return findings
