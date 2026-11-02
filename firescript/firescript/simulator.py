"""Stage 3: simulate a single packet against a list of Rule objects.

The simulator walks rules top-to-bottom (firewall order) and returns:
  - The first rule that matches (or a synthetic 'default deny' if none does).
  - The action that applies.
  - Every later rule that would ALSO have matched the packet (shadow list).

Input validation rejects bad IPs and out-of-range ports before scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address
from typing import List, Optional

from .models import Rule


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PacketError(ValueError):
    """Raised when the packet description is invalid (bad IP, port, etc.)."""


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class PacketResult:
    """Everything the caller needs to know about a simulated packet."""

    action: str                          # "allow" or "deny"
    matched_rule: Optional[Rule]         # None means 'default deny'
    reason: str                          # plain-English explanation
    also_matched: List[Rule] = field(default_factory=list)
    # Rules that would have matched if the first one had not fired first.

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


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_ip(text: str, label: str) -> IPv4Address:
    """Parse and return an IPv4Address; raise PacketError on bad input.

    Only plain host addresses (no CIDR prefix) are accepted here,
    because a packet has an exact IP, not a range.
    """
    if "/" in text:
        raise PacketError(
            f"The {label} IP '{text}' looks like a network range. "
            "Enter a single host address (e.g. 10.0.0.5), not a subnet."
        )
    try:
        addr = ip_address(text)
    except ValueError:
        raise PacketError(
            f"'{text}' is not a valid {label} IPv4 address. "
            "Use dotted-decimal notation, e.g. 192.168.1.1."
        )
    if not isinstance(addr, IPv4Address):
        raise PacketError(
            f"The {label} address '{text}' is an IPv6 address. "
            "FireScript only supports IPv4."
        )
    return addr


def _validate_port(port: int) -> int:
    """Check that port is an integer in [1, 65535]; raise PacketError otherwise."""
    if not isinstance(port, int) or isinstance(port, bool):
        raise PacketError(
            f"Port must be an integer, got {type(port).__name__!r}. "
            "Example: 80, 443, 22."
        )
    if not 1 <= port <= 65535:
        raise PacketError(
            f"Port {port} is out of range. "
            "Valid ports are 1 to 65535."
        )
    return port


def _validate_protocol(protocol: str) -> str:
    """Normalise and validate the protocol string."""
    p = protocol.strip().lower()
    allowed = {"tcp", "udp", "icmp"}
    if p not in allowed:
        raise PacketError(
            f"Protocol '{protocol}' is not supported. "
            f"Choose one of: {', '.join(sorted(allowed))}."
        )
    return p


# ---------------------------------------------------------------------------
# Matching helper
# ---------------------------------------------------------------------------

def _rule_matches(rule: Rule, protocol: str, src: IPv4Address,
                  dst: IPv4Address, port: int) -> bool:
    """Return True when this rule applies to the described packet.

    Matching logic (all conditions must hold):
      - Rule protocol is 'any' OR equals the packet's protocol.
      - Packet src IP is inside rule's src network.
      - Packet dst IP is inside rule's dst network.
      - Packet port is within rule's port range [port_start, port_end].
    """
    proto_ok = rule.protocol == "any" or rule.protocol == protocol
    src_ok = src in IPv4Network(rule.src)
    dst_ok = dst in IPv4Network(rule.dst)
    port_ok = rule.port_start <= port <= rule.port_end
    return proto_ok and src_ok and dst_ok and port_ok


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def test_packet(
    rules: List[Rule],
    protocol: str,
    src_ip: str,
    dst_ip: str,
    port: int,
) -> PacketResult:
    """Simulate a packet through the rule list and return the verdict.

    Parameters
    ----------
    rules    : ordered list of Rule objects (from parse_rules).
    protocol : 'tcp', 'udp', or 'icmp'.
    src_ip   : source IPv4 address string, e.g. '10.0.0.5'.
    dst_ip   : destination IPv4 address string, e.g. '192.168.1.1'.
    port     : destination port number (1–65535).

    Returns
    -------
    PacketResult with:
      - action        – 'allow' or 'deny'
      - matched_rule  – the first Rule that fired, or None (default deny)
      - reason        – plain-English sentence
      - also_matched  – later rules that would also have matched
    """
    # Validate inputs first so we fail fast with a clear message.
    proto = _validate_protocol(protocol)
    src = _validate_ip(src_ip, "source")
    dst = _validate_ip(dst_ip, "destination")
    _validate_port(port)

    first_match: Optional[Rule] = None
    also_matched: List[Rule] = []

    for rule in rules:
        if _rule_matches(rule, proto, src, dst, port):
            if first_match is None:
                first_match = rule
            else:
                also_matched.append(rule)

    if first_match is None:
        return PacketResult(
            action="deny",
            matched_rule=None,
            reason=(
                f"No rule matched {proto} packet from {src_ip} to {dst_ip} "
                f"on port {port}. Default policy is deny."
            ),
            also_matched=[],
        )

    hidden_note = ""
    if also_matched:
        lines = ", ".join(f"line {r.line}" for r in also_matched)
        hidden_note = (
            f" Rules on {lines} would also have matched but were not reached."
        )

    reason = (
        f"Matched rule on line {first_match.line} "
        f"({first_match.text}). "
        f"Packet: {proto} from {src_ip} to {dst_ip} port {port}.{hidden_note}"
    )

    return PacketResult(
        action=first_match.action,
        matched_rule=first_match,
        reason=reason,
        also_matched=also_matched,
    )


# Tell pytest not to collect this function as a test case.
test_packet.__test__ = False  # type: ignore[attr-defined]
