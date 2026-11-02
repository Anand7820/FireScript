"""Data model: what one firewall rule looks like after parsing (the 'AST')."""
from dataclasses import dataclass
from ipaddress import IPv4Network


@dataclass(frozen=True)
class Rule:
    line: int            # line number in the source text (starts at 1)
    action: str          # "allow" or "deny"
    protocol: str        # "tcp", "udp", "icmp" or "any"
    src: IPv4Network     # source range. "any" becomes 0.0.0.0/0
    dst: IPv4Network     # destination range
    port_start: int      # first port in the range
    port_end: int        # last port in the range ("any" becomes 0-65535)
    text: str            # the original rule text, used in reports

    def __str__(self) -> str:
        return f"Line {self.line}: {self.text}"
