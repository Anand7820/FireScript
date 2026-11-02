"""Stage 1: read rule text, check the syntax, and build Rule objects.

Rule format (one rule per line, '#' starts a comment):

    allow tcp from 10.0.0.0/24 to any port 80
    deny  tcp from any to any port 22
    allow udp from any to 8.8.8.8 port 53
    deny  any from any to any port 1000-2000

Each line is parsed on its own, so one bad line never hides the others
and every error can point at an exact line number.
"""
from dataclasses import dataclass, field
from ipaddress import IPv4Network, ip_network
from typing import List

from lark import Lark, Transformer, Token
from lark.exceptions import UnexpectedInput

from .models import Rule

GRAMMAR = r"""
start: ACTION protocol "from" endpoint "to" endpoint "port" ports

protocol: PROTOCOL | ANY
endpoint: ANY | ADDRESS
ports: ANY             -> any_ports
     | PORT            -> single_port
     | PORT "-" PORT   -> port_range

ACTION: "allow" | "deny"
PROTOCOL: "tcp" | "udp" | "icmp"
ANY: "any"
ADDRESS: /\d+\.\d+\.\d+\.\d+(\/\d+)?/
PORT: /\d+/

%import common.WS_INLINE
%ignore WS_INLINE
"""

_parser = Lark(GRAMMAR, parser="lalr", start="start")


@dataclass
class ParseError:
    line: int
    message: str

    def __str__(self) -> str:
        return f"Line {self.line}: {self.message}"


@dataclass
class ParseResult:
    rules: List[Rule] = field(default_factory=list)
    errors: List[ParseError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class RuleError(ValueError):
    """A rule that is written correctly but means something invalid."""


def _to_network(text: str) -> IPv4Network:
    """Parse a CIDR string or plain IP into an IPv4Network.

    Accepts 'any' (becomes 0.0.0.0/0), a CIDR like '10.0.0.0/24',
    or a bare host address like '8.8.8.8' (becomes /32).
    Raises RuleError with a friendly hint on failure.
    """
    if text == "any":
        return ip_network("0.0.0.0/0")
    # Allow bare host IPs by upgrading them to /32 before strict parsing.
    if "/" not in text:
        text = f"{text}/32"
    try:
        return ip_network(text, strict=True)
    except ValueError as exc:
        msg = str(exc)
        if "host bits set" in msg:
            # e.g. 10.0.0.5/24 — offer the two valid alternatives
            host, prefix = text.split("/")
            corrected = ip_network(text, strict=False)
            raise RuleError(
                f"Address '{host}/{prefix}' has host bits set. "
                f"Did you mean the network '{corrected}' "
                f"or the single host '{host}/32'?"
            )
        raise RuleError(
            f"Invalid address '{text}'. "
            "Use a plain IPv4 address (e.g. 8.8.8.8) or CIDR notation "
            "(e.g. 10.0.0.0/24), or write 'any' for all addresses."
        )


def _to_port(text: str) -> int:
    """Convert a port string to an integer in 1–65535.

    Raises RuleError with a clear range reminder on failure.
    """
    port = int(text)
    if not 1 <= port <= 65535:
        raise RuleError(
            f"Port {port} is out of the valid range. "
            "Ports must be between 1 and 65535 inclusive."
        )
    return port


class _RuleBuilder(Transformer):
    """Turns the parse tree into plain values, checking meaning as it goes."""

    def __init__(self, line_no: int, text: str):
        super().__init__()
        self.line_no = line_no
        self.text = text

    def protocol(self, items):
        return str(items[0])

    def endpoint(self, items):
        return _to_network(str(items[0]))

    def any_ports(self, _items):
        return (1, 65535)

    def single_port(self, items):
        port = _to_port(str(items[0]))
        return (port, port)

    def port_range(self, items):
        first, last = _to_port(str(items[0])), _to_port(str(items[1]))
        if first > last:
            raise RuleError(f"Port range {first}-{last} is backwards (start must be <= end)")
        return (first, last)

    def start(self, items):
        action, protocol, src, dst, (p1, p2) = items
        return Rule(
            line=self.line_no, action=str(action), protocol=protocol,
            src=src, dst=dst, port_start=p1, port_end=p2, text=self.text,
        )


def _friendly_syntax_error(exc: UnexpectedInput, line: str) -> str:
    """Make Lark's technical error readable for a normal admin."""
    column = getattr(exc, "column", 0)
    token = getattr(exc, "token", None)
    if isinstance(token, Token) and token.type != "$END":
        found = f"unexpected '{token}' at column {column}"
    elif token is not None and getattr(token, "type", "") == "$END":
        found = "the rule ends too early"
    else:
        found = f"unexpected character '{line[column - 1:column]}' at column {column}"
    return (f"Syntax error: {found}. "
            "Expected format: <allow|deny> <tcp|udp|icmp|any> from <ip|any> to <ip|any> port <port|a-b|any>")


def parse_rules(source: str) -> ParseResult:
    """Parse a whole rule file. Returns the good rules and a list of errors."""
    result = ParseResult()
    for line_no, raw in enumerate(source.splitlines(), start=1):
        text = raw.split("#", 1)[0].strip()      # drop comments and spaces
        if not text:
            continue                              # skip blank lines
        lowered = text.lower()
        try:
            tree = _parser.parse(lowered)
            result.rules.append(_RuleBuilder(line_no, text).transform(tree))
        except UnexpectedInput as exc:
            result.errors.append(ParseError(line_no, _friendly_syntax_error(exc, lowered)))
        except Exception as exc:                  # RuleError may arrive wrapped by Lark
            cause = exc.orig_exc if hasattr(exc, "orig_exc") else exc
            result.errors.append(ParseError(line_no, str(cause)))
    return result
