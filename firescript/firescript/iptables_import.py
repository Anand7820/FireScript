"""Convert iptables rules into FireScript text.

Input is the output of `iptables -S` (or `iptables-save`). One chain is
converted at a time (default: INPUT). The result is ordinary FireScript text,
so the existing parser, analyzer and simulator work on it unchanged.

Only what FireScript can model is converted:
  - targets ACCEPT (allow), DROP and REJECT (deny)
  - protocol (tcp, udp, icmp, all), source, destination, destination port(s)

A rule that uses anything else (interfaces, connection state, negation with
"!", source ports, jumps to other chains, ...) is SKIPPED, not guessed.
Ignoring an unsupported condition would make the rule broader than it really
is and produce wrong findings, so every skipped rule gets a warning.
"""
import re
import shlex
from dataclasses import dataclass, field
from ipaddress import ip_network
from typing import List, Optional

_PROTOCOLS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "all": "any",
              "6": "tcp", "17": "udp", "1": "icmp"}
_TARGETS = {"ACCEPT": "allow", "DROP": "deny", "REJECT": "deny"}
_HARMLESS_MODULES = {"tcp", "udp", "icmp", "comment", "multiport"}


@dataclass
class ImportResult:
    text: str = ""                       # FireScript rules, ready for parse_rules()
    warnings: List[str] = field(default_factory=list)
    converted: int = 0                   # iptables rules converted
    skipped: int = 0                     # iptables rules that could not be converted
    policy: Optional[str] = None         # default policy of the chain (ACCEPT/DROP)

    @property
    def complete(self) -> bool:
        """True when every rule of the chain was converted."""
        return self.skipped == 0


class _Unsupported(Exception):
    """Raised when one rule uses something FireScript cannot represent."""


def _address(value: str) -> str:
    """Convert an iptables address to FireScript form ('any' or a CIDR block)."""
    try:
        net = ip_network(value, strict=False)
    except ValueError:
        raise _Unsupported(f"address '{value}' (hostnames are not supported)")
    if net.version != 4:
        raise _Unsupported(f"address '{value}' (IPv6 is not supported)")
    return "any" if net.prefixlen == 0 else str(net)


def _port(value: str) -> str:
    """Convert '80' or '1024:2048' to FireScript form ('80' or '1024-2048')."""
    match = re.fullmatch(r"(\d+)(?::(\d+))?", value)
    if not match:
        raise _Unsupported(f"port '{value}' (only numeric ports are supported)")
    first = int(match.group(1))
    last = int(match.group(2)) if match.group(2) else first
    if not (1 <= first <= last <= 65535):
        raise _Unsupported(f"port '{value}' (must be within 1-65535, start <= end)")
    return str(first) if first == last else f"{first}-{last}"


def _value(opts: List[str], i: int) -> str:
    """Return the value that follows option opts[i]."""
    if i + 1 >= len(opts):
        raise _Unsupported(f"option '{opts[i]}' has no value")
    return opts[i + 1]


def _convert_rule(opts: List[str], lineno: int) -> List[str]:
    """Convert the options of one '-A CHAIN ...' line into FireScript lines."""
    proto, src, dst, ports, target = "any", "any", "any", ["any"], None
    problems: List[str] = []
    i = 0
    while i < len(opts):
        opt = opts[i]
        if opt == "!":
            problems.append("negation with '!'")
            i += 1
        elif opt in ("-p", "--protocol"):
            name = _value(opts, i).lower()
            if name not in _PROTOCOLS:
                problems.append(f"protocol '{name}'")
            else:
                proto = _PROTOCOLS[name]
            i += 2
        elif opt in ("-s", "--source"):
            src = _address(_value(opts, i)); i += 2
        elif opt in ("-d", "--destination"):
            dst = _address(_value(opts, i)); i += 2
        elif opt in ("--dport", "--destination-port"):
            ports = [_port(_value(opts, i))]; i += 2
        elif opt in ("--dports", "--destination-ports"):
            ports = [_port(p) for p in _value(opts, i).split(",")]; i += 2
        elif opt in ("-m", "--match"):
            module = _value(opts, i)
            if module not in _HARMLESS_MODULES:
                problems.append(f"match module '-m {module}'")
            i += 2
        elif opt == "--comment":
            i += 2
        elif opt in ("-j", "--jump", "-g", "--goto"):
            target = _value(opts, i); i += 2
        else:
            problems.append(f"option '{opt}'")
            i += 1
    if problems:
        raise _Unsupported("uses " + problems[0])
    if target is None:
        raise _Unsupported("it has no target (-j)")
    if target not in _TARGETS:
        raise _Unsupported(f"target '{target}' (only ACCEPT, DROP and REJECT are supported)")
    if ports != ["any"] and proto not in ("tcp", "udp"):
        raise _Unsupported("ports can only be used with tcp or udp")
    action = _TARGETS[target]
    return [f"{action} {proto} from {src} to {dst} port {p}  # iptables line {lineno}"
            for p in ports]


def import_iptables(source: str, chain: str = "INPUT") -> ImportResult:
    """Convert one chain of `iptables -S` / `iptables-save` output to FireScript."""
    result = ImportResult()
    rules: List[str] = []
    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if not line or line[0] in "#*" or line == "COMMIT":
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            result.warnings.append(f"iptables line {lineno} ignored: unbalanced quotes")
            continue
        if tokens[0] == "-P" and len(tokens) >= 3:            # iptables -S policy
            if tokens[1] == chain:
                result.policy = tokens[2]
        elif tokens[0].startswith(":") and len(tokens) >= 2:   # iptables-save policy
            if tokens[0][1:] == chain:
                result.policy = tokens[1]
        elif tokens[0] == "-A" and len(tokens) >= 2 and tokens[1] == chain:
            try:
                rules.extend(_convert_rule(tokens[2:], lineno))
                result.converted += 1
            except _Unsupported as exc:
                result.skipped += 1
                result.warnings.append(f"iptables line {lineno} skipped: {exc}")

    if result.converted == 0 and result.skipped == 0:
        result.warnings.append(f"No rules found for chain '{chain}'.")
    if result.skipped:
        result.warnings.append(
            f"Partial analysis: {result.skipped} rule(s) were skipped. Skipped rules "
            "can change which rules really apply, so treat the findings with care.")

    header = f"# Imported from iptables: chain {chain}, default policy {result.policy or 'unknown'}"
    if result.policy == "ACCEPT":
        rules.append("allow any from any to any port any  # default policy ACCEPT")
    result.text = "\n".join([header] + rules) + "\n"
    return result
