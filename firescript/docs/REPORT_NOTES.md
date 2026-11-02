# FireScript — Project Report Notes

> **Course:** PBL (Project-Based Learning) — Compiler, Language & Automated Processing Systems  
> **Project:** FireScript: a domain-specific language and static analyzer for firewall rules

---

## 1. Problem Statement

Network administrators write firewall rules as ordered lists. A firewall tests
each incoming or outgoing packet against the list from top to bottom and applies
the **first matching rule**. This model has three common failure modes:

| Problem | Description |
|---------|-------------|
| **Shadowed rule** | A broad earlier rule matches everything a later rule would match, so the later rule *never fires*. The admin believes protection is active when it is not. |
| **Redundant rule** | An earlier rule already permits/blocks traffic; the later rule is wasted configuration that must be maintained for no benefit. |
| **Contradiction** | Two rules overlap (some traffic matches both) with different actions. Which action applies depends on the order, which is fragile and hard to reason about. |

Existing commercial tools that detect these issues are expensive, require
live firewall access, or are locked to a specific vendor. FireScript solves
this problem **purely in software** with no network access needed:

1. Write rules in a simple domain-specific language (`.fs` files).
2. Run the static analyzer to get a report of conflicts.
3. Simulate a packet to trace exactly which rule would fire.

---

## 2. System Architecture

```
┌──────────────────────────────────────────────────────┐
│                   app.py  (Streamlit UI)             │
│  ┌────────────┐  ┌─────────────┐  ┌───────────────┐ │
│  │ Rule editor│  │ Analyzer    │  │ Packet        │ │
│  │ + upload   │  │ findings    │  │ simulator     │ │
│  └─────┬──────┘  └──────┬──────┘  └───────┬───────┘ │
│        │                │                  │         │
└────────┼────────────────┼──────────────────┼─────────┘
         │  calls         │  calls           │  calls
         ▼                ▼                  ▼
┌─────────────┐   ┌──────────────┐   ┌──────────────┐
│  parser.py  │   │ analyzer.py  │   │ simulator.py │
│             │   │              │   │              │
│ parse_rules │──▶│  analyze()   │   │ test_packet()│
│ ParseResult │   │  Finding     │   │ PacketResult │
└──────┬──────┘   └──────────────┘   └──────────────┘
       │  produces
       ▼
┌──────────────┐
│  models.py   │
│  Rule        │
└──────────────┘
```

### Module responsibilities

| Module | Stage | Responsibility |
|--------|-------|----------------|
| `models.py` | 1 | `Rule` frozen dataclass — the in-memory AST node |
| `parser.py` | 1 | LALR grammar (Lark), line-by-line parsing, `parse_rules()` |
| `analyzer.py` | 2 | Pairwise rule comparison, `analyze()`, `Finding` dataclass |
| `simulator.py` | 3 | Top-to-bottom packet walk, `test_packet()`, `PacketResult` |
| `app.py` | 4 | Streamlit UI — no logic, only calls the above |

**Key design rule:** The UI (`app.py`) contains no analysis logic. It only
calls `parse_rules()`, `analyze()`, and `test_packet()`. This means the
core can be tested without Streamlit and reused in other contexts (CLI,
API, etc.).

---

## 3. Algorithm Explanation

### 3.1 Parsing (Stage 1)

The grammar is an **LALR(1)** grammar defined in [Lark](https://lark-parser.readthedocs.io/):

```
start: ACTION protocol "from" endpoint "to" endpoint "port" ports

protocol: PROTOCOL | ANY
endpoint: ANY | ADDRESS
ports: ANY | PORT | PORT "-" PORT
```

`parse_rules(source)` splits the input on newlines and parses each line
independently. Errors on one line never prevent other lines from parsing.
Each successfully parsed line is transformed by `_RuleBuilder` (a Lark
`Transformer`) into a `Rule` dataclass.

`any` addresses are normalised to `0.0.0.0/0` (an `IPv4Network`); `any`
ports become the range `[1, 65535]`.

### 3.2 Coverage test — `_covers(A, B)`

Rule A **covers** rule B when every packet that could match B also matches A.
This is equivalent to four containment checks:

```
_covers(A, B)  ⟺
    (A.protocol == "any"  OR  A.protocol == B.protocol)   # proto ⊇
    AND B.src.subnet_of(A.src)                             # src ⊆
    AND B.dst.subnet_of(A.dst)                             # dst ⊆
    AND A.port_start ≤ B.port_start                        # port ⊇
    AND B.port_end   ≤ A.port_end
```

`IPv4Network.subnet_of()` from the Python standard library implements the
subnet relationship: `N.subnet_of(M)` is `True` when every address in N
is also in M (i.e., N ⊆ M).

### 3.3 Overlap test — `_rules_overlap(A, B)`

Two rules **overlap** when some packet could match both. This is a weaker
test than coverage:

```
_rules_overlap(A, B)  ⟺
    _protocols_overlap(A.protocol, B.protocol)   # share ≥1 protocol
    AND A.src.overlaps(B.src)                    # share ≥1 src address
    AND A.dst.overlaps(B.dst)                    # share ≥1 dst address
    AND A.port_start ≤ B.port_end                # ranges intersect
    AND B.port_start ≤ A.port_end
```

`IPv4Network.overlaps()` is the standard-library complement to `subnet_of`.

### 3.4 Finding classification — `analyze(rules)`

The algorithm is O(n²) pairwise comparison (acceptable for typical rule
sets of tens to low hundreds of rules):

```
Pass 1 — backward look from each rule B (index i):
  for each earlier rule A (index j < i):
    if NOT _rules_overlap(A, B):  continue   # no interaction

    a_covers_b = _covers(A, B)
    b_covers_a = _covers(B, A)
    different  = A.action ≠ B.action

    if a_covers_b and different:         → SHADOWED
    if a_covers_b and not different:     → REDUNDANT
    if not a_covers_b and not b_covers_a and different: → CONTRADICTION

Pass 2 — forward look for generalizations:
  for each later rule B (index i > j):
    if pair already reported:  skip
    if _covers(B, A) and different: → GENERALIZATION
```

Results are sorted by `rule_line` so the report reads top-to-bottom.

### 3.5 Packet simulation — `test_packet()`

```
validate(protocol, src_ip, dst_ip, port)   # raise PacketError on bad input
first_match = None
also_matched = []

for rule in rules:                         # preserves file order
    if _rule_matches(rule, …):
        if first_match is None:
            first_match = rule
        else:
            also_matched.append(rule)      # hidden by the first match

if first_match is None:
    return PacketResult(action="deny", …, reason="default policy")
return PacketResult(action=first_match.action, also_matched=also_matched, …)
```

`_rule_matches` checks the same four conditions as `_covers` but with an
exact host address instead of a network range:
- `rule.protocol == "any"` or `== packet_protocol`
- `packet_src_ip  in rule.src`   (Python: `addr in network`)
- `packet_dst_ip  in rule.dst`
- `rule.port_start ≤ packet_port ≤ rule.port_end`

---

## 4. Limitations

| Limitation | Explanation |
|------------|-------------|
| **IPv4 only** | The grammar and all logic use `IPv4Network`/`IPv4Address`. IPv6 is not supported. |
| **TCP/UDP/ICMP only** | Protocol field accepts `tcp`, `udp`, `icmp`, and `any`. Real firewalls also support GRE, ESP, AH, etc. |
| **No stateful rules** | FireScript models stateless (packet-filter) rules only. Connection tracking (`ESTABLISHED`, `RELATED`) is not modelled. |
| **Single destination port** | Rules have one port or port range. Real firewalls can match multiple disjoint port sets (e.g. `80,443,8080`) in one rule. |
| **O(n²) analyzer** | The pairwise comparison is fine for tens or hundreds of rules, but would be slow for thousands. |
| **No interface or direction** | Rules have no concept of inbound/outbound interface. All rules are treated as a single flat policy. |
| **No negation** | There is no `!` (not) operator for addresses or ports. |

---

## 5. Viva Questions and Short Answers

### Q1. What is a domain-specific language (DSL) and why did you build one for this project?
A DSL is a small language designed for one problem domain, rather than a
general-purpose language. FireScript is a DSL because firewall rules have a
fixed, narrow structure: action, protocol, source, destination, port. A DSL
lets administrators write rules in plain English-like syntax and lets the tool
understand and reason about the rules at a semantic level (not just as text).

---

### Q2. What parsing technique does FireScript use, and why?
FireScript uses an **LALR(1)** parser generated by the Lark library. LALR(1)
parsers are fast (linear time), require no backtracking, and are easy to
describe with a grammar. The rule language is simple enough to fit an LALR
grammar — there are no ambiguities that would require a more powerful parser.

---

### Q3. What does "SHADOWED" mean, and why is it dangerous?
A rule is SHADOWED when an earlier rule already covers all the traffic it
would match. Because a firewall applies the **first** matching rule, the
shadowed rule never fires. This is dangerous when the intent is to allow
a specific subnet that an earlier "deny all" already blocks — the
administrator believes traffic is permitted, but it is actually denied.

---

### Q4. What is the difference between SHADOWED and REDUNDANT?
Both mean an earlier rule covers the later rule. The difference is the action:
- **SHADOWED** — the actions *differ* (e.g., deny then allow). The later rule
  is unreachable and the intent is being defeated.
- **REDUNDANT** — the actions are the *same* (e.g., allow then allow). The
  later rule is safe but wastes configuration and maintenance effort.

---

### Q5. How do you decide if one rule "covers" another?
Rule A covers rule B when every packet matching B also matches A. This
requires four containment checks to all be true simultaneously:
1. A's protocol is `any` or equals B's protocol.
2. B's source network is a subnet of (or equal to) A's source network.
3. B's destination network is a subnet of (or equal to) A's destination network.
4. B's port range is entirely inside A's port range.

The Python `ipaddress` module's `subnet_of()` method implements step 2 and 3.

---

### Q6. How is "overlap" different from "coverage", and when does it lead to CONTRADICTION?
Two rules *overlap* when some packet could match both — their traffic spaces
intersect but neither may contain the other entirely. A CONTRADICTION is
reported when two rules overlap, neither covers the other, and they have
different actions. This means the outcome for packets in the intersection
depends entirely on rule order — a fragile situation.

---

### Q7. What is a GENERALIZATION finding and why is it marked as info-level?
A GENERALIZATION occurs when a *later* rule is broader than an *earlier* rule
and has a different action. For example: `deny tcp from 10.0.0.5 port 22`
(specific exception) followed by `allow any from any port any` (catch-all
permit). This pattern is intentional and common — it is the "specific
exception before general rule" design. Marking it as info rather than
error avoids false alarms.

---

### Q8. What is the default policy and how is it implemented in the simulator?
If no rule in the list matches a packet, firewalls conventionally **deny** it.
In `test_packet()`, after the loop over all rules, if `first_match` is still
`None`, the function returns a `PacketResult` with `action="deny"` and
`matched_rule=None`. The reason string explicitly says "default policy".

---

### Q9. What does `also_matched` in `PacketResult` tell the user?
It is the list of every rule *after* the first match that would also have
matched the packet if the first rule had not fired. This helps the user
understand which rules are being hidden and diagnose analyzer findings like
SHADOWED or REDUNDANT in a concrete, per-packet way.

---

### Q10. Why is the analyzer O(n²) and is that a problem?
The analyzer compares every rule with every earlier rule — for n rules there
are n(n-1)/2 pairs, which is O(n²). For typical firewall rule sets (tens to
low hundreds of rules) this is negligible (microseconds in practice). For
very large enterprise rule sets (thousands of rules) a more efficient approach
such as interval trees or BDDs (Binary Decision Diagrams) would be needed.

---

### Q11. How does the parser handle errors on individual lines without failing entirely?
`parse_rules()` splits the source on newlines and processes each line in a
`try/except` block. A Lark `UnexpectedInput` exception on line N is caught,
converted to a `ParseError(line=N, message=…)`, and appended to
`result.errors`. Parsing then continues with line N+1. Good lines are
collected in `result.rules`. This ensures one typo never silences the rest
of the file.

---

### Q12. What is the role of `IPv4Network.subnet_of()` in the coverage check?
`B.src.subnet_of(A.src)` returns `True` when every address in B's source
network is also in A's source network (i.e., B.src ⊆ A.src). This is
exactly the containment condition needed: if A matches any source in A.src
and B only uses sources in B.src, and B.src ⊆ A.src, then A will always
fire before B can for those sources.

---

### Q13. Why does the grammar treat bare host IPs differently from CIDR notation, and how is that handled?
In the rule language, destinations like `8.8.8.8` (no `/prefix`) refer to a
single host. In `_to_network()`, if the text contains no `/`, the code
appends `/32` before parsing, converting it to `8.8.8.8/32`. This makes
host addresses semantically consistent with CIDR networks throughout the rest
of the code.

---

### Q14. How does the Streamlit UI stay clean — why is there no analysis logic in app.py?
The AGENTS rule for this project explicitly requires keeping parser, analyzer,
and UI in separate modules. `app.py` only calls `parse_rules()`, `analyze()`,
and `test_packet()` — all defined in the `firescript` package — and then
renders their results. This separation means the core logic can be tested
independently with `pytest` and reused in a CLI or API without touching the UI.

---

### Q15. How would you extend FireScript to support IPv6?
Three changes would be needed:
1. **Grammar** — allow IPv6 address literals (colons, hex digits) in the
   `ADDRESS` terminal. Python's `ipaddress` module handles both
   `IPv4Network` and `IPv6Network`.
2. **models.py** — change the type annotation of `src` and `dst` from
   `IPv4Network` to `Union[IPv4Network, IPv6Network]`.
3. **simulator.py** — change `_validate_ip` to accept `IPv6Address` instead
   of raising `PacketError`.
4. **Tests** — add test cases with `::1/128`, `2001:db8::/32`, etc.
   The `subnet_of()` and `overlaps()` methods work for IPv6 networks too,
   so the analyzer logic itself would not change.
