# 🔥 FireScript — Firewall Rule Analyzer

A college PBL project (theme: **Compiler, Language & Automated Processing Systems**).

FireScript is a small domain-specific language for writing firewall rules and a
static analyzer that finds mistakes and conflicts **without touching a real
firewall or network**.

---

## Table of Contents
1. [Setup](#setup)
2. [Rule Syntax](#rule-syntax)
3. [Running the UI](#running-the-ui)
4. [Running the tests](#running-the-tests)
5. [Project layout](#project-layout)
6. [Feature overview](#feature-overview)
7. [Screenshot walkthrough](#screenshot-walkthrough)
8. [Progress](#progress)

---

## Setup

**Prerequisites:** Python 3.10 or newer.

```bash
# 1. Clone / enter the project
cd firescript/

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify everything works
pytest
```

> **requirements.txt** lists: `lark>=1.1`, `streamlit>=1.30`, `pytest>=7.0`.
> No database, no React, no extra frameworks.

---

## Rule Syntax

Each rule occupies one line and follows this format:

```
<action> <protocol> from <src> to <dst> port <ports>
```

| Field      | Values                                      | Example          |
|------------|---------------------------------------------|------------------|
| `action`   | `allow` \| `deny`                           | `allow`          |
| `protocol` | `tcp` \| `udp` \| `icmp` \| `any`          | `tcp`            |
| `src`      | IPv4 CIDR, bare host IP, or `any`           | `10.0.0.0/24`    |
| `dst`      | IPv4 CIDR, bare host IP, or `any`           | `8.8.8.8`        |
| `ports`    | single port, `start-end` range, or `any`    | `80`, `1000-2000`, `any` |

- `any` in the **protocol** field matches TCP, UDP, and ICMP.
- `any` in **src** or **dst** means `0.0.0.0/0` (all addresses).
- `any` in **ports** means ports 1 – 65535.
- `#` starts a comment; the rest of the line is ignored.
- Rules are **case-insensitive** — `ALLOW TCP` works the same as `allow tcp`.
- Bare host IPs like `8.8.8.8` are automatically treated as `/32`.

### Examples

```fs
# Allow inbound HTTP and HTTPS from the internal network
allow tcp from 10.0.0.0/24 to any port 80
allow tcp from 10.0.0.0/24 to any port 443

# Allow DNS queries to Google's resolver
allow udp from any to 8.8.8.8 port 53

# Block SSH from the outside, but allow the admin host
deny  tcp from any       to any port 22
allow tcp from 10.0.0.5  to any port 22

# Default-deny everything else
deny any from any to any port any
```

### Common mistakes and what you'll see

| Mistake | Error message |
|---------|---------------|
| `10.0.0.5/24` (host bits set) | *"Address '10.0.0.5/24' has host bits set. Did you mean the network '10.0.0.0/24' or the single host '10.0.0.5/32'?"* |
| `port 70000` (out of range) | *"Port 70000 is out of the valid range. Ports must be between 1 and 65535 inclusive."* |
| Wrong keyword order | *"Syntax error: unexpected '…' at column N. Expected format: …"* |

---

## CAN Gateway Rules (Vehicle Bus)

FireScript includes an optional module for analyzing and simulating gateway filter rules on vehicle Controller Area Network (CAN) buses.

> ⚠️ **IMPORTANT DISCLAIMER:**
> This module is a **simplified software-based simulation** for compiler and automated processing education. It is **purely an in-memory model and is NOT connected to real vehicles, physical CAN buses, OBD-II ports, or automotive Electronic Control Units (ECUs)**.

### CAN Rule Syntax

Each CAN rule occupies one line:

```
<action> can from bus <source> to bus <destination> id <hex|a-b|any>
```

| Field | Values | Example |
|---|---|---|
| `action` | `allow` \| `deny` | `deny` |
| `from bus` | Bus name identifier or `any` | `infotainment`, `any` |
| `to bus` | Bus name identifier or `any` | `powertrain`, `chassis` |
| `id` | Hex ID, `start-end` range, or `any` | `0x120`, `0x100-0x1FF`, `any` |

- Standard 11-bit CAN identifiers span **0x000 to 0x7FF** (0 to 2047 decimal).
- `any` bus matches every bus; `any` id covers 0x000 to 0x7FF.
- Bus names must start with a letter and contain letters, numbers, underscores, or hyphens.
- Rules are case-insensitive (`ALLOW CAN FROM BUS ...` works identically).

### CAN Example Rules

```fs
# Block infotainment from sending commands to powertrain IDs 0x100-0x1FF
deny  can from bus infotainment to bus powertrain id 0x100-0x1FF

# Explicitly permit high-priority diagnostics from OBD to any bus
allow can from bus obd          to bus any        id 0x7DF

# Permit display telemetry
allow can from bus infotainment to bus display    id 0x200-0x2FF

# Default policy: block everything else
deny  can from bus any          to bus any        id any
```

---

## Running the UI

```bash
# From inside firescript/
streamlit run app.py
```

Open **http://localhost:8501** in your browser.

### UI sections

| # | Section | What it does |
|---|---------|--------------|
| **①** | Rule Editor & Analyzer | Edit rules, click **Analyze rules** to see findings |
| **②** | Import from iptables | Convert `iptables -S` / `iptables-save` output, choose chain, view warnings |
| **③** | Test a Packet | Fill protocol / IPs / port, click **Simulate packet** |
| **④** | Load a file (sidebar) | Upload a `.fs` rules file to replace the editor content |

### Manual check: Importing from iptables

To verify the iptables import feature in the Streamlit UI:

1. Launch the UI: `streamlit run app.py`
2. Click the **"📥 Import from iptables"** expander above the editor.
3. Select chain **INPUT** (default).
4. Either:
   - Upload `sample_iptables.txt` using the file uploader, or
   - Paste output from your own system (`sudo iptables -S`).
5. Click **"📥 Import"**:
   - You will see the summary: **`converted 6 rules, skipped 3 rules`**.
   - Below it, a **yellow warning box** lists why specific rules were skipped (e.g. interface `-i lo`, stateful module `-m conntrack`, custom target `-j LOGGING`).
   - The converted FireScript rules are automatically populated into the **FireScript rules** text area below.
6. Click **"🔍 Analyze rules"** to run static analysis on the converted rules:
   - Notice that FireScript identifies the conflict where rule on line 4 is shadowed by line 3 (`deny tcp from any to any port 22` overrides `allow tcp from 10.0.0.5/32 to any port 22`), and redundant rules on lines 4 and 7.
7. Test packets in **② Test a Packet** against the imported iptables policy!

---

## Running the tests

```bash
# Run all tests with verbose output
pytest -v

# Run specific test suites
pytest tests/test_can_rules.py -v
pytest tests/test_can_analyzer.py -v
pytest tests/test_analyzer.py -v
pytest tests/test_iptables_import.py -v
pytest tests/test_edge_cases.py -v
```

Expected output: **142 passed** (all 110 existing tests + 32 CAN gateway tests).

---

## Project layout

```
firescript/
├── app.py                  # Streamlit UI (IP firewall & CAN gateway tabs)
├── requirements.txt
├── sample_rules.fs         # Demo FireScript rule set
├── sample_iptables.txt     # Demo iptables -S dump
├── pytest.ini
├── conftest.py
│
├── firescript/             # Core Python package
│   ├── __init__.py         # Public API exports
│   ├── models.py           # Stage 1 – Rule dataclass
│   ├── parser.py           # Stage 1 – Lark grammar + parse_rules()
│   ├── analyzer.py         # Stage 2 – analyze() + Finding dataclass
│   ├── simulator.py        # Stage 3 – test_packet() + PacketResult
│   ├── iptables_import.py  # Stage 5 – import_iptables() converter
│   ├── can_rules.py        # CAN – CanRule AST, parser & test_message()
│   └── can_analyzer.py     # CAN – analyze_can() & CanFinding
│
├── tests/
│   ├── test_parser.py          # 12 parser tests
│   ├── test_analyzer.py        # 20 analyzer tests
│   ├── test_simulator.py       # 25 simulator tests
│   ├── test_edge_cases.py      # 31 boundary & integration tests
│   ├── test_iptables_import.py # 22 iptables conversion tests
│   ├── test_can_rules.py       # 18 CAN parsing, validation & simulator tests
│   └── test_can_analyzer.py    # 14 CAN conflict analyzer tests
│
└── docs/
    └── REPORT_NOTES.md     # Problem statement, architecture, viva Q&A
```

---

## Feature overview

### Stage 1 – Parser
- LALR grammar written in [Lark](https://lark-parser.readthedocs.io/).
- One-error-per-line reporting: a bad line is skipped; good lines still parse.
- Converts `any` to canonical IPv4 representations.
- Accepts bare host IPs (auto-promotes to `/32`).

### Stage 2 – Analyzer
Compares every rule against all earlier rules and classifies interactions:

| Finding | Meaning |
|---------|---------|
| 🔴 **SHADOWED** | An earlier rule covers this one with a *different* action — this rule never runs |
| 🟠 **REDUNDANT** | An earlier rule covers this one with the *same* action — safe but wasteful |
| 🟣 **CONTRADICTION** | Two rules overlap but neither covers the other, and they have different actions — order determines the winner |
| 🔵 **GENERALIZATION** | A later rule is broader than an earlier one with a different action — usually intentional (e.g. specific exception followed by default) |

### Stage 3 – Simulator
- `test_packet(rules, protocol, src_ip, dst_ip, port)` walks rules top-to-bottom.
- Returns the **first** matching rule and its action.
- If nothing matches, applies the **default deny** policy.
- Also returns every *later* rule that would also have matched (the hidden rules).
- Validates all inputs and raises `PacketError` with clear messages.

### Stage 4 – Streamlit UI
- Live rule editing with pre-loaded sample.
- Summary metrics strip and colour-coded findings table.
- Packet simulator form with verdict banner and hidden-rules expander.
- Sidebar file uploader for `.fs` files.
- Integrated **Import from iptables** with chain selector, conversion summary, and yellow warning box.
- Separate **CAN Gateway Rules** tab with editor, conflict analyzer, and message simulator.

### Stage 5 – iptables Importer
- Converts `iptables -S` and `iptables-save` rules into FireScript syntax.
- Filters by chain (default: `INPUT`).
- Skips unsupported features (conntrack, interfaces, negation, custom targets) and flags them with descriptive warnings.
- Output feeds directly into the parser, analyzer, and packet simulator.

### Optional Module – CAN Gateway Rules
- Parses rules for inter-bus CAN message routing (`allow|deny can from bus <src> to bus <dst> id <hex|range|any>`).
- Validates standard 11-bit CAN identifiers (`0x000` to `0x7FF`) and bus naming.
- Reuses firewall verification logic to report SHADOWED, REDUNDANT, CONTRADICTION, and GENERALIZATION on CAN buses.
- Simulates CAN message decisions with `test_message(rules, from_bus, to_bus, can_id)`.
- *Purely an educational software simulation; not connected to physical vehicles.*

---

## Screenshot walkthrough

> **To add screenshots for your viva submission:**
>
> 1. Run `streamlit run app.py`.
> 2. Open **http://localhost:8501** in Chrome or Firefox.
> 3. Use your OS screenshot tool (macOS: `⌘ Shift 4`, Windows: `Win + Shift + S`).
> 4. Suggested captures:
>    - The editor pre-loaded with `sample_rules.fs`.
>    - The **"Import from iptables"** expander open, showing conversion of `sample_iptables.txt`, the `converted 6 rules, skipped 3 rules` count, and the yellow warnings box.
>    - After clicking **Analyze rules** — showing the coloured findings table and
>      summary metrics.
>    - The **② Test a Packet** form filled in (e.g. TCP / 10.0.0.5 / 1.2.3.4 / port 22)
>      and the DENIED verdict banner.
>    - The CAN Gateway tab showing CAN rule analysis and message simulation.
> 5. Save images to `docs/screenshots/` and reference them here:
>    ```markdown
>    ![Analyzer findings table](docs/screenshots/findings_table.png)
>    ```

---

## Progress

- [x] Stage 1 — Grammar, parser, Rule model, validation errors
- [x] Stage 2 — Conflict detector (SHADOWED, REDUNDANT, CONTRADICTION, GENERALIZATION)
- [x] Stage 3 — Packet simulator with first-match + hidden-rule reporting
- [x] Stage 4 — Streamlit UI (editor, analyzer, simulator, file upload)
- [x] Stage 5 — iptables import, edge-case tests, README, REPORT_NOTES
- [x] CAN Gateway Module — CanRule parser, analyze_can, test_message, UI tab, and tests


