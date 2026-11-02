# FireScript project rules

FireScript is a college PBL project (theme: Compiler, Language & Automated
Processing Systems). It is a small domain-specific language for firewall rules
plus an analyzer that finds mistakes and conflicts. It ONLY analyzes and
simulates rules. It never touches a real firewall or network.

Stack: Python 3.10+, Lark (parser), ipaddress (built-in), Streamlit (UI), pytest.
No database. No React. No extra frameworks.

Rules for you:
- Work on ONE stage at a time. Do not build features from later stages.
- Keep the code simple and readable. Student developers must explain it in a viva.
- Every function gets a short docstring in plain English.
- Keep parser, analyzer and UI in separate modules. No logic in the UI file.
- Write pytest tests for every feature, including edge cases.
- Never claim something works unless you ran the tests and showed the output.
- Do not rewrite or rename the existing Stage 1 files unless a test requires it.
- Do not add dependencies without asking.
- At the end of each stage, summarize what changed and what to test.