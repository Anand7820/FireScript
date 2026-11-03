"""Stage 4 – FireScript Streamlit UI.

Three sections:
  1. Rule editor + analyzer   (parse, show errors and findings table)
  2. Packet simulator form    (verdict, matched rule, hidden rules)
  3. File uploader            (replace the editor content with a .fs file)

All analysis is delegated to firescript.*; no logic lives here.
"""

import pathlib
import streamlit as st

from firescript import (
    parse_rules,
    analyze,
    test_packet,
    PacketError,
    import_iptables,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SAMPLE_PATH = pathlib.Path(__file__).parent / "sample_rules.fs"

# Badge colours (background, text) per finding kind
_KIND_STYLE: dict[str, tuple[str, str]] = {
    "SHADOWED":       ("#d62728", "#ffffff"),   # red
    "REDUNDANT":      ("#ff7f0e", "#000000"),   # orange
    "CONTRADICTION":  ("#9467bd", "#ffffff"),   # purple
    "GENERALIZATION": ("#1f77b4", "#ffffff"),   # blue (info)
}

_ACTION_STYLE: dict[str, tuple[str, str]] = {
    "allow": ("#2ca02c", "#ffffff"),
    "deny":  ("#d62728", "#ffffff"),
}

# ---------------------------------------------------------------------------
# Tiny HTML helpers (keep all styling inline so no extra CSS files needed)
# ---------------------------------------------------------------------------

def _badge(text: str, bg: str, fg: str) -> str:
    """Return an inline HTML badge span."""
    style = (
        f"background:{bg};color:{fg};padding:2px 8px;"
        "border-radius:4px;font-weight:bold;font-size:0.85em;"
    )
    return f'<span style="{style}">{text}</span>'


def _kind_badge(kind: str) -> str:
    bg, fg = _KIND_STYLE.get(kind, ("#888", "#fff"))
    return _badge(kind, bg, fg)


def _action_badge(action: str) -> str:
    bg, fg = _ACTION_STYLE.get(action, ("#888", "#fff"))
    return _badge(action.upper(), bg, fg)


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="FireScript Analyzer",
    page_icon="🔥",
    layout="wide",
)

st.title("🔥 FireScript – Firewall Rule Analyzer")
st.caption(
    "Write firewall rules, detect conflicts, and simulate packets — "
    "purely in software without touching real hardware or networks."
)

# ---------------------------------------------------------------------------
# Session-state: keep the rule text between interactions
# ---------------------------------------------------------------------------

if "rule_text" not in st.session_state:
    try:
        st.session_state.rule_text = _SAMPLE_PATH.read_text()
    except FileNotFoundError:
        st.session_state.rule_text = "# Write your FireScript rules here\n"
    st.session_state.editor = st.session_state.rule_text

# ---------------------------------------------------------------------------
# Section 3 – File upload (top sidebar so it sets text before the editor)
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("📂 Load a rules file")
    uploaded = st.file_uploader("Upload a .fs file", type=["fs", "txt"], key="fs_file_uploader")
    if uploaded is not None:
        file_sig = f"{uploaded.name}_{uploaded.size}"
        if st.session_state.get("_loaded_file_sig") != file_sig:
            st.session_state._loaded_file_sig = file_sig
            content = uploaded.getvalue().decode("utf-8", errors="replace")
            st.session_state.editor = content
            st.session_state.rule_text = content
            st.session_state.pop("import_result", None)
            st.rerun()
        st.success(f"Loaded **{uploaded.name}** ({len(st.session_state.get('editor', '').splitlines())} lines)")
    else:
        st.session_state.pop("_loaded_file_sig", None)

    st.divider()
    st.markdown(
        "**Rule format**\n"
        "```\n"
        "allow tcp from 10.0.0.0/24 to any port 80\n"
        "deny  any from any to any  port any\n"
        "```\n"
        "`#` starts a comment."
    )

# ---------------------------------------------------------------------------
# Section 1 – Rule Editor & Analyzer
# ---------------------------------------------------------------------------

st.header("① Rule Editor & Analyzer")

# ---- Import from iptables expander ----
with st.expander("📥 Import from iptables (`iptables -S` / `iptables-save`)", expanded=("import_result" in st.session_state)):
    st.caption("Convert rules from `iptables -S` or `iptables-save` into FireScript syntax.")
    col_chain, col_upload = st.columns([1, 2])
    with col_chain:
        chain_choice = st.selectbox(
            "Chain",
            ["INPUT", "FORWARD", "OUTPUT", "Custom..."],
            index=0,
            help="Select the iptables chain to convert (default: INPUT)",
        )
        if chain_choice == "Custom...":
            chain = st.text_input("Custom chain name", value="INPUT")
        else:
            chain = chain_choice

    with col_upload:
        ipt_file = st.file_uploader(
            "Upload iptables dump file",
            type=["txt", "rules", "save", "dump", "log"],
            key="iptables_file_upload",
            help="Upload output from iptables -S or iptables-save",
        )

    file_text = ""
    if ipt_file is not None:
        file_text = ipt_file.read().decode("utf-8", errors="replace")

    ipt_text = st.text_area(
        label="`iptables -S` or `iptables-save` output",
        value=file_text if file_text else st.session_state.get("ipt_text_val", ""),
        height=140,
        key="ipt_text_val",
        placeholder="-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp --dport 80 -j ACCEPT\n-A INPUT -j DROP",
        help="Paste the raw output of `iptables -S` or `iptables-save` here.",
    )

    col_btn, col_clear = st.columns([1, 4])
    with col_btn:
        import_clicked = st.button("📥 Import", type="primary", key="btn_import_iptables")
    with col_clear:
        if "import_result" in st.session_state:
            if st.button("✕ Dismiss import status", key="btn_clear_import"):
                st.session_state.pop("import_result", None)
                st.rerun()

    if import_clicked:
        raw_to_convert = ipt_text.strip() or file_text.strip()
        if not raw_to_convert:
            st.warning("Please paste iptables output or upload a file first.")
        else:
            result = import_iptables(raw_to_convert, chain=chain)
            st.session_state.rule_text = result.text
            st.session_state.editor = result.text
            st.session_state.import_result = result
            st.rerun()

    if "import_result" in st.session_state:
        res = st.session_state.import_result
        st.markdown(f"**converted {res.converted} rules, skipped {res.skipped} rules**")
        if res.warnings:
            st.warning("\n\n".join(f"• {w}" for w in res.warnings))

col_editor, col_numbered = st.columns([1, 1])

with col_editor:
    st.markdown("##### ✏️ FireScript Rules (Editor)")
    rule_text: str = st.text_area(
        label="FireScript rules editor",
        height=320,
        key="editor",
        label_visibility="collapsed",
        help="One rule per line. '#' starts a comment.",
    )
    # Keep session state in sync with the widget
    st.session_state.rule_text = rule_text

with col_numbered:
    st.markdown("##### 🔢 Rules with Line Numbers (Inspector)")
    with st.container(height=320):
        st.code(
            rule_text if rule_text.strip() else "# No rules in editor",
            language="bash",
            line_numbers=True,
        )

analyze_clicked = st.button("🔍 Analyze rules", type="primary")

if analyze_clicked or True:
    # Always parse so the packet simulator can use the rules live.
    parse_result = parse_rules(rule_text)

    # ---- Syntax errors ----
    if parse_result.errors:
        st.subheader("⛔ Syntax errors")
        for err in parse_result.errors:
            st.markdown(
                f'<p style="color:#d62728;margin:2px 0">'
                f'<b>Line {err.line}:</b> {err.message}</p>',
                unsafe_allow_html=True,
            )

    rules = parse_result.rules

    if not rules:
        if analyze_clicked:
            st.info("No valid rules to analyze.")
    else:
        findings = analyze(rules)

        if analyze_clicked:
            # ---- Summary counts ----
            counts: dict[str, int] = {}
            for f in findings:
                counts[f.kind] = counts.get(f.kind, 0) + 1

            cols = st.columns(len(_KIND_STYLE) + 1)
            cols[0].metric("✅ Valid rules", len(rules))
            for idx, kind in enumerate(["SHADOWED", "REDUNDANT", "CONTRADICTION", "GENERALIZATION"]):
                n = counts.get(kind, 0)
                cols[idx + 1].metric(kind.capitalize(), n)

            st.divider()

            if not findings:
                st.success("✅ No conflicts or redundancies found.")
            else:
                st.subheader(f"📋 Findings ({len(findings)} total)")

                # Build table rows as HTML for coloured badges
                rows_html = ""
                for f in findings:
                    kind_cell   = _kind_badge(f.kind)
                    rule_cell   = f"<td style='text-align:center;padding:8px 10px'>{f.rule_line}</td>"
                    other_cell  = f"<td style='text-align:center;padding:8px 10px'>{f.other_line}</td>"
                    expl_cell   = f"<td style='padding:8px 10px'>{f.explanation}</td>"

                    rows_html += (
                        f"<tr style='border-bottom:1px solid rgba(128,128,128,0.2)'>"
                        f"<td style='padding:8px 10px'>{kind_cell}</td>"
                        f"{rule_cell}"
                        f"{other_cell}"
                        f"{expl_cell}"
                        f"</tr>"
                    )

                table_html = f"""
                <table style="width:100%;border-collapse:collapse;font-size:0.9em">
                  <thead>
                    <tr style="background:rgba(128, 128, 128, 0.2);text-align:left;border-bottom:2px solid rgba(128, 128, 128, 0.3)">
                      <th style="padding:8px 10px;color:inherit">Kind</th>
                      <th style="padding:8px 10px;text-align:center;color:inherit">Rule line</th>
                      <th style="padding:8px 10px;text-align:center;color:inherit">Conflicts with</th>
                      <th style="padding:8px 10px;color:inherit">Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows_html}
                  </tbody>
                </table>
                """
                st.markdown(table_html, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Section 2 – Packet simulator
# ---------------------------------------------------------------------------

st.divider()
st.header("② Test a Packet")

with st.form("packet_form"):
    c1, c2, c3, c4 = st.columns(4)
    proto  = c1.selectbox("Protocol",     ["tcp", "udp", "icmp"])
    src_ip = c2.text_input("Source IP",   placeholder="e.g. 10.0.0.5")
    dst_ip = c3.text_input("Destination IP", placeholder="e.g. 8.8.8.8")
    port   = c4.number_input("Port", min_value=1, max_value=65535, value=80, step=1)

    submitted = st.form_submit_button("▶ Simulate packet", type="primary")

if submitted:
    if not src_ip.strip() or not dst_ip.strip():
        st.warning("Please enter both source and destination IP addresses.")
    else:
        # Re-parse the current text to get up-to-date rules
        sim_result_parse = parse_rules(st.session_state.rule_text)
        sim_rules = sim_result_parse.rules

        try:
            result = test_packet(sim_rules, proto, src_ip.strip(), dst_ip.strip(), int(port))

            # ---- Verdict banner ----
            bg, fg = _ACTION_STYLE[result.action]
            icon = "✅" if result.action == "allow" else "🚫"
            st.markdown(
                f'<div style="background:{bg};color:{fg};padding:12px 18px;'
                f'border-radius:6px;font-size:1.2em;font-weight:bold;">'
                f'{icon} &nbsp; Packet {result.action.upper()}ED</div>',
                unsafe_allow_html=True,
            )
            st.write("")

            # ---- Matched rule ----
            if result.matched_rule:
                st.markdown(
                    f"**Matched rule — Line {result.matched_rule.line}:** "
                    f"`{result.matched_rule.text}`"
                )
            else:
                st.markdown("**No rule matched** — default policy applied.")

            # ---- Reason ----
            st.caption(result.reason)

            # ---- Hidden rules ----
            if result.also_matched:
                with st.expander(
                    f"⚠️ {len(result.also_matched)} hidden rule(s) would also have matched"
                ):
                    for r in result.also_matched:
                        st.markdown(f"- **Line {r.line}:** `{r.text}`")

        except PacketError as exc:
            st.error(f"Invalid packet description: {exc}")


