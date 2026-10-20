"""
app.py
------
ContractGuard — Single-Page Streamlit Cybersecurity UI for Smart Contract
Vulnerability Detection, Classification, and Security Recommendations.

Launch command:
    streamlit run app.py
"""

import re
import streamlit as st

from predict import analyze_solidity_contract

# Configure single-page layout (no sidebar navigation)
st.set_page_config(
    page_title="ContractGuard | Smart Contract Security Analyzer",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Custom CSS: Deep Navy SaaS Cybersecurity Theme Matching Reference Design
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    /* Hide default Streamlit chrome, header, menu, and footer */
    #MainMenu {visibility: hidden;}
    header[data-testid="stHeader"] {display: none;}
    footer {display: none;}
    div[data-testid="stToolbar"] {display: none;}
    section[data-testid="stSidebar"] {display: none;}

    /* App background and base typography */
    .stApp {
        background-color: #0B1220;
        color: #F8FAFC;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }

    .block-container {
        max-width: 880px !important;
        padding-top: 1.8rem !important;
        padding-bottom: 1.8rem !important;
    }

    /* 1. Navigation Header */
    .cg-navbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 1.15rem;
        margin-bottom: 1.8rem;
        border-bottom: 1px solid #1E293B;
    }
    .cg-brand-wrap {
        display: flex;
        align-items: center;
        gap: 0.85rem;
    }
    .cg-shield-box {
        width: 42px;
        height: 42px;
        border-radius: 10px;
        background: rgba(59, 130, 246, 0.12);
        border: 1px solid rgba(59, 130, 246, 0.28);
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
    }
    .cg-brand-title {
        font-size: 1.25rem;
        font-weight: 700;
        color: #F8FAFC;
        line-height: 1.2;
        letter-spacing: -0.01em;
    }
    .cg-brand-sub {
        font-size: 0.80rem;
        color: #CBD5E1;
        margin-top: 0.12rem;
    }
    .cg-status-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        background: rgba(16, 185, 129, 0.12);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.28);
        padding: 0.35rem 0.85rem;
        border-radius: 999px;
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.01em;
    }
    .cg-status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background-color: #10B981;
    }

    /* 2. Hero Section */
    .cg-hero {
        margin-bottom: 1.4rem;
    }
    .cg-hero h1 {
        font-size: 1.65rem !important;
        font-weight: 700 !important;
        color: #F8FAFC !important;
        margin: 0 0 0.35rem 0 !important;
        padding: 0 !important;
        letter-spacing: -0.015em;
    }
    .cg-hero p {
        font-size: 0.95rem !important;
        color: #CBD5E1 !important;
        margin: 0 !important;
        line-height: 1.5;
    }

    /* 3. Card Containers (st.container(border=True)) */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #142238 !important;
        border: 1px solid #30415B !important;
        border-radius: 12px !important;
        padding: 1.35rem 1.5rem !important;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.35) !important;
        margin-bottom: 1.25rem !important;
    }

    .cg-card-title {
        display: flex;
        align-items: center;
        gap: 0.55rem;
        font-size: 0.98rem;
        font-weight: 600;
        color: #F8FAFC;
        margin-bottom: 0.75rem;
    }

    /* Pill-style Streamlit Tabs (Ensure selected & unselected tab labels are readable) */
    div[data-testid="stTabs"] button[data-baseweb="tab"],
    div[data-testid="stTabs"] button[data-baseweb="tab"] p,
    div[data-testid="stTabs"] button[data-baseweb="tab"] span,
    div[data-testid="stTabs"] button[data-baseweb="tab"] div {
        background-color: transparent !important;
        color: #CBD5E1 !important;
        font-size: 0.88rem !important;
        font-weight: 600 !important;
    }
    div[data-testid="stTabs"] button[data-baseweb="tab"] {
        border-radius: 8px !important;
        padding: 0.45rem 1rem !important;
        border: 1px solid transparent !important;
        margin-right: 0.4rem !important;
        transition: all 0.18s ease !important;
    }
    div[data-testid="stTabs"] button[data-baseweb="tab"]:hover,
    div[data-testid="stTabs"] button[data-baseweb="tab"]:hover p,
    div[data-testid="stTabs"] button[data-baseweb="tab"]:hover span,
    div[data-testid="stTabs"] button[data-baseweb="tab"]:hover div {
        color: #F8FAFC !important;
    }
    div[data-testid="stTabs"] button[data-baseweb="tab"]:hover {
        background-color: rgba(59, 130, 246, 0.08) !important;
    }
    div[data-testid="stTabs"] button[data-baseweb="tab"][aria-selected="true"] {
        background-color: rgba(59, 130, 246, 0.18) !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(59, 130, 246, 0.42) !important;
    }
    div[data-testid="stTabs"] button[data-baseweb="tab"][aria-selected="true"] p,
    div[data-testid="stTabs"] button[data-baseweb="tab"][aria-selected="true"] span,
    div[data-testid="stTabs"] button[data-baseweb="tab"][aria-selected="true"] div {
        color: #F8FAFC !important;
    }
    div[data-testid="stTabs"] div[data-baseweb="tab-highlight"] {
        display: none !important;
    }
    div[data-testid="stTabs"] div[data-baseweb="tab-border"] {
        background-color: #24344D !important;
        height: 1px !important;
    }

    /* Styled Drag-and-Drop File Uploader & All Internal Text Contrast */
    div[data-testid="stFileUploader"] label,
    div[data-testid="stFileUploader"] label p,
    div[data-testid="stFileUploader"] [data-testid="stWidgetLabel"] p {
        color: #CBD5E1 !important;
        font-size: 0.86rem !important;
        font-weight: 500 !important;
    }
    div[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"] {
        background-color: #0E192D !important;
        border: 1.5px dashed #30415B !important;
        border-radius: 10px !important;
        padding: 1.8rem 1.2rem !important;
        transition: border-color 0.2s ease, background-color 0.2s ease !important;
    }
    div[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"]:hover {
        border-color: #3B82F6 !important;
        background-color: #111F38 !important;
    }
    div[data-testid="stFileUploader"] [data-testid="stFileUploaderDropzoneInstructions"],
    div[data-testid="stFileUploader"] [data-testid="stFileUploaderDropzoneInstructions"] span,
    div[data-testid="stFileUploader"] [data-testid="stFileUploaderDropzoneInstructions"] div,
    div[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"] span,
    div[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"] p {
        color: #CBD5E1 !important;
    }
    div[data-testid="stFileUploader"] [data-testid="stFileUploaderDropzoneInstructions"] small,
    div[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"] small {
        color: #CBD5E1 !important;
        opacity: 0.9 !important;
    }
    div[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"] svg {
        fill: #CBD5E1 !important;
        color: #CBD5E1 !important;
    }
    div[data-testid="stFileUploader"] button,
    div[data-testid="stFileUploader"] button span,
    div[data-testid="stFileUploader"] button p {
        background-color: #1E293B !important;
        color: #F8FAFC !important;
        border: 1px solid #30415B !important;
        border-radius: 6px !important;
    }

    /* Uploaded File Row: Filename, File Size, and Delete Icon Contrast */
    div[data-testid="stFileUploaderFile"],
    div[data-testid="stFileUploader"] ul li {
        background-color: rgba(30, 41, 59, 0.85) !important;
        border: 1px solid #30415B !important;
        border-radius: 8px !important;
        padding: 0.35rem 0.65rem !important;
    }
    div[data-testid="stFileUploaderFileName"],
    div[data-testid="stFileUploaderFile"] [data-testid="stFileUploaderFileName"],
    div[data-testid="stFileUploader"] [data-testid="stFileUploaderFile"] span,
    div[data-testid="stFileUploader"] [data-testid="stFileUploaderFile"] div {
        color: #F8FAFC !important;
        font-weight: 600 !important;
    }
    div[data-testid="stFileUploaderFile"] small,
    div[data-testid="stFileUploader"] ul li small,
    div[data-testid="stFileUploaderFileData"] small {
        color: #CBD5E1 !important;
        font-size: 0.80rem !important;
        font-weight: 500 !important;
    }
    div[data-testid="stFileUploaderFile"] svg,
    div[data-testid="stFileUploaderDeleteBtn"] svg,
    div[data-testid="stFileUploaderDeleteBtn"] button {
        color: #CBD5E1 !important;
        fill: #CBD5E1 !important;
        background: transparent !important;
        border: none !important;
    }

    /* Selected File Pill */
    .cg-file-selected {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        background-color: rgba(59, 130, 246, 0.14);
        border: 1px solid rgba(59, 130, 246, 0.36);
        color: #CBD5E1 !important;
        padding: 0.4rem 0.85rem;
        border-radius: 8px;
        font-size: 0.83rem;
        font-weight: 500;
        margin-top: 0.45rem;
    }
    .cg-file-selected strong {
        color: #F8FAFC !important;
        font-weight: 600;
    }

    /* Dark Code Editor Textarea */
    div[data-testid="stTextArea"] textarea {
        background-color: #0E192D !important;
        color: #F8FAFC !important;
        border: 1px solid #30415B !important;
        border-radius: 10px !important;
        font-family: 'JetBrains Mono', 'Consolas', monospace !important;
        font-size: 0.86rem !important;
        line-height: 1.55 !important;
        padding: 0.85rem !important;
    }
    div[data-testid="stTextArea"] textarea::placeholder {
        color: #CBD5E1 !important;
        opacity: 0.65 !important;
    }
    div[data-testid="stTextArea"] textarea:focus {
        border-color: #3B82F6 !important;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.22) !important;
    }
    div[data-testid="stTextArea"] label,
    div[data-testid="stTextArea"] label p,
    div[data-testid="stTextArea"] [data-testid="stWidgetLabel"] p {
        color: #CBD5E1 !important;
        font-size: 0.83rem !important;
    }

    /* Prominent Electric-Blue Analyze Button */
    div[data-testid="stButton"] > button[kind="primary"] {
        background: linear-gradient(180deg, #3B82F6 0%, #2563EB 100%) !important;
        color: #FFFFFF !important;
        border: 1px solid #60A5FA !important;
        border-radius: 8px !important;
        padding: 0.68rem 1.4rem !important;
        font-size: 0.95rem !important;
        font-weight: 600 !important;
        width: 100% !important;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.32) !important;
        transition: all 0.18s ease !important;
        margin-top: 0.35rem !important;
    }
    div[data-testid="stButton"] > button[kind="primary"]:hover {
        background: linear-gradient(180deg, #60A5FA 0%, #2563EB 100%) !important;
        box-shadow: 0 6px 18px rgba(59, 130, 246, 0.42) !important;
        transform: translateY(-1px);
    }

    /* 4. Security Analysis Section Header */
    .cg-section-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin: 1.6rem 0 0.75rem 0;
    }
    .cg-section-title {
        font-size: 1.08rem;
        font-weight: 600;
        color: #F8FAFC;
    }
    .cg-badge-red {
        background-color: rgba(239, 68, 68, 0.14);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.32);
        padding: 0.25rem 0.75rem;
        border-radius: 999px;
        font-size: 0.76rem;
        font-weight: 600;
    }
    .cg-badge-green {
        background-color: rgba(16, 185, 129, 0.14);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.32);
        padding: 0.25rem 0.75rem;
        border-radius: 999px;
        font-size: 0.76rem;
        font-weight: 600;
    }

    /* Security Result Banner Card */
    .cg-result-card-vuln {
        background: linear-gradient(180deg, rgba(20, 34, 56, 0.98) 0%, rgba(28, 25, 43, 0.85) 100%);
        border: 1px solid rgba(248, 113, 113, 0.38);
        border-left: 4px solid #F87171;
        border-radius: 12px;
        padding: 1.3rem 1.45rem;
        margin-bottom: 1.15rem;
    }
    .cg-result-card-safe {
        background: linear-gradient(180deg, rgba(20, 34, 56, 0.98) 0%, rgba(16, 42, 45, 0.85) 100%);
        border: 1px solid rgba(52, 211, 153, 0.38);
        border-left: 4px solid #34D399;
        border-radius: 12px;
        padding: 1.3rem 1.45rem;
        margin-bottom: 1.15rem;
    }
    .cg-status-heading-vuln {
        display: flex;
        align-items: center;
        gap: 0.55rem;
        color: #F87171;
        font-size: 1.05rem;
        font-weight: 600;
        margin-bottom: 0.45rem;
    }
    .cg-status-heading-safe {
        display: flex;
        align-items: center;
        gap: 0.55rem;
        color: #34D399;
        font-size: 1.05rem;
        font-weight: 600;
        margin-bottom: 0.45rem;
    }
    .cg-vuln-category-line {
        font-size: 1.02rem;
        font-weight: 600;
        color: #F8FAFC;
        margin-bottom: 0.4rem;
    }
    .cg-meta-line {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 0.65rem;
        font-size: 0.83rem;
        color: #CBD5E1;
        margin-top: 0.35rem;
    }
    .cg-source-split-box {
        display: flex;
        flex-wrap: wrap;
        gap: 0.65rem;
        margin-top: 0.85rem;
        padding-top: 0.75rem;
        border-top: 1px solid rgba(148, 163, 184, 0.16);
        font-size: 0.80rem;
        color: #CBD5E1;
    }
    .cg-source-chip {
        background-color: rgba(15, 23, 42, 0.65);
        border: 1px solid #30415B;
        border-radius: 6px;
        padding: 0.3rem 0.65rem;
    }

    /* Tab Content Typography */
    .cg-tab-heading {
        font-size: 0.98rem;
        font-weight: 600;
        color: #F8FAFC;
        margin: 0.65rem 0 0.35rem 0;
    }
    .cg-tab-text {
        font-size: 0.90rem;
        color: #CBD5E1;
        line-height: 1.6;
        margin-bottom: 0.85rem;
        overflow-wrap: break-word;
    }

    /* Code blocks */
    div[data-testid="stCodeBlock"] pre {
        background-color: #0B1220 !important;
        border: 1px solid #30415B !important;
        border-radius: 8px !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def _strip_markdown_bold(text: str) -> str:
    """Clean markdown bold markers when rendering inside structured HTML blocks."""
    return re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", str(text))


def _build_corrected_solidity_preview(source_code: str, verified_mistakes: list) -> str:
    """
    Build a helpful corrected Solidity snippet when a verified rule-based pattern
    has a known direct transformation (such as adding require(msg.sender == owner)
    to changeOwner() or replacing tx.origin with msg.sender).
    """
    if not verified_mistakes:
        return ""

    pattern_names = [m.get("pattern_name", "") for m in verified_mistakes]

    # Case 1: Missing Owner Authorization in changeOwner()
    if any("changeOwner" in p for p in pattern_names):
        m = next(item for item in verified_mistakes if "changeOwner" in item.get("pattern_name", ""))
        raw_snippet = m.get("code_line", "")
        clean_lines = [
            re.sub(r"^Line\s+\d+:\s?", "", ln)
            for ln in raw_snippet.splitlines()
        ]
        fixed_lines = []
        inserted = False
        for ln in clean_lines:
            fixed_lines.append(ln)
            if not inserted and "function changeOwner" in ln and "{" in ln:
                fixed_lines.append('        require(msg.sender == owner, "Only owner can change owner");')
                inserted = True
        return "\n".join(fixed_lines)

    # Case 2: tx.origin authentication
    if any("tx.origin" in p for p in pattern_names):
        m = next(item for item in verified_mistakes if "tx.origin" in item.get("pattern_name", ""))
        raw_line = re.sub(r"^Line\s+\d+:\s?", "", m.get("code_line", ""))
        return raw_line.replace("tx.origin", "msg.sender")

    # Case 3: External Value Call (Reentrancy)
    if any("External Value Call" in p for p in pattern_names):
        return (
            "// Update user balance BEFORE external value transfer (Checks-Effects-Interactions)\n"
            "uint256 amount = balances[msg.sender];\n"
            "require(amount > 0, \"Insufficient balance\");\n"
            "balances[msg.sender] = 0;\n"
            "(bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "require(success, \"ETH transfer failed\");"
        )

    # Case 4: Unchecked .send() or .call()
    if any("Unchecked .send()" in p for p in pattern_names):
        return (
            "(bool success, ) = recipient.call{value: amount}(\"\");\n"
            "require(success, \"Transfer failed\");"
        )

    return ""


# ---------------------------------------------------------------------------
# 1. Header
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="cg-navbar">
        <div class="cg-brand-wrap">
            <div class="cg-shield-box">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="m9 12 2 2 4-4"/>
                </svg>
            </div>
            <div>
                <div class="cg-brand-title">ContractGuard</div>
                <div class="cg-brand-sub">Smart Contract Security Analyzer</div>
            </div>
        </div>
        <div class="cg-status-pill">
            <span class="cg-status-dot"></span>
            Analyzer Ready
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# 2. Hero Section
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="cg-hero">
        <h1>Analyze Your Smart Contract</h1>
        <p>Detect potential Solidity vulnerabilities, understand security risks, and discover recommended fixes.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = None
if "analyzed_source_code" not in st.session_state:
    st.session_state["analyzed_source_code"] = ""
if "analyzed_contract_name" not in st.session_state:
    st.session_state["analyzed_contract_name"] = ""
if "pasted_solidity_code" not in st.session_state:
    st.session_state["pasted_solidity_code"] = ""

# ---------------------------------------------------------------------------
# 3. Contract Upload Section (Card with Two Interactive Tabs)
# ---------------------------------------------------------------------------
with st.container(border=True):
    st.markdown(
        """
        <div class="cg-card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="16 18 22 12 16 6"></polyline>
                <polyline points="8 6 2 12 8 18"></polyline>
            </svg>
            Contract Input
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_upload, tab_paste = st.tabs(["Upload Solidity File", "Paste Solidity Code"])

    with tab_upload:
        uploaded_file = st.file_uploader(
            "Drop your Solidity file here (Supports .sol files)",
            type=["sol"],
            key="solidity_file_uploader",
        )
        if uploaded_file is not None:
            st.markdown(
                f"""
                <div class="cg-file-selected">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#60A5FA" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                    </svg>
                    Selected file: <strong>{uploaded_file.name}</strong>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with tab_paste:
        pasted_code = st.text_area(
            "Solidity Source Code Editor",
            key="pasted_solidity_code",
            height=220,
            placeholder="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\ncontract Example {\n    // Paste your Solidity contract code here...\n}",
        )

    analyze_clicked = st.button("Analyze Contract", type="primary", use_container_width=True)

# ---------------------------------------------------------------------------
# Handle Analysis Trigger (Connected to Existing Backend Pipeline)
# ---------------------------------------------------------------------------
if analyze_clicked:
    # Prioritize pasted code if non-empty and no file uploaded, or uploaded file if present
    active_code = ""
    active_name = "SmartContract.sol"

    if uploaded_file is not None:
        active_name = uploaded_file.name
        active_code = uploaded_file.getvalue().decode("utf-8", errors="replace")
    elif pasted_code and pasted_code.strip():
        active_name = "PastedContract.sol"
        active_code = pasted_code

    with st.spinner("Running security analysis..."):
        st.session_state["analysis_result"] = analyze_solidity_contract(active_code)
        st.session_state["analyzed_source_code"] = active_code
        st.session_state["analyzed_contract_name"] = active_name

# ---------------------------------------------------------------------------
# 4. Security Result & 5. Interactive Results Tabs
# ---------------------------------------------------------------------------
result = st.session_state.get("analysis_result")

if result is not None:
    if result.get("error"):
        st.error(result["error"])
    else:
        is_vuln = result["is_vulnerable"]
        verified_mistakes = result.get("verified_mistakes", [])
        vuln_types = result.get("vulnerability_types", ["None Detected"])
        contract_label = st.session_state.get("analyzed_contract_name", "SmartContract.sol")

        # Section header above result card
        badge_html = (
            f'<span class="cg-badge-red">{contract_label} &bull; Action Recommended</span>'
            if is_vuln
            else f'<span class="cg-badge-green">{contract_label} &bull; Passed Checks</span>'
        )
        st.markdown(
            f"""
            <div class="cg-section-bar">
                <div class="cg-section-title">Security Analysis</div>
                {badge_html}
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Build headline & location metadata from backend result
        if is_vuln:
            primary_cat = ", ".join(vuln_types)
            if verified_mistakes:
                first_m = verified_mistakes[0]
                target_line = first_m.get("assignment_line") or first_m.get("line_number")
                headline_text = f"{primary_cat} &mdash; {first_m.get('pattern_name', 'Verified Pattern')}"
                source_tag = (
                    f"Line {target_line} &bull; Rule-based &amp; ML finding"
                    if result.get("ml_is_vulnerable")
                    else f"Line {target_line} &bull; Rule-based finding"
                )
            else:
                headline_text = f"{primary_cat} &mdash; Lexical Risk Signal"
                source_tag = "Contract-level &bull; ML model finding"

            # Disagreement / dual-source transparency bar
            st.markdown(
                f"""
                <div class="cg-result-card-vuln">
                    <div class="cg-status-heading-vuln">
                        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="#F87171" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        Potential Vulnerability Detected
                    </div>
                    <div class="cg-vuln-category-line">{headline_text}</div>
                    <div class="cg-meta-line">
                        <span>&#9679; {source_tag}</span>
                    </div>
                    <div class="cg-source-split-box">
                        <span class="cg-source-chip"><strong>ML Detector (Linear SVM):</strong> {result['ml_binary_prediction']} (score: {result['svm_decision_score']:+.4f}, conf: {result['svm_confidence_pct']:.1f}%)</span>
                        <span class="cg-source-chip"><strong>Rule-Based Check:</strong> {result['rule_based_status']}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="cg-result-card-safe">
                    <div class="cg-status-heading-safe">
                        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="#34D399" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        No Vulnerability Detected
                    </div>
                    <div class="cg-vuln-category-line">No Known Vulnerability Patterns Flagged</div>
                    <div class="cg-meta-line">
                        <span>Neither the trained machine learning classifiers nor the rule-based code analyzer detected known security weaknesses in this contract. Automated analysis does not guarantee complete security or replace a formal manual audit.</span>
                    </div>
                    <div class="cg-source-split-box">
                        <span class="cg-source-chip"><strong>ML Detector (Linear SVM):</strong> {result['ml_binary_prediction']} (score: {result['svm_decision_score']:+.4f}, conf: {result['svm_confidence_pct']:.1f}%)</span>
                        <span class="cg-source-chip"><strong>Rule-Based Check:</strong> {result['rule_based_status']}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # -------------------------------------------------------------------
        # 5. Three Interactive Result Tabs (Explanation | Affected Code | Recommended Fix)
        # -------------------------------------------------------------------
        with st.container(border=True):
            res_tab_explain, res_tab_code, res_tab_fix = st.tabs(
                ["Explanation", "Affected Code", "Recommended Fix"]
            )

            # TAB 1: Explanation (Why flagged, Root cause, Coding mistake)
            with res_tab_explain:
                st.markdown('<div class="cg-tab-heading">Why is it vulnerable?</div>', unsafe_allow_html=True)
                for reason in result.get("why_vulnerable", []):
                    st.markdown(
                        f'<div class="cg-tab-text">{_strip_markdown_bold(reason)}</div>',
                        unsafe_allow_html=True,
                    )

                st.markdown('<div class="cg-tab-heading">Root Cause &amp; Analysis Source</div>', unsafe_allow_html=True)
                st.markdown(
                    f'<div class="cg-tab-text">{_strip_markdown_bold(result.get("mistake_summary", ""))}</div>',
                    unsafe_allow_html=True,
                )

                if verified_mistakes:
                    st.markdown('<div class="cg-tab-heading">Identified Coding Mistake(s)</div>', unsafe_allow_html=True)
                    for m in verified_mistakes:
                        st.markdown(
                            f'<div class="cg-tab-text">&bull; <strong>{m["pattern_name"]} (Line {m["line_number"]}):</strong> {m["coding_mistake"]}</div>',
                            unsafe_allow_html=True,
                        )

            # TAB 2: Affected Code (Relevant Solidity snippet & verified line numbers)
            with res_tab_code:
                if verified_mistakes:
                    st.markdown(
                        '<div class="cg-tab-heading">Verified Vulnerable Source Location(s)</div>',
                        unsafe_allow_html=True,
                    )
                    for m in verified_mistakes:
                        line_info = (
                            f"Lines {m['line_number']} (State assignment on Line {m['assignment_line']})"
                            if m.get("assignment_line") and m.get("assignment_line") != m["line_number"]
                            else f"Line {m['line_number']}"
                        )
                        st.markdown(
                            f'<div class="cg-tab-text"><strong>{m["category_name"]} &mdash; {m["pattern_name"]}</strong> ({line_info})</div>',
                            unsafe_allow_html=True,
                        )
                        st.code(m["code_line"], language="solidity")
                else:
                    st.markdown(
                        '<div class="cg-tab-heading">Contract Source Code</div>',
                        unsafe_allow_html=True,
                    )
                    if is_vuln:
                        st.markdown(
                            '<div class="cg-tab-text">Flagged by ML token statistics across the contract. No single line was isolated by rule-based checks; inspect the full contract source below:</div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            '<div class="cg-tab-text">No vulnerable code lines were flagged. Full analyzed Solidity source with line numbers:</div>',
                            unsafe_allow_html=True,
                        )
                    numbered_src = "\n".join(
                        f"Line {idx + 1}: {line}"
                        for idx, line in enumerate(st.session_state.get("analyzed_source_code", "").splitlines())
                    )
                    st.code(numbered_src, language="solidity")

            # TAB 3: Recommended Fix (How to overcome, Corrected Solidity code, Short explanation)
            with res_tab_fix:
                st.markdown('<div class="cg-tab-heading">Recommended Security Remediation</div>', unsafe_allow_html=True)
                for sol in result.get("suggested_solutions", []):
                    st.markdown(
                        f'<div class="cg-tab-text">{_strip_markdown_bold(sol)}</div>',
                        unsafe_allow_html=True,
                    )

                corrected_snippet = _build_corrected_solidity_preview(
                    st.session_state.get("analyzed_source_code", ""),
                    verified_mistakes,
                )
                if corrected_snippet:
                    st.markdown(
                        '<div class="cg-tab-heading">Suggested Corrected Solidity Code</div>',
                        unsafe_allow_html=True,
                    )
                    st.code(corrected_snippet, language="solidity")
                    st.markdown(
                        '<div class="cg-tab-text"><strong>How this fix works:</strong> Enforces explicit caller verification or safe execution ordering before modifying sensitive contract state or transferring funds. Review and unit-test before deployment.</div>',
                        unsafe_allow_html=True,
                    )
