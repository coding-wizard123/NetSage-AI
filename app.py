"""
NetSage AI - Interactive Troubleshooting & Human Review Dashboard (app.py)
Streamlit Application for Cisco Network Engineering Troubleshooting with Human Review.
"""

import os
import sys
import json
import csv
from datetime import datetime
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Add current and src dir to python path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(ROOT_DIR)
sys.path.append(os.path.join(ROOT_DIR, "src"))

from checker import RuleChecker
from pipeline import NetSagePipeline
from utils import load_cases, validate_dataset

# ==========================================
# Page Configuration & Styling
# ==========================================
st.set_page_config(
    page_title="NetSage AI - Cisco Troubleshooting Helper",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Sleek NOC / Dark Terminal Theme
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        margin-bottom: 12px;
    }
    .metric-title {
        color: #94a3b8;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        color: #38bdf8;
        font-size: 1.9rem;
        font-weight: 700;
        margin-top: 4px;
    }
    .stCodeBlock {
        border-radius: 8px !important;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# File Paths & Data Helpers
# ==========================================
CASES_FILE = os.path.join(ROOT_DIR, "cases.csv") if os.path.exists(os.path.join(ROOT_DIR, "cases.csv")) else os.path.join(ROOT_DIR, "data", "cases.csv")
EVAL_FILE = os.path.join(ROOT_DIR, "data", "evaluation_results.json")
REVIEWS_FILE = os.path.join(ROOT_DIR, "human_reviews.csv")

def init_human_reviews_csv():
    """Ensure persistent human reviews CSV exists with proper headers."""
    if not os.path.exists(REVIEWS_FILE):
        headers = [
            "timestamp", "case_id", "symptom", "show_output",
            "ai_root_cause", "ai_confidence", "ai_osi_layer",
            "human_decision", "human_agreed", "final_root_cause",
            "final_fix_steps", "reviewer_notes"
        ]
        with open(REVIEWS_FILE, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

init_human_reviews_csv()

def save_human_review(review_data: dict):
    """Appends a review record to human_reviews.csv."""
    with open(REVIEWS_FILE, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            review_data.get("case_id", "CUSTOM"),
            review_data.get("symptom", ""),
            review_data.get("show_output", ""),
            review_data.get("ai_root_cause", ""),
            review_data.get("ai_confidence", ""),
            review_data.get("ai_osi_layer", ""),
            review_data.get("human_decision", "ACCEPTED"),
            review_data.get("human_agreed", True),
            review_data.get("final_root_cause", ""),
            review_data.get("final_fix_steps", ""),
            review_data.get("reviewer_notes", "")
        ])

@st.cache_data
def get_dataset():
    if os.path.exists(CASES_FILE):
        return load_cases(CASES_FILE)
    return []

@st.cache_data
def get_evaluation_data():
    if not os.path.exists(EVAL_FILE):
        pipeline = NetSagePipeline(CASES_FILE)
        pipeline.run_all(EVAL_FILE)
    with open(EVAL_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

cases_data = get_dataset()
eval_summary = get_evaluation_data()
records = eval_summary.get("records", [])

# ==========================================
# Sidebar Context
# ==========================================
st.sidebar.image("https://img.icons8.com/fluency/96/network-switch.png", width=64)
st.sidebar.title("NetSage AI")
st.sidebar.caption("Cisco Packet Tracer Troubleshooting Assistant")

# Optional Gemini API Key config
api_key = st.sidebar.text_input("Gemini API Key (Optional):", type="password", placeholder="Enter API Key for live LLM")
if api_key:
    os.environ["GEMINI_API_KEY"] = api_key
    st.sidebar.success("🔑 Custom API Key active")

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚙️ System Telemetry")
st.sidebar.markdown(f"**Benchmark Dataset:** `{len(cases_data)} Cases`")
st.sidebar.markdown(f"**Rule Engine:** `27 Cisco Regex Rules`")
st.sidebar.markdown(f"**HITL Review Gate:** `Active (Persistent CSV)`")

# Top Navigation Tabs
tab_troubleshoot, tab_review, tab_analytics, tab_responsible_ai, tab_dataset = st.tabs([
    "🔍 Live Troubleshooter",
    "👨‍💻 Human Review Station",
    "📊 Analytics Dashboard",
    "🛡️ Responsible AI Log",
    "📁 Dataset & Docs"
])

# ==========================================
# TAB 1: LIVE TROUBLESHOOTER
# ==========================================
with tab_troubleshoot:
    st.header("🔍 NetSage Live Diagnostic Workbench")
    st.markdown("Input symptoms, topology notes, and Cisco IOS `show` command outputs to run the hybrid deterministic + LLM diagnostic engine.")

    input_mode = st.radio("Choose Input Mode:", ["Select from Benchmark Cases (C001 - C030)", "Enter Custom Scenario"], horizontal=True)

    curr_case = {}
    if input_mode.startswith("Select"):
        case_labels = [f"{c['case_id']} - [{c['concept']}] {c['symptom'][:55]}..." for c in cases_data]
        selected_idx = st.selectbox("Select Case:", range(len(case_labels)), format_func=lambda i: case_labels[i])
        curr_case = cases_data[selected_idx]
        
        sym_input = curr_case["symptom"]
        topo_input = curr_case["topology_note"]
        show_input = curr_case["show_output"]
    else:
        sym_input = st.text_area("Symptom Description:", "PC in VLAN 10 gets IP 192.168.10.25 but cannot ping remote network 10.0.0.1")
        topo_input = st.text_input("Topology Context:", "PC default gateway is set to 192.168.20.1 on Router R1")
        show_input = st.text_area("Cisco IOS Show Output:", "PC ipconfig: 192.168.10.25/24, gateway 192.168.20.1")
        curr_case = {
            "case_id": "CUSTOM",
            "issue_type": "Custom",
            "concept": "Custom",
            "severity": "High",
            "osi_layer": "Layer 3",
            "symptom": sym_input,
            "topology_note": topo_input,
            "show_output": show_input,
            "expected_fault": "Custom Defect"
        }

    c_left, c_mid, c_right = st.columns(3)
    c_left.info(f"**Symptom:**\n{sym_input}")
    c_mid.info(f"**Topology:**\n{topo_input}")
    c_right.info(f"**Show Output:**\n`{show_input}`")

    if st.button("🚀 Run NetSage AI Diagnostic", type="primary", use_container_width=True):
        checker = RuleChecker()
        rule_res = checker.diagnose(sym_input, show_input, topo_input)
        pipeline = NetSagePipeline(CASES_FILE)
        ai_diag = pipeline.diagnose_single(curr_case)

        st.markdown("---")
        st.subheader("🧠 Diagnostic Analysis Results")

        res_c1, res_c2 = st.columns(2)

        with res_c1:
            st.markdown("#### ⚙️ 1. Deterministic Rule Checker")
            if rule_res["rule_matched"]:
                st.success(f"✅ **Rule Matched:** `{rule_res['rule_name']}`")
            else:
                st.warning("⚠️ **No Deterministic Match** (Deferred to LLM reasoning)")

            st.markdown(f"**Root Cause:** {rule_res['root_cause']}")
            st.markdown(f"**OSI Layer:** `{rule_res['osi_layer']}`")
            st.markdown(f"**Confidence:** `{rule_res['confidence'] * 100:.1f}%`")
            st.markdown(f"**Evidence:** *\"{rule_res['evidence']}\"*")
            st.markdown(f"**Verification Command:** `{rule_res['next_command']}`")

        with res_c2:
            st.markdown("#### 🤖 2. NetSage AI Diagnostic Synthesis")
            st.markdown(f"**Root Cause:** {ai_diag['root_cause']}")
            st.markdown(f"**Confidence:** `{ai_diag['confidence'] * 100:.1f}%`")
            st.progress(ai_diag['confidence'])

            if ai_diag["human_review_recommended"]:
                st.warning(f"🛡️ **HITL Warning:** {ai_diag['review_reason']}")
            else:
                st.success("✅ **High Confidence - Safe for Review**")

            st.markdown("**🔧 Prescribed Cisco IOS CLI Fix:**")
            st.code("\n".join(ai_diag["fix_steps"]), language="text")

# ==========================================
# TAB 2: HUMAN REVIEW STATION
# ==========================================
with tab_review:
    st.header("👨‍💻 Human Review Station & HITL Sign-off")
    st.markdown("Network engineers validate AI recommendations before deployment. Decisions are saved to `human_reviews.csv` for audit compliance.")

    rev_case_idx = st.selectbox(
        "Select Case for Human Review:",
        range(len(cases_data)),
        format_func=lambda i: f"{cases_data[i]['case_id']} - [{cases_data[i]['concept']}] {cases_data[i]['symptom'][:50]}..."
    )
    rev_case = cases_data[rev_case_idx]
    
    checker = RuleChecker()
    pipeline = NetSagePipeline(CASES_FILE)
    rev_ai = pipeline.diagnose_single(rev_case)
    rev_sim = pipeline.simulate_human_review(rev_ai, rev_case)

    rev_col1, rev_col2 = st.columns(2)
    with rev_col1:
        st.markdown("#### 🤖 AI Proposed Diagnosis")
        st.markdown(f"**Case ID:** `{rev_case['case_id']}`")
        st.markdown(f"**Symptom:** {rev_case['symptom']}")
        st.markdown(f"**Show Output:** `{rev_case['show_output']}`")
        st.markdown(f"**AI Root Cause:** {rev_ai['root_cause']}")
        st.markdown(f"**OSI Layer:** `{rev_ai['osi_layer']}` | **Confidence:** `{rev_ai['confidence']*100:.1f}%`")
        st.markdown("**AI Fix Commands:**")
        st.code("\n".join(rev_ai["fix_steps"]), language="text")

    with rev_col2:
        st.markdown("#### ✍️ Engineer Review Console")
        decision = st.selectbox(
            "Review Decision:",
            ["ACCEPTED (Approve AI)", "EDITED (Correct AI)", "REJECTED (Override AI)"],
            index=0 if rev_sim["human_decision"] == "APPROVED" else 1
        )
        
        final_root_cause = st.text_area(
            "Final Root Cause Description:",
            value=rev_sim["corrected_root_cause"] if decision.startswith("EDITED") else rev_ai["root_cause"]
        )
        
        final_cli = st.text_area(
            "Final Cisco IOS Remediation Commands (Line-separated):",
            value="\n".join(rev_sim.get("corrected_fix_steps", rev_ai["fix_steps"])) if decision.startswith("EDITED") else "\n".join(rev_ai["fix_steps"]),
            height=120
        )
        
        reviewer_notes = st.text_input(
            "Reviewer Engineering Notes:",
            value=rev_sim["human_reviewer_notes"]
        )

        if st.button("💾 Submit & Persist Human Review", type="primary", use_container_width=True):
            review_payload = {
                "case_id": rev_case["case_id"],
                "symptom": rev_case["symptom"],
                "show_output": rev_case["show_output"],
                "ai_root_cause": rev_ai["root_cause"],
                "ai_confidence": rev_ai["confidence"],
                "ai_osi_layer": rev_ai["osi_layer"],
                "human_decision": decision.split()[0],
                "human_agreed": decision.startswith("ACCEPTED"),
                "final_root_cause": final_root_cause,
                "final_fix_steps": final_cli.replace("\n", "; "),
                "reviewer_notes": reviewer_notes
            }
            save_human_review(review_payload)
            st.success(f"✅ Review decision '{decision}' saved to human_reviews.csv for case {rev_case['case_id']}!")

    # Live View of Persistent human_reviews.csv
    st.markdown("---")
    st.subheader("📜 Recent Human Review Audit Trail (`human_reviews.csv`)")
    if os.path.exists(REVIEWS_FILE):
        df_revs = pd.read_csv(REVIEWS_FILE)
        if not df_revs.empty:
            st.dataframe(df_revs.tail(10), use_container_width=True, hide_index=True)
        else:
            st.info("No manual reviews logged yet. Submit a review above to populate.")

# ==========================================
# TAB 3: ANALYTICS DASHBOARD
# ==========================================
with tab_analytics:
    st.header("📊 NetSage AI Troubleshooting Analytics")
    st.markdown("Key performance indicators across 30 Cisco Packet Tracer failure modes and Human-in-the-Loop agreement.")

    # Top KPI Metrics Cards
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Total Benchmark Cases</div>
            <div class="metric-value">{eval_summary.get("total_cases", 0)}</div>
        </div>
        """, unsafe_allow_html=True)
    with k2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Rule Engine Hit Rate</div>
            <div class="metric-value">{eval_summary.get("rule_engine_match_rate_pct", 0)}%</div>
        </div>
        """, unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Human Agreement Rate</div>
            <div class="metric-value">{eval_summary.get("human_agreement_rate_pct", 0)}%</div>
        </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Human Corrections</div>
            <div class="metric-value">{eval_summary.get("human_corrected_count", 0)}</div>
        </div>
        """, unsafe_allow_html=True)
    with k5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Average Confidence</div>
            <div class="metric-value">{eval_summary.get("average_confidence", 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    df_records = pd.DataFrame(records)
    c_chart1, c_chart2 = st.columns(2)

    with c_chart1:
        st.subheader("📌 Faults by Network Concept")
        if not df_records.empty:
            fig_concept = px.pie(
                df_records,
                names="concept",
                hole=0.45,
                color_discrete_sequence=px.colors.qualitative.Prism,
                title="Cases by Network Domain"
            )
            fig_concept.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_concept, use_container_width=True)

    with c_chart2:
        st.subheader("📶 OSI Layer Distribution")
        if not df_records.empty:
            osi_counts = df_records["osi_layer"].value_counts().reset_index()
            osi_counts.columns = ["OSI Layer", "Count"]
            fig_osi = px.bar(
                osi_counts,
                x="OSI Layer",
                y="Count",
                color="OSI Layer",
                color_discrete_sequence=px.colors.qualitative.Bold,
                title="Faults across OSI Layers"
            )
            fig_osi.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", showlegend=False)
            st.plotly_chart(fig_osi, use_container_width=True)

    c_chart3, c_chart4 = st.columns(2)
    with c_chart3:
        st.subheader("⚠️ Severity Breakdown")
        if not df_records.empty:
            sev_counts = df_records["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            color_map = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}
            fig_sev = px.pie(
                sev_counts,
                names="Severity",
                values="Count",
                color="Severity",
                color_discrete_map=color_map,
                hole=0.4,
                title="Fault Severity Levels"
            )
            fig_sev.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_sev, use_container_width=True)

    with c_chart4:
        st.subheader("🛡️ Human Review Decisions")
        if not df_records.empty:
            decisions = [r["human_review"]["human_decision"] for r in records]
            df_dec = pd.DataFrame({"Decision": decisions})
            fig_dec = px.bar(
                df_dec["Decision"].value_counts().reset_index(),
                x="Decision",
                y="count",
                color="Decision",
                color_discrete_map={"APPROVED": "#10b981", "CORRECTED": "#f59e0b", "OVERRIDDEN": "#ef4444"},
                title="HITL Decision Distribution"
            )
            fig_dec.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", showlegend=False)
            st.plotly_chart(fig_dec, use_container_width=True)

# ==========================================
# TAB 4: RESPONSIBLE AI LOG
# ==========================================
with tab_responsible_ai:
    st.header("🛡️ Responsible AI & Human-in-the-Loop Audit Log")
    st.markdown("Detailed audit of 5 network troubleshooting cases where Human-in-the-Loop review refined, corrected, or safeguarded the AI output.")

    cases_corrected = [
        {
            "id": "C012",
            "domain": "Routing (OSPF)",
            "title": "OSPF Passive Interface vs Process Restart",
            "ai_init": "AI suggested 'clear ip ospf process' and re-entering network statements.",
            "human_corr": "Human identified 'passive-interface Gi0/0' suppressing Hellos and removed it with 'no passive-interface Gi0/0'.",
            "risk": "Prevented network-wide routing protocol flapping and unnecessary packet drops.",
            "cli": "router ospf 1\nno passive-interface GigabitEthernet0/0\nend"
        },
        {
            "id": "C015",
            "domain": "ACL / Security",
            "title": "VTY Line Access-Class vs Crypto Key Regeneration",
            "ai_init": "AI suspected crypto RSA key corruption or SSH version misconfiguration.",
            "human_corr": "Human verified VTY access-class ACL explicitly denying management station IP on TCP port 22.",
            "risk": "Prevented accidental management lockout and certificate disruption.",
            "cli": "ip access-list extended VTY-ACL\npermit tcp host 192.168.5.10 any eq 22\nend"
        },
        {
            "id": "C018",
            "domain": "NAT / Routing",
            "title": "NAT Overload Return Route vs ACL Re-indexing",
            "ai_init": "AI suggested re-creating NAT overload pool statement.",
            "human_corr": "Human observed active translations but caught missing default route (0.0.0.0/0) to ISP.",
            "risk": "Avoided redundant configuration churn without addressing egress gateway reachability.",
            "cli": "ip route 0.0.0.0 0.0.0.0 203.0.113.1\nend\nshow ip route"
        },
        {
            "id": "C020",
            "domain": "Wireless / ACL",
            "title": "Guest Wi-Fi Isolation: L2 Switchport vs Layer 3 Boundary",
            "ai_init": "AI recommended Layer 2 client isolation on Access Point.",
            "human_corr": "Human applied Layer 3 inter-VLAN ACL on SVI to prevent guest access to RFC1918 subnets.",
            "risk": "Prevented guest breach into corporate internal servers across VLAN boundaries.",
            "cli": "ip access-list extended GUEST_SEGREGATION\ndeny ip any 10.0.0.0 0.255.255.255\ndeny ip any 192.168.0.0 0.0.255.255\npermit ip any any\ninterface Vlan40\nip access-group GUEST_SEGREGATION in"
        },
        {
            "id": "C029",
            "domain": "Interface / Security",
            "title": "Port Security Err-Disable vs Cable Replacement",
            "ai_init": "AI hypothesized physical Ethernet cable defect or duplex mismatch.",
            "human_corr": "Human identified port-security violation and executed shutdown / no shutdown recovery.",
            "risk": "Prevented false hardware replacement downtime for an operational port-security latch.",
            "cli": "interface GigabitEthernet0/10\nshutdown\nno shutdown\nswitchport port-security violation restrict\nend"
        }
    ]

    for c in cases_corrected:
        with st.expander(f"📌 Case {c['id']} — [{c['domain']}] {c['title']}", expanded=True):
            ec1, ec2 = st.columns(2)
            with ec1:
                st.markdown(f"**🤖 Initial AI Suggestion:**\n{c['ai_init']}")
                st.markdown(f"**⚠️ Risk Prevented:**\n{c['risk']}")
            with ec2:
                st.markdown(f"**👨‍💻 Human Reviewer Correction:**\n{c['human_corr']}")
                st.markdown("**🔧 Verified CLI Remediation:**")
                st.code(c["cli"], language="text")

# ==========================================
# TAB 5: DATASET EXPLORER & DOCS
# ==========================================
with tab_dataset:
    st.header("📁 Dataset Explorer & Video Presentation Guide")

    df_cases = pd.DataFrame(cases_data)

    st.subheader("30 Benchmark Cases (`cases.csv`)")
    f_c1, f_c2 = st.columns(2)
    with f_c1:
        domain_f = st.multiselect("Filter by Domain:", df_cases["concept"].unique(), default=df_cases["concept"].unique())
    with f_c2:
        sev_f = st.multiselect("Filter by Severity:", df_cases["severity"].unique(), default=df_cases["severity"].unique())

    filtered_cases = df_cases[df_cases["concept"].isin(domain_f) & df_cases["severity"].isin(sev_f)]
    st.dataframe(filtered_cases[["case_id", "concept", "severity", "osi_layer", "symptom", "show_output", "expected_fault"]], use_container_width=True, hide_index=True)

    st.download_button(
        "📥 Download cases.csv",
        filtered_cases.to_csv(index=False).encode('utf-8'),
        "cases.csv",
        "text/csv"
    )
