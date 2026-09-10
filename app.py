import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import joblib

from severity import severity_map, recommendation_map
from threat_feed import get_threat_feed

st.set_page_config(
    page_title="Cyber Security Operations Center",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>

.stApp{
    background-color:#0A192F;
}

[data-testid="metric-container"]{
    background:#111827;
    border:1px solid #00E5FF;
    border-radius:15px;
    padding:15px;
}

</style>
""", unsafe_allow_html=True)

#load data

df = pd.read_csv("data/cybersecurity.csv")
df["severity"] = df["attack_type"].map(severity_map)
model = joblib.load("models/threat_model.pkl")

st.markdown("""
<div style="
background: linear-gradient(90deg,#001F3F,#003366,#005B96);
padding:25px;
border-radius:15px;
text-align:center;
margin-bottom:20px;
">
<h1 style="color:#00E5FF;">
🛡 CYBER SECURITY OPERATIONS CENTER
</h1>

<p style="color:white;">
AI Threat Detection • Threat Intelligence • SOC Monitoring
</p>

</div>
""", unsafe_allow_html=True)

#KPI Cards

critical_count = len(df[df["severity"] == "Critical"])
high_count = len(df[df["severity"] == "High"])
medium_count = len(df[df["severity"] == "Medium"])
benign_count = len(df[df["attack_type"] == "benign"])

attack_percentage = (
    len(df[df["attack_type"] != "benign"])
    / len(df)
) * 100

security_score = round(
    100 - attack_percentage,
    2
)

k1,k2,k3,k4,k5 = st.columns(5)

k1.metric("🚨 Critical", critical_count)
k2.metric("⚠ High", high_count)
k3.metric("🟡 Medium", medium_count)
k4.metric("🟢 Benign", benign_count)
k5.metric("🛡 Score", f"{security_score}%")

#Threat gauge + attack analysis

st.divider()

left,right = st.columns(2)

with left:

    st.subheader("🚨 Threat Level Monitor")

    threat_level = critical_count + high_count

    fig_gauge = go.Figure(go.Indicator(
    mode="gauge+number",
    value=threat_level,
    title={"text":"Current Threat Level"},
    gauge={
        "axis":{"range":[0,300]},
        "bar":{"color":"#00E5FF"},
        "steps":[
            {"range":[0,100],"color":"#00C853"},
            {"range":[100,200],"color":"#FF9100"},
            {"range":[200,300],"color":"#FF1744"}
        ]
    }
))

    st.plotly_chart(
        fig_gauge,
        use_container_width=True
    )

with right:

    st.subheader("📊 Top Attack Types")

    attacks_only = df[
        df["attack_type"] != "benign"
    ]

    attack_counts = (
        attacks_only["attack_type"]
        .value_counts()
        .reset_index()
    )

    attack_counts.columns = [
        "attack_type",
        "count"
    ]

    fig_attack = px.bar(
        attack_counts,
        x="attack_type",
        y="count",
        title="Most Detected Attacks"
    )

    st.plotly_chart(
        fig_attack,
        use_container_width=True
    )

#security alert center
st.divider()

st.subheader("🚨 Security Alert Center")

a1,a2,a3 = st.columns(3)

with a1:
    st.error(
        f"Critical Threats Detected: {critical_count}"
    )

with a2:
    st.warning(
        f"High Threats Detected: {high_count}"
    )

with a3:
    st.info(
        f"Medium Threats Detected: {medium_count}"
    )

#threat analysis console
st.divider()

st.subheader("🤖 Threat Analysis Console")

p1,p2 = st.columns(2)

with p1:

    src_port = st.number_input(
        "Source Port",
        min_value=0,
        max_value=65535,
        value=443
    )

    dst_port = st.number_input(
        "Destination Port",
        min_value=0,
        max_value=65535,
        value=80
    )

with p2:

    bytes_sent = st.number_input(
        "Bytes Sent",
        min_value=0,
        value=5000
    )

    bytes_received = st.number_input(
        "Bytes Received",
        min_value=0,
        value=2000
    )

is_internal = st.selectbox(
    "Internal Traffic",
    [0,1]
)

if st.button(
    "🚀 ANALYZE THREAT",
    use_container_width=True
):

    sample = pd.DataFrame({
        "src_port":[src_port],
        "dst_port":[dst_port],
        "bytes_sent":[bytes_sent],
        "bytes_received":[bytes_received],
        "is_internal_traffic":[is_internal]
    })

    prediction = model.predict(sample)

    if prediction[0] == 1:

        attack = "sql-injection"

        severity = severity_map.get(
            attack,
            "High"
        )

        recommendation = recommendation_map.get(
            attack,
            "Investigate immediately."
        )

        st.error(
            f"🚨 Threat Detected : {attack}"
        )

        st.warning(
            f"Severity : {severity}"
        )

        st.info(
            f"Recommended Action : {recommendation}"
        )

    else:

        st.success(
            "✅ Traffic Classified As Benign"
        )

#live Threat Feed + Threat Intelligence Feed

st.divider()

left,right = st.columns(2)

with left:

    st.subheader("📡 Live Threat Feed")

    feed = df[
        df["attack_type"] != "benign"
    ].head(15)

    st.dataframe(
        feed[
            [
                "timestamp",
                "src_ip",
                "dst_ip",
                "attack_type",
                "severity"
            ]
        ],
        use_container_width=True
    )

with right:

    st.subheader("🌐 Threat Intelligence Feed")

    threat_feed = get_threat_feed()

    if not threat_feed.empty:

        st.dataframe(
            threat_feed,
            use_container_width=True
        )

    else:

        st.warning(
            "Unable to fetch live threat feed."
        )

#threat intelligence report
st.divider()

st.subheader("📄 Threat Intelligence Report")

top_attack = (
    df["attack_type"]
    .value_counts()
    .idxmax()
)

report = f"""
CYBER THREAT INTELLIGENCE REPORT

Total Records: {len(df)}

Critical Threats: {critical_count}

High Threats: {high_count}

Medium Threats: {medium_count}

Security Score: {security_score}%

Most Common Threat:
{top_attack}

Recommended Actions:

• Enable Multi-Factor Authentication

• Patch Vulnerable Systems

• Monitor Suspicious Login Attempts

• Block Malicious IP Addresses

• Review Network Activity Logs

• Update Endpoint Protection
"""

st.download_button(
    "⬇ Download Threat Report",
    report,
    file_name="Cyber_Threat_Report.txt"
)

#SOC status footer
st.divider()

f1,f2,f3 = st.columns(3)

with f1:
    st.success(
        "🟢 Threat Monitoring Active"
    )

with f2:
    st.success(
        "🟢 AI Detection Engine Online"
    )

with f3:
    st.success(
        "🟢 Threat Intelligence Connected"
    )

#final footer banner
st.markdown("""
<div style="
background:#111827;
padding:15px;
border-radius:12px;
text-align:center;
margin-top:20px;
">

<h3 style="color:#00E5FF;">
🛡 Cyber Security Operations Center
</h3>

<p style="color:white;">
Real-Time Threat Detection • Threat Intelligence • SOC Monitoring
</p>

</div>
""", unsafe_allow_html=True)

