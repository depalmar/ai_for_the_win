#!/usr/bin/env python3
"""
Security Dashboard Template

Streamlit dashboard for security monitoring and analysis.

Run with: streamlit run streamlit_dashboard.py
"""

# Uncomment for actual deployment
# import streamlit as st
# import pandas as pd
# import plotly.express as px
# import plotly.graph_objects as go
# from datetime import datetime, timedelta

"""
# Security Operations Dashboard

A comprehensive Streamlit dashboard template for security operations.

## Features
- Real-time alert monitoring
- Detection metrics visualization
- Threat intelligence overview
- Incident timeline
- MITRE ATT&CK coverage heatmap

## Installation

```bash
pip install streamlit pandas plotly
```

## Usage

```bash
streamlit run streamlit_dashboard.py
```

## Dashboard Code Template
"""

DASHBOARD_CODE = '''
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random

# Page config
st.set_page_config(
    page_title="Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
    }
    .alert-critical { border-left: 5px solid #e74c3c; }
    .alert-high { border-left: 5px solid #e67e22; }
    .alert-medium { border-left: 5px solid #f1c40f; }
    .alert-low { border-left: 5px solid #27ae60; }
</style>
""", unsafe_allow_html=True)


# =============================================================================
# Sidebar
# =============================================================================

with st.sidebar:
    st.image("https://via.placeholder.com/150x50?text=Security+Ops", width=150)
    st.title("🛡️ SecOps Dashboard")

    st.markdown("---")

    # Time range selector
    time_range = st.selectbox(
        "Time Range",
        ["Last 1 Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days"]
    )

    # Environment filter
    environment = st.multiselect(
        "Environment",
        ["Production", "Staging", "Development"],
        default=["Production"]
    )

    # Severity filter
    severity = st.multiselect(
        "Severity",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High"]
    )

    st.markdown("---")
    st.markdown("**Last Updated:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# =============================================================================
# Main Dashboard
# =============================================================================

# Title
st.title("🛡️ Security Operations Dashboard")

# Metrics Row
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="🚨 Open Alerts",
        value="47",
        delta="-12 from yesterday",
        delta_color="inverse"
    )

with col2:
    st.metric(
        label="🔴 Critical",
        value="3",
        delta="+1",
        delta_color="inverse"
    )

with col3:
    st.metric(
        label="⏱️ MTTR",
        value="23 min",
        delta="-5 min",
        delta_color="normal"
    )

with col4:
    st.metric(
        label="✅ Resolved Today",
        value="89",
        delta="+15"
    )


# =============================================================================
# Charts Row
# =============================================================================

st.markdown("---")

col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Alert Trend (Last 7 Days)")

    # Sample data
    dates = pd.date_range(end=datetime.now(), periods=7, freq='D')
    alerts_data = pd.DataFrame({
        'Date': dates,
        'Critical': [random.randint(1, 5) for _ in range(7)],
        'High': [random.randint(5, 15) for _ in range(7)],
        'Medium': [random.randint(10, 30) for _ in range(7)],
        'Low': [random.randint(20, 50) for _ in range(7)]
    })

    fig = px.area(
        alerts_data,
        x='Date',
        y=['Critical', 'High', 'Medium', 'Low'],
        color_discrete_map={
            'Critical': '#e74c3c',
            'High': '#e67e22',
            'Medium': '#f1c40f',
            'Low': '#27ae60'
        }
    )
    fig.update_layout(height=300)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("🎯 Detection by Category")

    category_data = pd.DataFrame({
        'Category': ['Malware', 'Phishing', 'C2', 'Exfiltration', 'Lateral Movement'],
        'Count': [45, 32, 18, 12, 8]
    })

    fig = px.pie(
        category_data,
        values='Count',
        names='Category',
        color_discrete_sequence=px.colors.qualitative.Set2
    )
    fig.update_layout(height=300)
    st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# MITRE ATT&CK Heatmap
# =============================================================================

st.markdown("---")
st.subheader("🗺️ MITRE ATT&CK Coverage")

tactics = ['Recon', 'Resource Dev', 'Initial Access', 'Execution',
           'Persistence', 'Priv Esc', 'Defense Evasion', 'Credential Access',
           'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact']

# Sample detection coverage data
coverage_data = [[random.randint(0, 100) for _ in range(13)] for _ in range(5)]

fig = go.Figure(data=go.Heatmap(
    z=coverage_data,
    x=tactics,
    y=['EDR', 'SIEM', 'NDR', 'Email', 'Cloud'],
    colorscale='RdYlGn',
    text=[[f"{v}%" for v in row] for row in coverage_data],
    texttemplate="%{text}",
    textfont={"size": 10}
))
fig.update_layout(height=250)
st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# Recent Alerts Table
# =============================================================================

st.markdown("---")
st.subheader("🚨 Recent Alerts")

alerts = pd.DataFrame({
    'Time': ['2 min ago', '5 min ago', '12 min ago', '23 min ago', '45 min ago'],
    'Severity': ['Critical', 'High', 'High', 'Medium', 'Low'],
    'Title': [
        'Ransomware encryption detected on WS-001',
        'Suspicious PowerShell execution',
        'Lateral movement via SMB',
        'Unusual outbound traffic to TOR',
        'Failed login attempts (5x)'
    ],
    'Source': ['EDR', 'SIEM', 'NDR', 'Firewall', 'AD'],
    'Status': ['Open', 'Investigating', 'Open', 'Resolved', 'Resolved']
})

# Color code by severity
def color_severity(val):
    colors = {
        'Critical': 'background-color: #fadbd8',
        'High': 'background-color: #fdebd0',
        'Medium': 'background-color: #fcf3cf',
        'Low': 'background-color: #d5f5e3'
    }
    return colors.get(val, '')

st.dataframe(
    alerts.style.applymap(color_severity, subset=['Severity']),
    use_container_width=True,
    hide_index=True
)


# =============================================================================
# Incident Timeline
# =============================================================================

st.markdown("---")
st.subheader("📅 Incident Timeline")

timeline_data = pd.DataFrame({
    'Time': pd.date_range(end=datetime.now(), periods=10, freq='30min'),
    'Event': [
        'Alert triggered: Suspicious file download',
        'Automated enrichment completed',
        'Analyst assigned: John D.',
        'Host isolated: WS-001',
        'Memory dump collected',
        'Malware sample extracted',
        'YARA rule created',
        'Lateral movement blocked',
        'Remediation in progress',
        'Incident escalated to CISO'
    ]
})

fig = px.scatter(
    timeline_data,
    x='Time',
    y=[1] * len(timeline_data),
    text='Event',
    size=[20] * len(timeline_data)
)
fig.update_traces(textposition='top center')
fig.update_layout(
    height=200,
    yaxis_visible=False,
    showlegend=False
)
st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# Footer
# =============================================================================

st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "Security Operations Dashboard | AI for the Win Training Program"
    "</div>",
    unsafe_allow_html=True
)
'''

# Write the dashboard code to a file
if __name__ == "__main__":
    print("Security Dashboard Template")
    print("=" * 50)
    print("\nTo run the dashboard:")
    print("  1. pip install streamlit pandas plotly")
    print("  2. Save the DASHBOARD_CODE to a .py file")
    print("  3. Run: streamlit run your_dashboard.py")
    print("\nDashboard features:")
    print("  - Real-time metrics (alerts, MTTR)")
    print("  - Alert trend visualization")
    print("  - Detection by category pie chart")
    print("  - MITRE ATT&CK coverage heatmap")
    print("  - Recent alerts table")
    print("  - Incident timeline")
