#!/usr/bin/env python3
"""
AI for the Win - Unified Demo Launcher

Enhanced Gradio application with interactive demos for all labs,
real model integration, and visualizations.

=============================================================================
FEATURES
=============================================================================

1. Lab Selection: Choose any lab from tabs
2. Real Integration: Uses actual models when available
3. Visualizations: Charts and graphs for analysis results
4. Progress Tracker: Track your learning journey

=============================================================================
USAGE
=============================================================================

    python demo/launcher.py

Then open http://localhost:7860 in your browser.

=============================================================================
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    import gradio as gr

    GRADIO_AVAILABLE = True
except ImportError:
    GRADIO_AVAILABLE = False
    print("Gradio not installed. Install with: pip install gradio")
    sys.exit(1)

try:
    import plotly.express as px
    import plotly.graph_objects as go

    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import numpy as np
    import pandas as pd
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import StandardScaler

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from dotenv import load_dotenv

load_dotenv()

# Check for LLM availability
LLM_AVAILABLE = False
LLM_PROVIDER = None
try:
    if os.getenv("ANTHROPIC_API_KEY"):
        from langchain_anthropic import ChatAnthropic

        LLM_AVAILABLE = True
        LLM_PROVIDER = "anthropic"
    elif os.getenv("OPENAI_API_KEY"):
        from langchain_openai import ChatOpenAI

        LLM_AVAILABLE = True
        LLM_PROVIDER = "openai"
except ImportError:
    pass


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def get_llm():
    """Get configured LLM client."""
    if not LLM_AVAILABLE:
        return None
    if LLM_PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
    elif LLM_PROVIDER == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(model="gpt-4o", temperature=0)
    return None


def create_status_badge():
    """Create status indicators for available features."""
    badges = []
    if ML_AVAILABLE:
        badges.append("ML Models")
    if LLM_AVAILABLE:
        badges.append(f"LLM ({LLM_PROVIDER})")
    if PLOTLY_AVAILABLE:
        badges.append("Visualizations")

    if badges:
        return f"Active: {', '.join(badges)}"
    return "Demo mode (no models loaded)"


# =============================================================================
# LAB 01: PHISHING CLASSIFIER
# =============================================================================


def demo_phishing_classifier(email_text: str, threshold: float) -> Tuple[str, Optional[object]]:
    """Lab 01: Phishing Email Classifier Demo."""
    if not email_text.strip():
        return "Please enter email text to analyze.", None

    # Weighted pattern matching for phishing detection
    suspicious_patterns = {
        "urgent": 0.15,
        "verify": 0.12,
        "suspended": 0.15,
        "click here": 0.12,
        "click now": 0.12,
        "password": 0.10,
        "immediately": 0.12,
        "limited time": 0.10,
        "act now": 0.12,
        "winner": 0.15,
        "congratulations": 0.12,
        "account": 0.08,
        "security": 0.08,
        "confirm": 0.08,
        "login": 0.08,
        "expire": 0.10,
        "prize": 0.12,
        "won": 0.10,
        "claim": 0.10,
        "bank": 0.08,
    }

    text_lower = email_text.lower()
    score = 0.0
    found = []

    for pattern, weight in suspicious_patterns.items():
        if pattern in text_lower:
            score += weight
            found.append(f"{pattern} (+{int(weight*100)}%)")

    # Check for suspicious links
    if "http://" in text_lower:
        score += 0.15
        found.append("http:// link (+15%)")
    if "https://" in text_lower and any(x in text_lower for x in ["verify", "login", "account"]):
        score += 0.10
        found.append("suspicious https link (+10%)")

    # Check for urgency indicators
    if "!" in email_text and email_text.count("!") >= 2:
        score += 0.08
        found.append("multiple exclamations (+8%)")

    # Cap at 100%
    score = min(1.0, score)
    score_pct = int(score * 100)
    threshold_pct = int(threshold * 100)

    is_phishing = score >= threshold
    features_info = (
        "\n".join(f"- {kw}" for kw in found) if found else "- No suspicious patterns detected"
    )

    # Create Plotly gauge
    fig = None
    if PLOTLY_AVAILABLE:
        # Determine colors based on score
        if score < 0.3:
            bar_color = "#2ecc71"  # Green
        elif score < 0.6:
            bar_color = "#f39c12"  # Orange
        else:
            bar_color = "#e74c3c"  # Red

        fig = go.Figure()

        # Add the gauge
        fig.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=score_pct,
                number={"suffix": "%", "font": {"size": 50, "color": bar_color}},
                delta={
                    "reference": threshold_pct,
                    "relative": False,
                    "position": "bottom",
                    "increasing": {"color": "#e74c3c"},
                    "decreasing": {"color": "#2ecc71"},
                },
                title={
                    "text": f"<b>{'PHISHING' if is_phishing else 'LEGITIMATE'}</b>",
                    "font": {"size": 24, "color": bar_color},
                },
                gauge={
                    "axis": {
                        "range": [0, 100],
                        "tickwidth": 2,
                        "tickcolor": "#666",
                        "tickvals": [0, 25, 50, 75, 100],
                    },
                    "bar": {"color": bar_color, "thickness": 0.75},
                    "bgcolor": "rgba(0,0,0,0)",
                    "borderwidth": 2,
                    "bordercolor": "#666",
                    "steps": [
                        {"range": [0, 30], "color": "rgba(46, 204, 113, 0.3)"},
                        {"range": [30, 60], "color": "rgba(243, 156, 18, 0.3)"},
                        {"range": [60, 100], "color": "rgba(231, 76, 60, 0.3)"},
                    ],
                    "threshold": {
                        "line": {"color": "#333", "width": 4},
                        "thickness": 0.85,
                        "value": threshold_pct,
                    },
                },
            )
        )

        fig.update_layout(
            height=280,
            margin=dict(l=30, r=30, t=50, b=30),
            paper_bgcolor="rgba(0,0,0,0)",
            font={"color": "#333", "family": "Arial"},
            annotations=[
                dict(
                    text=f"Threshold: {threshold_pct}%",
                    x=0.5,
                    y=-0.15,
                    showarrow=False,
                    font=dict(size=14, color="#666"),
                )
            ],
        )

    # Classification result
    if is_phishing:
        classification = f"**PHISHING DETECTED** (score {score_pct}% >= threshold {threshold_pct}%)"
    else:
        classification = f"**LEGITIMATE** (score {score_pct}% < threshold {threshold_pct}%)"

    result = f"""
## {classification}

### Detected Patterns
{features_info}

### How It Works
- Weighted pattern matching scores suspicious keywords
- Delta shows difference from threshold
- Adjust threshold slider to change sensitivity
"""
    return result, fig


# =============================================================================
# LAB 02: MALWARE CLUSTERING
# =============================================================================


def demo_malware_clustering(n_samples: int, n_clusters: int) -> Tuple[str, Optional[object]]:
    """Lab 02: Malware Sample Clustering with 3D interactive visualization."""
    if not ML_AVAILABLE:
        return "ML libraries not available. Install scikit-learn.", None

    # Generate synthetic malware features
    np.random.seed(42)

    families = ["Emotet", "TrickBot", "Ryuk", "CobaltStrike", "Generic"]
    data = []
    true_labels = []

    samples_per_family = n_samples // len(families)

    for idx, family in enumerate(families):
        if family == "Emotet":
            entropy = np.random.normal(7.2, 0.3, samples_per_family)
            size = np.random.lognormal(12, 0.5, samples_per_family)
            imports = np.random.randint(30, 60, samples_per_family)
        elif family == "TrickBot":
            entropy = np.random.normal(6.8, 0.4, samples_per_family)
            size = np.random.lognormal(11, 0.4, samples_per_family)
            imports = np.random.randint(40, 80, samples_per_family)
        elif family == "Ryuk":
            entropy = np.random.normal(7.5, 0.2, samples_per_family)
            size = np.random.lognormal(13, 0.6, samples_per_family)
            imports = np.random.randint(20, 40, samples_per_family)
        elif family == "CobaltStrike":
            entropy = np.random.normal(7.8, 0.2, samples_per_family)
            size = np.random.lognormal(10, 0.3, samples_per_family)
            imports = np.random.randint(10, 25, samples_per_family)
        else:
            entropy = np.random.normal(6.5, 0.6, samples_per_family)
            size = np.random.lognormal(11.5, 0.8, samples_per_family)
            imports = np.random.randint(20, 100, samples_per_family)

        for i in range(samples_per_family):
            data.append(
                {
                    "entropy": entropy[i],
                    "file_size": size[i],
                    "num_imports": imports[i],
                    "family": family,
                }
            )
            true_labels.append(idx)

    df = pd.DataFrame(data)

    # Feature matrix
    X = df[["entropy", "file_size", "num_imports"]].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Clustering
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    cluster_labels = kmeans.fit_predict(X_scaled)

    # PCA for 3D visualization
    pca = PCA(n_components=3)
    X_3d = pca.fit_transform(X_scaled)

    df["cluster"] = cluster_labels
    df["pc1"] = X_3d[:, 0]
    df["pc2"] = X_3d[:, 1]
    df["pc3"] = X_3d[:, 2]

    # Calculate silhouette score
    from sklearn.metrics import adjusted_rand_score, silhouette_score

    sil_score = silhouette_score(X_scaled, cluster_labels)
    ari = adjusted_rand_score(true_labels, cluster_labels)

    # Calculate variance explained
    var_explained = sum(pca.explained_variance_ratio_) * 100

    # Create 3D visualization
    fig = None
    if PLOTLY_AVAILABLE:
        try:
            # Convert cluster to string for proper color mapping
            df["cluster_str"] = "Cluster " + df["cluster"].astype(str)

            # Custom color palette for clusters
            cluster_colors = px.colors.qualitative.Set2[:n_clusters]

            fig = px.scatter_3d(
                df,
                x="pc1",
                y="pc2",
                z="pc3",
                color="cluster_str",
                symbol="family",
                title=f"3D Malware Clustering (Silhouette: {sil_score:.3f}, Var Explained: {var_explained:.1f}%)",
                labels={
                    "pc1": "PC1",
                    "pc2": "PC2",
                    "pc3": "PC3",
                    "cluster_str": "Cluster",
                },
                hover_data={
                    "entropy": ":.2f",
                    "num_imports": True,
                    "file_size": ":.0f",
                    "family": True,
                    "pc1": False,
                    "pc2": False,
                    "pc3": False,
                },
                color_discrete_sequence=cluster_colors,
            )

            # Update marker size and layout
            fig.update_traces(marker=dict(size=6, line=dict(width=1, color="white")))

            fig.update_layout(
                height=500,
                scene=dict(
                    xaxis_title="PC1",
                    yaxis_title="PC2",
                    zaxis_title="PC3",
                    camera=dict(eye=dict(x=1.5, y=1.5, z=1.2)),
                ),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="center",
                    x=0.5,
                    font=dict(size=10),
                ),
                margin=dict(l=0, r=0, t=50, b=0),
            )
        except Exception:
            fig = None  # Fall back to no visualization on error

    # Cluster analysis
    def get_dominant_family(x):
        """Get most common family in cluster."""
        if len(x) == 0:
            return "Unknown"
        mode = x.mode()
        return mode.iloc[0] if len(mode) > 0 else "Unknown"

    cluster_summary = (
        df.groupby("cluster")
        .agg(
            {
                "entropy": "mean",
                "file_size": "mean",
                "num_imports": "mean",
                "family": get_dominant_family,
            }
        )
        .round(2)
    )

    # Format cluster summary as manual markdown table
    table_rows = [
        "| Cluster | Entropy | File Size | Imports | Dominant Family |",
        "|---------|---------|-----------|---------|-----------------|",
    ]
    for cluster_id, row in cluster_summary.iterrows():
        table_rows.append(
            f"| {cluster_id} | {row['entropy']:.2f} | {row['file_size']:.0f} | {row['num_imports']:.0f} | {row['family']} |"
        )
    cluster_table = "\n".join(table_rows)

    result = f"""
## Clustering Results

**Samples:** {n_samples} | **Clusters:** {n_clusters}
**Silhouette Score:** {sil_score:.3f} (higher = better separation)
**Adjusted Rand Index:** {ari:.3f} (agreement with true families)
**Variance Explained:** {var_explained:.1f}% (by 3 principal components)

### Cluster Characteristics
{cluster_table}

### How Lab 02 Works
- **Features:** entropy, file size, import count
- **Algorithm:** K-Means groups similar samples
- **Visualization:** 3D interactive PCA plot (drag to rotate!)
- **Quality:** Silhouette score measures cluster separation
"""
    return result, fig


# =============================================================================
# LAB 03: ANOMALY DETECTION
# =============================================================================


def demo_anomaly_detection(
    bytes_sent: int, bytes_received: int, packets: int, duration: float, port: int, use_ml: bool
) -> Tuple[str, Optional[object]]:
    """Lab 03: Network Anomaly Detection with Isolation Forest and time series visualization."""

    findings = []
    fig = None

    # Generate synthetic time series data with the input as the last point
    np.random.seed(42)
    n_history = 50  # Historical data points

    if use_ml and ML_AVAILABLE:
        # Generate normal traffic baseline
        n_normal = 200

        normal_data = np.column_stack(
            [
                np.random.lognormal(10, 1, n_normal),  # bytes_sent
                np.random.lognormal(11, 1, n_normal),  # bytes_received
                np.random.randint(10, 200, n_normal),  # packets
                np.random.exponential(60, n_normal),  # duration
                np.random.choice([80, 443, 8080, 22], n_normal),  # port
            ]
        )

        # Train Isolation Forest
        clf = IsolationForest(contamination=0.1, random_state=42)
        clf.fit(normal_data)

        # Score the input
        test_point = np.array([[bytes_sent, bytes_received, packets, duration, port]])
        raw_score = clf.score_samples(test_point)[0]
        anomaly_score = max(0, min(1, (0.5 - raw_score) * 2))  # Normalize to 0-1
        is_anomaly = clf.predict(test_point)[0] == -1

        method = "Isolation Forest ML Model"

        if is_anomaly:
            findings.append("ML model flagged this flow as anomalous")

        # Generate historical scores for time series
        history_data = np.column_stack(
            [
                np.random.lognormal(10, 0.8, n_history),
                np.random.lognormal(11, 0.8, n_history),
                np.random.randint(10, 150, n_history),
                np.random.exponential(50, n_history),
                np.random.choice([80, 443, 8080, 22], n_history),
            ]
        )
        history_scores = clf.score_samples(history_data)
        history_anomaly = [max(0, min(1, (0.5 - s) * 2)) for s in history_scores]
    else:
        # Rule-based fallback
        anomaly_score = 0.0

        if bytes_sent > 10_000_000:
            anomaly_score += 0.3
            findings.append(f"Large outbound: {bytes_sent/1_000_000:.1f} MB sent")
        if bytes_received > 0 and bytes_sent / max(bytes_received, 1) > 10:
            anomaly_score += 0.2
            findings.append(f"High send/recv ratio: {bytes_sent/max(bytes_received,1):.1f}x")
        if packets > 1000 and duration < 60:
            anomaly_score += 0.2
            findings.append(f"High packet rate: {packets/max(duration,1):.0f} pkt/sec")
        if port in [4444, 5555, 6666, 31337, 1337]:
            anomaly_score += 0.3
            findings.append(f"Suspicious port: {port}")
        if duration < 1 and bytes_sent > 100000:
            anomaly_score += 0.2
            findings.append("Rapid large transfer (possible exfil)")

        anomaly_score = min(1.0, anomaly_score)
        is_anomaly = anomaly_score >= 0.5
        method = "Rule-based heuristics"

        # Generate random historical scores
        history_anomaly = np.random.beta(2, 8, n_history).tolist()  # Mostly low scores

    # Create time series visualization with anomaly highlighting
    if PLOTLY_AVAILABLE:
        import datetime

        # Create timestamps for the last hour
        now = datetime.datetime.now()
        timestamps = [now - datetime.timedelta(minutes=60 - i) for i in range(n_history)]
        timestamps.append(now)  # Current point

        # Add current score to history
        all_scores = history_anomaly + [anomaly_score]

        # Determine colors based on threshold (0.5)
        colors = ["#e74c3c" if s >= 0.5 else "#2ecc71" for s in all_scores]

        fig = go.Figure()

        # Add the time series line
        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=all_scores,
                mode="lines+markers",
                name="Anomaly Score",
                line=dict(color="#3498db", width=2),
                marker=dict(color=colors, size=8, line=dict(width=1, color="#fff")),
                hovertemplate="Time: %{x}<br>Score: %{y:.2f}<extra></extra>",
            )
        )

        # Add threshold line
        fig.add_hline(
            y=0.5,
            line_dash="dash",
            line_color="#e74c3c",
            annotation_text="Threshold (0.5)",
            annotation_position="right",
        )

        # Highlight anomalous regions
        anomaly_regions = []
        in_anomaly = False
        start_idx = 0
        for i, score in enumerate(all_scores):
            if score >= 0.5 and not in_anomaly:
                in_anomaly = True
                start_idx = i
            elif score < 0.5 and in_anomaly:
                in_anomaly = False
                anomaly_regions.append((start_idx, i - 1))
        if in_anomaly:
            anomaly_regions.append((start_idx, len(all_scores) - 1))

        # Add shaded regions for anomalies
        for start, end in anomaly_regions:
            fig.add_vrect(
                x0=timestamps[start],
                x1=timestamps[min(end, len(timestamps) - 1)],
                fillcolor="rgba(231, 76, 60, 0.2)",
                layer="below",
                line_width=0,
            )

        # Highlight current point
        fig.add_trace(
            go.Scatter(
                x=[timestamps[-1]],
                y=[anomaly_score],
                mode="markers",
                name="Current Flow",
                marker=dict(
                    color="#e74c3c" if is_anomaly else "#2ecc71",
                    size=15,
                    symbol="star",
                    line=dict(width=2, color="#fff"),
                ),
                hovertemplate="CURRENT<br>Score: %{y:.2f}<extra></extra>",
            )
        )

        fig.update_layout(
            title=f"Network Anomaly Time Series - {'ANOMALY' if is_anomaly else 'NORMAL'}",
            xaxis_title="Time",
            yaxis_title="Anomaly Score",
            yaxis=dict(range=[0, 1.1]),
            height=350,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02),
            margin=dict(l=50, r=30, t=60, b=50),
        )

    # Build visual score bar
    score_pct = int(anomaly_score * 100)
    bar_filled = int(20 * anomaly_score)
    bar_empty = 20 - bar_filled
    score_bar = f"[{'#' * bar_filled}{'-' * bar_empty}] {score_pct}%"

    findings_text = "\n".join(f"- {f}" for f in findings) if findings else "- No anomalies detected"

    result = f"""
## Anomaly Detection Results

### Status: {"ANOMALY DETECTED" if is_anomaly else "NORMAL TRAFFIC"}

```
Anomaly Score: {score_bar}
```

### Network Flow
| Metric | Value | Assessment |
|--------|-------|------------|
| Bytes Sent | {bytes_sent:,} | {"High" if bytes_sent > 5_000_000 else "Normal"} |
| Bytes Received | {bytes_received:,} | {"Low ratio" if bytes_sent > bytes_received * 5 else "Normal"} |
| Packets | {packets:,} | {"High" if packets > 500 else "Normal"} |
| Duration | {duration:.1f}s | {"Short" if duration < 5 else "Normal"} |
| Port | {port} | {"Suspicious" if port in [4444,5555,6666,31337] else "Standard"} |

### Findings
{findings_text}

### Method: {method}

### How Lab 03 Works
- Isolation Forest learns "normal" traffic patterns
- Anomalous flows are those easily separated from normal
- Time series shows historical anomaly scores with highlights
- Useful for C2 beaconing, data exfiltration, port scanning
"""
    return result, fig


# =============================================================================
# LAB 04: LOG ANALYSIS
# =============================================================================


def demo_log_analysis(log_entries: str, use_llm: bool) -> Tuple[str, Optional[object]]:
    """Lab 04: LLM-Powered Log Analysis with event timeline visualization."""
    if not log_entries.strip():
        return "Please enter log entries to analyze.", None

    lines = log_entries.strip().split("\n")
    fig = None

    # Parse log entries for timeline visualization
    parsed_events = []
    for i, line in enumerate(lines):
        # Determine severity based on keywords
        line_lower = line.lower()
        if any(kw in line_lower for kw in ["critical", "error", "fail", "attack", "malicious"]):
            severity = "Critical"
            color = "#e74c3c"
            score = 9
        elif any(kw in line_lower for kw in ["warning", "suspicious", "unusual", "blocked"]):
            severity = "High"
            color = "#e67e22"
            score = 7
        elif any(kw in line_lower for kw in ["powershell", "cmd", "exec", "certutil", "bitsadmin"]):
            severity = "Medium"
            color = "#f39c12"
            score = 5
        elif any(kw in line_lower for kw in ["info", "success", "accepted", "established"]):
            severity = "Low"
            color = "#27ae60"
            score = 2
        else:
            severity = "Info"
            color = "#3498db"
            score = 1

        # Extract timestamp if present
        timestamp_match = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
        if timestamp_match:
            timestamp = timestamp_match.group(1)
        else:
            # Use synthetic timestamps
            timestamp = f"Event {i+1}"

        parsed_events.append(
            {
                "index": i,
                "timestamp": timestamp,
                "severity": severity,
                "color": color,
                "score": score,
                "text": line[:80] + ("..." if len(line) > 80 else ""),
            }
        )

    if use_llm and LLM_AVAILABLE:
        llm = get_llm()
        from langchain_core.messages import HumanMessage, SystemMessage

        system_prompt = """You are a security log analyst. Analyze the provided logs and extract:
1. All IOCs (IPs, domains, hashes)
2. Suspicious activities
3. MITRE ATT&CK techniques if applicable
4. Severity assessment (1-10)

Format as structured analysis."""

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"Analyze these logs:\n\n{log_entries}"),
        ]

        try:
            response = llm.invoke(messages)
            analysis = response.content
            method = f"LLM Analysis ({LLM_PROVIDER})"
        except Exception as e:
            analysis = f"LLM error: {e}. Falling back to regex."
            method = "Regex (LLM failed)"
            use_llm = False

    if not use_llm or not LLM_AVAILABLE:
        # Regex-based extraction
        iocs = {"ips": [], "domains": [], "commands": []}

        for line in lines:
            # IPs
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            iocs["ips"].extend(ips)

            # Commands
            if any(kw in line.lower() for kw in ["exec", "cmd", "powershell"]):
                iocs["commands"].append(line[:100])

        iocs["ips"] = list(set(iocs["ips"]))

        analysis = f"""### Extracted IOCs
**IPs:** {', '.join(iocs['ips'][:10]) or 'None'}

**Suspicious Commands:**
{chr(10).join('- ' + c for c in iocs['commands'][:5]) or '- None detected'}"""
        method = "Regex pattern matching"

    # Create timeline visualization
    if PLOTLY_AVAILABLE and parsed_events:
        fig = go.Figure()

        # Add scatter points for each event
        for event in parsed_events:
            fig.add_trace(
                go.Scatter(
                    x=[event["index"]],
                    y=[event["score"]],
                    mode="markers+text",
                    name=event["severity"],
                    marker=dict(
                        size=20,
                        color=event["color"],
                        symbol="circle",
                        line=dict(width=2, color="#fff"),
                    ),
                    text=[event["severity"][0]],  # First letter
                    textposition="middle center",
                    textfont=dict(color="white", size=10, family="Arial Black"),
                    hovertemplate=f"<b>{event['timestamp']}</b><br>"
                    + f"Severity: {event['severity']}<br>"
                    + f"Event: {event['text']}<extra></extra>",
                    showlegend=False,
                )
            )

        # Add connecting line
        fig.add_trace(
            go.Scatter(
                x=[e["index"] for e in parsed_events],
                y=[e["score"] for e in parsed_events],
                mode="lines",
                line=dict(color="#bdc3c7", width=1, dash="dot"),
                showlegend=False,
                hoverinfo="skip",
            )
        )

        # Add severity zones
        fig.add_hrect(y0=8, y1=10, fillcolor="rgba(231, 76, 60, 0.1)", line_width=0)
        fig.add_hrect(y0=6, y1=8, fillcolor="rgba(230, 126, 34, 0.1)", line_width=0)
        fig.add_hrect(y0=4, y1=6, fillcolor="rgba(243, 156, 18, 0.1)", line_width=0)
        fig.add_hrect(y0=0, y1=4, fillcolor="rgba(39, 174, 96, 0.1)", line_width=0)

        # Add legend entries
        severity_colors = [
            ("Critical", "#e74c3c"),
            ("High", "#e67e22"),
            ("Medium", "#f39c12"),
            ("Low", "#27ae60"),
        ]
        for sev, col in severity_colors:
            fig.add_trace(
                go.Scatter(
                    x=[None],
                    y=[None],
                    mode="markers",
                    marker=dict(size=12, color=col),
                    name=sev,
                    showlegend=True,
                )
            )

        fig.update_layout(
            title="Log Event Timeline by Severity",
            xaxis_title="Event Sequence",
            yaxis_title="Severity Score",
            yaxis=dict(
                range=[0, 10.5], tickvals=[2, 5, 7, 9], ticktext=["Low", "Med", "High", "Crit"]
            ),
            height=350,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02),
            margin=dict(l=50, r=30, t=60, b=50),
        )

    result = f"""
## Log Analysis Results

**Lines Analyzed:** {len(lines)}
**Method:** {method}

### Severity Summary
- Critical: {sum(1 for e in parsed_events if e['severity'] == 'Critical')}
- High: {sum(1 for e in parsed_events if e['severity'] == 'High')}
- Medium: {sum(1 for e in parsed_events if e['severity'] == 'Medium')}
- Low/Info: {sum(1 for e in parsed_events if e['severity'] in ['Low', 'Info'])}

{analysis}

### How Lab 04 Works
- LLM parses unstructured log data
- Extracts IOCs using NLP understanding
- Maps activities to MITRE ATT&CK
- Timeline shows event severity over time
"""
    return result, fig


# =============================================================================
# LAB 05: THREAT INTEL AGENT
# =============================================================================


def demo_threat_intel(ioc_value: str, ioc_type: str) -> Tuple[str, Optional[object]]:
    """Lab 05: Threat Intel Agent Demo with network graph visualization."""
    if not ioc_value.strip():
        return "Please enter an IOC to investigate.", None

    fig = None

    # Simulated threat intel with realistic data and relationships
    intel_db = {
        "185.143.223.47": {
            "reputation": "Malicious",
            "category": "C2 Server",
            "first_seen": "2024-01-10",
            "reports": 47,
            "malware": ["Emotet", "TrickBot"],
            "related_iocs": ["evil-domain.tk", "192.168.1.100", "45.33.32.156"],
            "campaigns": ["APT-Winter-2024"],
        },
        "45.33.32.156": {
            "reputation": "Suspicious",
            "category": "Scanner",
            "first_seen": "2024-02-15",
            "reports": 12,
            "malware": [],
            "related_iocs": ["185.143.223.47"],
            "campaigns": [],
        },
        "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890": {
            "reputation": "Malicious",
            "category": "Ransomware",
            "first_seen": "2024-03-20",
            "reports": 156,
            "malware": ["LockBit 3.0"],
            "related_iocs": ["lockbit-ransom.onion", "185.143.223.47"],
            "campaigns": ["LockBit-Q1-2024"],
        },
        "evil-domain.tk": {
            "reputation": "Malicious",
            "category": "Phishing Domain",
            "first_seen": "2024-02-01",
            "reports": 89,
            "malware": ["AgentTesla"],
            "related_iocs": ["185.143.223.47", "phish-kit.ru"],
            "campaigns": ["Phishing-Campaign-Alpha"],
        },
    }

    # Check if IOC matches known entries
    if ioc_value in intel_db:
        intel = intel_db[ioc_value]

        # Create network graph visualization
        if PLOTLY_AVAILABLE:
            import math

            # Build graph data
            nodes = [{"id": ioc_value, "type": "primary", "label": ioc_value[:20]}]
            edges = []

            # Add related IOCs
            for related in intel.get("related_iocs", []):
                nodes.append({"id": related, "type": "related_ioc", "label": related[:20]})
                edges.append({"from": ioc_value, "to": related})

            # Add malware families
            for malware in intel.get("malware", []):
                nodes.append({"id": malware, "type": "malware", "label": malware})
                edges.append({"from": ioc_value, "to": malware})

            # Add campaigns
            for campaign in intel.get("campaigns", []):
                nodes.append({"id": campaign, "type": "campaign", "label": campaign})
                edges.append({"from": ioc_value, "to": campaign})

            # Calculate positions in a circular layout
            n_nodes = len(nodes)
            node_positions = {}
            for i, node in enumerate(nodes):
                if node["type"] == "primary":
                    node_positions[node["id"]] = (0, 0)
                else:
                    angle = 2 * math.pi * (i - 1) / (n_nodes - 1) if n_nodes > 1 else 0
                    radius = 1.5
                    node_positions[node["id"]] = (
                        radius * math.cos(angle),
                        radius * math.sin(angle),
                    )

            # Create figure
            fig = go.Figure()

            # Add edges
            for edge in edges:
                x0, y0 = node_positions[edge["from"]]
                x1, y1 = node_positions[edge["to"]]
                fig.add_trace(
                    go.Scatter(
                        x=[x0, x1],
                        y=[y0, y1],
                        mode="lines",
                        line=dict(color="#bdc3c7", width=2),
                        hoverinfo="skip",
                        showlegend=False,
                    )
                )

            # Node colors and sizes by type
            type_styles = {
                "primary": {"color": "#e74c3c", "size": 40, "symbol": "circle"},
                "related_ioc": {"color": "#3498db", "size": 25, "symbol": "diamond"},
                "malware": {"color": "#9b59b6", "size": 25, "symbol": "square"},
                "campaign": {"color": "#f39c12", "size": 25, "symbol": "triangle-up"},
            }

            # Add nodes by type for proper legend
            for node_type, style in type_styles.items():
                type_nodes = [n for n in nodes if n["type"] == node_type]
                if type_nodes:
                    fig.add_trace(
                        go.Scatter(
                            x=[node_positions[n["id"]][0] for n in type_nodes],
                            y=[node_positions[n["id"]][1] for n in type_nodes],
                            mode="markers+text",
                            name=node_type.replace("_", " ").title(),
                            marker=dict(
                                size=style["size"],
                                color=style["color"],
                                symbol=style["symbol"],
                                line=dict(width=2, color="#fff"),
                            ),
                            text=[n["label"] for n in type_nodes],
                            textposition="bottom center",
                            textfont=dict(size=9),
                            hovertemplate="%{text}<extra></extra>",
                        )
                    )

            fig.update_layout(
                title=f"IOC Relationship Graph: {ioc_value[:30]}...",
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=1.02),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=400,
                margin=dict(l=20, r=20, t=60, b=20),
            )

        result = f"""
## Threat Intelligence Report

### IOC: {ioc_value} ({ioc_type})

**Reputation:** {intel['reputation']}
**Category:** {intel['category']}
**First Seen:** {intel['first_seen']}
**Report Count:** {intel['reports']}
**Associated Malware:** {', '.join(intel['malware']) or 'None'}
**Related IOCs:** {len(intel.get('related_iocs', []))} connections

### Agent Reasoning (ReAct Pattern)

1. **Thought:** I need to check this IOC against threat intel sources
2. **Action:** Query VirusTotal, AbuseIPDB, Shodan
3. **Observation:** Found {intel['reports']} reports flagging this as {intel['category']}
4. **Thought:** This IOC has significant malicious indicators
5. **Action:** Check for associated malware families
6. **Observation:** Linked to {', '.join(intel['malware']) or 'no specific'} malware
7. **Final Answer:** {intel['reputation']} - recommend blocking

### How Lab 05 Works
- Network graph shows IOC relationships
- ReAct agent: Reasoning + Acting loop
- Autonomous tool selection
"""
    else:
        # Generic response for unknown IOCs
        result = f"""
## Threat Intelligence Report

### IOC: {ioc_value} ({ioc_type})

**Reputation:** Unknown
**Category:** Not in database

### Agent Reasoning (ReAct Pattern)

1. **Thought:** I need to check this IOC against threat intel sources
2. **Action:** Query VirusTotal, AbuseIPDB
3. **Observation:** No results found in threat databases
4. **Thought:** This could be new or benign
5. **Final Answer:** No threat data available - monitor for future activity

### How Lab 05 Works
- ReAct agent: Reasoning + Acting loop
- Autonomous tool selection (IP lookup, domain analysis, hash check)
- Memory for investigation context
- Multi-step reasoning chains
"""
    return result, fig


# =============================================================================
# LAB 06: SECURITY RAG
# =============================================================================


def demo_security_rag(query: str) -> str:
    """Lab 06: Security RAG Demo."""
    if not query.strip():
        return "Please enter a security question."

    # Simulated knowledge base
    knowledge = {
        "mitre": {
            "content": "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It covers Enterprise, Mobile, and ICS matrices.",
            "techniques": [
                "T1059 - Command and Scripting Interpreter",
                "T1003 - OS Credential Dumping",
                "T1486 - Data Encrypted for Impact",
            ],
        },
        "cve": {
            "content": "CVE (Common Vulnerabilities and Exposures) is a list of publicly disclosed security flaws. Each CVE has a unique ID, description, and CVSS score.",
            "examples": [
                "CVE-2021-44228 (Log4Shell)",
                "CVE-2023-23397 (Outlook)",
                "CVE-2024-3094 (XZ Utils)",
            ],
        },
        "yara": {
            "content": "YARA is a tool for identifying and classifying malware based on textual or binary patterns. Rules consist of strings and conditions.",
            "syntax": "rule name { meta: strings: condition: }",
        },
        "ransomware": {
            "content": "Ransomware encrypts victim files and demands payment for decryption. Detection involves monitoring for mass file modifications, shadow copy deletion, and high-entropy files.",
            "families": ["LockBit", "BlackCat/ALPHV", "Cl0p", "Royal"],
        },
    }

    # Find relevant context
    query_lower = query.lower()
    relevant = []

    for key, data in knowledge.items():
        if key in query_lower or any(term in query_lower for term in key.split()):
            relevant.append((key, data))

    if relevant:
        context_parts = []
        for key, data in relevant:
            context_parts.append(f"**{key.upper()}:** {data['content']}")
        context = "\n\n".join(context_parts)

        answer = f"Based on the retrieved security knowledge: {relevant[0][1]['content']}"
    else:
        context = "No specific context found. Try queries about MITRE, CVE, YARA, or ransomware."
        answer = "I don't have specific information about this topic in my knowledge base."

    result = f"""
## Security Knowledge Query

### Your Question
{query}

### Retrieved Context
{context}

### Answer
{answer}

### How Lab 06 Works
- Documents are chunked and embedded as vectors
- ChromaDB stores and indexes embeddings
- Semantic search finds relevant context
- LLM generates answer using retrieved context
"""
    return result


# =============================================================================
# LAB 07: YARA GENERATOR
# =============================================================================


def demo_yara_generator(sample_strings: str, malware_family: str, rule_name: str) -> str:
    """Lab 07: YARA Rule Generator Demo."""
    if not sample_strings.strip():
        return "Please enter sample strings (one per line)."

    strings = [s.strip() for s in sample_strings.split("\n") if s.strip()]

    if not rule_name:
        rule_name = f"Detect_{malware_family.replace(' ', '_')}"

    # Generate YARA rule
    string_defs = []
    for i, s in enumerate(strings[:10]):
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        string_defs.append(f'        $s{i} = "{escaped}" ascii wide')

    rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects {malware_family} malware"
        author = "AI Security Training"
        date = "2024-12-26"

    strings:
{chr(10).join(string_defs)}

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        2 of ($s*)
}}"""

    result = f"""
## Generated YARA Rule

```yara
{rule}
```

### Rule Analysis
- **Name:** {rule_name}
- **Family:** {malware_family}
- **Strings:** {len(strings[:10])} patterns
- **Condition:** PE file, <5MB, 2+ string matches

### How Lab 07 Works
- Static analysis extracts strings from binaries
- LLM selects distinctive patterns
- Rule validation with yara-python
- Testing against known samples
"""
    return result


# =============================================================================
# LAB 08-10: ADVANCED DEMOS
# =============================================================================


def demo_vuln_scanner(cve_list: str) -> str:
    """Lab 08: Vulnerability Scanner AI Demo."""
    if not cve_list.strip():
        return "Please enter CVE IDs (one per line)."

    cves = [c.strip() for c in cve_list.split("\n") if c.strip()]

    # Simulated CVE database
    cve_db = {
        "CVE-2021-44228": {"cvss": 10.0, "name": "Log4Shell", "priority": "CRITICAL"},
        "CVE-2023-23397": {"cvss": 9.8, "name": "Outlook Elevation", "priority": "CRITICAL"},
        "CVE-2024-3094": {"cvss": 10.0, "name": "XZ Utils Backdoor", "priority": "CRITICAL"},
        "CVE-2023-4966": {"cvss": 9.4, "name": "Citrix Bleed", "priority": "HIGH"},
    }

    results = []
    for cve in cves:
        if cve.upper() in cve_db:
            data = cve_db[cve.upper()]
            results.append(f"| {cve} | {data['name']} | {data['cvss']} | {data['priority']} |")
        else:
            results.append(f"| {cve} | Unknown | - | REVIEW |")

    result = f"""
## Vulnerability Assessment

### Analyzed CVEs
| CVE ID | Name | CVSS | Priority |
|--------|------|------|----------|
{chr(10).join(results)}

### Remediation Priority
1. Patch CRITICAL vulnerabilities within 24 hours
2. Patch HIGH vulnerabilities within 7 days
3. Review unknown CVEs for applicability

### How Lab 08 Works
- Aggregates CVE data from NVD, vendor advisories
- AI prioritizes based on exploitability, business impact
- Generates remediation roadmap
"""
    return result


def demo_detection_pipeline(events: str) -> Tuple[str, Optional[object]]:
    """Lab 09: Detection Pipeline Demo with Sankey diagram visualization."""
    if not events.strip():
        return "Please enter security events (one per line).", None

    event_list = events.strip().split("\n")
    fig = None

    # Simulate multi-stage pipeline with more granular breakdown
    stage1_passed = len(event_list)
    stage2_benign = max(1, int(stage1_passed * 0.5))  # 50% filtered as benign
    stage2_suspicious = stage1_passed - stage2_benign
    stage3_false_positive = max(0, int(stage2_suspicious * 0.4))  # 40% FP
    stage3_enriched = stage2_suspicious - stage3_false_positive
    stage4_low = max(0, int(stage3_enriched * 0.3))  # 30% low priority
    stage4_medium = max(0, int(stage3_enriched * 0.4))  # 40% medium
    stage4_high = stage3_enriched - stage4_low - stage4_medium  # Rest high priority

    # Create Sankey diagram
    if PLOTLY_AVAILABLE:
        # Define nodes
        node_labels = [
            "Raw Events",  # 0
            "ML Filter",  # 1
            "Benign (Auto-closed)",  # 2
            "Suspicious",  # 3
            "LLM Enrichment",  # 4
            "False Positives",  # 5
            "Enriched",  # 6
            "Low Priority",  # 7
            "Medium Priority",  # 8
            "High Priority Alerts",  # 9
        ]

        node_colors = [
            "#3498db",  # Raw Events - blue
            "#9b59b6",  # ML Filter - purple
            "#27ae60",  # Benign - green
            "#e67e22",  # Suspicious - orange
            "#9b59b6",  # LLM Enrichment - purple
            "#27ae60",  # False Positives - green
            "#f39c12",  # Enriched - yellow
            "#3498db",  # Low - blue
            "#e67e22",  # Medium - orange
            "#e74c3c",  # High - red
        ]

        # Define links (source, target, value)
        links = [
            (0, 1, stage1_passed),  # Raw -> ML Filter
            (1, 2, stage2_benign),  # ML -> Benign
            (1, 3, stage2_suspicious),  # ML -> Suspicious
            (3, 4, stage2_suspicious),  # Suspicious -> LLM
            (4, 5, stage3_false_positive),  # LLM -> FP
            (4, 6, stage3_enriched),  # LLM -> Enriched
            (6, 7, stage4_low),  # Enriched -> Low
            (6, 8, stage4_medium),  # Enriched -> Medium
            (6, 9, stage4_high),  # Enriched -> High
        ]

        # Filter out zero-value links
        links = [(s, t, v) for s, t, v in links if v > 0]

        fig = go.Figure(
            go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="white", width=1),
                    label=node_labels,
                    color=node_colors,
                ),
                link=dict(
                    source=[l[0] for l in links],
                    target=[l[1] for l in links],
                    value=[l[2] for l in links],
                    color=[
                        "rgba(52, 152, 219, 0.4)",  # Blue for initial
                        "rgba(39, 174, 96, 0.4)",  # Green for benign
                        "rgba(230, 126, 34, 0.4)",  # Orange for suspicious
                        "rgba(230, 126, 34, 0.4)",  # Orange
                        "rgba(39, 174, 96, 0.4)",  # Green for FP
                        "rgba(243, 156, 18, 0.4)",  # Yellow for enriched
                        "rgba(52, 152, 219, 0.4)",  # Blue for low
                        "rgba(230, 126, 34, 0.4)",  # Orange for medium
                        "rgba(231, 76, 60, 0.4)",  # Red for high
                    ][: len(links)],
                ),
            )
        )

        fig.update_layout(
            title="Detection Pipeline Event Flow",
            font=dict(size=12),
            height=400,
            margin=dict(l=20, r=20, t=50, b=20),
        )

    result = f"""
## Detection Pipeline Results

### Pipeline Stages
```
Events ({stage1_passed}) ─► ML Filter ─► LLM Enrichment ─► Alerts
     100%           {stage2_suspicious/stage1_passed*100:.0f}% suspicious    {stage4_high} high priority
```

### Stage Breakdown
1. **Ingestion:** {stage1_passed} events received
2. **ML Filter:** {stage2_benign} benign (auto-closed), {stage2_suspicious} suspicious
3. **LLM Analysis:** {stage3_false_positive} false positives, {stage3_enriched} enriched
4. **Alert Triage:** {stage4_low} low, {stage4_medium} medium, {stage4_high} high priority

### Cost Efficiency
- ML processing: ~$0.001 per 1000 events (all {stage1_passed} events)
- LLM processing: ~$0.05 per event (only {stage2_suspicious} events)
- **Total savings:** {(1 - stage2_suspicious/stage1_passed)*100:.0f}% reduction in LLM costs

### How Lab 09 Works
- Stage 1: Normalize and ingest events
- Stage 2: Isolation Forest filters noise
- Stage 3: LLM enriches suspicious events
- Stage 4: Correlation and priority-based alerting
- Sankey diagram shows event flow through pipeline
"""
    return result, fig


def demo_ir_copilot(incident_query: str) -> str:
    """Lab 10: IR Copilot Demo."""
    if not incident_query.strip():
        return "Please describe the incident or ask a question."

    # Simulated copilot responses
    responses = {
        "ransomware": """
### IR Copilot Response: Ransomware Incident

**Immediate Actions:**
1. Isolate affected systems from network
2. Preserve memory dumps before shutdown
3. Check for shadow copy deletion (vssadmin)
4. Identify patient zero and lateral movement

**Investigation Queries:**
```
# Check for ransomware indicators
index=windows EventCode=4688 | search *vssadmin* OR *bcdedit*

# Find encrypted files
index=filesystem | where entropy > 7.5
```

**Do you want me to:**
- [ ] Execute containment playbook?
- [ ] Generate IOC report?
- [ ] Check backup status?
""",
        "phishing": """
### IR Copilot Response: Phishing Incident

**Triage Steps:**
1. Identify all recipients of the phishing email
2. Check who clicked the link/opened attachment
3. Reset credentials for affected users
4. Block sender domain and URLs

**Investigation Queries:**
```
# Find email recipients
index=mail subject="*suspicious*" | stats count by recipient

# Check URL clicks
index=proxy | search clicked_url="*malicious-domain*"
```
""",
    }

    # Match query to response
    query_lower = incident_query.lower()
    response = None
    for key, resp in responses.items():
        if key in query_lower:
            response = resp
            break

    if not response:
        response = f"""
### IR Copilot Response

I'll help investigate: "{incident_query}"

**Recommended Steps:**
1. Gather initial evidence and timeline
2. Identify affected systems and users
3. Determine scope of compromise
4. Execute appropriate containment

**Available Commands:**
- `investigate <IOC>` - Deep dive on indicator
- `contain <host>` - Isolate system
- `report` - Generate incident summary

What would you like to do next?
"""

    result = f"""
## IR Copilot

{response}

### How Lab 10 Works
- Conversational interface for IR workflows
- Multi-tool orchestration (SIEM, EDR, SOAR)
- Human-in-the-loop confirmations
- Playbook execution and documentation
"""
    return result


# =============================================================================
# GRADIO INTERFACE
# =============================================================================


def create_demo():
    """Create the enhanced Gradio demo interface."""

    with gr.Blocks(title="AI for the Win - Security Labs") as demo:

        # Header with logo and status
        with gr.Row():
            with gr.Column(scale=4):
                gr.Markdown(
                    """
# AI for the Win
### Interactive Security AI Training Labs
                """
                )
            with gr.Column(scale=1):
                gr.Markdown(
                    f"""
**System Status**
{create_status_badge()}
                """
                )

        with gr.Tabs():

            # Lab 01: Phishing Classifier
            with gr.TabItem("01 Phishing"):
                gr.Markdown(
                    "### Phishing Email Classification\nAnalyze emails using weighted pattern matching."
                )

                with gr.Row():
                    with gr.Column(scale=1):
                        email_input = gr.Textbox(
                            label="Email Text", lines=5, placeholder="Paste email content..."
                        )
                        threshold = gr.Slider(
                            0.1, 0.9, value=0.5, step=0.05, label="Detection Threshold"
                        )
                        btn_01 = gr.Button("Analyze", variant="primary")
                    with gr.Column(scale=1):
                        plot_01 = gr.Plot(label="Phishing Score")
                        output_01 = gr.Markdown()

                btn_01.click(
                    demo_phishing_classifier, [email_input, threshold], [output_01, plot_01]
                )

                gr.Examples(
                    [
                        [
                            "URGENT: Your account suspended! Click here immediately to verify your identity!",
                            0.5,
                        ],
                        ["Hi team, the quarterly report is attached for review.", 0.5],
                        [
                            "Congratulations! You've won $1,000,000! Click here to claim your prize now!",
                            0.3,
                        ],
                        [
                            "Please verify your password immediately or your account will expire!",
                            0.7,
                        ],
                    ],
                    [email_input, threshold],
                )

            # Lab 02: Malware Clustering
            with gr.TabItem("02 Clustering"):
                gr.Markdown(
                    "### Malware Sample Clustering\nGroup similar malware using unsupervised learning."
                )

                with gr.Row():
                    with gr.Column():
                        n_samples = gr.Slider(
                            50, 500, value=200, step=50, label="Number of Samples"
                        )
                        n_clusters = gr.Slider(2, 10, value=5, step=1, label="Number of Clusters")
                        btn_02 = gr.Button("Cluster Samples", variant="primary")
                    with gr.Column():
                        output_02 = gr.Markdown()

                plot_02 = gr.Plot()
                btn_02.click(demo_malware_clustering, [n_samples, n_clusters], [output_02, plot_02])

                gr.Examples(
                    [
                        [200, 5],  # Default: 200 samples, 5 clusters (matches 5 families)
                        [100, 3],  # Fewer samples, fewer clusters
                        [500, 7],  # More samples, more clusters
                    ],
                    [n_samples, n_clusters],
                )

            # Lab 03: Anomaly Detection
            with gr.TabItem("03 Anomaly"):
                gr.Markdown(
                    "### Network Anomaly Detection\nDetect C2 beaconing, data exfiltration, and scanning."
                )

                with gr.Row():
                    with gr.Column():
                        bytes_sent = gr.Number(label="Bytes Sent", value=50000)
                        bytes_recv = gr.Number(label="Bytes Received", value=10000)
                        packets = gr.Number(label="Packets", value=100)
                        duration = gr.Number(label="Duration (sec)", value=30)
                        port = gr.Number(label="Port", value=443)
                        use_ml_03 = gr.Checkbox(label="Use ML Model", value=ML_AVAILABLE)
                        btn_03 = gr.Button("Detect", variant="primary")
                    with gr.Column():
                        output_03 = gr.Markdown()

                plot_03 = gr.Plot(label="Anomaly Time Series")
                btn_03.click(
                    demo_anomaly_detection,
                    [bytes_sent, bytes_recv, packets, duration, port, use_ml_03],
                    [output_03, plot_03],
                )

                gr.Examples(
                    [
                        [50000, 45000, 100, 30, 443, True],  # Normal HTTPS traffic
                        [50000000, 1000, 5000, 10, 4444, True],  # Exfil on Metasploit port
                        [100, 100, 2000, 5, 22, True],  # Port scanning behavior
                        [10000000, 500, 50, 2, 31337, True],  # Rapid exfil on leet port
                        [1000000, 500, 50, 120, 80, True],  # Large upload, normal port
                    ],
                    [bytes_sent, bytes_recv, packets, duration, port, use_ml_03],
                )

            # Lab 04: Log Analysis
            with gr.TabItem("04 Logs"):
                gr.Markdown("### LLM-Powered Log Analysis\nExtract IOCs and map to MITRE ATT&CK.")

                with gr.Row():
                    with gr.Column():
                        log_input = gr.Textbox(
                            label="Log Entries", lines=8, placeholder="Paste logs..."
                        )
                        use_llm_04 = gr.Checkbox(label="Use LLM", value=LLM_AVAILABLE)
                        btn_04 = gr.Button("Analyze", variant="primary")
                    with gr.Column():
                        output_04 = gr.Markdown()

                plot_04 = gr.Plot(label="Event Severity Timeline")
                btn_04.click(demo_log_analysis, [log_input, use_llm_04], [output_04, plot_04])

                gr.Examples(
                    [
                        [
                            "2024-01-15 03:22:10 Failed login from 185.143.223.47\n2024-01-15 03:22:11 CMD: powershell -enc SGVsbG8=\n2024-01-15 03:22:12 Connection to 192.168.1.100:4444",
                            True,
                        ],
                        [
                            "Jan 15 08:15:22 webserver sshd[1234]: Accepted publickey for admin\nJan 15 08:15:23 webserver sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash",
                            False,
                        ],
                        [
                            "ERROR: SQL injection attempt detected from 10.0.0.55\nWARNING: XSS payload in request parameter 'search'\nCRITICAL: Admin password reset from unknown IP 203.0.113.50",
                            True,
                        ],
                        [
                            "2024-01-15 12:00:00 Process cmd.exe spawned by excel.exe\n2024-01-15 12:00:01 certutil.exe downloading from http://evil.com/payload.exe\n2024-01-15 12:00:05 New scheduled task created: WindowsUpdate",
                            True,
                        ],
                    ],
                    [log_input, use_llm_04],
                )

            # Lab 05: Threat Intel
            with gr.TabItem("05 Threat Intel"):
                gr.Markdown(
                    "### Threat Intelligence Agent\nAutonomous IOC investigation using ReAct pattern."
                )

                with gr.Row():
                    with gr.Column():
                        ioc_value = gr.Textbox(
                            label="IOC Value", placeholder="IP, domain, or hash..."
                        )
                        ioc_type = gr.Dropdown(
                            ["IP Address", "Domain", "Hash"], value="IP Address", label="Type"
                        )
                        btn_05 = gr.Button("Investigate", variant="primary")
                    with gr.Column():
                        output_05 = gr.Markdown()

                plot_05 = gr.Plot(label="IOC Relationship Graph")
                btn_05.click(demo_threat_intel, [ioc_value, ioc_type], [output_05, plot_05])

                gr.Examples(
                    [
                        ["185.143.223.47", "IP Address"],
                        ["evil-domain.tk", "Domain"],
                        [
                            "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
                            "Hash",
                        ],
                        ["45.33.32.156", "IP Address"],
                    ],
                    [ioc_value, ioc_type],
                )

            # Lab 06: Security RAG
            with gr.TabItem("06 RAG"):
                gr.Markdown(
                    "### Security Knowledge RAG\nQuery security docs with semantic search + LLM."
                )

                with gr.Row():
                    with gr.Column():
                        rag_query = gr.Textbox(
                            label="Security Question", placeholder="Ask about MITRE, CVE, YARA..."
                        )
                        btn_06 = gr.Button("Search", variant="primary")
                    with gr.Column():
                        output_06 = gr.Markdown()

                btn_06.click(demo_security_rag, [rag_query], output_06)

                gr.Examples(
                    [
                        ["What is MITRE ATT&CK?"],
                        ["How do YARA rules work?"],
                        ["Tell me about ransomware detection"],
                    ],
                    [rag_query],
                )

            # Lab 07: YARA Generator
            with gr.TabItem("07 YARA"):
                gr.Markdown(
                    "### AI YARA Rule Generator\nGenerate detection rules from sample strings."
                )

                with gr.Row():
                    with gr.Column():
                        sample_strings = gr.Textbox(
                            label="Sample Strings (one per line)",
                            lines=6,
                            placeholder="http://evil.com/callback\ncmd.exe /c whoami\nCreateRemoteThread",
                        )
                        family = gr.Textbox(label="Malware Family", value="GenericTrojan")
                        rule_name = gr.Textbox(label="Rule Name (optional)")
                        btn_07 = gr.Button("Generate Rule", variant="primary")
                    with gr.Column():
                        output_07 = gr.Markdown()

                btn_07.click(demo_yara_generator, [sample_strings, family, rule_name], output_07)

                gr.Examples(
                    [
                        [
                            "http://evil-c2.com/beacon\ncmd.exe /c whoami\nCreateRemoteThread\nVirtualAllocEx",
                            "CobaltStrike",
                            "Detect_CobaltStrike",
                        ],
                        [
                            "ransom_note.txt\nvssadmin delete shadows\nYour files have been encrypted\n.locked extension",
                            "Ransomware",
                            "Detect_Ransomware",
                        ],
                        [
                            "keylogger.dll\nGetAsyncKeyState\nSetWindowsHookEx\nClipboardData",
                            "Keylogger",
                            "Detect_Keylogger",
                        ],
                    ],
                    [sample_strings, family, rule_name],
                )

            # Lab 08: Vuln Scanner
            with gr.TabItem("08 Vulns"):
                gr.Markdown(
                    "### Vulnerability Scanner AI\nPrioritize CVEs based on exploitability and risk."
                )

                with gr.Row():
                    with gr.Column():
                        cve_input = gr.Textbox(
                            label="CVE IDs (one per line)",
                            lines=5,
                            placeholder="CVE-2021-44228\nCVE-2023-23397",
                        )
                        btn_08 = gr.Button("Analyze", variant="primary")
                    with gr.Column():
                        output_08 = gr.Markdown()

                btn_08.click(demo_vuln_scanner, [cve_input], output_08)

                gr.Examples(
                    [
                        ["CVE-2021-44228\nCVE-2023-23397\nCVE-2024-3094"],
                        ["CVE-2023-4966\nCVE-2021-44228"],
                        ["CVE-2024-1234\nCVE-2023-9999"],  # Unknown CVEs
                    ],
                    [cve_input],
                )

            # Lab 09: Detection Pipeline
            with gr.TabItem("09 Pipeline"):
                gr.Markdown(
                    "### Threat Detection Pipeline\nMulti-stage ML + LLM detection with cost optimization."
                )

                with gr.Row():
                    with gr.Column():
                        events_input = gr.Textbox(
                            label="Security Events",
                            lines=6,
                            placeholder="Enter security events (one per line)...",
                        )
                        btn_09 = gr.Button("Process", variant="primary")
                    with gr.Column():
                        output_09 = gr.Markdown()

                plot_09 = gr.Plot(label="Pipeline Flow (Sankey)")
                btn_09.click(demo_detection_pipeline, [events_input], [output_09, plot_09])

                gr.Examples(
                    [
                        [
                            "User login from new location\nFile download from SharePoint\nEmail sent to external recipient\nVPN connection established\nLarge file upload detected"
                        ],
                        [
                            "Failed login attempt\nFailed login attempt\nFailed login attempt\nAccount lockout triggered\nPassword reset requested"
                        ],
                        [
                            "Process cmd.exe spawned\nPowerShell execution\nRegistry modification\nScheduled task created\nOutbound connection to unknown IP"
                        ],
                    ],
                    [events_input],
                )

            # Lab 10: IR Copilot
            with gr.TabItem("10 IR Copilot"):
                gr.Markdown(
                    "### Incident Response Copilot\nConversational IR assistant with playbook execution."
                )

                with gr.Row():
                    with gr.Column():
                        ir_query = gr.Textbox(
                            label="Describe the incident",
                            lines=4,
                            placeholder="We detected ransomware on server-01...",
                        )
                        btn_10 = gr.Button("Get Help", variant="primary")
                    with gr.Column():
                        output_10 = gr.Markdown()

                btn_10.click(demo_ir_copilot, [ir_query], output_10)

                gr.Examples(
                    [
                        ["We detected ransomware on multiple systems"],
                        ["User reported clicking a phishing link"],
                    ],
                    [ir_query],
                )

        gr.Markdown(
            """
---
**Quick Guide:** Labs 01-03 (ML) | Labs 04-07 (LLM) | Labs 08-10 (Advanced)

For full implementations, complete the hands-on labs in the `labs/` directory.
        """
        )

    return demo


# =============================================================================
# MAIN
# =============================================================================


def main():
    """Launch the Gradio demo."""
    print("=" * 60)
    print("AI for the Win - Enhanced Demo Launcher")
    print("=" * 60)
    print(f"\nStatus: {create_status_badge()}")

    demo = create_demo()

    print("\nLaunching demo server...")
    print("Open http://localhost:7860 in your browser")
    print("Press Ctrl+C to stop\n")

    demo.launch(server_name="0.0.0.0", server_port=7860, share=False, theme=gr.themes.Soft())


if __name__ == "__main__":
    main()
