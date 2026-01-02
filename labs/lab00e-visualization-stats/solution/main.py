"""
Lab 00e: Visualization & Statistics for Security - Solution

Learn to create interactive visualizations and perform statistical analysis
on security data using Plotly and Python.

No API keys required!
"""

import json
import sys
from pathlib import Path

# Fix Windows console encoding for emojis
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from scipy import stats

# Plotly template for consistent styling
PLOTLY_TEMPLATE = "plotly_white"

# Color scheme for security visualizations
COLORS = {
    "primary": "#2E86AB",
    "secondary": "#A23B72",
    "success": "#2ECC71",
    "warning": "#F39C12",
    "danger": "#E74C3C",
    "info": "#3498DB",
}


def load_security_data() -> dict:
    """Load sample security event data."""
    data_path = Path(__file__).parent.parent / "data" / "security_events.json"
    with open(data_path) as f:
        return json.load(f)


# =============================================================================
# Exercise 1: Statistical Analysis
# =============================================================================


def calculate_baseline_stats(values: list[float]) -> dict:
    """
    Calculate baseline statistics for security metrics.

    These statistics help establish normal behavior baselines
    for anomaly detection and SLA monitoring.

    Args:
        values: List of numeric values (e.g., response times, request counts)

    Returns:
        Dictionary with statistical measures
    """
    arr = np.array(values)
    return {
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "std": float(np.std(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
    }


def calculate_zscore(values: list[float]) -> list[float]:
    """
    Calculate Z-scores for anomaly detection.

    Z-score = (value - mean) / std_dev

    Values with |z-score| > 2 are often considered anomalies.
    Values with |z-score| > 3 are extreme outliers.

    Args:
        values: List of numeric values

    Returns:
        List of z-scores
    """
    return stats.zscore(values).tolist()


# =============================================================================
# Exercise 2: Distribution Visualization
# =============================================================================


def plot_threat_score_distribution(scores: list[float]) -> go.Figure:
    """
    Create a histogram of threat scores with statistics overlay.

    Args:
        scores: List of threat scores (0.0 to 1.0)

    Returns:
        Plotly Figure object
    """
    # Create DataFrame for easier manipulation
    df = pd.DataFrame({"score": scores})

    # Categorize threat levels
    df["threat_level"] = pd.cut(
        df["score"],
        bins=[0, 0.3, 0.7, 1.0],
        labels=["Low", "Medium", "High"],
        include_lowest=True,
    )

    # Calculate statistics
    mean_score = np.mean(scores)
    median_score = np.median(scores)

    # Create histogram with color by threat level
    fig = px.histogram(
        df,
        x="score",
        color="threat_level",
        nbins=20,
        title="Threat Score Distribution",
        template=PLOTLY_TEMPLATE,
        color_discrete_map={
            "Low": COLORS["success"],
            "Medium": COLORS["warning"],
            "High": COLORS["danger"],
        },
    )

    # Add mean line
    fig.add_vline(
        x=mean_score,
        line_dash="dash",
        line_color=COLORS["primary"],
        annotation_text=f"Mean: {mean_score:.2f}",
        annotation_position="top",
    )

    # Add median line
    fig.add_vline(
        x=median_score,
        line_dash="dot",
        line_color=COLORS["secondary"],
        annotation_text=f"Median: {median_score:.2f}",
        annotation_position="bottom",
    )

    # Update layout
    fig.update_layout(
        xaxis_title="Threat Score",
        yaxis_title="Count",
        legend_title="Threat Level",
        height=400,
        bargap=0.1,
    )

    return fig


def plot_response_time_boxplot(df: pd.DataFrame) -> go.Figure:
    """
    Create box plots comparing response times by event type.

    Box plots show:
    - Median (center line)
    - IQR (box)
    - Whiskers (1.5 * IQR)
    - Outliers (points beyond whiskers)

    Args:
        df: DataFrame with 'event_type' and 'response_ms' columns

    Returns:
        Plotly Figure object
    """
    fig = px.box(
        df,
        x="event_type",
        y="response_ms",
        color="event_type",
        title="Response Time Distribution by Event Type",
        template=PLOTLY_TEMPLATE,
        points="outliers",  # Show outlier points
    )

    fig.update_layout(
        xaxis_title="Event Type",
        yaxis_title="Response Time (ms)",
        showlegend=False,
        height=400,
    )

    # Add threshold line for SLA
    fig.add_hline(
        y=100,
        line_dash="dash",
        line_color=COLORS["warning"],
        annotation_text="SLA Threshold (100ms)",
        annotation_position="right",
    )

    return fig


# =============================================================================
# Exercise 3: Time Series Dashboard
# =============================================================================


def plot_traffic_timeline(traffic_df: pd.DataFrame) -> go.Figure:
    """
    Create an interactive time series of network traffic.

    Args:
        traffic_df: DataFrame with 'hour', 'requests', 'errors' columns

    Returns:
        Plotly Figure object
    """
    # Calculate z-scores to identify anomalies
    z_scores = stats.zscore(traffic_df["requests"])
    traffic_df["is_anomaly"] = abs(z_scores) > 2

    # Create figure with secondary y-axis
    fig = make_subplots(specs=[[{"secondary_y": True}]])

    # Add requests trace (primary y-axis)
    fig.add_trace(
        go.Scatter(
            x=traffic_df["hour"],
            y=traffic_df["requests"],
            name="Requests",
            mode="lines+markers",
            line=dict(color=COLORS["primary"], width=2),
            marker=dict(size=8),
            hovertemplate="Hour %{x}<br>Requests: %{y:,}<extra></extra>",
        ),
        secondary_y=False,
    )

    # Highlight anomalies
    anomaly_df = traffic_df[traffic_df["is_anomaly"]]
    if not anomaly_df.empty:
        fig.add_trace(
            go.Scatter(
                x=anomaly_df["hour"],
                y=anomaly_df["requests"],
                name="Anomaly",
                mode="markers",
                marker=dict(color=COLORS["danger"], size=15, symbol="x"),
                hovertemplate="⚠️ ANOMALY<br>Hour %{x}<br>Requests: %{y:,}<extra></extra>",
            ),
            secondary_y=False,
        )

    # Add errors trace (secondary y-axis)
    fig.add_trace(
        go.Scatter(
            x=traffic_df["hour"],
            y=traffic_df["errors"],
            name="Errors",
            mode="lines+markers",
            line=dict(color=COLORS["danger"], width=2, dash="dot"),
            marker=dict(size=6),
            hovertemplate="Hour %{x}<br>Errors: %{y}<extra></extra>",
        ),
        secondary_y=True,
    )

    # Update layout
    fig.update_layout(
        title="Network Traffic Over 24 Hours",
        template=PLOTLY_TEMPLATE,
        height=450,
        legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01),
        hovermode="x unified",
    )

    fig.update_xaxes(title_text="Hour of Day", dtick=2)
    fig.update_yaxes(title_text="Request Count", secondary_y=False)
    fig.update_yaxes(title_text="Error Count", secondary_y=True)

    return fig


# =============================================================================
# Exercise 4: Correlation Heatmap
# =============================================================================


def plot_correlation_heatmap(df: pd.DataFrame, columns: list[str]) -> go.Figure:
    """
    Create a correlation heatmap for security features.

    Correlation values:
    - +1: Perfect positive correlation
    - 0: No correlation
    - -1: Perfect negative correlation

    Args:
        df: DataFrame with numeric columns
        columns: List of column names to include

    Returns:
        Plotly Figure object
    """
    # Calculate correlation matrix
    corr_matrix = df[columns].corr()

    # Create heatmap
    fig = go.Figure(
        data=go.Heatmap(
            z=corr_matrix.values,
            x=corr_matrix.columns,
            y=corr_matrix.index,
            colorscale="RdBu_r",
            zmid=0,
            text=np.round(corr_matrix.values, 2),
            texttemplate="%{text}",
            textfont={"size": 12},
            hovertemplate="%{x} vs %{y}<br>Correlation: %{z:.3f}<extra></extra>",
        )
    )

    fig.update_layout(
        title="Feature Correlation Matrix",
        template=PLOTLY_TEMPLATE,
        height=450,
        width=500,
        xaxis_title="Feature",
        yaxis_title="Feature",
    )

    return fig


# =============================================================================
# Exercise 5: Security Dashboard
# =============================================================================


def create_security_dashboard(data: dict) -> go.Figure:
    """
    Create a comprehensive security dashboard with multiple panels.

    Args:
        data: Dictionary with security event data

    Returns:
        Plotly Figure with subplots
    """
    # Prepare data
    events_df = pd.DataFrame(data["events"])
    traffic_df = pd.DataFrame(data["traffic_samples"])
    threat_scores = data["threat_scores"]

    # Create 2x2 subplot grid
    fig = make_subplots(
        rows=2,
        cols=2,
        subplot_titles=[
            "📈 Traffic Over Time",
            "🎯 Threat Score Distribution",
            "⚠️ Events by Severity",
            "🌐 Top Source IPs",
        ],
        specs=[
            [{"secondary_y": True}, {}],
            [{}, {}],
        ],
        vertical_spacing=0.15,
        horizontal_spacing=0.1,
    )

    # Panel 1: Traffic timeline (top-left)
    fig.add_trace(
        go.Scatter(
            x=traffic_df["hour"],
            y=traffic_df["requests"],
            name="Requests",
            mode="lines+markers",
            line=dict(color=COLORS["primary"]),
        ),
        row=1,
        col=1,
        secondary_y=False,
    )
    fig.add_trace(
        go.Scatter(
            x=traffic_df["hour"],
            y=traffic_df["errors"],
            name="Errors",
            mode="lines",
            line=dict(color=COLORS["danger"], dash="dot"),
        ),
        row=1,
        col=1,
        secondary_y=True,
    )

    # Panel 2: Threat score histogram (top-right)
    fig.add_trace(
        go.Histogram(
            x=threat_scores,
            nbinsx=15,
            name="Threat Scores",
            marker_color=COLORS["warning"],
            showlegend=False,
        ),
        row=1,
        col=2,
    )

    # Panel 3: Events by severity (bottom-left)
    severity_counts = events_df["severity"].value_counts()
    severity_colors = {
        "info": COLORS["info"],
        "warning": COLORS["warning"],
        "critical": COLORS["danger"],
    }
    fig.add_trace(
        go.Bar(
            x=severity_counts.index,
            y=severity_counts.values,
            name="Severity",
            marker_color=[severity_colors.get(s, COLORS["primary"]) for s in severity_counts.index],
            showlegend=False,
        ),
        row=2,
        col=1,
    )

    # Panel 4: Top source IPs (bottom-right)
    ip_counts = events_df["source_ip"].value_counts().head(5)
    fig.add_trace(
        go.Bar(
            x=ip_counts.values,
            y=ip_counts.index,
            orientation="h",
            name="Source IPs",
            marker_color=COLORS["secondary"],
            showlegend=False,
        ),
        row=2,
        col=2,
    )

    # Update layout
    fig.update_layout(
        title=dict(
            text="🔒 Security Operations Dashboard",
            font=dict(size=20),
        ),
        template=PLOTLY_TEMPLATE,
        height=700,
        width=1000,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )

    # Update axes labels
    fig.update_xaxes(title_text="Hour", row=1, col=1)
    fig.update_yaxes(title_text="Requests", row=1, col=1, secondary_y=False)
    fig.update_yaxes(title_text="Errors", row=1, col=1, secondary_y=True)

    fig.update_xaxes(title_text="Threat Score", row=1, col=2)
    fig.update_yaxes(title_text="Count", row=1, col=2)

    fig.update_xaxes(title_text="Severity Level", row=2, col=1)
    fig.update_yaxes(title_text="Event Count", row=2, col=1)

    fig.update_xaxes(title_text="Event Count", row=2, col=2)
    fig.update_yaxes(title_text="Source IP", row=2, col=2)

    return fig


# =============================================================================
# Bonus: Advanced Visualizations
# =============================================================================


def plot_attack_timeline(events_df: pd.DataFrame) -> go.Figure:
    """
    Create an attack timeline visualization showing event progression.

    Args:
        events_df: DataFrame with timestamp and severity columns

    Returns:
        Plotly Figure object
    """
    events_df = events_df.copy()
    events_df["timestamp"] = pd.to_datetime(events_df["timestamp"])

    severity_map = {"info": 1, "warning": 2, "critical": 3}
    events_df["severity_num"] = events_df["severity"].map(severity_map)

    fig = px.scatter(
        events_df,
        x="timestamp",
        y="event_type",
        color="severity",
        size="severity_num",
        title="Attack Timeline",
        template=PLOTLY_TEMPLATE,
        color_discrete_map={
            "info": COLORS["info"],
            "warning": COLORS["warning"],
            "critical": COLORS["danger"],
        },
        hover_data=["source_ip", "user"],
    )

    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Event Type",
        height=400,
    )

    return fig


def plot_exfiltration_detection(traffic_df: pd.DataFrame) -> go.Figure:
    """
    Detect potential data exfiltration by analyzing bytes out/in ratio.

    Normal traffic: bytes_out << bytes_in (downloading content)
    Exfiltration: bytes_out >> bytes_in (uploading/stealing data)

    Args:
        traffic_df: DataFrame with bytes_in and bytes_out columns

    Returns:
        Plotly Figure object
    """
    df = traffic_df.copy()

    # Calculate exfiltration risk metrics
    df["out_in_ratio"] = df["bytes_out"] / df["bytes_in"]
    df["total_bytes"] = df["bytes_in"] + df["bytes_out"]

    # Normal ratio is ~0.25 (25% out vs in), flag if > 0.5
    baseline_ratio = df["out_in_ratio"].median()
    df["ratio_zscore"] = stats.zscore(df["out_in_ratio"])
    df["exfil_risk"] = pd.cut(
        df["out_in_ratio"],
        bins=[0, 0.3, 0.5, 1.0, float("inf")],
        labels=["Normal", "Elevated", "Suspicious", "Critical"],
    )

    # Create multi-panel figure
    fig = make_subplots(
        rows=2,
        cols=2,
        subplot_titles=[
            "Bytes Out/In Ratio Over Time",
            "Exfiltration Risk by Hour",
            "Bandwidth Distribution",
            "Risk Assessment",
        ],
        specs=[
            [{"secondary_y": True}, {}],
            [{}, {"type": "pie"}],
        ],
    )

    # Panel 1: Ratio over time with threshold
    fig.add_trace(
        go.Scatter(
            x=df["hour"],
            y=df["out_in_ratio"],
            mode="lines+markers",
            name="Out/In Ratio",
            line=dict(color=COLORS["primary"], width=2),
            hovertemplate="Hour %{x}<br>Ratio: %{y:.2f}<extra></extra>",
        ),
        row=1,
        col=1,
    )

    # Add threshold line
    fig.add_hline(
        y=0.5,
        line_dash="dash",
        line_color=COLORS["warning"],
        annotation_text="Elevated Risk",
        row=1,
        col=1,
    )
    fig.add_hline(
        y=1.0,
        line_dash="dash",
        line_color=COLORS["danger"],
        annotation_text="Critical Risk",
        row=1,
        col=1,
    )

    # Panel 2: Stacked bar of bytes in/out
    fig.add_trace(
        go.Bar(
            x=df["hour"],
            y=df["bytes_in"] / 1000,
            name="Bytes In (KB)",
            marker_color=COLORS["info"],
        ),
        row=1,
        col=2,
    )
    fig.add_trace(
        go.Bar(
            x=df["hour"],
            y=df["bytes_out"] / 1000,
            name="Bytes Out (KB)",
            marker_color=COLORS["warning"],
        ),
        row=1,
        col=2,
    )

    # Panel 3: Histogram of ratios
    risk_colors = {
        "Normal": COLORS["success"],
        "Elevated": COLORS["warning"],
        "Suspicious": COLORS["danger"],
        "Critical": "#8B0000",
    }
    for risk in ["Normal", "Elevated", "Suspicious", "Critical"]:
        risk_data = df[df["exfil_risk"] == risk]
        if not risk_data.empty:
            fig.add_trace(
                go.Histogram(
                    x=risk_data["out_in_ratio"],
                    name=risk,
                    marker_color=risk_colors[risk],
                    opacity=0.7,
                ),
                row=2,
                col=1,
            )

    # Panel 4: Risk pie chart
    risk_counts = df["exfil_risk"].value_counts()
    fig.add_trace(
        go.Pie(
            labels=risk_counts.index,
            values=risk_counts.values,
            marker_colors=[risk_colors.get(r, "gray") for r in risk_counts.index],
            hole=0.4,
            textinfo="label+percent",
        ),
        row=2,
        col=2,
    )

    fig.update_layout(
        title=dict(
            text="🔍 Data Exfiltration Detection Dashboard",
            font=dict(size=18),
        ),
        template=PLOTLY_TEMPLATE,
        height=600,
        width=1000,
        barmode="group",
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
    )

    fig.update_xaxes(title_text="Hour", row=1, col=1)
    fig.update_yaxes(title_text="Out/In Ratio", row=1, col=1)
    fig.update_xaxes(title_text="Hour", row=1, col=2)
    fig.update_yaxes(title_text="Kilobytes", row=1, col=2)
    fig.update_xaxes(title_text="Out/In Ratio", row=2, col=1)
    fig.update_yaxes(title_text="Count", row=2, col=1)

    return fig


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Run all visualization exercises."""
    print("=" * 60)
    print("Lab 00e: Visualization & Statistics for Security")
    print("=" * 60)

    # Load data
    data = load_security_data()
    events_df = pd.DataFrame(data["events"])
    traffic_df = pd.DataFrame(data["traffic_samples"])
    threat_scores = data["threat_scores"]

    # Exercise 1: Statistical Analysis
    print("\n📊 Exercise 1: Statistical Analysis")
    print("-" * 40)

    requests = traffic_df["requests"].tolist()
    baseline = calculate_baseline_stats(requests)
    print("Traffic baseline statistics:")
    for key, value in baseline.items():
        print(f"  {key}: {value:.2f}")

    # Z-score analysis
    z_scores = calculate_zscore(requests)
    anomalies = [(i, z) for i, z in enumerate(z_scores) if abs(z) > 2]
    print(f"\nAnomaly detection (|z| > 2): {len(anomalies)} anomalies found")
    for hour, z in anomalies:
        print(f"  Hour {hour}: z-score = {z:.2f} (requests: {requests[hour]:,})")

    # Exercise 2: Distribution Visualization
    print("\n📈 Exercise 2: Distribution Visualization")
    print("-" * 40)

    fig_dist = plot_threat_score_distribution(threat_scores)
    print("✅ Threat score distribution created")
    fig_dist.show()

    fig_box = plot_response_time_boxplot(events_df)
    print("✅ Response time box plot created")
    fig_box.show()

    # Exercise 3: Time Series
    print("\n📉 Exercise 3: Time Series Dashboard")
    print("-" * 40)

    fig_timeline = plot_traffic_timeline(traffic_df)
    print("✅ Traffic timeline created")
    fig_timeline.show()

    # Exercise 4: Correlation Heatmap
    print("\n🔥 Exercise 4: Correlation Heatmap")
    print("-" * 40)

    fig_corr = plot_correlation_heatmap(traffic_df, ["requests", "bytes_in", "bytes_out", "errors"])
    print("✅ Correlation heatmap created")
    fig_corr.show()

    # Exercise 5: Security Dashboard
    print("\n🖥️  Exercise 5: Security Dashboard")
    print("-" * 40)

    fig_dashboard = create_security_dashboard(data)
    print("✅ Security dashboard created")
    fig_dashboard.show()

    # Bonus visualizations
    print("\n🎁 Bonus Visualizations")
    print("-" * 40)

    fig_attack = plot_attack_timeline(events_df)
    print("✅ Attack timeline created")
    fig_attack.show()

    fig_exfil = plot_exfiltration_detection(traffic_df)
    print("✅ Exfiltration detection dashboard created")
    fig_exfil.show()

    print("\n" + "=" * 60)
    print("Lab complete! Check the generated visualizations.")
    print("=" * 60)

    # Summary statistics
    print("\n📋 Summary:")
    print(f"  - Events analyzed: {len(events_df)}")
    print(f"  - Traffic hours: {len(traffic_df)}")
    print(f"  - Threat scores: {len(threat_scores)}")
    print(f"  - Critical events: {(events_df['severity'] == 'critical').sum()}")
    print(f"  - Traffic anomalies: {len(anomalies)}")


if __name__ == "__main__":
    main()
