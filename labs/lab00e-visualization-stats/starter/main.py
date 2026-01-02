"""
Lab 00e: Visualization & Statistics for Security - Starter Code

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

    TODO: Calculate and return:
    - mean: Average value
    - median: Middle value (robust to outliers)
    - std: Standard deviation (variability)
    - min/max: Range boundaries
    - p95: 95th percentile (for SLA thresholds)
    - p99: 99th percentile

    Args:
        values: List of numeric values (e.g., response times, request counts)

    Returns:
        Dictionary with statistical measures
    """
    # TODO: Implement statistical calculations
    # Hint: Use np.mean(), np.median(), np.std(), np.percentile()

    return {
        "mean": None,  # TODO
        "median": None,  # TODO
        "std": None,  # TODO
        "min": None,  # TODO
        "max": None,  # TODO
        "p95": None,  # TODO
        "p99": None,  # TODO
    }


def calculate_zscore(values: list[float]) -> list[float]:
    """
    Calculate Z-scores for anomaly detection.

    Z-score = (value - mean) / std_dev

    Values with |z-score| > 2 are often considered anomalies.

    TODO: Calculate z-scores for each value

    Args:
        values: List of numeric values

    Returns:
        List of z-scores
    """
    # TODO: Implement z-score calculation
    # Hint: Use scipy.stats.zscore() or calculate manually

    pass  # TODO: Replace with implementation


# =============================================================================
# Exercise 2: Distribution Visualization
# =============================================================================


def plot_threat_score_distribution(scores: list[float]) -> go.Figure:
    """
    Create a histogram of threat scores with statistics overlay.

    TODO: Create a Plotly histogram showing:
    - Distribution of threat scores (0-1 range)
    - Vertical lines for mean and median
    - Color coding by threat level (low/medium/high)

    Args:
        scores: List of threat scores (0.0 to 1.0)

    Returns:
        Plotly Figure object
    """
    # TODO: Create histogram using px.histogram or go.Histogram
    # Hint: Add vertical lines with fig.add_vline()
    # Hint: Use color to distinguish threat levels

    fig = go.Figure()

    # TODO: Add histogram trace

    # TODO: Add mean/median lines

    # TODO: Update layout with title and labels

    return fig


def plot_response_time_boxplot(df: pd.DataFrame) -> go.Figure:
    """
    Create box plots comparing response times by event type.

    Box plots show:
    - Median (center line)
    - IQR (box)
    - Whiskers (1.5 * IQR)
    - Outliers (points beyond whiskers)

    TODO: Create box plots grouped by event_type

    Args:
        df: DataFrame with 'event_type' and 'response_ms' columns

    Returns:
        Plotly Figure object
    """
    # TODO: Create box plot using px.box()
    # Hint: x="event_type", y="response_ms"

    pass  # TODO: Replace with implementation


# =============================================================================
# Exercise 3: Time Series Dashboard
# =============================================================================


def plot_traffic_timeline(traffic_df: pd.DataFrame) -> go.Figure:
    """
    Create an interactive time series of network traffic.

    TODO: Create a multi-trace line chart showing:
    - Request count over time
    - Error count (secondary y-axis)
    - Highlight anomalous hours

    Args:
        traffic_df: DataFrame with 'hour', 'requests', 'errors' columns

    Returns:
        Plotly Figure object
    """
    # TODO: Create figure with secondary y-axis
    # Hint: Use make_subplots(specs=[[{"secondary_y": True}]])

    fig = make_subplots(specs=[[{"secondary_y": True}]])

    # TODO: Add requests trace (primary y-axis)

    # TODO: Add errors trace (secondary y-axis)

    # TODO: Update layout and axis labels

    return fig


# =============================================================================
# Exercise 4: Correlation Heatmap
# =============================================================================


def plot_correlation_heatmap(
    df: pd.DataFrame, columns: list[str], labels: dict[str, str] | None = None
) -> go.Figure:
    """
    Create an improved correlation heatmap for security features.

    Correlation values:
    - +1: Perfect positive correlation (both variables increase together)
    - 0: No correlation (no relationship)
    - -1: Perfect negative correlation (one increases, other decreases)

    TODO: Create a heatmap showing correlations between features

    Improvements to implement:
    - Mask upper triangle (matrix is symmetric, redundant data)
    - Add significance markers (*** >0.9, ** >0.7, * >0.5)
    - Use human-readable labels
    - Add clear colorbar with interpretation

    Args:
        df: DataFrame with numeric columns
        columns: List of column names to include
        labels: Optional dict mapping column names to display labels

    Returns:
        Plotly Figure object
    """
    # TODO: Calculate correlation matrix
    # Hint: corr_matrix = df[columns].corr()

    # TODO: Create display labels (optional improvement)
    # Hint: labels = {c: c.replace("_", " ").title() for c in columns}

    # TODO: Mask upper triangle for cleaner visualization
    # Hint: mask = np.triu(np.ones_like(corr_matrix, dtype=bool), k=1)
    #       masked_corr = corr_matrix.where(~mask)

    # TODO: Create heatmap using go.Heatmap
    # Key parameters:
    #   - z: correlation values
    #   - colorscale: "RdBu_r" (blue=positive, red=negative)
    #   - zmid: 0 (center color scale at zero)
    #   - text: annotation values
    #   - texttemplate: "%{text}"

    pass  # TODO: Replace with implementation


# =============================================================================
# Exercise 5: Security Dashboard
# =============================================================================


def create_security_dashboard(data: dict) -> go.Figure:
    """
    Create a comprehensive security dashboard with multiple panels.

    TODO: Create a 2x2 dashboard with:
    1. Traffic timeline (top-left)
    2. Threat score distribution (top-right)
    3. Events by severity (bottom-left)
    4. Top source IPs (bottom-right)

    Args:
        data: Dictionary with security event data

    Returns:
        Plotly Figure with subplots
    """
    # TODO: Create 2x2 subplot grid
    # Hint: make_subplots(rows=2, cols=2, subplot_titles=[...])

    fig = make_subplots(
        rows=2,
        cols=2,
        subplot_titles=[
            "Traffic Over Time",
            "Threat Score Distribution",
            "Events by Severity",
            "Top Source IPs",
        ],
    )

    # TODO: Add traces to each subplot
    # Hint: Use row=1, col=1 for top-left, etc.

    # TODO: Update layout

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
        if value is not None:
            print(f"  {key}: {value:.2f}")
        else:
            print(f"  {key}: TODO - implement calculate_baseline_stats()")
            break

    # Z-score analysis
    z_scores = calculate_zscore(requests)
    if z_scores is not None:
        anomalies = [(i, z) for i, z in enumerate(z_scores) if abs(z) > 2]
        print(f"\nAnomaly detection (|z| > 2): {len(anomalies)} anomalies found")
        for hour, z in anomalies:
            print(f"  Hour {hour}: z-score = {z:.2f}")
    else:
        print("\nTODO - implement calculate_zscore()")

    # Exercise 2: Distribution Visualization
    print("\n📈 Exercise 2: Distribution Visualization")
    print("-" * 40)

    fig_dist = plot_threat_score_distribution(threat_scores)
    if fig_dist and len(fig_dist.data) > 0:
        print("✅ Threat score distribution created")
        fig_dist.show()
    else:
        print("TODO - implement plot_threat_score_distribution()")

    fig_box = plot_response_time_boxplot(events_df)
    if fig_box:
        print("✅ Response time box plot created")
        fig_box.show()
    else:
        print("TODO - implement plot_response_time_boxplot()")

    # Exercise 3: Time Series
    print("\n📉 Exercise 3: Time Series Dashboard")
    print("-" * 40)

    fig_timeline = plot_traffic_timeline(traffic_df)
    if fig_timeline and len(fig_timeline.data) > 0:
        print("✅ Traffic timeline created")
        fig_timeline.show()
    else:
        print("TODO - implement plot_traffic_timeline()")

    # Exercise 4: Correlation Heatmap
    print("\n🔥 Exercise 4: Correlation Heatmap")
    print("-" * 40)

    fig_corr = plot_correlation_heatmap(traffic_df, ["requests", "bytes_in", "bytes_out", "errors"])
    if fig_corr:
        print("✅ Correlation heatmap created")
        fig_corr.show()
    else:
        print("TODO - implement plot_correlation_heatmap()")

    # Exercise 5: Security Dashboard
    print("\n🖥️  Exercise 5: Security Dashboard")
    print("-" * 40)

    fig_dashboard = create_security_dashboard(data)
    if fig_dashboard and len(fig_dashboard.data) > 0:
        print("✅ Security dashboard created")
        fig_dashboard.show()
    else:
        print("TODO - implement create_security_dashboard()")

    print("\n" + "=" * 60)
    print("Lab complete! Check the generated visualizations.")
    print("=" * 60)


if __name__ == "__main__":
    main()
