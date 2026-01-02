# Lab 00e: Visualization & Statistics Walkthrough

Step-by-step guide to mastering data visualization and statistical analysis for security data.

## Overview

This lab teaches you to:
1. Calculate baseline statistics for anomaly detection
2. Use Z-scores to identify outliers
3. Create interactive visualizations with Plotly
4. Build security dashboards

**Difficulty:** Intro  
**Time:** 30-45 minutes  
**Prerequisites:** Basic Python (Lab 00a)

---

## Exercise 1: Statistical Analysis

### Objective
Calculate baseline statistics to establish "normal" behavior.

### Key Concepts

| Statistic | Purpose in Security |
|-----------|---------------------|
| Mean | Establish average baseline |
| Median | Robust to outliers (better for traffic) |
| Std Dev | Measure variability |
| P95/P99 | SLA thresholds |
| Z-Score | Anomaly scoring |

### Solution Walkthrough

```python
def calculate_baseline_stats(values):
    """Calculate baseline statistics."""
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
```

**Why these statistics?**
- **Mean vs Median**: For security data, median is often better because it's not affected by outliers (attacks)
- **P95/P99**: Critical for SLAs - "99% of requests complete in X ms"
- **Std Dev**: High std dev = unpredictable traffic (potential attack)

### Z-Score Analysis

```python
from scipy import stats

z_scores = stats.zscore(traffic_df["requests"])
anomalies = traffic_df[abs(z_scores) > 2]  # |z| > 2 is unusual
```

**Interpretation:**
- |z| > 2: Unusual (5% probability)
- |z| > 3: Extreme outlier (0.3% probability)

---

## Exercise 2: Distribution Visualization

### Objective
Visualize how data is distributed to understand normal patterns.

### Histogram with Statistics

```python
fig = px.histogram(
    df,
    x="score",
    color="threat_level",
    nbins=25,
    title="Threat Score Distribution",
    color_discrete_map={
        "Low": "#2ECC71",
        "Medium": "#F39C12",
        "High": "#E74C3C",
    },
)

# Add reference lines
fig.add_vline(x=mean_score, line_dash="dash", annotation_text=f"Mean: {mean_score:.2f}")
fig.add_vline(x=median_score, line_dash="dot", annotation_text=f"Median: {median_score:.2f}")
```

**Why this matters:**
- Color-coding by threat level shows imbalanced classes
- Mean vs median difference reveals skew
- Helps set appropriate thresholds

### Box Plot for Group Comparison

```python
fig = px.box(
    events_df,
    x="event_type",
    y="response_ms",
    color="severity",
    points="outliers",  # Show outlier points
)

# Add SLA threshold
fig.add_hline(y=100, line_dash="dash", annotation_text="SLA: 100ms")
```

**Box plot components:**
- Box: Interquartile range (IQR = Q3 - Q1)
- Line: Median
- Whiskers: 1.5 × IQR
- Points: Outliers beyond whiskers

---

## Exercise 3: Time Series Dashboard

### Objective
Visualize temporal patterns to identify attack windows.

### Multi-Axis Time Series

```python
fig = make_subplots(specs=[[{"secondary_y": True}]])

# Primary axis: Requests
fig.add_trace(
    go.Scatter(x=df["hour"], y=df["requests"], name="Requests"),
    secondary_y=False,
)

# Secondary axis: Errors
fig.add_trace(
    go.Scatter(x=df["hour"], y=df["errors"], name="Errors", line=dict(dash="dot")),
    secondary_y=True,
)

fig.update_yaxes(title_text="Requests", secondary_y=False)
fig.update_yaxes(title_text="Errors", secondary_y=True)
```

**Why secondary axis?**
- Requests and errors have different scales
- Correlation is visible (errors spike when requests spike)
- Anomalies are highlighted against baseline

### Highlighting Anomalies

```python
# Mark anomaly points
anomaly_df = traffic_df[traffic_df["is_anomaly"]]
fig.add_trace(
    go.Scatter(
        x=anomaly_df["hour"],
        y=anomaly_df["requests"],
        name="⚠️ Anomaly",
        mode="markers",
        marker=dict(color="red", size=18, symbol="x"),
    )
)
```

---

## Exercise 4: Correlation Heatmap

### Objective
Discover relationships between security features.

### Creating the Heatmap

```python
corr_matrix = df[columns].corr()

fig = go.Figure(
    data=go.Heatmap(
        z=corr_matrix.values,
        x=corr_matrix.columns,
        y=corr_matrix.index,
        colorscale="RdBu_r",  # Red-Blue, reversed
        zmid=0,  # Center at 0
        text=np.round(corr_matrix.values, 2),
        texttemplate="%{text}",
    )
)
```

**Correlation interpretation:**
- **+1**: Perfect positive (both increase together)
- **0**: No relationship
- **-1**: Perfect negative (one increases, other decreases)

**Security insights:**
- High correlation between `requests` and `bytes_in` is expected
- Unexpected correlations may indicate attack patterns
- Use for feature selection in ML models

---

## Exercise 5: Security Dashboard

### Objective
Combine multiple visualizations for SOC overview.

### Creating Subplots

```python
fig = make_subplots(
    rows=2,
    cols=3,
    subplot_titles=[
        "Traffic Timeline",
        "Threat Distribution",
        "Events by Severity",
        "Top Source IPs",
        "Event Types",
        "Response Time",
    ],
)

# Add traces to specific positions
fig.add_trace(go.Scatter(...), row=1, col=1)  # Top-left
fig.add_trace(go.Histogram(...), row=1, col=2)  # Top-center
# ... etc
```

### Dashboard Design Tips

1. **Top row**: Time-based and distribution views
2. **Bottom row**: Categorical breakdowns
3. **Consistent colors**: Use a theme (e.g., `plotly_white`)
4. **Legends**: Show only when necessary
5. **Interactivity**: Hover data for details

---

## Common Errors

### 1. Empty Figures

```python
# Problem: Figure shows but is empty
fig = go.Figure()
fig.show()

# Solution: Add traces before showing
fig.add_trace(go.Scatter(x=[1,2,3], y=[4,5,6]))
fig.show()
```

### 2. Wrong Subplot Position

```python
# Problem: Trace appears in wrong panel
fig.add_trace(trace, row=1, col=1)  # Forgot row/col

# Solution: Always specify row and col for subplots
fig.add_trace(trace, row=2, col=1)
```

### 3. Axis Labels Not Updating

```python
# Problem: update_layout doesn't work on subplots
fig.update_layout(xaxis_title="Time")  # Only updates first subplot

# Solution: Use update_xaxes with row/col
fig.update_xaxes(title_text="Time", row=1, col=1)
```

### 4. Secondary Y-Axis Issues

```python
# Problem: Secondary y-axis data on primary axis
fig.add_trace(trace)  # Missing secondary_y

# Solution: Specify secondary_y=True
fig.add_trace(trace, secondary_y=True)
```

---

## Key Takeaways

1. **Statistics before visualization**: Know your data's distribution
2. **Z-scores for anomalies**: |z| > 2 flags unusual values
3. **Use appropriate charts**: Time series for temporal, histograms for distributions
4. **Highlight what matters**: Color, size, and annotations draw attention
5. **Dashboards tell stories**: Combine views for complete picture

---

## Bonus: Data Exfiltration Detection Dashboard

The solution includes an advanced 4-panel dashboard for detecting data exfiltration.

### Detecting Exfiltration by Ratio Analysis

```python
# Calculate out/in ratio - exfiltration shows high outbound traffic
df['out_in_ratio'] = df['bytes_out'] / df['bytes_in']

# Categorize risk levels
df['exfil_risk'] = pd.cut(
    df['out_in_ratio'],
    bins=[0, 0.3, 0.5, 1.0, float('inf')],
    labels=['Normal', 'Elevated', 'Suspicious', 'Critical'],
)
```

### Risk Levels

| Risk Level | Out/In Ratio | Interpretation |
|------------|--------------|----------------|
| Normal | < 0.3 | Typical download-heavy traffic |
| Elevated | 0.3 - 0.5 | Worth monitoring |
| Suspicious | 0.5 - 1.0 | Unusual upload activity |
| Critical | > 1.0 | Possible exfiltration |

### 4-Panel Dashboard Layout

```python
fig = make_subplots(rows=2, cols=2, subplot_titles=[
    'Out/In Ratio Over Time',     # Trend analysis
    'Bandwidth Distribution',      # Bytes in vs out
    'Risk Distribution',           # Histogram of ratios
    'Risk Assessment',             # Pie chart summary
])

# Add threshold lines for visual alerts
fig.add_hline(y=0.5, line_dash='dash', annotation_text='Elevated Risk')
fig.add_hline(y=1.0, line_dash='dash', annotation_text='Critical Risk')
```

### Security Insight

Normal traffic patterns:
- **Web browsing**: bytes_out << bytes_in (downloading pages)
- **Email**: Roughly balanced
- **Exfiltration**: bytes_out >> bytes_in (uploading stolen data)

---

## Extension Exercises

### Challenge 1: Add More Panels
Extend the dashboard to include:
- Login success/failure ratio over time
- Geolocation map of source IPs
- Attack chain timeline

### Challenge 2: Interactive Filtering
Add dropdown menus to filter:
- By time range
- By severity level
- By event type

### Challenge 3: Real-Time Updates
Modify the dashboard to:
- Refresh every 30 seconds
- Show streaming data
- Alert on threshold breaches

---

## Next Steps

After completing this lab:
- **Lab 01**: Apply visualizations to phishing classification
- **Lab 02**: Visualize malware clustering with t-SNE
- **Lab 03**: Build anomaly detection dashboards
