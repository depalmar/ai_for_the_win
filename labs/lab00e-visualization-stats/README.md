# Lab 00e: Visualization & Statistics for Security

**Difficulty:** 🟢 Beginner | **Time:** 45-60 min | **Prerequisites:** Lab 00a

Master interactive data visualization and statistical analysis for security data using Plotly and Python.

## Learning Objectives

By the end of this lab, you will be able to:

1. **Statistical Fundamentals**: Calculate and interpret key statistics for security metrics
2. **Interactive Visualizations**: Create dynamic charts with Plotly for threat analysis
3. **Security Dashboards**: Build multi-panel dashboards for SOC operations
4. **Time Series Analysis**: Visualize temporal patterns in security events
5. **Distribution Analysis**: Understand and visualize data distributions for anomaly context

## Prerequisites

- Basic Python knowledge (Lab 00a)
- No API keys required
- ~30 minutes to complete

## Why This Matters

Security analysts spend significant time interpreting data. Effective visualization:

- **Accelerates triage**: Spot anomalies at a glance
- **Communicates risk**: Present findings to stakeholders
- **Reveals patterns**: Discover attack trends and baselines
- **Supports decisions**: Data-driven incident response

## Key Concepts

### Statistical Measures for Security

| Measure | Security Use Case |
|---------|-------------------|
| Mean | Average request rate (baseline) |
| Median | Typical response time (robust to outliers) |
| Std Dev | Traffic variability (spike detection) |
| Percentiles | SLA thresholds (P95, P99 latency) |
| Z-Score | Anomaly scoring (deviations from normal) |

### Visualization Types

| Chart Type | Best For |
|------------|----------|
| Time Series | Log volume, attack timeline |
| Histogram | Score distributions, entropy |
| Box Plot | Comparing groups, outlier detection |
| Heatmap | Correlation, confusion matrix |
| Scatter | Feature relationships, clustering |
| Bar Chart | Category counts, top-N lists |
| Pie/Sunburst | Proportion breakdown |

---

## NumPy Essentials for Security ML

NumPy is the foundation of data science in Python. All ML libraries (scikit-learn, PyTorch, TensorFlow) use NumPy arrays under the hood. Here's what you need to know:

### Why NumPy?

| Use Python Lists | Use NumPy Arrays |
|------------------|------------------|
| General-purpose collections | Numerical computations |
| Mixed types (`[1, "hello", True]`) | Same type (all floats, all ints) |
| Slow for math operations | Fast vectorized operations |
| `[x*2 for x in list]` | `array * 2` (much faster) |

### Creating Arrays

```python
import numpy as np

# From Python lists
risk_scores = np.array([7, 3, 9, 2, 5])
print(risk_scores)  # [7 3 9 2 5]

# 2D array (like a spreadsheet - rows and columns)
# Each row is a sample, each column is a feature
features = np.array([
    [100, 443, 1],    # Sample 1: bytes, port, is_encrypted
    [500, 80, 0],     # Sample 2
    [250, 22, 1],     # Sample 3
])
print(features.shape)  # (3, 4) = 3 samples, 3 features

# Useful creation functions
zeros = np.zeros((5, 3))       # 5x3 array of zeros
ones = np.ones((5, 3))         # 5x3 array of ones
range_arr = np.arange(0, 10, 2)  # [0, 2, 4, 6, 8]
```

### Array Operations (Vectorized = Fast!)

```python
import numpy as np

# Element-wise operations - no loops needed!
scores = np.array([7, 3, 9, 2, 5])

# Math on entire array
normalized = scores / scores.max()  # Scale to 0-1
print(normalized)  # [0.78, 0.33, 1.0, 0.22, 0.56]

# Comparisons return boolean arrays
high_risk = scores > 5
print(high_risk)  # [True, False, True, False, False]

# Use boolean array to filter
print(scores[high_risk])  # [7, 9] - only high-risk scores

# Multiple conditions
critical = scores[(scores > 5) & (scores < 9)]
print(critical)  # [7]
```

### Statistics with NumPy

```python
import numpy as np

bytes_transferred = np.array([100, 150, 120, 5000, 130, 110])

# Basic statistics
print(f"Mean: {bytes_transferred.mean()}")      # 935.0
print(f"Median: {np.median(bytes_transferred)}")  # 125.0 (robust to outliers!)
print(f"Std Dev: {bytes_transferred.std()}")    # Shows variability
print(f"Min/Max: {bytes_transferred.min()} / {bytes_transferred.max()}")

# Percentiles - useful for thresholds
print(f"95th percentile: {np.percentile(bytes_transferred, 95)}")

# Notice mean (935) vs median (125) - the 5000 outlier skews the mean!
# For security baselines, median is often better than mean
```

### 2D Array Operations (For Features)

```python
import numpy as np

# Security features: [bytes_sent, bytes_recv, connections, duration]
network_data = np.array([
    [1000, 500, 10, 60],    # Normal
    [1200, 600, 12, 55],    # Normal
    [50000, 100, 1, 3600],  # Suspicious: high bytes, long duration
    [900, 450, 8, 70],      # Normal
])

# Shape tells you dimensions
print(network_data.shape)  # (4, 4) = 4 samples, 4 features

# Access columns (features)
bytes_sent = network_data[:, 0]  # First column (all rows)
print(bytes_sent)  # [1000, 1200, 50000, 900]

# Access rows (samples)
first_sample = network_data[0, :]  # First row (all columns)
print(first_sample)  # [1000, 500, 10, 60]

# Statistics per column (axis=0)
feature_means = network_data.mean(axis=0)
print(f"Feature means: {feature_means}")

# Statistics per row (axis=0)
sample_sums = network_data.sum(axis=1)
print(f"Sample totals: {sample_sums}")
```

### Reshaping Arrays (Important for ML!)

```python
import numpy as np

# ML models expect specific shapes
scores = np.array([7, 3, 9, 2, 5])
print(scores.shape)  # (5,) - 1D array

# Reshape to column vector (5 samples, 1 feature)
scores_column = scores.reshape(-1, 1)  # -1 means "figure it out"
print(scores_column.shape)  # (5, 1)

# Reshape to row vector (1 sample, 5 features)
scores_row = scores.reshape(1, -1)
print(scores_row.shape)  # (1, 5)

# Flatten back to 1D
flat = scores_column.flatten()
print(flat.shape)  # (5,)
```

### Security Example: Z-Score Anomaly Detection

```python
import numpy as np

# Request counts per hour (baseline data)
hourly_requests = np.array([100, 105, 98, 102, 95, 110, 103, 99, 105, 101])

# Calculate baseline statistics
mean = hourly_requests.mean()
std = hourly_requests.std()

# New observation
new_hour = 250  # Suspicious spike!

# Z-score: how many standard deviations from mean?
z_score = (new_hour - mean) / std
print(f"Z-score: {z_score:.2f}")  # ~30+ standard deviations!

# Threshold: |z| > 3 is typically considered anomalous
if abs(z_score) > 3:
    print(f"ANOMALY DETECTED: {new_hour} requests (z={z_score:.1f})")
```

### NumPy + Pandas Together

```python
import numpy as np
import pandas as pd

# Create DataFrame from NumPy array
features = np.array([
    [100, 443, 1],
    [500, 80, 0],
    [250, 22, 1],
])

df = pd.DataFrame(features, columns=["bytes", "port", "encrypted"])
print(df)

# Convert DataFrame to NumPy for ML
X = df.values  # or df.to_numpy()
print(type(X))  # <class 'numpy.ndarray'>

# Get specific columns as NumPy array
ports = df["port"].values
print(ports)  # [443, 80, 22]
```

### Quick Reference

```python
import numpy as np

# Creation
np.array([1,2,3])           # From list
np.zeros((3, 4))            # 3x4 zeros
np.ones((3, 4))             # 3x4 ones
np.arange(0, 10, 2)         # Range with step

# Properties
arr.shape                   # Dimensions
arr.dtype                   # Data type
len(arr)                    # Length of first dimension

# Operations
arr + 5                     # Add to all elements
arr * 2                     # Multiply all
arr > 5                     # Boolean mask
arr[arr > 5]                # Filter by condition

# Statistics
arr.mean(), arr.std()       # Mean, standard deviation
arr.min(), arr.max()        # Min, max
arr.sum()                   # Sum all
np.median(arr)              # Median
np.percentile(arr, 95)      # 95th percentile

# Reshaping
arr.reshape(-1, 1)          # To column vector
arr.reshape(1, -1)          # To row vector
arr.flatten()               # To 1D

# Indexing 2D
arr[0, :]                   # First row
arr[:, 0]                   # First column
arr[0:3, 1:4]               # Slice rows and columns
```

---

## Lab Structure

```
lab00e-visualization-stats/
├── README.md           # This file
├── starter/
│   └── main.py         # Exercises with TODOs
├── solution/
│   └── main.py         # Reference implementation
└── data/
    └── security_events.json  # Sample security data
```

## Exercises

### Exercise 1: Statistical Analysis
Calculate baseline statistics for network traffic data.

### Exercise 2: Distribution Visualization
Create histograms and box plots to understand data spread.

### Exercise 3: Time Series Dashboard
Build an interactive timeline of security events.

### Exercise 4: Correlation Heatmap
Visualize relationships between security features.

### Exercise 5: Security Dashboard
Combine multiple visualizations into a SOC dashboard.

## Quick Start

```bash
# Run the starter code
python labs/lab00e-visualization-stats/starter/main.py

# Run the solution
python labs/lab00e-visualization-stats/solution/main.py
```

## Key Libraries

```python
import plotly.express as px          # Quick interactive charts
import plotly.graph_objects as go    # Custom visualizations
from plotly.subplots import make_subplots  # Dashboards
import pandas as pd                  # Data manipulation
import numpy as np                   # Numerical operations
from scipy import stats              # Statistical functions
```

## Tips

1. **Start with summary stats** before visualizing
2. **Use appropriate chart types** for your data
3. **Add interactivity** (hover, zoom, filter) for exploration
4. **Consider color-blind friendly palettes**
5. **Label axes and add titles** for clarity

## Next Steps

After completing this lab:
- **Lab 01**: Apply visualizations to phishing classification
- **Lab 02**: Visualize malware clustering results  
- **Lab 03**: Create anomaly detection dashboards

---

## Part 2: Building Interactive UIs with Gradio

### Why Gradio?

Gradio lets you wrap your Python functions in a web UI with minimal code:

```python
import gradio as gr

def analyze_log(log_text):
    # Your analysis logic
    return f"Analyzed: {log_text}"

demo = gr.Interface(fn=analyze_log, inputs="text", outputs="text")
demo.launch()
```

This creates a full web app in ~5 lines!

### When to Use Gradio vs Plotly

| Tool | Best For |
|------|----------|
| **Plotly** | Static reports, notebooks, dashboards |
| **Gradio** | Interactive tools, demos, prototypes |
| **Streamlit** | Multi-page apps, complex dashboards |

### Gradio Components for Security Tools

| Component | Use Case |
|-----------|----------|
| `gr.Textbox` | Log entry input, analysis output |
| `gr.File` | Upload logs, PCAP, samples |
| `gr.Dropdown` | Select analysis type, model |
| `gr.Slider` | Threshold adjustment |
| `gr.Dataframe` | Display results table |
| `gr.Plot` | Embed Plotly figures |
| `gr.JSON` | Display structured output |

### Exercise 6: Simple Security UI

Build a log analyzer UI:

```python
import gradio as gr

def analyze_log(log_entry: str, threshold: float) -> dict:
    """Analyze a log entry for threats."""
    # Your analysis logic here
    suspicious_keywords = ["failed", "admin", "root", "error"]
    score = sum(1 for kw in suspicious_keywords if kw in log_entry.lower())
    
    return {
        "log": log_entry,
        "threat_score": score / len(suspicious_keywords),
        "is_suspicious": score / len(suspicious_keywords) > threshold
    }

demo = gr.Interface(
    fn=analyze_log,
    inputs=[
        gr.Textbox(label="Log Entry", placeholder="Paste log here..."),
        gr.Slider(0, 1, value=0.5, label="Threshold")
    ],
    outputs=gr.JSON(label="Analysis Result"),
    title="🔍 Log Analyzer",
    description="Analyze log entries for suspicious activity"
)

demo.launch()
```

### Exercise 7: Multi-Tab Security Dashboard

Build a more complex UI with tabs:

```python
import gradio as gr

with gr.Blocks() as demo:
    gr.Markdown("# 🛡️ Security Analysis Dashboard")
    
    with gr.Tabs():
        with gr.TabItem("📝 Log Analysis"):
            log_input = gr.Textbox(label="Log Entry")
            analyze_btn = gr.Button("Analyze")
            log_output = gr.JSON(label="Results")
            
        with gr.TabItem("📊 Statistics"):
            file_input = gr.File(label="Upload Log File")
            stats_output = gr.Dataframe(label="Statistics")
            
        with gr.TabItem("📈 Visualization"):
            plot_output = gr.Plot(label="Threat Distribution")

demo.launch()
```

### Tips for Security UIs

1. **Validate inputs** - Don't trust user-provided data
2. **Add examples** - Help users understand expected format
3. **Show confidence** - Display threat scores, not just yes/no
4. **Enable export** - Let users save results
5. **Use appropriate components** - File upload for bulk analysis

## Resources

- [Plotly Python Documentation](https://plotly.com/python/)
- [Gradio Documentation](https://gradio.app/docs/)
- [Pandas Visualization Guide](https://pandas.pydata.org/docs/user_guide/visualization.html)
- [Security Data Visualization Best Practices](https://www.sans.org/white-papers/)
