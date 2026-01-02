# Lab 00e: Visualization & Statistics for Security

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

## Resources

- [Plotly Python Documentation](https://plotly.com/python/)
- [Pandas Visualization Guide](https://pandas.pydata.org/docs/user_guide/visualization.html)
- [Security Data Visualization Best Practices](https://www.sans.org/white-papers/)
