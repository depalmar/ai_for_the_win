# Lab 02 Walkthrough: Malware Clustering

## Overview

This walkthrough guides you through clustering malware samples using unsupervised learning to identify malware families.

**Time to complete walkthrough:** 25 minutes

---

## Step 1: Understanding the Problem

### What We're Building

```
INPUT: Malware feature vectors (PE metadata)
    |
    v
[Feature Scaling]
    |
    v
[Dimensionality Reduction (t-SNE)]
    |
    v
[Clustering (K-Means / DBSCAN)]
    |
    v
OUTPUT: Malware family groupings
```

### Why Clustering?
- **No labels needed** - Works without knowing malware families
- **Discover new families** - Find previously unknown groups
- **Triage at scale** - Group thousands of samples quickly
- **Behavioral similarity** - Samples that behave similarly cluster together

---

## Step 2: Loading and Exploring Data

### Load Malware Metadata

```python
import json
import pandas as pd
import numpy as np

# Load sample malware metadata
with open('data/malware/samples.json') as f:
    samples = json.load(f)

# Convert to DataFrame
df = pd.DataFrame(samples)

# Explore the data
print(f"Total samples: {len(df)}")
print(f"Features available: {df.columns.tolist()}")
print(f"\nSample distribution:")
print(df['label'].value_counts())
```

### Expected Output
```
Total samples: 10
Features available: ['sha256', 'filename', 'family', 'entropy', 'file_size', ...]

Sample distribution:
malicious    5
benign       5
```

### Understanding Features

| Feature | Description | Relevance |
|---------|-------------|-----------|
| `entropy` | Randomness measure (0-8) | Packed/encrypted malware = high entropy |
| `file_size` | Size in bytes | Some families have characteristic sizes |
| `section_count` | PE sections | Unusual counts indicate tampering |
| `import_count` | Imported functions | API usage patterns |
| `packer_detected` | Packing tool | Same packer = possible same family |

---

## Step 3: Feature Engineering

### Extract Numeric Features

```python
def extract_features(sample: dict) -> list:
    """Extract numeric features for clustering"""
    return [
        sample.get('entropy', 0),
        sample.get('file_size', 0) / 1000000,  # Normalize to MB
        sample.get('section_count', 0),
        sample.get('import_count', 0),
        sample.get('export_count', 0),
        len(sample.get('suspicious_imports', [])),
        sample.get('strings_count', 0) / 100,  # Normalize
        1 if sample.get('packer_detected') else 0
    ]

# Create feature matrix
features = np.array([extract_features(s) for s in samples])
feature_names = ['entropy', 'file_size_mb', 'sections', 'imports',
                 'exports', 'suspicious_imports', 'strings_norm', 'packed']

print(f"Feature matrix shape: {features.shape}")
```

### Why These Features?
- **Entropy**: Packed malware typically has entropy > 7.0
- **Import count**: Malware often imports specific APIs
- **Suspicious imports**: Direct indicators of malicious behavior
- **Packer detection**: Evasion technique common in malware

### Common Error #1: Mixed Data Types
```
ValueError: could not convert string to float
```

**Solution:** Ensure all features are numeric:
```python
# Handle categorical features
sample['packed'] = 1 if sample.get('packer_detected') else 0
```

---

## Step 4: Feature Scaling

### Why Scale?
Features on different scales (entropy: 0-8, file_size: 0-millions) can bias clustering algorithms.

```python
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

# Verify scaling worked
print(f"Mean (should be ~0): {features_scaled.mean(axis=0).round(2)}")
print(f"Std (should be ~1): {features_scaled.std(axis=0).round(2)}")
```

### Scaling Methods Compared

| Method | When to Use |
|--------|-------------|
| `StandardScaler` | Features are roughly Gaussian |
| `MinMaxScaler` | Need values in [0, 1] range |
| `RobustScaler` | Data has outliers |

---

## Step 5: Dimensionality Reduction with t-SNE

### Why t-SNE?
- Preserves local structure (similar samples stay together)
- Great for visualization
- Reveals clusters that aren't obvious in high dimensions

```python
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt

# Apply t-SNE
tsne = TSNE(
    n_components=2,      # 2D for visualization
    perplexity=5,        # Adjust based on sample size (5-50)
    random_state=42,
    n_iter=1000
)
features_2d = tsne.fit_transform(features_scaled)

# Plot
plt.figure(figsize=(10, 8))
labels = [s['label'] for s in samples]
colors = ['red' if l == 'malicious' else 'green' for l in labels]
plt.scatter(features_2d[:, 0], features_2d[:, 1], c=colors, s=100)

# Add labels
for i, s in enumerate(samples):
    plt.annotate(s.get('family', s['label'])[:8],
                (features_2d[i, 0], features_2d[i, 1]))

plt.title('Malware Samples - t-SNE Visualization')
plt.xlabel('t-SNE 1')
plt.ylabel('t-SNE 2')
plt.savefig('tsne_visualization.png')
plt.show()
```

### Perplexity Parameter
- **Low (5-10)**: Focus on very local structure
- **Medium (30)**: Balance local and global
- **High (50+)**: More global structure

**Rule of thumb:** perplexity should be less than sample_count / 3

### Common Error #2: Perplexity Too High
```
ValueError: perplexity must be less than n_samples
```

**Solution:** Reduce perplexity for small datasets:
```python
perplexity = min(30, len(samples) // 3)
```

---

## Step 6: K-Means Clustering

### Finding Optimal K

```python
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

# Test different k values
k_range = range(2, min(8, len(samples)))
silhouette_scores = []
inertias = []

for k in k_range:
    kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
    labels = kmeans.fit_predict(features_scaled)

    silhouette_scores.append(silhouette_score(features_scaled, labels))
    inertias.append(kmeans.inertia_)

# Plot elbow curve
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))

ax1.plot(k_range, inertias, 'bo-')
ax1.set_xlabel('Number of Clusters (k)')
ax1.set_ylabel('Inertia')
ax1.set_title('Elbow Method')

ax2.plot(k_range, silhouette_scores, 'ro-')
ax2.set_xlabel('Number of Clusters (k)')
ax2.set_ylabel('Silhouette Score')
ax2.set_title('Silhouette Analysis')

plt.tight_layout()
plt.savefig('kmeans_analysis.png')
plt.show()

# Best k
best_k = k_range[np.argmax(silhouette_scores)]
print(f"Optimal k (by silhouette): {best_k}")
```

### Interpreting Results
- **Elbow method**: Look for "elbow" where inertia stops dropping fast
- **Silhouette score**: Higher is better (max 1.0), measures cluster separation

### Apply Final Clustering

```python
# Final clustering with optimal k
kmeans = KMeans(n_clusters=best_k, random_state=42, n_init=10)
cluster_labels = kmeans.fit_predict(features_scaled)

# Add to DataFrame
df['cluster'] = cluster_labels

# Analyze clusters
print("\nCluster composition:")
for cluster_id in range(best_k):
    cluster_samples = df[df['cluster'] == cluster_id]
    print(f"\nCluster {cluster_id} ({len(cluster_samples)} samples):")
    print(f"  Families: {cluster_samples['family'].value_counts().to_dict()}")
    print(f"  Avg entropy: {cluster_samples['entropy'].mean():.2f}")
```

---

## Step 7: DBSCAN Alternative

### When to Use DBSCAN
- Unknown number of clusters
- Irregular cluster shapes
- Need to identify outliers

```python
from sklearn.cluster import DBSCAN

# DBSCAN clustering
dbscan = DBSCAN(
    eps=0.8,          # Maximum distance between samples
    min_samples=2,    # Minimum samples in a cluster
    metric='euclidean'
)
dbscan_labels = dbscan.fit_predict(features_scaled)

# Analyze results
n_clusters = len(set(dbscan_labels)) - (1 if -1 in dbscan_labels else 0)
n_noise = list(dbscan_labels).count(-1)

print(f"DBSCAN found {n_clusters} clusters")
print(f"Noise points (outliers): {n_noise}")
```

### DBSCAN Parameters
- **eps**: Smaller = tighter clusters, more noise points
- **min_samples**: Higher = fewer, denser clusters

### Common Error #3: All Points as Noise
```
All samples marked as -1 (noise)
```

**Solution:** Increase eps or decrease min_samples:
```python
# Start with larger eps and tune down
eps_values = [0.5, 1.0, 1.5, 2.0]
for eps in eps_values:
    labels = DBSCAN(eps=eps, min_samples=2).fit_predict(features_scaled)
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    print(f"eps={eps}: {n_clusters} clusters")
```

---

## Step 8: Cluster Interpretation

### Analyze Cluster Characteristics

```python
def analyze_cluster(df, cluster_id):
    """Analyze characteristics of a cluster"""
    cluster = df[df['cluster'] == cluster_id]

    print(f"\n=== Cluster {cluster_id} Analysis ===")
    print(f"Size: {len(cluster)} samples")

    # Feature statistics
    numeric_cols = ['entropy', 'file_size', 'section_count', 'import_count']
    for col in numeric_cols:
        if col in cluster.columns:
            print(f"{col}: mean={cluster[col].mean():.2f}, "
                  f"std={cluster[col].std():.2f}")

    # Common attributes
    if 'packer_detected' in cluster.columns:
        packers = cluster['packer_detected'].value_counts()
        print(f"Packers: {packers.to_dict()}")

    if 'family' in cluster.columns:
        families = cluster['family'].value_counts()
        print(f"Families: {families.to_dict()}")

    return cluster

# Analyze each cluster
for i in range(best_k):
    analyze_cluster(df, i)
```

### Security Insights from Clusters

| Cluster Characteristic | Security Meaning |
|------------------------|------------------|
| High entropy + packed | Likely evasive malware |
| Many suspicious imports | Active malicious capability |
| Same packer + similar size | Possibly same campaign |
| Low imports, high entropy | Encrypted payload |

---

## Common Mistakes & Solutions

### Mistake 1: Not Scaling Features
```python
# WRONG: Features on different scales
kmeans.fit(features)  # file_size dominates

# RIGHT: Scale first
kmeans.fit(features_scaled)
```

### Mistake 2: Using t-SNE for Clustering
```python
# WRONG: Cluster on t-SNE output
tsne_output = tsne.fit_transform(features)
kmeans.fit(tsne_output)  # t-SNE distorts distances!

# RIGHT: Cluster on scaled features, visualize with t-SNE
kmeans.fit(features_scaled)
tsne_output = tsne.fit_transform(features_scaled)  # Only for viz
```

### Mistake 3: Ignoring Outliers
```python
# Check for outliers before clustering
from sklearn.ensemble import IsolationForest

iso = IsolationForest(contamination=0.1)
outlier_labels = iso.fit_predict(features_scaled)
outliers = features_scaled[outlier_labels == -1]
print(f"Detected {len(outliers)} outliers")
```

---

## Extension Exercises

### Exercise A: Add Behavioral Features

```python
def extract_behavioral_features(sample):
    """Extract behavioral indicators"""
    suspicious = sample.get('suspicious_imports', [])

    return {
        'has_process_injection': any('CreateRemoteThread' in s for s in suspicious),
        'has_network': any('Http' in s or 'Internet' in s for s in suspicious),
        'has_crypto': any('Crypt' in s for s in suspicious),
        'has_persistence': any('RegSet' in s for s in suspicious)
    }
```

### Exercise B: Hierarchical Clustering

```python
from scipy.cluster.hierarchy import dendrogram, linkage

# Create linkage matrix
Z = linkage(features_scaled, method='ward')

# Plot dendrogram
plt.figure(figsize=(12, 6))
dendrogram(Z, labels=[s['filename'][:10] for s in samples])
plt.title('Malware Hierarchical Clustering')
plt.xlabel('Sample')
plt.ylabel('Distance')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('dendrogram.png')
```

### Exercise C: Cluster Stability

```python
from sklearn.model_selection import cross_val_score
from sklearn.cluster import KMeans

def cluster_stability(X, k, n_runs=10):
    """Measure clustering stability across runs"""
    all_labels = []

    for i in range(n_runs):
        kmeans = KMeans(n_clusters=k, random_state=i)
        labels = kmeans.fit_predict(X)
        all_labels.append(labels)

    # Calculate agreement between runs
    from sklearn.metrics import adjusted_rand_score
    scores = []
    for i in range(n_runs):
        for j in range(i+1, n_runs):
            scores.append(adjusted_rand_score(all_labels[i], all_labels[j]))

    return np.mean(scores), np.std(scores)
```

---

## Bonus: Malware Discovery Timeline

The notebook includes a timeline visualization showing when malware families were first discovered.

### Adding Discovery Dates

```python
from datetime import datetime, timedelta

# Different families emerge at different times
family_ranges = {
    'emotet': (0, 30),      # Early campaign
    'trickbot': (20, 50),   # Mid-campaign
    'cobalt_strike': (10, 40),
    'qakbot': (30, 60),
    'redline': (0, 90),     # Persistent throughout
}

for sample in samples:
    days = random.randint(*family_ranges[sample['family']])
    sample['first_seen'] = base_date + timedelta(days=days)
```

### Visualizing Family Emergence

```python
fig = make_subplots(rows=2, cols=1,
    subplot_titles=['Daily Discoveries by Family', 'Cumulative Samples'])

# Stacked area chart - shows which families are active when
for family in families:
    fig.add_trace(go.Scatter(
        x=dates, y=counts[family],
        name=family, stackgroup='one'
    ), row=1, col=1)

# Cumulative line - shows sample collection rate
fig.add_trace(go.Scatter(
    x=dates, y=cumulative,
    fill='tozeroy', name='Total'
), row=2, col=1)
```

### Security Insight

Malware campaigns follow predictable patterns:
- **New families emerge** at specific times (development cycles)
- **Active campaigns** show burst discovery patterns
- **Persistent families** (like info stealers) appear throughout
- **APT tools** often appear later (targeted, slower spread)

---

## Key Takeaways

1. **Feature selection matters** - Choose features relevant to malware behavior
2. **Always scale features** - Prevents large-scale features from dominating
3. **t-SNE is for visualization** - Don't cluster on t-SNE output
4. **Multiple algorithms** - K-Means and DBSCAN find different structures
5. **Interpret clusters** - Understand what each cluster represents
6. **Timeline analysis** - Family emergence patterns aid attribution

---

## Next Lab

Continue to [Lab 03: Anomaly Detection](./lab03-walkthrough.md) to learn outlier detection for security events.
