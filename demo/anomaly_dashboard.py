#!/usr/bin/env python3
"""
NGFW Anomaly Detection Dashboard

Interactive Gradio dashboard for exploring firewall traffic anomaly detection.
Based on Lab 03 - demonstrates L7 deep packet inspection across 6 protocols.

Usage:
    python demo/anomaly_dashboard.py

Features:
    - Real-time traffic generation with attack injection
    - Interactive model selection (Isolation Forest, One-Class SVM, LOF)
    - L7 protocol breakdown (HTTP, DNS, TLS, QUIC, gRPC, WebSocket)
    - Firewall action distribution
    - Anomaly score visualization
    - MITRE ATT&CK mapping
"""

import gradio as gr
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def generate_traffic(n_normal: int = 500, attack_pct: float = 0.15) -> pd.DataFrame:
    """Generate synthetic firewall traffic with attacks."""
    np.random.seed(42)
    n_attack = int(n_normal * attack_pct / (1 - attack_pct))
    
    # Normal traffic profiles
    traffic_types = []
    
    # Web traffic
    n_web = int(n_normal * 0.4)
    traffic_types.append({
        "bytes_sent": np.random.lognormal(7, 0.8, n_web),
        "bytes_recv": np.random.lognormal(10, 1.5, n_web),
        "duration": np.random.exponential(3, n_web),
        "dst_port": np.random.choice([80, 443], n_web, p=[0.2, 0.8]),
        "protocol": np.full(n_web, "TCP"),
        "action": np.full(n_web, "allow"),
        "app_id": np.random.choice(["web-browsing", "ssl"], n_web),
        "threat_category": np.full(n_web, "none"),
        "attack_type": np.full(n_web, "normal"),
        "label": np.zeros(n_web),
    })
    
    # DNS traffic
    n_dns = int(n_normal * 0.2)
    traffic_types.append({
        "bytes_sent": np.random.normal(70, 15, n_dns).clip(40, 200),
        "bytes_recv": np.random.normal(150, 40, n_dns).clip(80, 400),
        "duration": np.random.uniform(0.001, 0.2, n_dns),
        "dst_port": np.full(n_dns, 53),
        "protocol": np.full(n_dns, "UDP"),
        "action": np.full(n_dns, "allow"),
        "app_id": np.full(n_dns, "dns"),
        "threat_category": np.full(n_dns, "none"),
        "attack_type": np.full(n_dns, "normal"),
        "label": np.zeros(n_dns),
    })
    
    # QUIC traffic
    n_quic = int(n_normal * 0.1)
    traffic_types.append({
        "bytes_sent": np.random.lognormal(7, 0.9, n_quic),
        "bytes_recv": np.random.lognormal(10, 1.3, n_quic),
        "duration": np.random.exponential(2, n_quic),
        "dst_port": np.full(n_quic, 443),
        "protocol": np.full(n_quic, "UDP"),
        "action": np.full(n_quic, "allow"),
        "app_id": np.random.choice(["quic", "http3"], n_quic),
        "threat_category": np.full(n_quic, "none"),
        "attack_type": np.full(n_quic, "normal"),
        "label": np.zeros(n_quic),
    })
    
    # gRPC traffic
    n_grpc = int(n_normal * 0.1)
    traffic_types.append({
        "bytes_sent": np.random.lognormal(6, 0.7, n_grpc),
        "bytes_recv": np.random.lognormal(7, 0.9, n_grpc),
        "duration": np.random.exponential(0.3, n_grpc),
        "dst_port": np.random.choice([50051, 443], n_grpc),
        "protocol": np.full(n_grpc, "TCP"),
        "action": np.full(n_grpc, "allow"),
        "app_id": np.full(n_grpc, "grpc"),
        "threat_category": np.full(n_grpc, "none"),
        "attack_type": np.full(n_grpc, "normal"),
        "label": np.zeros(n_grpc),
    })
    
    # WebSocket traffic
    n_ws = int(n_normal * 0.1)
    traffic_types.append({
        "bytes_sent": np.random.lognormal(7, 1.2, n_ws),
        "bytes_recv": np.random.lognormal(8, 1.5, n_ws),
        "duration": np.random.uniform(60, 3600, n_ws),
        "dst_port": np.random.choice([80, 443], n_ws, p=[0.2, 0.8]),
        "protocol": np.full(n_ws, "TCP"),
        "action": np.full(n_ws, "allow"),
        "app_id": np.full(n_ws, "websocket"),
        "threat_category": np.full(n_ws, "none"),
        "attack_type": np.full(n_ws, "normal"),
        "label": np.zeros(n_ws),
    })
    
    # Other traffic
    n_other = n_normal - n_web - n_dns - n_quic - n_grpc - n_ws
    traffic_types.append({
        "bytes_sent": np.random.lognormal(8, 1.0, n_other),
        "bytes_recv": np.random.lognormal(9, 1.2, n_other),
        "duration": np.random.exponential(5, n_other),
        "dst_port": np.random.choice([22, 25, 3306, 5432], n_other),
        "protocol": np.full(n_other, "TCP"),
        "action": np.full(n_other, "allow"),
        "app_id": np.random.choice(["ssh", "smtp", "mysql"], n_other),
        "threat_category": np.full(n_other, "none"),
        "attack_type": np.full(n_other, "normal"),
        "label": np.zeros(n_other),
    })
    
    # Attack traffic
    attack_types = [
        ("port_scan", "scan", ["deny", "drop"]),
        ("c2_beacon", "command-and-control", ["allow", "alert"]),
        ("dns_tunnel", "dns-tunneling", ["allow", "alert"]),
        ("data_exfil", "data-theft", ["allow", "alert"]),
        ("quic_c2", "command-and-control", ["allow", "alert"]),
        ("grpc_abuse", "api-abuse", ["allow", "alert"]),
        ("websocket_c2", "command-and-control", ["allow", "alert"]),
    ]
    
    n_per_attack = n_attack // len(attack_types)
    
    for attack_name, threat_cat, actions in attack_types:
        n_atk = n_per_attack
        traffic_types.append({
            "bytes_sent": np.random.lognormal(9, 1.5, n_atk),
            "bytes_recv": np.random.lognormal(10, 1.8, n_atk),
            "duration": np.random.uniform(10, 1000, n_atk),
            "dst_port": np.random.choice([80, 443, 53, 50051], n_atk),
            "protocol": np.random.choice(["TCP", "UDP"], n_atk),
            "action": np.random.choice(actions, n_atk),
            "app_id": np.random.choice(["unknown-tcp", "unknown-udp", "ssl"], n_atk),
            "threat_category": np.full(n_atk, threat_cat),
            "attack_type": np.full(n_atk, attack_name),
            "label": np.ones(n_atk),
        })
    
    df = pd.concat([pd.DataFrame(t) for t in traffic_types], ignore_index=True)
    
    # Engineer features
    df["log_bytes"] = np.log1p(df["bytes_sent"] + df["bytes_recv"])
    df["bytes_ratio"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["log_duration"] = np.log1p(df["duration"])
    df["is_encrypted"] = df["dst_port"].isin([443, 8443]).astype(int)
    df["has_threat"] = (df["threat_category"] != "none").astype(int)
    
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


def run_detection(df: pd.DataFrame, contamination: float = 0.1):
    """Run Isolation Forest detection."""
    features = ["log_bytes", "bytes_ratio", "log_duration", "is_encrypted", "has_threat"]
    X = df[features].values
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
    df["prediction"] = model.fit_predict(X_scaled)
    df["anomaly_score"] = -model.score_samples(X_scaled)
    df["predicted_anomaly"] = (df["prediction"] == -1).astype(int)
    
    return df


def create_dashboard(n_samples: int, attack_pct: float, contamination: float):
    """Generate all dashboard visualizations."""
    # Generate and analyze traffic
    df = generate_traffic(n_normal=n_samples, attack_pct=attack_pct / 100)
    df = run_detection(df, contamination=contamination / 100)
    
    # Calculate metrics
    tp = ((df["predicted_anomaly"] == 1) & (df["label"] == 1)).sum()
    fp = ((df["predicted_anomaly"] == 1) & (df["label"] == 0)).sum()
    fn = ((df["predicted_anomaly"] == 0) & (df["label"] == 1)).sum()
    tn = ((df["predicted_anomaly"] == 0) & (df["label"] == 0)).sum()
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    # 1. Protocol Distribution
    protocol_counts = df.groupby(["app_id", "label"]).size().reset_index(name="count")
    fig_protocols = px.bar(
        protocol_counts,
        x="app_id",
        y="count",
        color=protocol_counts["label"].map({0: "Normal", 1: "Attack"}),
        barmode="stack",
        title="Traffic by Application Protocol",
        template="plotly_white",
        color_discrete_map={"Normal": "#2ecc71", "Attack": "#e74c3c"},
    )
    fig_protocols.update_layout(legend_title="Traffic Type", xaxis_title="Application", yaxis_title="Sessions")
    
    # 2. Firewall Actions
    action_counts = df["action"].value_counts()
    fig_actions = px.pie(
        values=action_counts.values,
        names=action_counts.index,
        title="Firewall Action Distribution",
        template="plotly_white",
        color_discrete_sequence=["#2ecc71", "#f39c12", "#e74c3c", "#9b59b6"],
    )
    
    # 3. Anomaly Score Distribution
    fig_scores = go.Figure()
    fig_scores.add_trace(go.Histogram(
        x=df[df["label"] == 0]["anomaly_score"],
        name="Normal",
        marker_color="#2ecc71",
        opacity=0.7,
    ))
    fig_scores.add_trace(go.Histogram(
        x=df[df["label"] == 1]["anomaly_score"],
        name="Attack",
        marker_color="#e74c3c",
        opacity=0.7,
    ))
    threshold = df["anomaly_score"].quantile(1 - contamination / 100)
    fig_scores.add_vline(x=threshold, line_dash="dash", line_color="black", annotation_text="Threshold")
    fig_scores.update_layout(
        title="Anomaly Score Distribution",
        xaxis_title="Anomaly Score",
        yaxis_title="Count",
        barmode="overlay",
        template="plotly_white",
    )
    
    # 4. Confusion Matrix
    cm = [[tn, fp], [fn, tp]]
    fig_cm = px.imshow(
        cm,
        labels=dict(x="Predicted", y="Actual", color="Count"),
        x=["Normal", "Anomaly"],
        y=["Normal", "Anomaly"],
        color_continuous_scale="RdYlGn_r",
        title="Confusion Matrix",
        template="plotly_white",
        text_auto=True,
    )
    
    # 5. Attack Type Detection Rates
    attack_detection = df[df["label"] == 1].groupby("attack_type").agg({
        "predicted_anomaly": "mean",
        "label": "count"
    }).reset_index()
    attack_detection.columns = ["Attack Type", "Detection Rate", "Count"]
    attack_detection["Detection Rate"] *= 100
    
    fig_attacks = px.bar(
        attack_detection,
        x="Attack Type",
        y="Detection Rate",
        title="Detection Rate by Attack Type",
        template="plotly_white",
        color="Detection Rate",
        color_continuous_scale="RdYlGn",
    )
    fig_attacks.add_hline(y=80, line_dash="dash", line_color="green", annotation_text="80% target")
    fig_attacks.update_layout(yaxis_title="Detection Rate (%)")
    
    # 6. Threat Category Breakdown
    threat_counts = df[df["threat_category"] != "none"]["threat_category"].value_counts()
    fig_threats = px.bar(
        x=threat_counts.index,
        y=threat_counts.values,
        title="Threat Categories Detected",
        template="plotly_white",
        color=threat_counts.values,
        color_continuous_scale="Reds",
    )
    fig_threats.update_layout(xaxis_title="Threat Category", yaxis_title="Count", showlegend=False)
    
    # Summary stats
    summary = f"""
### Detection Summary
- **Total Sessions**: {len(df):,}
- **Normal Traffic**: {(df['label'] == 0).sum():,} ({100 * (df['label'] == 0).mean():.1f}%)
- **Attack Traffic**: {(df['label'] == 1).sum():,} ({100 * (df['label'] == 1).mean():.1f}%)

### Model Performance
- **Precision**: {precision:.2%}
- **Recall**: {recall:.2%}
- **F1 Score**: {f1:.2%}

### Detections
- **True Positives**: {tp}
- **False Positives**: {fp}
- **True Negatives**: {tn}
- **False Negatives**: {fn}
"""
    
    return fig_protocols, fig_actions, fig_scores, fig_cm, fig_attacks, fig_threats, summary


def main():
    """Launch the Gradio dashboard."""
    with gr.Blocks(title="NGFW Anomaly Detection Dashboard", theme=gr.themes.Soft()) as demo:
        gr.Markdown("""
# 🔥 NGFW Anomaly Detection Dashboard

Interactive dashboard for exploring firewall traffic anomaly detection with **Layer 7 deep packet inspection** across 6 protocols: HTTP, DNS, TLS, QUIC, gRPC, and WebSocket.

Based on **Lab 03** from the AI for the Win training program.
        """)
        
        with gr.Row():
            n_samples = gr.Slider(100, 2000, value=500, step=100, label="Normal Traffic Samples")
            attack_pct = gr.Slider(5, 30, value=15, step=1, label="Attack Percentage (%)")
            contamination = gr.Slider(5, 25, value=10, step=1, label="Contamination (model sensitivity)")
        
        run_btn = gr.Button("🚀 Generate & Analyze Traffic", variant="primary")
        
        with gr.Row():
            with gr.Column():
                summary_md = gr.Markdown("Click 'Generate & Analyze' to start")
            with gr.Column():
                fig_actions = gr.Plot(label="Firewall Actions")
        
        with gr.Row():
            fig_protocols = gr.Plot(label="Protocol Distribution")
            fig_scores = gr.Plot(label="Anomaly Scores")
        
        with gr.Row():
            fig_cm = gr.Plot(label="Confusion Matrix")
            fig_attacks = gr.Plot(label="Attack Detection Rates")
        
        with gr.Row():
            fig_threats = gr.Plot(label="Threat Categories")
        
        run_btn.click(
            fn=create_dashboard,
            inputs=[n_samples, attack_pct, contamination],
            outputs=[fig_protocols, fig_actions, fig_scores, fig_cm, fig_attacks, fig_threats, summary_md],
        )
        
        gr.Markdown("""
---
### MITRE ATT&CK Coverage

| Attack Type | Technique | Protocol Abuse |
|-------------|-----------|----------------|
| Port Scan | T1046 | TCP/UDP probes |
| C2 Beacon | T1071 | HTTP, WebSocket |
| DNS Tunnel | T1071.004 | DNS TXT |
| Data Exfil | T1048 | HTTPS, DNS |
| QUIC C2 | T1572 | QUIC tunnel |
| gRPC Abuse | T1190 | gRPC API |
| WebSocket C2 | T1071.001 | WebSocket |
        """)
    
    demo.launch(share=False)


if __name__ == "__main__":
    main()
