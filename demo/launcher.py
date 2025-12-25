#!/usr/bin/env python3
"""
AI for the Win - Unified Demo Launcher

This Gradio application provides interactive demos for all labs in the
AI Security Training Program.

=============================================================================
REQUIREMENTS
=============================================================================

- Gradio 6.1.0+ (updated from 4.x for security fixes)
- Note: Some UI elements may need updates for Gradio 6 compatibility
- If you encounter issues, check: https://www.gradio.app/main/guides/gradio-6-migration-guide

=============================================================================
FEATURES
=============================================================================

1. Lab Selection: Choose any lab from the dropdown
2. Interactive Input: Configure parameters for each demo
3. Real-time Output: See results immediately
4. Educational Context: Learn what each lab demonstrates

=============================================================================
USAGE
=============================================================================

    python demo/launcher.py

Then open http://localhost:7860 in your browser.

=============================================================================
"""

import os
import sys
from pathlib import Path
from typing import Optional

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

from dotenv import load_dotenv

load_dotenv()


# =============================================================================
# LAB DEMOS
# =============================================================================


def demo_phishing_classifier(email_text: str, threshold: float) -> str:
    """
    Lab 01: Phishing Email Classifier Demo

    Demonstrates text classification using TF-IDF and Random Forest.
    """
    if not email_text.strip():
        return "Please enter email text to analyze."

    # Simplified phishing detection (actual lab uses trained model)
    suspicious_keywords = [
        "urgent",
        "verify",
        "account",
        "suspended",
        "click here",
        "password",
        "confirm",
        "immediately",
        "security",
        "update",
        "limited time",
        "act now",
        "winner",
        "congratulations",
    ]

    text_lower = email_text.lower()
    score = 0.0
    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in text_lower:
            score += 0.1
            found_keywords.append(keyword)

    # Check for suspicious patterns
    if "http://" in text_lower:
        score += 0.2
        found_keywords.append("http:// link")
    if "@" in text_lower and "click" in text_lower:
        score += 0.15
        found_keywords.append("email + click pattern")

    score = min(1.0, score)
    is_phishing = score >= threshold

    result = f"""
## Analysis Results

**Classification:** {"PHISHING" if is_phishing else "LEGITIMATE"}
**Confidence Score:** {score:.1%}
**Threshold:** {threshold:.1%}

### Detected Indicators
{chr(10).join(f"- {kw}" for kw in found_keywords) if found_keywords else "- No suspicious keywords found"}

### How It Works
This demo uses keyword matching as a simplified example.
The actual Lab 01 implementation uses:
- TF-IDF vectorization for text features
- Random Forest classifier trained on labeled data
- Cross-validation for model evaluation
"""
    return result


def demo_anomaly_detection(
    bytes_sent: int, bytes_received: int, packets: int, duration: float, port: int
) -> str:
    """
    Lab 03: Network Anomaly Detection Demo

    Demonstrates anomaly detection using Isolation Forest.
    """
    # Simple anomaly heuristics (actual lab uses trained model)
    score = 0.0
    anomalies = []

    # Large data transfer
    if bytes_sent > 10_000_000:
        score += 0.3
        anomalies.append(f"Large outbound transfer: {bytes_sent/1e6:.1f} MB")

    # Unusual ratio
    if bytes_received > 0 and bytes_sent / bytes_received > 10:
        score += 0.2
        anomalies.append("High send/receive ratio (possible exfiltration)")

    # High packet count
    if packets > 1000 and duration < 60:
        score += 0.2
        anomalies.append("High packet rate (possible scanning)")

    # Suspicious ports
    suspicious_ports = [4444, 5555, 6666, 8080, 31337]
    if port in suspicious_ports:
        score += 0.3
        anomalies.append(f"Suspicious port: {port}")

    # Short duration with data
    if duration < 1 and bytes_sent > 100000:
        score += 0.2
        anomalies.append("Rapid large transfer")

    score = min(1.0, score)
    is_anomaly = score >= 0.5

    result = f"""
## Anomaly Detection Results

**Status:** {"ANOMALY DETECTED" if is_anomaly else "NORMAL"}
**Anomaly Score:** {score:.1%}

### Network Flow Summary
- Bytes Sent: {bytes_sent:,}
- Bytes Received: {bytes_received:,}
- Packets: {packets:,}
- Duration: {duration:.1f}s
- Port: {port}

### Detected Anomalies
{chr(10).join(f"- {a}" for a in anomalies) if anomalies else "- No anomalies detected"}

### How It Works
This demo uses rule-based heuristics as a simplified example.
The actual Lab 03 implementation uses:
- Isolation Forest for unsupervised anomaly detection
- Feature engineering for network flows
- Autoencoder-based detection (advanced)
"""
    return result


def demo_log_analysis(log_entries: str) -> str:
    """
    Lab 04: LLM Log Analysis Demo

    Demonstrates log parsing and IOC extraction.
    """
    if not log_entries.strip():
        return "Please enter log entries to analyze."

    lines = log_entries.strip().split("\n")
    findings = []
    iocs = {"ips": [], "domains": [], "hashes": []}

    # Simple pattern matching (actual lab uses LLM)
    import re

    for line in lines:
        # IP addresses
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        for ip in ips:
            if ip not in iocs["ips"]:
                iocs["ips"].append(ip)

        # Suspicious keywords
        if any(kw in line.lower() for kw in ["failed", "error", "denied", "attack"]):
            findings.append(f"Suspicious: {line[:100]}")

        # Potential command execution
        if any(kw in line.lower() for kw in ["exec", "cmd", "powershell", "bash"]):
            findings.append(f"Command execution: {line[:100]}")

    result = f"""
## Log Analysis Results

### Summary
- Lines analyzed: {len(lines)}
- Suspicious entries: {len(findings)}
- IOCs extracted: {len(iocs['ips'])} IPs

### Extracted IOCs
**IP Addresses:**
{chr(10).join(f"- {ip}" for ip in iocs['ips'][:10]) if iocs['ips'] else "- None found"}

### Suspicious Findings
{chr(10).join(f"- {f}" for f in findings[:5]) if findings else "- No suspicious patterns detected"}

### How It Works
This demo uses regex pattern matching as a simplified example.
The actual Lab 04 implementation uses:
- LLM-powered log parsing
- Structured output extraction
- MITRE ATT&CK technique mapping
- Context-aware analysis
"""
    return result


def demo_threat_intel(ioc_value: str, ioc_type: str) -> str:
    """
    Lab 05: Threat Intel Agent Demo

    Demonstrates autonomous threat intelligence gathering.
    """
    if not ioc_value.strip():
        return "Please enter an IOC to investigate."

    # Simulated threat intel (actual lab uses real APIs)
    intel = {
        "ioc": ioc_value,
        "type": ioc_type,
        "reputation": "Unknown",
        "sources": [],
        "related_iocs": [],
    }

    # Simple simulation based on IOC type
    if ioc_type == "IP Address":
        if ioc_value.startswith("10.") or ioc_value.startswith("192.168."):
            intel["reputation"] = "Private/Internal"
        elif ioc_value.startswith("185.") or ioc_value.startswith("45."):
            intel["reputation"] = "Potentially Suspicious"
            intel["sources"] = ["AbuseIPDB", "VirusTotal"]
        else:
            intel["reputation"] = "Unknown"

    elif ioc_type == "Domain":
        if any(tld in ioc_value for tld in [".tk", ".ml", ".ga", ".cf"]):
            intel["reputation"] = "Suspicious (free TLD)"
        elif any(brand in ioc_value.lower() for brand in ["google", "microsoft", "apple"]):
            intel["reputation"] = "Potential typosquatting"

    elif ioc_type == "Hash":
        if len(ioc_value) == 32:
            intel["hash_type"] = "MD5"
        elif len(ioc_value) == 64:
            intel["hash_type"] = "SHA256"

    result = f"""
## Threat Intelligence Report

### IOC Details
- **Value:** {intel['ioc']}
- **Type:** {intel['type']}
- **Reputation:** {intel['reputation']}

### Intelligence Sources
{chr(10).join(f"- {s}" for s in intel['sources']) if intel['sources'] else "- No threat intel sources queried (demo mode)"}

### Analysis
This is a simulated analysis for demonstration purposes.

### How It Works
This demo shows a simplified version of threat intel lookup.
The actual Lab 05 implementation uses:
- ReAct agent pattern for autonomous investigation
- Real threat intel APIs (VirusTotal, Shodan, AbuseIPDB)
- Multi-step reasoning and tool selection
- Memory for investigation history
"""
    return result


def demo_security_rag(query: str) -> str:
    """
    Lab 06: Security RAG Demo

    Demonstrates retrieval-augmented generation for security docs.
    """
    if not query.strip():
        return "Please enter a security question."

    # Simulated knowledge base
    knowledge = {
        "mitre": "MITRE ATT&CK is a knowledge base of adversary tactics and techniques.",
        "cve": "CVE (Common Vulnerabilities and Exposures) is a list of publicly disclosed security flaws.",
        "yara": "YARA is a tool for identifying and classifying malware based on pattern matching.",
        "sigma": "Sigma is a generic signature format for SIEM systems.",
        "ioc": "Indicators of Compromise (IOCs) are artifacts that indicate a potential security breach.",
    }

    # Find relevant context
    query_lower = query.lower()
    relevant = []
    for key, value in knowledge.items():
        if key in query_lower:
            relevant.append(value)

    result = f"""
## Security Knowledge Query

### Your Question
{query}

### Retrieved Context
{chr(10).join(f"> {r}" for r in relevant) if relevant else "> No specific context found for this query."}

### Response
{"Based on the retrieved context, " + relevant[0] if relevant else "I don't have specific information about this topic in my knowledge base."}

### How It Works
This demo uses simple keyword matching as a simplified example.
The actual Lab 06 implementation uses:
- Vector embeddings for semantic search
- ChromaDB for efficient retrieval
- Document chunking strategies
- LLM-powered response generation
"""
    return result


# =============================================================================
# GRADIO INTERFACE
# =============================================================================


def create_demo():
    """Create the Gradio demo interface."""

    with gr.Blocks(title="AI for the Win - Security Labs", theme=gr.themes.Soft()) as demo:

        gr.Markdown(
            """
        # AI for the Win - Interactive Lab Demos

        Explore AI-powered security tools through these interactive demos.
        Each demo showcases key concepts from the corresponding lab.

        > **Note:** These are simplified demos for learning. The actual labs
        > implement full solutions with trained models and real APIs.
        """
        )

        with gr.Tabs():

            # Lab 01: Phishing Classifier
            with gr.TabItem("Lab 01: Phishing Classifier"):
                gr.Markdown(
                    """
                ## Phishing Email Classification

                Analyze email text to detect potential phishing attempts.
                Uses text features and machine learning for classification.
                """
                )

                with gr.Row():
                    with gr.Column():
                        email_input = gr.Textbox(
                            label="Email Text",
                            placeholder="Paste email content here...",
                            lines=8,
                        )
                        threshold = gr.Slider(
                            minimum=0.1,
                            maximum=0.9,
                            value=0.5,
                            label="Classification Threshold",
                        )
                        analyze_btn = gr.Button("Analyze Email", variant="primary")

                    with gr.Column():
                        phishing_output = gr.Markdown(label="Results")

                analyze_btn.click(
                    demo_phishing_classifier,
                    inputs=[email_input, threshold],
                    outputs=phishing_output,
                )

                gr.Examples(
                    examples=[
                        [
                            "URGENT: Your account has been suspended! Click here immediately to verify your identity and restore access. Act now before your account is permanently deleted!",
                            0.5,
                        ],
                        [
                            "Hi team, the quarterly report is attached. Please review and send feedback by Friday. Thanks!",
                            0.5,
                        ],
                    ],
                    inputs=[email_input, threshold],
                )

            # Lab 03: Anomaly Detection
            with gr.TabItem("Lab 03: Anomaly Detection"):
                gr.Markdown(
                    """
                ## Network Anomaly Detection

                Analyze network flow data to detect anomalous behavior.
                Useful for identifying C2 beaconing, data exfiltration, and scanning.
                """
                )

                with gr.Row():
                    with gr.Column():
                        bytes_sent = gr.Number(label="Bytes Sent", value=50000)
                        bytes_recv = gr.Number(label="Bytes Received", value=10000)
                        packets = gr.Number(label="Packet Count", value=100)
                        duration = gr.Number(label="Duration (seconds)", value=30.0)
                        port = gr.Number(label="Destination Port", value=443)
                        detect_btn = gr.Button("Detect Anomalies", variant="primary")

                    with gr.Column():
                        anomaly_output = gr.Markdown(label="Results")

                detect_btn.click(
                    demo_anomaly_detection,
                    inputs=[bytes_sent, bytes_recv, packets, duration, port],
                    outputs=anomaly_output,
                )

            # Lab 04: Log Analysis
            with gr.TabItem("Lab 04: Log Analysis"):
                gr.Markdown(
                    """
                ## LLM-Powered Log Analysis

                Parse and analyze security logs to extract IOCs and
                identify suspicious patterns.
                """
                )

                with gr.Row():
                    with gr.Column():
                        log_input = gr.Textbox(
                            label="Log Entries",
                            placeholder="Paste log entries here (one per line)...",
                            lines=10,
                        )
                        parse_btn = gr.Button("Analyze Logs", variant="primary")

                    with gr.Column():
                        log_output = gr.Markdown(label="Results")

                parse_btn.click(demo_log_analysis, inputs=[log_input], outputs=log_output)

                gr.Examples(
                    examples=[
                        [
                            "2024-01-15 03:22:10 Failed login attempt from 185.143.223.47\n2024-01-15 03:22:11 CMD exec: powershell -enc SGVsbG8=\n2024-01-15 03:22:12 Connection to 192.168.1.100:4444 established"
                        ]
                    ],
                    inputs=[log_input],
                )

            # Lab 05: Threat Intel
            with gr.TabItem("Lab 05: Threat Intel"):
                gr.Markdown(
                    """
                ## Threat Intelligence Agent

                Investigate IOCs using autonomous threat intelligence gathering.
                Demonstrates the ReAct agent pattern for security research.
                """
                )

                with gr.Row():
                    with gr.Column():
                        ioc_value = gr.Textbox(
                            label="IOC Value",
                            placeholder="Enter IP, domain, or hash...",
                        )
                        ioc_type = gr.Dropdown(
                            choices=["IP Address", "Domain", "Hash"],
                            label="IOC Type",
                            value="IP Address",
                        )
                        intel_btn = gr.Button("Investigate", variant="primary")

                    with gr.Column():
                        intel_output = gr.Markdown(label="Results")

                intel_btn.click(
                    demo_threat_intel,
                    inputs=[ioc_value, ioc_type],
                    outputs=intel_output,
                )

            # Lab 06: Security RAG
            with gr.TabItem("Lab 06: Security RAG"):
                gr.Markdown(
                    """
                ## Security Knowledge RAG

                Query security documentation using retrieval-augmented generation.
                Combines semantic search with LLM-powered responses.
                """
                )

                with gr.Row():
                    with gr.Column():
                        rag_query = gr.Textbox(
                            label="Security Question",
                            placeholder="Ask about CVEs, MITRE ATT&CK, YARA, etc...",
                        )
                        rag_btn = gr.Button("Search & Answer", variant="primary")

                    with gr.Column():
                        rag_output = gr.Markdown(label="Results")

                rag_btn.click(demo_security_rag, inputs=[rag_query], outputs=rag_output)

                gr.Examples(
                    examples=[
                        ["What is MITRE ATT&CK?"],
                        ["How do YARA rules work?"],
                        ["What are IOCs in cybersecurity?"],
                    ],
                    inputs=[rag_query],
                )

        gr.Markdown(
            """
        ---
        ### About This Demo

        These interactive demos provide a simplified introduction to each lab's concepts.
        For full implementations with trained models, real APIs, and production features,
        complete the hands-on labs.

        **Resources:**
        - [Lab Documentation](./labs/README.md)
        - [Learning Guide](./LEARNING_GUIDE.md)
        - [Setup Instructions](./setup/dev-environment-setup.md)
        """
        )

    return demo


# =============================================================================
# MAIN
# =============================================================================


def main():
    """Launch the Gradio demo."""
    print("=" * 60)
    print("AI for the Win - Interactive Demo Launcher")
    print("=" * 60)

    if not GRADIO_AVAILABLE:
        print("\nError: Gradio is required.")
        print("Install with: pip install gradio")
        return

    demo = create_demo()

    print("\nLaunching demo server...")
    print("Open http://localhost:7860 in your browser")
    print("Press Ctrl+C to stop\n")

    demo.launch(server_name="0.0.0.0", server_port=7860, share=False)


if __name__ == "__main__":
    main()
