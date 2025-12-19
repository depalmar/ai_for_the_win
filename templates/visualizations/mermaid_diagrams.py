#!/usr/bin/env python3
"""
Mermaid Diagram Generator for Security Analysis

Generate Mermaid diagrams for visualizing:
- Attack chains and kill chains
- Detection pipelines
- Incident timelines
- System architectures
- Data flow diagrams
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum


class DiagramType(Enum):
    FLOWCHART = "flowchart"
    SEQUENCE = "sequenceDiagram"
    GANTT = "gantt"
    STATE = "stateDiagram-v2"
    PIE = "pie"
    TIMELINE = "timeline"
    MINDMAP = "mindmap"
    SANKEY = "sankey-beta"


@dataclass
class TimelineEvent:
    """Event for timeline visualization."""
    timestamp: datetime
    title: str
    description: str
    category: str
    severity: str = "medium"  # low, medium, high, critical


@dataclass
class AttackStep:
    """Step in an attack chain."""
    id: str
    name: str
    technique_id: str
    description: str
    next_steps: List[str]


class MermaidGenerator:
    """Generate Mermaid diagrams for security analysis."""

    # ==========================================================================
    # Attack Chain Diagrams
    # ==========================================================================

    @staticmethod
    def ransomware_kill_chain() -> str:
        """Generate ransomware kill chain diagram."""
        return """```mermaid
flowchart LR
    subgraph Initial["🎯 Initial Access"]
        A1[Phishing Email]
        A2[RDP Brute Force]
        A3[Exploit Public App]
    end

    subgraph Execution["⚡ Execution"]
        B1[Loader/Dropper]
        B2[PowerShell]
        B3[WMI/WMIC]
    end

    subgraph Persistence["🔒 Persistence"]
        C1[Registry Run Keys]
        C2[Scheduled Tasks]
        C3[Services]
    end

    subgraph Discovery["🔍 Discovery"]
        D1[Network Shares]
        D2[Domain Enum]
        D3[File Discovery]
    end

    subgraph Lateral["↔️ Lateral Movement"]
        E1[PsExec]
        E2[SMB/Admin Shares]
        E3[RDP]
    end

    subgraph Exfil["📤 Exfiltration"]
        F1[Cloud Upload]
        F2[C2 Transfer]
        F3[Data Staging]
    end

    subgraph Impact["💥 Impact"]
        G1[Encrypt Files]
        G2[Delete Shadows]
        G3[Ransom Note]
    end

    A1 & A2 & A3 --> B1 & B2 & B3
    B1 & B2 & B3 --> C1 & C2 & C3
    C1 & C2 & C3 --> D1 & D2 & D3
    D1 & D2 & D3 --> E1 & E2 & E3
    E1 & E2 & E3 --> F1 & F2 & F3
    F1 & F2 & F3 --> G1 & G2 & G3

    style Initial fill:#ff6b6b,color:#fff
    style Execution fill:#ffa502,color:#fff
    style Persistence fill:#f9ca24,color:#000
    style Discovery fill:#7bed9f,color:#000
    style Lateral fill:#70a1ff,color:#fff
    style Exfil fill:#5352ed,color:#fff
    style Impact fill:#2f3542,color:#fff
```"""

    @staticmethod
    def detection_pipeline() -> str:
        """Generate detection pipeline diagram."""
        return """```mermaid
flowchart TB
    subgraph Ingestion["📥 Data Ingestion"]
        I1[Sysmon Events]
        I2[Network Flows]
        I3[EDR Telemetry]
        I4[Cloud Logs]
    end

    subgraph Normalize["🔄 Normalization"]
        N1[Parse & Extract]
        N2[Enrich Context]
        N3[Schema Mapping]
    end

    subgraph ML["🤖 ML Detection"]
        M1[Anomaly Score]
        M2[Classification]
        M3[Clustering]
    end

    subgraph LLM["🧠 LLM Analysis"]
        L1[Context Analysis]
        L2[IOC Extraction]
        L3[MITRE Mapping]
    end

    subgraph Correlate["🔗 Correlation"]
        C1[Event Linking]
        C2[Attack Chain]
        C3[Entity Resolution]
    end

    subgraph Output["📊 Output"]
        O1[Alerts]
        O2[Reports]
        O3[Dashboards]
    end

    I1 & I2 & I3 & I4 --> N1
    N1 --> N2 --> N3
    N3 --> M1 & M2 & M3
    M1 & M2 & M3 --> L1 & L2 & L3
    L1 & L2 & L3 --> C1 & C2 & C3
    C1 & C2 & C3 --> O1 & O2 & O3

    style Ingestion fill:#74b9ff,color:#000
    style Normalize fill:#81ecec,color:#000
    style ML fill:#a29bfe,color:#fff
    style LLM fill:#fd79a8,color:#fff
    style Correlate fill:#fdcb6e,color:#000
    style Output fill:#00b894,color:#fff
```"""

    @staticmethod
    def incident_response_workflow() -> str:
        """Generate IR workflow diagram."""
        return """```mermaid
stateDiagram-v2
    [*] --> Detection: Alert Triggered

    Detection --> Triage: Analyze Alert
    Triage --> FalsePositive: Not Malicious
    Triage --> Investigation: Confirmed Threat

    FalsePositive --> [*]: Close Alert

    Investigation --> Containment: Threat Validated
    Investigation --> Triage: Need More Info

    Containment --> Eradication: Threat Contained
    Containment --> Escalation: Cannot Contain

    Escalation --> Containment: Resources Added
    Escalation --> CrisisMode: Major Incident

    Eradication --> Recovery: Threat Removed
    Recovery --> Monitoring: Systems Restored
    Monitoring --> [*]: Incident Closed

    CrisisMode --> Eradication: Crisis Managed

    note right of Detection
        Automated detection
        from SIEM/EDR/XDR
    end note

    note right of Containment
        Network isolation
        Process termination
        Account lockout
    end note

    note right of Recovery
        Backup restoration
        System rebuild
        Validation testing
    end note
```"""

    # ==========================================================================
    # Timeline Diagrams
    # ==========================================================================

    @staticmethod
    def generate_attack_timeline(events: List[TimelineEvent]) -> str:
        """Generate attack timeline from events."""
        lines = ["```mermaid", "timeline"]
        lines.append("    title Attack Timeline")

        current_date = None
        for event in sorted(events, key=lambda x: x.timestamp):
            date_str = event.timestamp.strftime("%Y-%m-%d %H:%M")
            if current_date != event.timestamp.date():
                current_date = event.timestamp.date()
                lines.append(f"    section {current_date}")
            lines.append(f"        {date_str} : {event.title}")
            lines.append(f"            : {event.description}")

        lines.append("```")
        return "\n".join(lines)

    @staticmethod
    def ransomware_timeline_example() -> str:
        """Example ransomware attack timeline."""
        return """```mermaid
timeline
    title Ransomware Attack Timeline

    section Day 1 - Initial Access
        09:15 : Phishing Email Received
             : Employee clicks malicious link
        09:17 : Malware Downloaded
             : Initial loader executed
        09:20 : C2 Established
             : Beacon to attacker infrastructure

    section Day 1 - Reconnaissance
        10:30 : Network Discovery
             : Internal network enumeration
        11:45 : AD Enumeration
             : Domain admin accounts identified
        14:00 : Share Mapping
             : Critical file shares discovered

    section Day 2 - Lateral Movement
        02:00 : Credential Harvesting
             : Mimikatz executed on DC
        03:30 : Lateral Spread
             : Access to 15 additional hosts
        05:00 : Privilege Escalation
             : Domain admin obtained

    section Day 3 - Data Exfiltration
        01:00 : Data Staging
             : 500GB staged for exfil
        02:00 : Cloud Upload
             : Data exfiltrated to cloud storage
        04:00 : Evidence Cleanup
             : Logs partially cleared

    section Day 3 - Impact
        04:30 : Shadow Deletion
             : VSS copies destroyed
        04:35 : Encryption Started
             : File encryption begins
        06:00 : Ransom Notes
             : Notes dropped across network
        07:00 : Detection
             : SOC alerted to incident
```"""

    # ==========================================================================
    # Statistical Visualization
    # ==========================================================================

    @staticmethod
    def detection_metrics_pie(metrics: Dict[str, float]) -> str:
        """Generate pie chart for detection metrics."""
        lines = ["```mermaid", "pie showData"]
        lines.append('    title "Detection Results"')
        for label, value in metrics.items():
            lines.append(f'    "{label}" : {value}')
        lines.append("```")
        return "\n".join(lines)

    @staticmethod
    def mitre_coverage_example() -> str:
        """Example MITRE coverage visualization."""
        return """```mermaid
pie showData
    title "MITRE ATT&CK Coverage"
    "Detected" : 45
    "Partial" : 20
    "Not Covered" : 35
```"""

    # ==========================================================================
    # System Architecture
    # ==========================================================================

    @staticmethod
    def security_architecture() -> str:
        """Generate security architecture diagram."""
        return """```mermaid
flowchart TB
    subgraph External["🌐 External"]
        Internet[Internet]
        ThreatFeeds[Threat Intel Feeds]
    end

    subgraph Perimeter["🛡️ Perimeter"]
        FW[Firewall]
        WAF[WAF]
        Proxy[Proxy]
    end

    subgraph Network["🔌 Network"]
        IDS[IDS/IPS]
        NDR[NDR]
        NetFlow[NetFlow]
    end

    subgraph Endpoint["💻 Endpoints"]
        EDR[EDR Agents]
        AV[Antivirus]
        DLP[DLP]
    end

    subgraph Data["📊 Data Collection"]
        SIEM[SIEM]
        DataLake[Data Lake]
        SOAR[SOAR]
    end

    subgraph AI["🤖 AI/ML Layer"]
        Detection[ML Detection]
        Analysis[LLM Analysis]
        Correlation[Event Correlation]
    end

    subgraph Response["⚡ Response"]
        Alerts[Alert Console]
        Playbooks[Playbooks]
        Automation[Automation]
    end

    Internet --> FW
    ThreatFeeds --> SIEM
    FW --> WAF --> Proxy
    Proxy --> IDS & NDR
    IDS & NDR --> NetFlow
    NetFlow --> SIEM
    EDR & AV & DLP --> SIEM
    SIEM --> DataLake
    DataLake --> Detection & Analysis
    Detection & Analysis --> Correlation
    Correlation --> SOAR
    SOAR --> Alerts & Playbooks & Automation

    style External fill:#ff7675,color:#fff
    style Perimeter fill:#fdcb6e,color:#000
    style Network fill:#74b9ff,color:#000
    style Endpoint fill:#a29bfe,color:#fff
    style Data fill:#81ecec,color:#000
    style AI fill:#fd79a8,color:#fff
    style Response fill:#00b894,color:#fff
```"""

    # ==========================================================================
    # Gantt Charts for IR
    # ==========================================================================

    @staticmethod
    def ir_gantt_chart() -> str:
        """Generate IR timeline as Gantt chart."""
        return """```mermaid
gantt
    title Incident Response Timeline
    dateFormat  HH:mm
    axisFormat  %H:%M

    section Detection
    Alert Triggered           :a1, 07:00, 5m
    Initial Triage            :a2, after a1, 15m

    section Investigation
    Log Analysis              :b1, after a2, 30m
    Endpoint Forensics        :b2, after a2, 45m
    Network Analysis          :b3, after a2, 30m
    Scope Assessment          :b4, after b1, 20m

    section Containment
    Network Isolation         :c1, after b4, 10m
    Account Lockout           :c2, after c1, 5m
    Process Termination       :c3, after c2, 10m

    section Eradication
    Malware Removal           :d1, after c3, 30m
    Persistence Cleanup       :d2, after d1, 20m
    Validation Scan           :d3, after d2, 15m

    section Recovery
    Backup Restoration        :e1, after d3, 60m
    Service Validation        :e2, after e1, 30m
    User Communication        :e3, after e2, 15m

    section Documentation
    Timeline Creation         :f1, after e3, 30m
    Lessons Learned           :f2, after f1, 45m
    Final Report              :f3, after f2, 60m
```"""

    # ==========================================================================
    # Data Flow Diagrams
    # ==========================================================================

    @staticmethod
    def ransomware_data_flow() -> str:
        """Generate ransomware data flow diagram."""
        return """```mermaid
flowchart LR
    subgraph Victim["Victim Environment"]
        Files[(Files)]
        VSS[(Shadow Copies)]
        Backup[(Backups)]
    end

    subgraph Ransomware["Ransomware Process"]
        Enum[File Enumeration]
        Encrypt[Encryption Engine]
        Keys[Key Generation]
    end

    subgraph Attacker["Attacker Infrastructure"]
        C2[C2 Server]
        KeyServer[Key Server]
        LeakSite[Leak Site]
    end

    Files --> Enum
    Enum --> Keys
    Keys --> Encrypt
    Encrypt --> Files

    Keys -.->|Key Upload| KeyServer
    VSS -.->|Delete| Ransomware
    Files -.->|Exfiltrate| LeakSite

    style Victim fill:#74b9ff,color:#000
    style Ransomware fill:#ff7675,color:#fff
    style Attacker fill:#2d3436,color:#fff
```"""


class MermaidTemplates:
    """Pre-built templates for common security diagrams."""

    PHISHING_ANALYSIS = """```mermaid
flowchart TD
    A[📧 Email Received] --> B{Header Analysis}
    B -->|Suspicious| C[Extract Features]
    B -->|Clean| D[Allow]

    C --> E[TF-IDF Vectorization]
    E --> F[ML Classification]

    F -->|Phishing| G[🚫 Block & Alert]
    F -->|Legitimate| H[✅ Deliver]
    F -->|Uncertain| I[🔍 Manual Review]

    G --> J[Extract IOCs]
    J --> K[Update Threat Intel]
    K --> L[Block Similar]

    style A fill:#3498db,color:#fff
    style G fill:#e74c3c,color:#fff
    style H fill:#2ecc71,color:#fff
    style I fill:#f39c12,color:#fff
```"""

    MALWARE_CLUSTERING = """```mermaid
flowchart LR
    subgraph Input["📥 Sample Input"]
        S1[Sample 1]
        S2[Sample 2]
        S3[Sample N]
    end

    subgraph Features["🔍 Feature Extraction"]
        F1[Import Hash]
        F2[Section Entropy]
        F3[String Analysis]
        F4[API Calls]
    end

    subgraph Clustering["🎯 Clustering"]
        C1[K-Means]
        C2[DBSCAN]
        C3[Hierarchical]
    end

    subgraph Output["📊 Results"]
        O1[Family A]
        O2[Family B]
        O3[Outliers]
    end

    S1 & S2 & S3 --> F1 & F2 & F3 & F4
    F1 & F2 & F3 & F4 --> C1 & C2 & C3
    C1 & C2 & C3 --> O1 & O2 & O3

    style Input fill:#9b59b6,color:#fff
    style Features fill:#3498db,color:#fff
    style Clustering fill:#e67e22,color:#fff
    style Output fill:#27ae60,color:#fff
```"""

    ANOMALY_DETECTION = """```mermaid
flowchart TB
    subgraph Data["📊 Network Data"]
        D1[Flow Logs]
        D2[Packet Captures]
        D3[Connection Stats]
    end

    subgraph Baseline["📈 Baseline"]
        B1[Normal Patterns]
        B2[User Behavior]
        B3[Traffic Profiles]
    end

    subgraph Detection["🔍 Detection"]
        DE1[Isolation Forest]
        DE2[Autoencoder]
        DE3[Statistical Tests]
    end

    subgraph Scoring["📉 Scoring"]
        S1[Anomaly Score]
        S2[Confidence Level]
        S3[Risk Assessment]
    end

    subgraph Action["⚡ Action"]
        A1[Alert]
        A2[Investigate]
        A3[Block]
    end

    D1 & D2 & D3 --> B1 & B2 & B3
    B1 & B2 & B3 --> DE1 & DE2 & DE3
    DE1 & DE2 & DE3 --> S1 & S2 & S3
    S1 & S2 & S3 --> A1 & A2 & A3

    style Data fill:#3498db,color:#fff
    style Baseline fill:#2ecc71,color:#fff
    style Detection fill:#9b59b6,color:#fff
    style Scoring fill:#e67e22,color:#fff
    style Action fill:#e74c3c,color:#fff
```"""

    THREAT_INTEL_FLOW = """```mermaid
flowchart LR
    subgraph Sources["📰 Intel Sources"]
        S1[OSINT]
        S2[Commercial Feeds]
        S3[ISAC/ISAO]
        S4[Dark Web]
    end

    subgraph Processing["⚙️ Processing"]
        P1[IOC Extraction]
        P2[TTP Mapping]
        P3[Actor Attribution]
        P4[Confidence Scoring]
    end

    subgraph Enrichment["🔗 Enrichment"]
        E1[VirusTotal]
        E2[Shodan]
        E3[WHOIS]
        E4[Passive DNS]
    end

    subgraph Output["📤 Output"]
        O1[STIX Bundles]
        O2[YARA Rules]
        O3[Sigma Rules]
        O4[Hunt Queries]
    end

    S1 & S2 & S3 & S4 --> P1 & P2 & P3 & P4
    P1 & P2 & P3 & P4 --> E1 & E2 & E3 & E4
    E1 & E2 & E3 & E4 --> O1 & O2 & O3 & O4

    style Sources fill:#e74c3c,color:#fff
    style Processing fill:#3498db,color:#fff
    style Enrichment fill:#9b59b6,color:#fff
    style Output fill:#27ae60,color:#fff
```"""


def main():
    """Demo the Mermaid diagram generator."""
    print("=" * 60)
    print("Mermaid Diagram Generator")
    print("=" * 60)

    gen = MermaidGenerator()

    print("\n[1] Ransomware Kill Chain:")
    print(gen.ransomware_kill_chain())

    print("\n[2] Detection Pipeline:")
    print(gen.detection_pipeline())

    print("\n[3] IR Workflow:")
    print(gen.incident_response_workflow())

    print("\n[4] Attack Timeline:")
    print(gen.ransomware_timeline_example())

    print("\n[5] IR Gantt Chart:")
    print(gen.ir_gantt_chart())


if __name__ == "__main__":
    main()
