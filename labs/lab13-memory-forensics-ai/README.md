# Lab 13: AI-Powered Memory Forensics

Analyze memory dumps using AI to detect malware, process injection, and hidden threats that evade disk-based detection.

## Learning Objectives

1. Understand memory forensics fundamentals and Volatility3
2. Use ML to detect anomalous processes and injected code
3. Apply LLMs to interpret forensic artifacts
4. Build automated memory triage pipelines
5. Extract IOCs and map to MITRE ATT&CK

## Estimated Time

4-5 hours

## Prerequisites

- Completed Labs 03 (Anomaly Detection), 04 (Log Analysis)
- Basic understanding of Windows internals (processes, DLLs, registry)
- Familiarity with memory acquisition concepts

## Background

### Why Memory Forensics?

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     MEMORY vs DISK FORENSICS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   DISK FORENSICS                    MEMORY FORENSICS                        │
│   ──────────────                    ────────────────                        │
│   • Files on disk                   • Running processes                     │
│   • Registry hives                  • Network connections                   │
│   • Event logs                      • Injected code                         │
│   • Deleted file recovery           • Decrypted malware                     │
│                                     • Encryption keys                       │
│   ✗ Misses fileless malware         • Command history                       │
│   ✗ Can't see injected code         • Unpacked/decoded payloads            │
│   ✗ Encrypted at rest                                                       │
│                                                                             │
│   Memory captures what's ACTUALLY RUNNING, not just what's on disk         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MITRE ATT&CK Techniques Detectable in Memory

| Technique | ID | Memory Artifacts |
|-----------|-----|------------------|
| Process Injection | T1055 | Hollowed processes, injected threads |
| Reflective DLL Loading | T1620 | Unmapped DLLs in process memory |
| Credential Dumping | T1003 | LSASS access, mimikatz patterns |
| Rootkit | T1014 | SSDT hooks, hidden processes |
| Fileless Malware | T1059 | PowerShell in memory only |

### Memory Analysis Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MEMORY FORENSICS PIPELINE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Memory      Profile       Extract        Analyze        Report             │
│  Dump   ──► Detection ──► Artifacts  ──► with AI   ──► Findings            │
│                                                                             │
│  .raw         OS version    • Processes    ML anomaly    IOCs               │
│  .vmem        Build info    • DLLs         detection     MITRE mapping      │
│  .dmp                       • Handles                    Timeline           │
│                             • Network      LLM           Recommendations    │
│                             • Registry     interpretation                   │
│                             • Malfind                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Tasks

### Task 1: Memory Artifact Extraction

Extract key artifacts from memory dumps using Volatility3-style parsing.

```python
# TODO: Implement artifact extraction
class MemoryAnalyzer:
    def __init__(self, memory_dump_path: str):
        """Initialize memory analyzer with dump file."""
        pass

    def extract_processes(self) -> List[ProcessInfo]:
        """Extract running processes with metadata."""
        # Extract: PID, PPID, name, path, command line, creation time
        pass

    def extract_network_connections(self) -> List[NetworkConnection]:
        """Extract active network connections."""
        # Extract: local/remote IP, ports, state, owning process
        pass

    def extract_loaded_dlls(self, pid: int) -> List[DLLInfo]:
        """Extract DLLs loaded by a process."""
        pass

    def detect_injected_code(self) -> List[InjectionIndicator]:
        """Detect potential code injection artifacts."""
        # Look for: RWX memory regions, unmapped executables
        pass
```

### Task 2: ML-Based Process Anomaly Detection

Build models to identify suspicious processes.

```python
# TODO: Implement process anomaly scoring
class ProcessAnomalyDetector:
    def __init__(self):
        self.baseline_features = self._load_baseline()

    def extract_features(self, process: ProcessInfo) -> np.ndarray:
        """Extract features for anomaly detection."""
        # Features: parent-child relationship, path anomalies,
        # command line entropy, DLL count, handle count
        pass

    def score_process(self, process: ProcessInfo) -> float:
        """Return anomaly score 0-1 for process."""
        pass

    def detect_process_hollowing(self, process: ProcessInfo) -> bool:
        """Detect signs of process hollowing."""
        # Compare on-disk vs in-memory image
        pass
```

### Task 3: LLM-Powered Artifact Interpretation

Use LLMs to analyze and explain forensic findings.

```python
# TODO: Implement LLM analysis
def analyze_suspicious_process(process: ProcessInfo, context: dict) -> dict:
    """Use LLM to analyze suspicious process."""

    prompt = f"""
    Analyze this potentially malicious process from a memory dump:

    Process: {process.name} (PID: {process.pid})
    Parent: {process.parent_name} (PPID: {process.ppid})
    Path: {process.path}
    Command Line: {process.cmdline}
    Creation Time: {process.create_time}

    Suspicious Indicators:
    {context.get('indicators', [])}

    Provide:
    1. Threat assessment (benign/suspicious/malicious)
    2. Likely malware family or technique
    3. MITRE ATT&CK techniques
    4. Recommended response actions
    5. Additional artifacts to investigate

    Return as JSON.
    """
    # Implement LLM call
    pass
```

### Task 4: Automated Memory Triage Pipeline

Build end-to-end automated analysis.

```python
# TODO: Implement triage pipeline
class MemoryTriagePipeline:
    def __init__(self, llm_provider: str = "auto"):
        self.analyzer = MemoryAnalyzer()
        self.detector = ProcessAnomalyDetector()
        self.llm = setup_llm(provider=llm_provider)

    def triage(self, memory_dump: str) -> TriageReport:
        """Run full automated triage on memory dump."""

        # 1. Extract all artifacts
        processes = self.analyzer.extract_processes()
        connections = self.analyzer.extract_network_connections()
        injections = self.analyzer.detect_injected_code()

        # 2. Score all processes
        scored = [(p, self.detector.score_process(p)) for p in processes]
        suspicious = [p for p, s in scored if s > 0.7]

        # 3. Deep analysis on suspicious
        findings = []
        for process in suspicious:
            analysis = analyze_suspicious_process(process, {
                'connections': self._get_process_connections(process, connections),
                'injections': self._get_process_injections(process, injections)
            })
            findings.append(analysis)

        # 4. Generate report
        return self._generate_report(findings)
```

### Task 5: IOC Extraction and MITRE Mapping

Extract actionable intelligence from findings.

```python
# TODO: Implement IOC extraction
def extract_iocs_from_memory(findings: List[dict]) -> IOCBundle:
    """Extract IOCs from memory analysis findings."""

    iocs = IOCBundle()

    for finding in findings:
        # Extract file hashes
        if finding.get('suspicious_dlls'):
            for dll in finding['suspicious_dlls']:
                iocs.add_hash(dll['sha256'], 'SHA256')

        # Extract network indicators
        if finding.get('c2_connections'):
            for conn in finding['c2_connections']:
                iocs.add_ip(conn['remote_ip'])
                iocs.add_domain(conn.get('domain'))

        # Extract MITRE techniques
        iocs.add_techniques(finding.get('mitre_techniques', []))

    return iocs
```

---

## Sample Data

The `data/` directory contains:
- `sample_process_list.json` - Simulated process listing with malicious entries
- `sample_connections.json` - Network connections including C2
- `sample_malfind.json` - Detected code injection artifacts
- `baseline_processes.json` - Known-good process baseline

---

## Hints

<details>
<summary>Hint 1: Process Hollowing Detection</summary>

Compare the in-memory image base with the on-disk PE header. Mismatches indicate hollowing:
```python
def detect_hollowing(process):
    disk_base = get_pe_image_base(process.path)
    memory_base = process.peb.image_base
    return disk_base != memory_base
```
</details>

<details>
<summary>Hint 2: Suspicious Parent-Child Relationships</summary>

Some parent-child relationships are almost always malicious:
- `outlook.exe` → `powershell.exe`
- `excel.exe` → `cmd.exe`
- `svchost.exe` spawned by anything other than `services.exe`
</details>

<details>
<summary>Hint 3: Command Line Entropy</summary>

High entropy in command lines often indicates encoded/obfuscated commands:
```python
import math
def entropy(s):
    prob = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)
```
</details>

---

## Bonus Challenges

1. **Timeline Reconstruction**: Build a timeline correlating process creation, network activity, and file operations
2. **YARA Integration**: Generate YARA rules from memory-extracted malware
3. **Credential Extraction**: Detect credential dumping attempts from LSASS access patterns
4. **Rootkit Detection**: Identify hidden processes by cross-referencing multiple sources

---

## Resources

- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [SANS Memory Forensics Cheat Sheet](https://www.sans.org/posters/memory-forensics-cheat-sheet/)
- [MemProcFS](https://github.com/ufrisk/MemProcFS)
- [MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

---

> **Stuck?** See the [Lab 13 Walkthrough](../../docs/walkthroughs/lab13-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 14 - AI-Powered C2 Traffic Analysis](../lab14-c2-traffic-analysis/)