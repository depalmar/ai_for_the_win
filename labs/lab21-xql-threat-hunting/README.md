# Lab 21: XQL Threat Hunting with AI

Build AI-assisted threat hunting queries for Cortex XDR using XQL.

## Learning Objectives

By the end of this lab, you will be able to:
- Write effective XQL queries for threat hunting
- Use LLMs to generate and optimize XQL queries
- Build detection rules from hunting findings
- Map detections to MITRE ATT&CK framework

## Prerequisites

- Completed Lab 04 (LLM Log Analysis)
- Basic understanding of threat hunting concepts
- Familiarity with MITRE ATT&CK
- Access to an LLM API (Claude, OpenAI, etc.)

## Background

### What is XQL?

XQL (XDR Query Language) is Palo Alto Networks' query language for Cortex XDR. It allows security analysts to:
- Hunt for threats across endpoint telemetry
- Build custom detection rules (BIOCs)
- Investigate incidents with correlated data

### XQL Datasets

| Dataset | Description | Use Case |
|---------|-------------|----------|
| `xdr_data` | Raw EDR events from agents + third-party logs | Threat hunting, process/network/file analysis |
| `endpoints` | Endpoint metadata (groups, IDs, status) | Asset inventory, endpoint correlation |
| `host_inventory` | Installed applications, OS info | Vulnerability context, software audit |

### XQL Presets (Filtered Views)

Presets are optimized subsets of datasets for specific analysis:

| Preset | Fields Included |
|--------|-----------------|
| `host_inventory_applications` | install_date, vendor, application_name, version |
| `host_inventory_endpoints` | endpoint_name, operating_system, endpoint_type |
| `network_story` | Combined NGFW + XDR agent network data |
| `authentication_story` | Unified authentication logs |

**Note:** Incidents and alerts are processed data and not directly queryable via XQL. Use the Incidents API for alert queries.

### AI-Assisted Threat Hunting

LLMs can help with:
- Generating XQL queries from natural language descriptions
- Explaining complex query logic
- Suggesting query optimizations
- Mapping findings to ATT&CK techniques

## Lab Tasks

### Task 1: Build a Query Generator (20 min)

Create an LLM-powered function that converts natural language threat descriptions into valid XQL queries.

```python
# TODO: Implement query_from_description()
# Input: "Find encoded PowerShell commands in the last 7 days"
# Output: Valid XQL query with config statements
```

**Requirements:**
- Include `config case_sensitive = false`
- Use time filtering: `_time >= now() - duration("7d")` (preferred) or `timestamp_diff()`
- Return properly formatted XQL

### Task 2: Query Validator (15 min)

Build a function that validates XQL query syntax and suggests improvements.

```python
# TODO: Implement validate_xql_query()
# Check for:
# - Valid dataset names (xdr_data, endpoints, etc.)
# - Proper ENUM usage
# - Time filter presence
# - Config statements
```

### Task 3: MITRE ATT&CK Mapper (15 min)

Create a function that analyzes XQL queries and maps them to relevant ATT&CK techniques.

```python
# TODO: Implement map_to_attack()
# Input: XQL query string
# Output: List of relevant technique IDs with descriptions
```

### Task 4: Detection Rule Builder (20 min)

Build a system that converts hunting queries into BIOC-style detection rules.

```python
# TODO: Implement create_detection_rule()
# Input: XQL query + metadata (name, severity, description)
# Output: Structured detection rule with MITRE mapping
```

### Task 5: Integration Test (10 min)

Test the complete workflow:
1. Describe a threat scenario in natural language
2. Generate XQL query
3. Validate the query
4. Map to ATT&CK
5. Create a detection rule

## Attack Scenario: Operation Midnight Heist

This lab uses a realistic attack chain to practice threat hunting. Each scenario builds on the previous one, following a ransomware operator's typical kill chain:

```
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ 1. INITIAL      │ → │ 2. CREDENTIAL   │ → │ 3. LATERAL      │
│    ACCESS       │   │    THEFT        │   │    MOVEMENT     │
│ Phishing email  │   │ Mimikatz dumps  │   │ PsExec to file  │
│ + macro payload │   │ LSASS creds     │   │ server          │
└─────────────────┘   └─────────────────┘   └─────────────────┘
         ↓                                           ↓
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ 4. PERSISTENCE  │ ← │ 5. DEFENSE      │ ← │                 │
│ Scheduled task  │   │    EVASION      │   │                 │
│ + registry key  │   │ Disable AV,     │   │                 │
│                 │   │ clear logs      │   │                 │
└─────────────────┘   └─────────────────┘   └─────────────────┘
         ↓
┌─────────────────┐   ┌─────────────────┐
│ 6. EXFILTRATION │ → │ 7. IMPACT       │
│ Certutil encode │   │ Shadow delete   │
│ + upload data   │   │ + ransomware    │
└─────────────────┘   └─────────────────┘
```

Each scenario includes:
- **Attack context**: What the attacker did and why
- **Hunt objectives**: What to look for in XQL
- **Query hints**: Field names and patterns to match
- **MITRE ATT&CK mapping**: Relevant technique IDs

## Sample Data

The `data/scenarios.json` file contains detailed threat scenarios with query building hints.

## Hints

<details>
<summary>Hint 1: Query Structure</summary>

XQL queries should follow this pattern:
```sql
config case_sensitive = false
config timeframe between "start" and "end"  // OR use timestamp_diff()
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter <your conditions>
| fields <selected fields>
| sort desc _time
| limit 100
```
</details>

<details>
<summary>Hint 2: System Prompt</summary>

Use a system prompt that establishes XQL expertise:
```
You are an expert in Cortex XDR XQL query language. You write queries that:
- Use config case_sensitive = false for case-insensitive matching
- Use timestamp_diff(current_time(), _time, "DAY") for relative time
- Use ENUM values for event types (ENUM.PROCESS, ENUM.NETWORK, etc.)
- Include appropriate limits to prevent timeouts
```
</details>

<details>
<summary>Hint 3: Validation Patterns</summary>

Key validation checks:
- Datasets: `xdr_data` (main), `endpoints`, `host_inventory`
- Presets: `host_inventory_applications`, `network_story`, `authentication_story`
- Event types use ENUM: `ENUM.PROCESS`, `ENUM.NETWORK`, `ENUM.FILE`, `ENUM.REGISTRY`
- Time filters must be present (use `now() - duration("7d")` or `timestamp_diff()`)
- Fields should match the XDR schema (actor_process_*, action_*, agent_*)
</details>

## Expected Output

```
=== AI-Assisted XQL Threat Hunting ===

Input: "Detect Mimikatz credential dumping attempts"

Generated Query:
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_command_line contains "sekurlsa"
    or actor_process_command_line contains "lsadump"
    or actor_process_command_line contains "privilege::debug"
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line
| sort desc _time
| limit 100

Validation: PASSED

MITRE ATT&CK Mapping:
- T1003.001: OS Credential Dumping: LSASS Memory
- T1003.002: OS Credential Dumping: Security Account Manager

Detection Rule Created:
- Name: Mimikatz Credential Dumping
- Severity: Critical
- MITRE: T1003.001, T1003.002
```

## Bonus Challenges

1. **Multi-Query Correlation**: Generate related queries that detect different stages of an attack chain
2. **Query Optimization**: Build a function that analyzes query performance and suggests improvements
3. **False Positive Reducer**: Add logic to exclude known-good patterns from queries
4. **Alert Enrichment**: Create queries that pull additional context for alerts

## Resources

- [XQL Guide](../../docs/guides/xql-guide.md) - Comprehensive XQL reference
- [XQL Templates](../../templates/xql/) - Pre-built query templates
- [Cortex XDR Docs](https://docs.paloaltonetworks.com/cortex/cortex-xdr) - Official documentation
- [MITRE ATT&CK](https://attack.mitre.org/) - Technique reference
