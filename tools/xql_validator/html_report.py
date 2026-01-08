"""
XQL Validator HTML Report Generator

Generates rich, interactive HTML reports with:
- Validation results with visual indicators
- Detection guidance and MITRE ATT&CK mapping
- False positive tuning recommendations
- Investigation next steps
- Query optimization suggestions
"""

import html
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from .validator import ValidationIssue, Severity, Category, XQLValidator, validate_query


# Stage descriptions for automatic documentation
STAGE_DESCRIPTIONS = {
    "dataset": {
        "name": "Data Source",
        "icon": "📦",
        "description": "Specifies which data source to query",
        "detail": "The dataset stage defines the telemetry source. Common datasets include xdr_data (endpoint events), panw_ngfw_* (firewall logs), and cloud_audit_logs.",
    },
    "filter": {
        "name": "Filter",
        "icon": "🔍",
        "description": "Reduces data to matching records",
        "detail": "Filter stages apply conditions to narrow results. Early, specific filters improve performance by reducing data processed in subsequent stages.",
    },
    "alter": {
        "name": "Transform",
        "icon": "🔧",
        "description": "Creates or modifies fields",
        "detail": "The alter stage computes new fields from existing data. Common uses include timestamp extraction, string manipulation, and conditional logic.",
    },
    "comp": {
        "name": "Aggregate",
        "icon": "📊",
        "description": "Groups and computes statistics",
        "detail": "Aggregation with comp calculates metrics like count(), sum(), avg() grouped by fields. Essential for thresholding and pattern detection.",
    },
    "fields": {
        "name": "Select Columns",
        "icon": "📋",
        "description": "Chooses which fields to return",
        "detail": "The fields stage limits output columns. Selecting only needed fields improves readability and reduces data transfer.",
    },
    "sort": {
        "name": "Order Results",
        "icon": "↕️",
        "description": "Orders results by field values",
        "detail": "Sort arranges results in ascending (asc) or descending (desc) order. Typically used to show newest events first.",
    },
    "limit": {
        "name": "Limit Output",
        "icon": "✂️",
        "description": "Restricts number of results",
        "detail": "Limit caps the number of returned rows. Always use limit to prevent overwhelming the UI with large result sets.",
    },
    "dedup": {
        "name": "Deduplicate",
        "icon": "🔄",
        "description": "Removes duplicate records",
        "detail": "Dedup removes duplicate rows based on specified fields. Useful for getting unique hosts, users, or file hashes.",
    },
    "join": {
        "name": "Join Data",
        "icon": "🔗",
        "description": "Combines data from multiple sources",
        "detail": "Join merges results from different datasets or subqueries. Enables correlation across data sources.",
    },
    "union": {
        "name": "Union Data",
        "icon": "➕",
        "description": "Combines multiple result sets",
        "detail": "Union appends results from multiple queries. All queries must have compatible field structures.",
    },
    "config": {
        "name": "Configuration",
        "icon": "⚙️",
        "description": "Sets query options",
        "detail": "Config sets query behavior like case_sensitive, timeframe, and other execution parameters.",
    },
    "target": {
        "name": "Materialize",
        "icon": "💾",
        "description": "Saves results to a dataset",
        "detail": "Target writes query results to a named dataset for later use. Enables detection chaining and complex workflows.",
    },
    "window": {
        "name": "Window Function",
        "icon": "🪟",
        "description": "Applies sliding window analytics",
        "detail": "Window functions perform calculations across a set of rows related to the current row.",
    },
}


def analyze_query_stages(query: str) -> list[dict]:
    """
    Parse and analyze each stage in an XQL query.
    Returns a list of stage information with descriptions.
    """
    stages = []
    known_stages = {'dataset', 'filter', 'alter', 'comp', 'fields', 'sort', 'limit',
                    'dedup', 'join', 'union', 'config', 'target', 'window', 'preset',
                    'call', 'arrayexpand', 'bin', 'iploc', 'view', 'getrole'}

    # Parse stages from query - handle multi-line content properly
    lines = query.split('\n')
    current_stage = None
    stage_content = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('//'):
            continue

        # Check for stage start (must start with | or be the first stage keyword)
        stage_match = re.match(r'\|\s*(\w+)\s*(.*)', stripped)
        if stage_match:
            stage_name = stage_match.group(1).lower()
            stage_value = stage_match.group(2).strip()

            # Check if this is a known stage
            if stage_name in known_stages:
                # Save previous stage
                if current_stage:
                    # Join content and clean up extra whitespace
                    content = ' '.join(stage_content)
                    # Add pipe prefix for display (except for config)
                    if current_stage != "config" and not content.startswith("|"):
                        content = "| " + content
                    # Truncate very long content for display
                    if len(content) > 500:
                        content = content[:500] + "..."
                    stages.append({
                        "stage_type": current_stage,
                        "content": content,
                        **STAGE_DESCRIPTIONS.get(current_stage, {
                            "name": current_stage.title(),
                            "icon": "▶️",
                            "description": f"Executes {current_stage} operation",
                            "detail": ""
                        })
                    })

                current_stage = stage_name
                # Keep the full expression including = for display
                # e.g., "= xdr_data" shows as "dataset = xdr_data"
                stage_content = [f"{stage_name} {stage_value}".strip()] if stage_value else [stage_name]
            elif current_stage:
                # Continuation of current stage
                stage_content.append(stripped)
        elif current_stage:
            # Check for non-pipe stage start (like config or first dataset)
            first_stage_match = re.match(r'(\w+)\s*=\s*(.*)', stripped)
            if first_stage_match and first_stage_match.group(1).lower() in known_stages:
                # Save previous stage first
                if stage_content:
                    content = ' '.join(stage_content)
                    # Add pipe prefix for display (except for config)
                    if current_stage != "config" and not content.startswith("|"):
                        content = "| " + content
                    if len(content) > 500:
                        content = content[:500] + "..."
                    stages.append({
                        "stage_type": current_stage,
                        "content": content,
                        **STAGE_DESCRIPTIONS.get(current_stage, {
                            "name": current_stage.title(),
                            "icon": "▶️",
                            "description": f"Executes {current_stage} operation",
                            "detail": ""
                        })
                    })
                current_stage = first_stage_match.group(1).lower()
                # Keep full expression for display
                stage_content = [f"{current_stage} = {first_stage_match.group(2).strip()}"]
            else:
                # Continuation of current stage (multi-line content)
                stage_content.append(stripped)
        else:
            # Check for first stage without pipe
            first_stage_match = re.match(r'(\w+)\s*=\s*(.*)', stripped)
            if first_stage_match and first_stage_match.group(1).lower() in known_stages:
                current_stage = first_stage_match.group(1).lower()
                # Keep full expression for display
                stage_content = [f"{current_stage} = {first_stage_match.group(2).strip()}"]

    # Don't forget the last stage
    if current_stage:
        content = ' '.join(stage_content)
        # Add pipe prefix for display (except for config which doesn't use pipe)
        if current_stage != "config" and not content.startswith("|"):
            content = "| " + content
        # Increase truncation limit to show more content
        if len(content) > 500:
            content = content[:500] + "..."
        stages.append({
            "stage_type": current_stage,
            "content": content,
            **STAGE_DESCRIPTIONS.get(current_stage, {
                "name": current_stage.title(),
                "icon": "▶️",
                "description": f"Executes {current_stage} operation",
                "detail": ""
            })
        })

    return stages


def generate_annotated_query(query: str) -> str:
    """
    Generate an annotated version of the query with inline comments.
    Provides context-aware explanations for each stage.
    """
    lines = query.split('\n')
    annotated = []
    filter_count = 0

    for line in lines:
        stripped = line.strip()

        # Skip existing comments and empty lines
        if stripped.startswith('//') or not stripped:
            annotated.append(line)
            continue

        # Check for stage keywords
        stage_match = re.match(r'\|?\s*(\w+)\s*[=:]?\s*(.*)', stripped)
        if stage_match:
            stage = stage_match.group(1).lower()
            content = stage_match.group(2).strip()

            # Generate context-aware comments
            if stage == "config":
                if "case_sensitive" in content.lower():
                    annotated.append("// CONFIG: Enable case-insensitive matching for regex patterns")
                elif "timeframe" in content.lower():
                    annotated.append("// CONFIG: Set the time window for the query")
                else:
                    annotated.append("// CONFIG: Set query execution options")

            elif stage == "dataset":
                if "xdr_data" in content:
                    annotated.append("// DATA SOURCE: Query endpoint telemetry (processes, files, network, registry)")
                elif "panw_ngfw" in content:
                    annotated.append("// DATA SOURCE: Query firewall traffic logs")
                elif "cloud_audit" in content:
                    annotated.append("// DATA SOURCE: Query cloud provider audit logs")
                else:
                    annotated.append(f"// DATA SOURCE: Query the {content} dataset")

            elif stage == "filter":
                filter_count += 1
                # Analyze filter content
                if "event_type" in content.lower():
                    event_type = re.search(r'ENUM\.(\w+)', content)
                    if event_type:
                        annotated.append(f"// FILTER #{filter_count}: Select only {event_type.group(1)} events")
                    else:
                        annotated.append(f"// FILTER #{filter_count}: Filter by event type")
                elif "days_ago" in content.lower() or "_time" in content.lower():
                    annotated.append(f"// FILTER #{filter_count}: Limit to recent time window (performance optimization)")
                elif "command_line" in content.lower() or "image_name" in content.lower():
                    annotated.append(f"// FILTER #{filter_count}: Match suspicious process patterns (detection logic)")
                elif "~=" in content or "contains" in content.lower():
                    annotated.append(f"// FILTER #{filter_count}: Pattern matching for threat indicators")
                else:
                    annotated.append(f"// FILTER #{filter_count}: Apply condition to narrow results")

            elif stage == "alter":
                if "timestamp_diff" in content.lower() or "days_ago" in content.lower():
                    annotated.append("// TRANSFORM: Time filtering (prefer 'config timeframe = 7d' for simplicity)")
                elif "extract" in content.lower():
                    annotated.append("// TRANSFORM: Extract substring or pattern from field")
                elif "if(" in content.lower() or "case(" in content.lower():
                    annotated.append("// TRANSFORM: Apply conditional logic to create derived field")
                else:
                    annotated.append("// TRANSFORM: Create computed field for analysis")

            elif stage == "comp":
                if "count()" in content.lower():
                    annotated.append("// AGGREGATE: Count occurrences - useful for threshold-based detection")
                elif "sum(" in content.lower() or "avg(" in content.lower():
                    annotated.append("// AGGREGATE: Calculate statistical metrics")
                else:
                    annotated.append("// AGGREGATE: Group and summarize data")

            elif stage == "fields":
                annotated.append("// OUTPUT: Select relevant columns for investigation")

            elif stage == "sort":
                if "desc" in content.lower():
                    annotated.append("// ORDER: Show newest/highest values first")
                else:
                    annotated.append("// ORDER: Arrange results for analysis")

            elif stage == "limit":
                limit_val = re.search(r'(\d+)', content)
                if limit_val:
                    annotated.append(f"// LIMIT: Return top {limit_val.group(1)} results (prevents UI overload)")
                else:
                    annotated.append("// LIMIT: Cap result count for performance")

            elif stage == "dedup":
                annotated.append("// DEDUPLICATE: Remove duplicate entries for cleaner results")

            elif stage == "join":
                annotated.append("// JOIN: Correlate with another dataset for enrichment")

            elif stage == "target":
                annotated.append("// MATERIALIZE: Save results for detection chaining or later use")

            elif stage == "window":
                annotated.append("// WINDOW: Apply sliding window analytics for time-series detection")

        annotated.append(line)

    return '\n'.join(annotated)


def explain_filter_condition(condition: str) -> str:
    """Explain what a filter condition does in plain English."""
    explanations = []

    # Common patterns
    if "event_type" in condition.lower() and "process" in condition.lower():
        explanations.append("Looks at process execution events")
    if "event_type" in condition.lower() and "network" in condition.lower():
        explanations.append("Looks at network connection events")
    if "event_type" in condition.lower() and "file" in condition.lower():
        explanations.append("Looks at file system events")
    if "event_type" in condition.lower() and "registry" in condition.lower():
        explanations.append("Looks at Windows registry events")

    if "command_line" in condition.lower() and "contains" in condition.lower():
        explanations.append("Searches command-line arguments for specific patterns")
    if "image_name" in condition.lower():
        explanations.append("Matches specific executable names")

    if "~=" in condition:
        explanations.append("Uses regex pattern matching")
    if " in (" in condition.lower():
        explanations.append("Checks against a list of known values")
    if " not in " in condition.lower():
        explanations.append("Excludes known-good values (allowlist)")

    if "days_ago" in condition.lower() or "timestamp_diff" in condition.lower():
        explanations.append("Limits to recent timeframe")

    return "; ".join(explanations) if explanations else "Applies custom filtering logic"


@dataclass
class DetectionMetadata:
    """Metadata extracted from XQL detection rule."""
    title: str = ""
    description: str = ""
    mitre_techniques: list[str] = None
    severity: str = "Medium"
    author: str = ""
    references: list[str] = None

    def __post_init__(self):
        if self.mitre_techniques is None:
            self.mitre_techniques = []
        if self.references is None:
            self.references = []


# MITRE ATT&CK technique descriptions for common detections with XQL examples
MITRE_TECHNIQUES = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "link": "https://attack.mitre.org/techniques/T1059/001/",
        "description": "Adversaries may abuse PowerShell for execution of malicious commands and payloads.",
        "detection_tips": [
            {
                "tip": "Look for encoded commands (-enc, -encodedcommand)",
                "xql": """// Detect base64 encoded PowerShell commands
// Attackers use encoding to evade detection and obfuscate payloads
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "powershell\\.exe"
| filter actor_process_command_line ~= "(?i)(-enc|-encodedcommand|frombase64)"
| fields _time, agent_hostname, actor_process_command_line""",
            },
            {
                "tip": "Monitor for suspicious cmdlets (Invoke-Expression, IEX, DownloadString)",
                "xql": """// Detect dynamic code execution and download cradles
// IEX and DownloadString are commonly used in malicious scripts
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "powershell\\.exe"
| filter actor_process_command_line ~= "(?i)(invoke-expression|iex|downloadstring|webclient)"
| fields _time, agent_hostname, actor_process_command_line""",
            },
            {
                "tip": "Watch for execution from unusual parent processes",
                "xql": """// Detect PowerShell spawned by unexpected parents
// Normal: explorer.exe, cmd.exe, svchost.exe. Suspicious: Word, Excel, browser
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "powershell\\.exe"
| filter causality_actor_process_image_name not in ("explorer.exe", "cmd.exe", "svchost.exe")
| fields _time, agent_hostname, causality_actor_process_image_name, actor_process_command_line""",
            },
        ],
        "fp_tuning": [
            {
                "tip": "Exclude known automation tools by path",
                "xql": """// Add these filters to exclude legitimate automation
| filter actor_process_image_path not contains "\\\\SCCM\\\\"
| filter actor_process_image_path not contains "\\\\Ansible\\\\"
| filter actor_process_image_path not contains "\\\\Automation\\\\" """,
            },
            {
                "tip": "Create allowlists for scheduled PowerShell tasks",
                "xql": """// Add these filters to allowlist known good scripts
| filter actor_process_command_line not contains "scheduled_backup.ps1"
| filter actor_process_command_line not contains "maintenance.ps1" """,
            },
        ],
    },
    "T1003.001": {
        "name": "LSASS Memory Dump",
        "tactic": "Credential Access",
        "link": "https://attack.mitre.org/techniques/T1003/001/",
        "description": "Adversaries may dump credentials from LSASS memory to obtain account login credentials.",
        "detection_tips": [
            {
                "tip": "Monitor for procdump targeting lsass",
                "xql": """// Detect procdump.exe being used to dump LSASS memory
// Procdump is a legitimate Microsoft tool often abused for credential theft
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1003/001/
config case_sensitive = false
| dataset = xdr_data
| filter actor_process_image_name in ("procdump.exe", "procdump64.exe")
| filter actor_process_command_line contains "lsass"
| fields _time, agent_hostname, actor_process_command_line, actor_effective_username""",
            },
            {
                "tip": "Watch for comsvcs.dll minidump technique",
                "xql": """// Detect comsvcs.dll MiniDump technique for LSASS dumping
// Uses rundll32 to call MiniDump export from comsvcs.dll
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1003/001/
config case_sensitive = false
| dataset = xdr_data
| filter actor_process_image_name ~= "rundll32\\.exe"
| filter actor_process_command_line contains "comsvcs"
| filter actor_process_command_line contains "minidump"
| fields _time, agent_hostname, actor_process_command_line""",
            },
            {
                "tip": "Alert on unusual processes accessing LSASS",
                "xql": """// Detect non-standard processes accessing LSASS
// Normal LSASS access: csrss.exe, wininit.exe, services.exe
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1003/001/
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter target_process_image_name ~= "lsass\\.exe"
| filter actor_process_image_name not in ("csrss.exe", "wininit.exe", "services.exe")
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line""",
            },
        ],
        "fp_tuning": [
            {
                "tip": "Exclude legitimate security tools (AV, EDR) by process path",
                "xql": """// Add these filters to exclude security products
| filter actor_process_image_path not contains "Program Files\\\\Windows Defender"
| filter actor_process_image_path not contains "ProgramData\\\\Microsoft\\\\Windows Defender"
| filter actor_process_image_path not contains "Program Files\\\\CrowdStrike"
| filter actor_process_image_path not contains "Program Files\\\\Palo Alto Networks"
| filter actor_process_image_path not contains "Program Files\\\\Confer" """,
            },
            {
                "tip": "Exclude Windows Error Reporting and crash handlers",
                "xql": """// Add these filters but still alert if they target lsass
| filter actor_process_image_name not in ("WerFault.exe", "WerFaultSecure.exe")
| filter causality_actor_process_image_name != "svchost.exe"
| filter action_process_image_name ~= "lsass" """,
            },
        ],
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "link": "https://attack.mitre.org/techniques/T1218/",
        "description": "Adversaries may use trusted binaries to proxy execution of malicious payloads (LOLBins).",
        "detection_tips": [
            {
                "tip": "Monitor certutil for download/decode operations",
                "xql": """// Detect certutil abuse for downloading or decoding payloads
// Certutil is a legitimate Windows tool often used to download malware
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1218/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "certutil\\.exe"
| filter actor_process_command_line ~= "(?i)(-urlcache|-decode|-encode)"
| fields _time, agent_hostname, actor_process_command_line""",
            },
            {
                "tip": "Look for mshta executing remote content",
                "xql": """// Detect mshta.exe running remote or script content
// MSHTA can execute HTA files from URLs or inline scripts
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1218/005/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "mshta\\.exe"
| filter actor_process_command_line ~= "(?i)(http|javascript|vbscript)"
| fields _time, agent_hostname, actor_process_command_line""",
            },
            {
                "tip": "Watch for regsvr32 with /s /u or scrobj",
                "xql": """// Detect regsvr32 Squiblydoo or Squiblytwo technique
// Can bypass application whitelisting by loading COM scriptlets
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1218/010/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "regsvr32\\.exe"
| filter actor_process_command_line ~= "(?i)(/s|/u|scrobj|/i:)"
| fields _time, agent_hostname, actor_process_command_line""",
            },
        ],
        "fp_tuning": [
            {
                "tip": "Baseline IT administration scripts",
                "xql": """// Add these filters to exclude IT admin activity
| filter actor_effective_username not in ("SYSTEM", "IT-Admin", "svc_deploy")
| filter actor_process_image_path not contains "\\\\IT\\\\Scripts\\\\" """,
            },
            {
                "tip": "Exclude software deployment tools",
                "xql": """// Add these filters to exclude deployment processes
| filter causality_actor_process_image_name not in ("ccmexec.exe", "msiexec.exe")
| filter actor_process_command_line not contains "Microsoft\\\\Office" """,
            },
        ],
    },
    "T1547.001": {
        "name": "Registry Run Keys",
        "tactic": "Persistence",
        "link": "https://attack.mitre.org/techniques/T1547/001/",
        "description": "Adversaries may add entries to Registry run keys to execute programs at startup.",
        "detection_tips": [
            {
                "tip": "Monitor Run/RunOnce key modifications",
                "xql": """// Detect modifications to Registry Run/RunOnce persistence keys
// Malware often writes to these keys to survive reboot
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/001/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY
| filter registry_key_name ~= "(?i)(\\\\Run$|\\\\RunOnce$)"
| filter action_registry_data != ""
| fields _time, agent_hostname, registry_key_name, action_registry_data, actor_process_image_name""",
            },
            {
                "tip": "Alert on non-standard executables in run keys",
                "xql": """// Detect executables in Run keys from non-standard paths
// Legitimate software typically installs to Program Files
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/001/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY
| filter registry_key_name ~= "(?i)\\\\Run"
| filter action_registry_data ~= "\\.(exe|bat|cmd|ps1|vbs|js)$"
| filter action_registry_data not contains "\\\\Program Files"
| fields _time, agent_hostname, registry_key_name, action_registry_data""",
            },
        ],
        "fp_tuning": [
            {
                "tip": "Exclude known legitimate software",
                "xql": """// Add these filters to exclude known-good apps
| filter action_registry_data not contains "Microsoft\\\\OneDrive"
| filter action_registry_data not contains "Dropbox"
| filter action_registry_data not contains "\\\\Teams\\\\" """,
            },
            {
                "tip": "Allow signed Microsoft binaries",
                "xql": """// Add these filters to allow Microsoft signed binaries
| filter action_registry_data not contains "\\\\Windows\\\\System32\\\\"
| filter actor_process_signature_vendor != "Microsoft Corporation" """,
            },
        ],
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Persistence/Execution",
        "link": "https://attack.mitre.org/techniques/T1053/005/",
        "description": "Adversaries may abuse Windows Task Scheduler to execute malicious code.",
        "detection_tips": [
            {
                "tip": "Monitor schtasks.exe /create commands",
                "xql": """// Detect scheduled task creation via schtasks.exe
// Attackers use scheduled tasks for persistence and execution
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/005/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "schtasks\\.exe"
| filter actor_process_command_line ~= "(?i)/create"
| fields _time, agent_hostname, actor_process_command_line, actor_effective_username""",
            },
            {
                "tip": "Look for tasks running from unusual paths",
                "xql": """// Detect scheduled tasks with executables in suspicious locations
// Legitimate tasks rarely run from Temp, AppData, or Public folders
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/005/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "schtasks\\.exe"
| filter actor_process_command_line ~= "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\users\\\\public)"
| fields _time, agent_hostname, actor_process_command_line""",
            },
        ],
        "fp_tuning": [
            {
                "tip": "Exclude IT management tools",
                "xql": """// Add these filters to exclude IT management
| filter actor_effective_username not in ("SYSTEM", "svc_sccm", "svc_intune")
| filter actor_process_command_line not contains "\\\\Microsoft\\\\Configuration Manager\\\\" """,
            },
            {
                "tip": "Allow Microsoft maintenance tasks",
                "xql": """// Add these filters to allow Windows maintenance
| filter actor_process_command_line not contains "\\\\Microsoft\\\\Windows\\\\Defrag"
| filter actor_process_command_line not contains "\\\\Windows\\\\SoftwareDistribution" """,
            },
        ],
    },
    "T1219": {
        "name": "Remote Access Software",
        "tactic": "Command and Control",
        "link": "https://attack.mitre.org/techniques/T1219/",
        "description": "Adversaries may use remote access tools to maintain access to victim systems.",
        "detection_tips": [
            {
                "tip": "Monitor RMM tool executions",
                "xql": """// Detect Remote Monitoring and Management (RMM) tool execution
// RMM tools provide legitimate remote access but are abused by attackers
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1219/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name in ("screenconnect.client.exe", "anydesk.exe", "teamviewer.exe")
| fields _time, agent_hostname, actor_process_image_name, action_remote_ip, actor_effective_username""",
            },
            {
                "tip": "Look for RMM tools spawning shells",
                "xql": """// Detect command shells spawned from RMM tools
// Legitimate RMM rarely spawns cmd.exe or PowerShell directly
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1219/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter causality_actor_process_image_name in ("screenconnect.client.exe", "anydesk.exe")
| filter actor_process_image_name in ("cmd.exe", "powershell.exe")
| fields _time, agent_hostname, causality_actor_process_image_name, actor_process_command_line""",
            },
        ],
        "fp_tuning": [
            {
                "tip": "Baseline authorized RMM tools",
                "xql": """// Add these filters to baseline authorized RMM usage
| filter actor_process_image_path contains "\\\\IT-Authorized\\\\"
| filter actor_effective_username in ("helpdesk", "it-support") """,
            },
        ],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "link": "https://attack.mitre.org/techniques/T1490/",
        "description": "Adversaries may delete shadow copies to prevent system recovery (ransomware indicator).",
        "detection_tips": [
            {
                "tip": "Alert on vssadmin delete shadows",
                "xql": """// Detect Volume Shadow Copy deletion via vssadmin
// CRITICAL: Almost always malicious - strong ransomware indicator
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1490/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "vssadmin\\.exe"
| filter actor_process_command_line ~= "(?i)delete.*shadows"
| fields _time, agent_hostname, actor_process_command_line, actor_effective_username""",
            },
            {
                "tip": "Monitor bcdedit recoveryenabled changes",
                "xql": """// Detect bcdedit disabling Windows recovery mode
// Prevents booting into recovery environment - ransomware tactic
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1490/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "bcdedit\\.exe"
| filter actor_process_command_line ~= "(?i)recoveryenabled.*no"
| fields _time, agent_hostname, actor_process_command_line""",
            },
            {
                "tip": "Watch for wmic shadowcopy delete",
                "xql": """// Detect WMIC-based shadow copy deletion
// Alternative method to vssadmin, same malicious intent
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1490/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter actor_process_image_name ~= "wmic\\.exe"
| filter actor_process_command_line ~= "(?i)shadowcopy.*delete"
| fields _time, agent_hostname, actor_process_command_line""",
            },
        ],
        "fp_tuning": [
            {
                "tip": "Very few legitimate reasons - investigate all. Allow known backup software only",
                "xql": """// CRITICAL: Investigate ALL matches carefully
// Add these filters ONLY for known backup software
| filter actor_process_image_path not contains "\\\\Veeam\\\\"
| filter actor_process_image_path not contains "\\\\Backup Exec\\\\" """,
            },
        ],
    },
}


def extract_metadata(query: str) -> DetectionMetadata:
    """Extract detection metadata from XQL query comments."""
    metadata = DetectionMetadata()

    # Extract title
    title_match = re.search(r'//\s*(?:Title|Detection):\s*(.+)', query, re.IGNORECASE)
    if title_match:
        metadata.title = title_match.group(1).strip()

    # Extract description
    desc_match = re.search(r'//\s*(?:Description|Desc):\s*(.+)', query, re.IGNORECASE)
    if desc_match:
        metadata.description = desc_match.group(1).strip()

    # Extract MITRE techniques
    mitre_matches = re.findall(r'T\d{4}(?:\.\d{3})?', query)
    metadata.mitre_techniques = list(set(mitre_matches))

    # Extract severity
    severity_match = re.search(r'//\s*Severity:\s*(\w+)', query, re.IGNORECASE)
    if severity_match:
        metadata.severity = severity_match.group(1).strip()

    # Extract author
    author_match = re.search(r'//\s*Author:\s*(.+)', query, re.IGNORECASE)
    if author_match:
        metadata.author = author_match.group(1).strip()

    return metadata


def analyze_query_purpose(query: str) -> dict:
    """Analyze the query to determine its purpose and provide guidance with XQL queries."""
    purpose = {
        "category": "Unknown",
        "description": "",
        "query_explanation": "",
        "threat_explanation": "",
        "next_steps": [],
        "related_queries": [],
    }

    query_lower = query.lower()

    # Determine category based on query content
    if "lsass" in query_lower or "sekurlsa" in query_lower or "mimikatz" in query_lower:
        purpose["category"] = "Credential Dumping Detection"
        purpose["description"] = "This query detects attempts to dump credentials from memory."
        purpose["query_explanation"] = """This query searches for process execution events that indicate credential dumping attempts targeting LSASS (Local Security Authority Subsystem Service). It looks for:

1. **Procdump targeting LSASS** - Microsoft's procdump.exe utility being used to create a memory dump of lsass.exe
2. **Comsvcs.dll MiniDump** - Using rundll32.exe to call the MiniDump export from comsvcs.dll, a known technique to dump LSASS memory
3. **Mimikatz patterns** - Command-line indicators of mimikatz or similar credential dumping tools

The query filters on process images and command-line arguments to identify these specific attack patterns."""

        purpose["threat_explanation"] = """**What is LSASS?**
LSASS (Local Security Authority Subsystem Service) is a Windows process that handles user authentication and stores credentials in memory. It contains password hashes, Kerberos tickets, and other sensitive authentication data.

**Why attackers target LSASS:**
- Extract plaintext passwords or NTLM hashes
- Obtain Kerberos tickets for lateral movement
- Impersonate users without knowing their passwords

**MITRE ATT&CK Technique:** [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

**Common tools used:**
- Mimikatz (sekurlsa::logonpasswords)
- Procdump (procdump -ma lsass.exe)
- Comsvcs.dll (rundll32 comsvcs.dll MiniDump)
- Task Manager (right-click → Create dump file)"""

        purpose["next_steps"] = [
            {
                "step": "Identify the affected host and user context",
                "xql": """// Get user authentication and session context on affected host
// Shows who logged in, logon types, and session details
// Replace <HOSTNAME> with actual hostname from detection
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1078/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.LOGIN
| filter agent_hostname = "<HOSTNAME>"
| fields _time, actor_effective_username, action_login_type, logon_session_id, action_remote_ip, action_status
| sort desc _time
| limit 100"""
            },
            {
                "step": "Check for lateral movement from this host",
                "xql": """// Find network connections to common lateral movement ports
// SMB(445), RPC(135), RDP(3389), WinRM(5985/5986)
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1021/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter agent_hostname = "<HOSTNAME>"
| filter action_remote_port in (445, 135, 3389, 5985, 5986)
| fields _time, action_remote_ip, action_remote_port, actor_process_image_name
| dedup action_remote_ip
| limit 50"""
            },
            {
                "step": "Review authentication logs for compromised accounts (summary)",
                "xql": """// STEP 1: Get aggregated login statistics for the compromised user
// Use comp to summarize - identifies anomalous hosts/login patterns quickly
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1550/002/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.LOGIN
| filter actor_effective_username = "<USERNAME>"
| comp count() as login_count by agent_hostname, action_login_type, action_status
| sort desc login_count"""
            },
            {
                "step": "Review authentication logs for compromised accounts (details)",
                "xql": """// STEP 2: Get detailed login records for specific host identified above
// Use fields for full event details - investigate individual login attempts
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1550/002/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.LOGIN
| filter actor_effective_username = "<USERNAME>"
| filter agent_hostname = "<HOSTNAME_FROM_STEP1>"
| fields _time, agent_hostname, action_login_type, action_status, action_remote_ip, logon_session_id
| sort desc _time
| limit 100"""
            },
            {
                "step": "Check for persistence mechanisms created",
                "xql": """// Look for registry/file-based persistence on affected host
// Attackers often establish persistence after credential theft
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/001/
config case_sensitive = false timeframe = 2h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter event_type in (ENUM.REGISTRY, ENUM.FILE)
| filter registry_key_name ~= "(?i)(Run|Services|Scheduled)"
    or action_file_path ~= "(?i)(startup|tasks)"
| fields _time, event_type, registry_key_name, action_file_path"""
            },
        ]
        purpose["related_queries"] = [
            {
                "name": "Pass-the-Hash Detection",
                "xql": """// Detect potential Pass-the-Hash via network logon abuse
// High network login counts from single user may indicate PtH
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1550/002/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.LOGIN
| filter action_login_type = "NETWORK"
| filter actor_effective_username != "SYSTEM"
| comp count() as logins by agent_hostname, actor_effective_username
| filter logins > 10
| sort desc logins"""
            },
            {
                "name": "Kerberoasting Detection",
                "xql": """// Detect Kerberoasting attacks (SPN ticket requests)
// Common tools: Rubeus, Invoke-Kerberoast
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1558/003/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter actor_process_command_line ~= "(?i)(kerberoast|invoke-kerberoast|rubeus.*kerberoast)"
| fields _time, agent_hostname, actor_process_command_line"""
            },
        ]

    elif "powershell" in query_lower and ("-enc" in query_lower or "encodedcommand" in query_lower):
        purpose["category"] = "Encoded PowerShell Detection"
        purpose["description"] = "This query detects obfuscated PowerShell execution."
        purpose["next_steps"] = [
            {
                "step": "Get the full encoded command for decoding",
                "xql": """// Extract encoded PowerShell commands for base64 decoding
// Use CyberChef or PowerShell to decode the base64 payload
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/001/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name ~= "powershell"
| filter actor_process_command_line ~= "(?i)(-enc|-encodedcommand)"
| fields _time, actor_process_command_line
| limit 10"""
            },
            {
                "step": "Identify parent process chain",
                "xql": """// Trace the process tree to find initial entry point
// Look for unusual parents spawning PowerShell
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/001/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name ~= "powershell"
| fields _time, causality_actor_process_image_name, causality_actor_process_command_line,
    actor_process_image_name, actor_process_command_line
| limit 20"""
            },
            {
                "step": "Check for network connections from PowerShell",
                "xql": """// Find C2 or download connections from PowerShell
// Check if any IPs/domains are known malicious
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1105/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name ~= "powershell"
| fields _time, action_remote_ip, action_remote_port, action_external_hostname
| dedup action_remote_ip"""
            },
            {
                "step": "Look for file downloads or writes",
                "xql": """// Find files dropped by PowerShell (potential payloads)
// Focus on executable and script file types
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1105/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.FILE
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name ~= "powershell"
| filter action_file_extension in ("exe", "dll", "ps1", "bat", "vbs")
| fields _time, action_file_path, action_file_name"""
            },
        ]
        purpose["related_queries"] = [
            {
                "name": "Script Block Logging Analysis",
                "xql": """// Analyze decoded script content from Windows Script Block logs
// Shows actual PowerShell code executed (if logging enabled)
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/001/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter event_type = ENUM.SCRIPT_EXECUTION
| fields _time, actor_process_image_name, action_script_content
| limit 50"""
            },
        ]

    elif any(x in query_lower for x in ["certutil", "mshta", "rundll32", "regsvr32", "bitsadmin"]):
        purpose["category"] = "LOLBin Detection"
        purpose["description"] = "This query detects abuse of legitimate Windows binaries (Living off the Land)."
        purpose["next_steps"] = [
            {
                "step": "Analyze full command-line arguments",
                "xql": """// Get full command lines for LOLBin executions
// Look for: -urlcache, -decode, scrobj.dll, javascript:, etc.
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1218/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name in ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe")
| fields _time, actor_process_image_name, actor_process_command_line
| limit 50"""
            },
            {
                "step": "Check network connections from LOLBins",
                "xql": """// Find downloads or C2 connections via LOLBins
// These binaries should rarely make external connections
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1105/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name in ("certutil.exe", "mshta.exe", "rundll32.exe", "bitsadmin.exe")
| fields _time, actor_process_image_name, action_remote_ip, action_external_hostname
| dedup action_remote_ip"""
            },
            {
                "step": "Identify files created or modified",
                "xql": """// Find payloads dropped by LOLBins
// Check file hashes against threat intel
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1140/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.FILE
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name in ("certutil.exe", "mshta.exe", "rundll32.exe", "bitsadmin.exe")
| fields _time, actor_process_image_name, action_file_path, action_file_name"""
            },
            {
                "step": "Review parent process chain",
                "xql": """// Identify what spawned the LOLBin
// Unexpected parents (Word, Excel, browser) indicate exploitation
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name in ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| fields _time, causality_actor_process_image_name, causality_actor_process_command_line,
    actor_process_image_name, actor_process_command_line"""
            },
        ]
        purpose["related_queries"] = [
            {
                "name": "Follow-on Process Execution",
                "xql": """// Find child processes spawned by LOLBins
// Payloads often spawn cmd.exe, powershell.exe, etc.
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1218/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter agent_hostname = "<HOSTNAME>"
| filter causality_actor_process_image_name in ("certutil.exe", "mshta.exe", "rundll32.exe")
| fields _time, actor_process_image_name, actor_process_command_line"""
            },
        ]

    elif "registry" in query_lower and ("run" in query_lower or "currentversion" in query_lower):
        purpose["category"] = "Persistence Detection"
        purpose["description"] = "This query detects registry-based persistence mechanisms."
        purpose["next_steps"] = [
            {
                "step": "Get full registry modification details",
                "xql": """// Extract Run key modifications with full registry data
// Check what executable is configured to run at startup
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/001/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY
| filter agent_hostname = "<HOSTNAME>"
| filter registry_key_name ~= "(?i)\\\\Run"
| fields _time, registry_key_name, action_registry_data, actor_process_image_name"""
            },
            {
                "step": "Check if the persistence executable exists",
                "xql": """// Verify the persisted executable file exists
// Get hash for threat intel lookup
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/001/
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.FILE
| filter agent_hostname = "<HOSTNAME>"
| filter action_file_path = "<EXECUTABLE_PATH>"
| fields _time, action_file_path, action_file_sha256, action_file_size"""
            },
            {
                "step": "Review what process made the registry change",
                "xql": """// Identify the process that created the persistence
// Trace back to initial compromise vector
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/001/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY
| filter agent_hostname = "<HOSTNAME>"
| filter registry_key_name ~= "(?i)\\\\Run"
| fields _time, actor_process_image_name, actor_process_command_line,
    causality_actor_process_image_name"""
            },
        ]
        purpose["related_queries"] = [
            {
                "name": "All Persistence Mechanisms",
                "xql": """// Comprehensive persistence scan across registry and file-based locations
// Covers Run keys, Services, Winlogon, Startup folder
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter event_type in (ENUM.REGISTRY, ENUM.FILE)
| filter registry_key_name ~= "(?i)(Run|Services|Winlogon|Startup)"
    or action_file_path ~= "(?i)(startup|schedtasks)"
| fields _time, event_type, registry_key_name, action_file_path, actor_process_image_name"""
            },
        ]

    elif "schtasks" in query_lower or "scheduled" in query_lower:
        purpose["category"] = "Scheduled Task Detection"
        purpose["description"] = "This query detects creation of scheduled tasks for persistence or execution."
        purpose["next_steps"] = [
            {
                "step": "Get full scheduled task creation details",
                "xql": """// Extract schtasks /create commands with full parameters
// Look for unusual task names or execution paths
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/005/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name ~= "schtasks"
| filter actor_process_command_line ~= "(?i)/create"
| fields _time, actor_process_command_line, actor_effective_username"""
            },
            {
                "step": "Check what the scheduled task executes",
                "xql": """// Parse the /tr parameter to see task action
// Flag tasks running from temp, appdata, or user directories
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/005/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name ~= "schtasks"
| alter task_action = extract(actor_process_command_line, "/tr\\s+[\"']?([^\"']+)[\"']?")
| fields _time, task_action, actor_process_command_line"""
            },
            {
                "step": "Look for task execution",
                "xql": """// Find processes spawned by Task Scheduler
// Correlate with suspicious task creations
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/005/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter agent_hostname = "<HOSTNAME>"
| filter causality_actor_process_image_name ~= "taskeng|taskhostw"
| fields _time, actor_process_image_name, actor_process_command_line"""
            },
        ]
        purpose["related_queries"] = []

    elif any(x in query_lower for x in ["screenconnect", "anydesk", "teamviewer"]):
        purpose["category"] = "RMM Tool Detection"
        purpose["description"] = "This query detects remote management tool activity."
        purpose["next_steps"] = [
            {
                "step": "Identify RMM tool executions and connections",
                "xql": """// Find RMM tool activity and remote connections
// Verify if tool is authorized in your environment
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1219/
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name ~= "(?i)(screenconnect|anydesk|teamviewer)"
| fields _time, actor_process_image_name, action_remote_ip, actor_effective_username"""
            },
            {
                "step": "Check what processes RMM spawned",
                "xql": """// Find commands executed through RMM tools
// cmd.exe, powershell.exe spawned by RMM = hands-on-keyboard activity
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1219/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter agent_hostname = "<HOSTNAME>"
| filter causality_actor_process_image_name ~= "(?i)(screenconnect|anydesk|teamviewer)"
| fields _time, actor_process_image_name, actor_process_command_line"""
            },
            {
                "step": "Look for file transfers via RMM",
                "xql": """// Detect files dropped via RMM tools
// Focus on executable and archive types
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1105/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.FILE
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name ~= "(?i)(screenconnect|anydesk|teamviewer)"
| filter action_file_extension in ("exe", "dll", "ps1", "bat", "zip", "7z")
| fields _time, action_file_path, action_file_name"""
            },
        ]
        purpose["related_queries"] = []

    elif "vssadmin" in query_lower or "shadowcopy" in query_lower or "recoveryenabled" in query_lower:
        purpose["category"] = "Ransomware Indicator"
        purpose["description"] = "This query detects shadow copy deletion, a common ransomware precursor."
        purpose["next_steps"] = [
            {
                "step": "CRITICAL: Get full context of shadow copy deletion",
                "xql": """// HIGH PRIORITY: Shadow copy deletion is a strong ransomware indicator
// Immediately investigate the parent process and user
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1490/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| filter actor_process_image_name in ("vssadmin.exe", "wmic.exe", "bcdedit.exe")
| filter actor_process_command_line ~= "(?i)(delete|shadows|recoveryenabled)"
| fields _time, actor_process_image_name, actor_process_command_line, actor_effective_username,
    causality_actor_process_image_name"""
            },
            {
                "step": "Check for mass file encryption activity",
                "xql": """// Detect ransomware file extensions being created
// High counts indicate active encryption
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1486/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.FILE
| filter agent_hostname = "<HOSTNAME>"
| filter action_file_extension ~= "(?i)(encrypted|locked|crypt|ransom)"
| comp count() as file_count by action_file_extension
| sort desc file_count"""
            },
            {
                "step": "Look for ransom notes",
                "xql": """// Search for ransom note files being dropped
// Common names: README, DECRYPT_FILES, RESTORE_FILES
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1486/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.FILE
| filter agent_hostname = "<HOSTNAME>"
| filter action_file_name ~= "(?i)(readme|decrypt|ransom|recover|restore).*\\.txt"
| fields _time, action_file_path, actor_process_image_name"""
            },
            {
                "step": "Check for lateral movement attempts",
                "xql": """// Detect ransomware spreading via SMB/RPC
// Multiple connections to same ports = worm-like behavior
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1021/002/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter agent_hostname = "<HOSTNAME>"
| filter action_remote_port in (445, 135)
| comp count() as conn_count by action_remote_ip
| filter conn_count > 5
| sort desc conn_count"""
            },
        ]
        purpose["related_queries"] = [
            {
                "name": "Mass File Modification Detection",
                "xql": """// Detect hosts with abnormal file modification rates
// Normal is <100/hour, ransomware can be 10000+/hour
// MITRE ATT&CK: https://attack.mitre.org/techniques/T1486/
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.FILE
| comp count() as file_changes by agent_hostname
| filter file_changes > 1000
| sort desc file_changes"""
            },
        ]

    else:
        purpose["category"] = "General Threat Hunt"
        purpose["description"] = "Custom detection query."
        purpose["next_steps"] = [
            {
                "step": "Review matching events for patterns",
                "xql": """// Aggregate events to identify patterns
// Customize filters based on your investigation
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| comp count() as event_count by event_type, agent_hostname
| sort desc event_count
| limit 50"""
            },
            {
                "step": "Correlate with other security telemetry",
                "xql": """// Get chronological activity on affected host
// Look for initial access, execution, persistence, lateral movement
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter agent_hostname = "<HOSTNAME>"
| fields _time, event_type, actor_process_image_name, actor_process_command_line
| sort asc _time
| limit 100"""
            },
        ]
        purpose["related_queries"] = []

    return purpose


def build_pipeline_html(query: str) -> str:
    """Build the visual pipeline representation HTML."""
    stages = analyze_query_stages(query)

    if not stages:
        return ""

    pipeline_items = []
    for i, stage in enumerate(stages):
        # Add arrow between stages
        if i > 0:
            pipeline_items.append('<span class="pipeline-arrow">→</span>')

        # Get stage info
        icon = stage.get("icon", "▶️")
        name = stage.get("name", stage.get("name", "Unknown")).upper()
        desc = stage.get("description", "")

        pipeline_items.append(f'''
            <div class="pipeline-stage" data-stage="{i}">
                <span class="icon">{icon}</span>
                <span class="stage-name">{name}</span>
                <span class="stage-desc">{html.escape(desc)}</span>
            </div>
        ''')

    # Build detail sections (shown when clicking on stages)
    detail_sections = []
    for i, stage in enumerate(stages):
        content = stage.get("content", "")
        detail = stage.get("detail", "")

        # Explain filter conditions
        explanation = ""
        if stage.get("name") == "filter" and content:
            explanation = explain_filter_condition(content)

        detail_sections.append(f'''
            <div class="pipeline-detail" id="stage-detail-{i}">
                <h4>{stage.get("icon", "▶️")} {stage.get("name", "Stage").title()}</h4>
                <p>{html.escape(detail)}</p>
                {f'<div class="content">{html.escape(content)}</div>' if content else ''}
                {f'<div class="explanation">{html.escape(explanation)}</div>' if explanation else ''}
            </div>
        ''')

    return f'''
        <h3>Query Pipeline</h3>
        <p style="color: var(--text-secondary); margin-bottom: 15px;">
            Click on each stage to see details about what it does.
        </p>
        <div class="pipeline-container">
            {"".join(pipeline_items)}
        </div>
        {"".join(detail_sections)}
    '''


def simple_markdown_to_html(text: str) -> str:
    """Convert simple markdown to HTML (bold, lists, line breaks)."""
    if not text:
        return ""

    # Escape HTML first
    text = html.escape(text)

    # Convert **bold** to <strong>
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)

    # Convert numbered lists (1. item)
    lines = text.split('\n')
    result = []
    in_list = False
    list_type = None

    for line in lines:
        stripped = line.strip()

        # Check for numbered list
        num_match = re.match(r'^(\d+)\.\s+(.+)$', stripped)
        # Check for bullet list
        bullet_match = re.match(r'^[-*]\s+(.+)$', stripped)

        if num_match:
            if not in_list or list_type != 'ol':
                if in_list:
                    result.append(f'</{list_type}>')
                result.append('<ol>')
                in_list = True
                list_type = 'ol'
            result.append(f'<li>{num_match.group(2)}</li>')
        elif bullet_match:
            if not in_list or list_type != 'ul':
                if in_list:
                    result.append(f'</{list_type}>')
                result.append('<ul>')
                in_list = True
                list_type = 'ul'
            result.append(f'<li>{bullet_match.group(1)}</li>')
        else:
            if in_list:
                result.append(f'</{list_type}>')
                in_list = False
                list_type = None
            if stripped:
                result.append(f'{stripped}<br>')
            else:
                result.append('<br>')

    if in_list:
        result.append(f'</{list_type}>')

    return '\n'.join(result)


def syntax_highlight_query(query: str) -> str:
    """Apply syntax highlighting to XQL query."""
    lines = query.split('\n')
    highlighted = []

    for line in lines:
        # Skip empty lines
        if not line.strip():
            highlighted.append(line)
            continue

        # Comments
        if line.strip().startswith('//'):
            highlighted.append(f'<span class="comment">{html.escape(line)}</span>')
            continue

        # Escape HTML first
        escaped = html.escape(line)

        # Use placeholders to protect spans we create
        parts = []
        last_end = 0

        # Highlight stage keywords with pipe
        for match in re.finditer(r'(\|\s*)(dataset|filter|alter|comp|fields|sort|limit|dedup|join|union|config|target|window)(\s+|\s*$)', escaped, re.IGNORECASE):
            parts.append(escaped[last_end:match.start()])
            parts.append(f'{match.group(1)}<span class="stage-keyword">{match.group(2)}</span>{match.group(3)}')
            last_end = match.end()
        parts.append(escaped[last_end:])
        result = ''.join(parts)

        # Highlight functions (word followed by parenthesis)
        result = re.sub(r'\b([a-zA-Z_]\w*)\s*\(', r'<span class="function">\1</span>(', result)

        # Highlight strings
        result = re.sub(r'(&quot;[^&]*&quot;)', r'<span class="string">\1</span>', result)

        # Highlight logical operators (word boundaries to avoid false matches)
        for op in ['and', 'or', 'not', 'in', 'contains']:
            result = re.sub(rf'(?<![a-zA-Z_])\b({op})\b(?![a-zA-Z_])', r'<span class="operator">\1</span>', result, flags=re.IGNORECASE)

        # Highlight comparison operators
        # Process multi-char operators first, use unique placeholders to avoid double-wrapping
        operator_map = [
            ('&lt;=', '___LE___'),
            ('&gt;=', '___GE___'),
            ('~=', '___REGEX___'),
            ('!=', '___NE___'),
            ('&lt;', '___LT___'),
            ('&gt;', '___GT___'),
        ]

        for op, placeholder in operator_map:
            result = result.replace(op, placeholder)

        # Replace standalone = (surrounded by spaces)
        result = re.sub(r'(\s)(=)(\s)', r'\1___EQ___\3', result)

        # Now convert placeholders to spans
        placeholder_to_span = {
            '___LE___': '<span class="operator">&lt;=</span>',
            '___GE___': '<span class="operator">&gt;=</span>',
            '___REGEX___': '<span class="operator">~=</span>',
            '___NE___': '<span class="operator">!=</span>',
            '___LT___': '<span class="operator">&lt;</span>',
            '___GT___': '<span class="operator">&gt;</span>',
            '___EQ___': '<span class="operator">=</span>',
        }

        for placeholder, span in placeholder_to_span.items():
            result = result.replace(placeholder, span)

        highlighted.append(result)

    return '\n'.join(highlighted)


def generate_html_report(
    query: str,
    issues: list[ValidationIssue],
    file_path: Optional[str] = None,
    include_guidance: bool = True
) -> str:
    """Generate a comprehensive HTML report for an XQL query."""

    metadata = extract_metadata(query)
    purpose = analyze_query_purpose(query)

    # Build MITRE section with XQL examples
    mitre_html = ""
    if metadata.mitre_techniques:
        mitre_items = []
        for tech_id in metadata.mitre_techniques:
            tech_info = MITRE_TECHNIQUES.get(tech_id, {})
            if tech_info:
                # Build detection tips with XQL code blocks
                tips_items = []
                for tip_item in tech_info.get('detection_tips', []):
                    if isinstance(tip_item, dict):
                        tip_text = html.escape(tip_item.get('tip', ''))
                        xql_code = tip_item.get('xql', '')
                        if xql_code:
                            tips_items.append(f'''<li>
                                <span class="tip-text">{tip_text}</span>
                                <details class="xql-example">
                                    <summary>Show XQL Example</summary>
                                    <pre class="xql-code">{html.escape(xql_code.strip())}</pre>
                                    <button class="copy-btn" onclick="copyXQL(this)">Copy</button>
                                </details>
                            </li>''')
                        else:
                            tips_items.append(f'<li>{tip_text}</li>')
                    else:
                        tips_items.append(f'<li>{html.escape(str(tip_item))}</li>')

                # Build FP tuning with XQL code blocks
                fp_items = []
                for fp_item in tech_info.get('fp_tuning', []):
                    if isinstance(fp_item, dict):
                        fp_text = html.escape(fp_item.get('tip', ''))
                        xql_code = fp_item.get('xql', '')
                        if xql_code:
                            fp_items.append(f'''<li>
                                <span class="tip-text">{fp_text}</span>
                                <details class="xql-example">
                                    <summary>Show XQL Tuning</summary>
                                    <pre class="xql-code">{html.escape(xql_code.strip())}</pre>
                                    <button class="copy-btn" onclick="copyXQL(this)">Copy</button>
                                </details>
                            </li>''')
                        else:
                            fp_items.append(f'<li>{fp_text}</li>')
                    else:
                        fp_items.append(f'<li>{html.escape(str(fp_item))}</li>')

                mitre_items.append(f"""
                <div class="mitre-technique">
                    <h4><a href="https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}" target="_blank">{tech_id}: {tech_info.get('name', 'Unknown')}</a></h4>
                    <p><strong>Tactic:</strong> {tech_info.get('tactic', 'N/A')}</p>
                    <p>{tech_info.get('description', '')}</p>

                    <div class="tips-section">
                        <h5>Detection Tips:</h5>
                        <ul>
                            {"".join(tips_items)}
                        </ul>
                    </div>

                    <div class="fp-section">
                        <h5>False Positive Tuning:</h5>
                        <ul>
                            {"".join(fp_items)}
                        </ul>
                    </div>
                </div>
                """)
            else:
                mitre_items.append(f"""
                <div class="mitre-technique">
                    <h4><a href="https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}" target="_blank">{tech_id}</a></h4>
                    <p>View on MITRE ATT&CK for details.</p>
                </div>
                """)
        mitre_html = "<div class='mitre-section'>" + "".join(mitre_items) + "</div>"

    # Build issues HTML
    issues_html = ""
    if issues:
        issue_rows = []
        for issue in sorted(issues, key=lambda x: (x.severity.value, x.line)):
            severity_class = issue.severity.value
            icon = {"error": "X", "warning": "!", "info": "i", "style": "*"}.get(severity_class, "?")

            issue_rows.append(f"""
            <tr class="issue-{severity_class}">
                <td class="icon">{icon}</td>
                <td>{issue.line}</td>
                <td><code>{issue.code}</code></td>
                <td>{issue.category.value}</td>
                <td>{html.escape(issue.message)}</td>
                <td class="suggestion">{html.escape(issue.suggestion or '')}</td>
            </tr>
            """)

        issues_html = f"""
        <div class="issues-section">
            <h3>Validation Issues</h3>
            <table class="issues-table">
                <thead>
                    <tr>
                        <th></th>
                        <th>Line</th>
                        <th>Code</th>
                        <th>Category</th>
                        <th>Message</th>
                        <th>Suggestion</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(issue_rows)}
                </tbody>
            </table>
        </div>
        """
    else:
        issues_html = """
        <div class="success-message">
            <span class="check">&#10004;</span> No validation issues found!
        </div>
        """

    # Build next steps HTML with XQL queries
    next_steps_html = ""
    if purpose["next_steps"]:
        steps_items = []
        for i, step_item in enumerate(purpose["next_steps"], 1):
            if isinstance(step_item, dict):
                step_text = html.escape(step_item.get('step', ''))
                xql_code = step_item.get('xql', '')
                if xql_code:
                    steps_items.append(f'''<li>
                        <span class="step-text">{step_text}</span>
                        <details class="xql-example" open>
                            <summary>XQL Query</summary>
                            <pre class="xql-code">{html.escape(xql_code.strip())}</pre>
                            <button class="copy-btn" onclick="copyXQL(this)">Copy</button>
                        </details>
                    </li>''')
                else:
                    steps_items.append(f'<li>{step_text}</li>')
            else:
                steps_items.append(f'<li>{html.escape(str(step_item))}</li>')

        next_steps_html = f"""
        <div class="next-steps">
            <h3>Investigation Next Steps</h3>
            <p class="step-note">Replace &lt;HOSTNAME&gt;, &lt;USERNAME&gt;, etc. with actual values from your detection.</p>
            <ol>{"".join(steps_items)}</ol>
        </div>
        """

    # Build related queries HTML with XQL
    related_html = ""
    if purpose["related_queries"]:
        query_items = []
        for q_item in purpose["related_queries"]:
            if isinstance(q_item, dict):
                q_name = html.escape(q_item.get('name', ''))
                xql_code = q_item.get('xql', '')
                if xql_code:
                    query_items.append(f'''<li>
                        <span class="query-name">{q_name}</span>
                        <details class="xql-example">
                            <summary>Show Query</summary>
                            <pre class="xql-code">{html.escape(xql_code.strip())}</pre>
                            <button class="copy-btn" onclick="copyXQL(this)">Copy</button>
                        </details>
                    </li>''')
                else:
                    query_items.append(f'<li>{q_name}</li>')
            else:
                query_items.append(f'<li>{html.escape(str(q_item))}</li>')

        related_html = f"""
        <div class="related-queries">
            <h3>Related Threat Hunting Queries</h3>
            <ul>{"".join(query_items)}</ul>
        </div>
        """

    # Build explanation sections
    query_explanation_html = ""
    if purpose.get("query_explanation"):
        query_explanation_html = f"""
            <div class="explanation-section">
                <h3 class="collapsible active">What This Query Does</h3>
                <div class="collapsible-content show">
                    <div class="explanation-content query-explanation">
                        {simple_markdown_to_html(purpose.get("query_explanation", ""))}
                    </div>
                </div>
            </div>
        """

    threat_explanation_html = ""
    if purpose.get("threat_explanation"):
        threat_explanation_html = f"""
            <div class="explanation-section">
                <h3 class="collapsible active">Understanding the Threat</h3>
                <div class="collapsible-content show">
                    <div class="explanation-content threat-explanation">
                        {simple_markdown_to_html(purpose.get("threat_explanation", ""))}
                    </div>
                </div>
            </div>
        """

    # Calculate summary
    error_count = sum(1 for i in issues if i.severity == Severity.ERROR)
    warning_count = sum(1 for i in issues if i.severity == Severity.WARNING)
    info_count = sum(1 for i in issues if i.severity == Severity.INFO)

    status_class = "success" if error_count == 0 else "error"
    status_text = "Valid" if error_count == 0 else "Issues Found"

    # Generate full HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XQL Validation Report - {html.escape(metadata.title or 'Detection Query')}</title>
    <style>
        :root {{
            /* Professional dark theme - high contrast */
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #21262d;
            --bg-code: #0d1117;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-purple: #a371f7;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-green: #3fb950;
            --accent-teal: #39d353;
            --accent-orange: #db6d28;
            --border-color: #30363d;
            /* Syntax highlighting - GitHub Dark */
            --syn-keyword: #ff7b72;
            --syn-function: #d2a8ff;
            --syn-string: #a5d6ff;
            --syn-operator: #ff7b72;
            --syn-comment: #8b949e;
            --syn-field: #ffa657;
        }}

        * {{ box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            background: var(--bg-secondary);
            padding: 20px 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid var(--accent-blue);
        }}

        h1 {{
            margin: 0 0 10px 0;
            color: var(--accent-blue);
        }}

        h2 {{
            color: var(--accent-blue);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
        }}

        h3 {{
            color: var(--text-primary);
            margin-top: 25px;
        }}

        .meta {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            color: var(--text-secondary);
        }}

        .meta span {{
            background: var(--bg-card);
            padding: 5px 12px;
            border-radius: 5px;
        }}

        .status-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 5px;
            font-weight: bold;
            margin: 10px 0;
        }}

        .status-badge.success {{
            background: var(--accent-green);
            color: #000;
        }}

        .status-badge.error {{
            background: var(--accent-red);
            color: #fff;
        }}

        .card {{
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }}

        .query-section {{
            background: var(--bg-code);
            border-radius: 8px;
            padding: 20px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
        }}

        .query-section pre {{
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 13px;
            line-height: 1.6;
        }}

        .issues-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}

        .issues-table th,
        .issues-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .issues-table th {{
            background: var(--bg-card);
            color: var(--accent-blue);
        }}

        .issue-error {{ background: rgba(233, 69, 96, 0.1); }}
        .issue-warning {{ background: rgba(243, 156, 18, 0.1); }}
        .issue-info {{ background: rgba(74, 144, 217, 0.1); }}

        .issue-error .icon {{ color: var(--accent-red); font-weight: bold; }}
        .issue-warning .icon {{ color: var(--accent-yellow); font-weight: bold; }}
        .issue-info .icon {{ color: var(--accent-blue); }}

        .suggestion {{ color: var(--text-secondary); font-style: italic; }}

        .success-message {{
            background: rgba(46, 204, 113, 0.1);
            border: 1px solid var(--accent-green);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            font-size: 18px;
        }}

        .success-message .check {{
            color: var(--accent-green);
            font-size: 24px;
            margin-right: 10px;
        }}

        .purpose-section {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}

        .purpose-section h4 {{
            color: var(--accent-blue);
            margin-top: 0;
        }}

        .mitre-technique {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--accent-red);
        }}

        .mitre-technique h4 {{
            margin-top: 0;
        }}

        .mitre-technique a {{
            color: var(--accent-blue);
            text-decoration: none;
        }}

        .mitre-technique a:hover {{
            text-decoration: underline;
        }}

        .tips-section, .fp-section {{
            margin-top: 15px;
        }}

        .tips-section h5, .fp-section h5 {{
            color: var(--accent-yellow);
            margin-bottom: 10px;
        }}

        .fp-section h5 {{
            color: var(--accent-green);
        }}

        .next-steps, .related-queries {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            margin-top: 15px;
        }}

        .next-steps ol, .related-queries ul {{
            margin: 10px 0;
            padding-left: 25px;
        }}

        .next-steps li, .related-queries li {{
            margin-bottom: 8px;
        }}

        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}

        .stat-card {{
            background: var(--bg-card);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-card .number {{
            font-size: 32px;
            font-weight: bold;
        }}

        .stat-card.errors .number {{ color: var(--accent-red); }}
        .stat-card.warnings .number {{ color: var(--accent-yellow); }}
        .stat-card.info .number {{ color: var(--accent-blue); }}

        /* Pipeline Visualization - improved flow diagram */
        .pipeline-container {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
            padding: 24px;
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-secondary) 100%);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
        }}

        .pipeline-stage {{
            display: flex;
            flex-direction: column;
            align-items: center;
            background: var(--bg-code);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 16px;
            min-width: 100px;
            max-width: 130px;
            transition: all 0.2s ease;
            cursor: pointer;
        }}

        .pipeline-stage:hover {{
            border-color: var(--accent-blue);
            transform: translateY(-3px);
            box-shadow: 0 4px 12px rgba(88, 166, 255, 0.2);
        }}

        .pipeline-stage.active {{
            border-color: var(--accent-green);
            background: var(--bg-card);
        }}

        .pipeline-stage .icon {{
            font-size: 20px;
            margin-bottom: 6px;
        }}

        .pipeline-stage .stage-name {{
            font-weight: 600;
            color: var(--accent-blue);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .pipeline-stage .stage-desc {{
            font-size: 9px;
            color: var(--text-secondary);
            text-align: center;
            margin-top: 4px;
            line-height: 1.3;
        }}

        .pipeline-arrow {{
            color: var(--accent-teal);
            font-size: 18px;
            padding: 0 2px;
            opacity: 0.7;
        }}

        .pipeline-detail {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 16px;
            margin-top: 16px;
            display: none;
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--accent-blue);
        }}

        .pipeline-detail.active {{
            display: block;
            animation: fadeIn 0.2s ease;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}

        .pipeline-detail h4 {{
            color: var(--accent-blue);
            margin-top: 0;
            font-size: 14px;
        }}

        .pipeline-detail p {{
            color: var(--text-secondary);
            font-size: 13px;
            margin: 8px 0;
        }}

        .pipeline-detail .content {{
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            background: var(--bg-code);
            padding: 12px;
            border-radius: 6px;
            font-size: 12px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }}

        .pipeline-detail .explanation {{
            color: var(--accent-green);
            font-style: italic;
            margin-top: 10px;
            font-size: 12px;
        }}

        /* Annotated Query with improved syntax highlighting */
        .annotated-query {{
            background: var(--bg-code);
            border-radius: 8px;
            padding: 20px;
            margin-top: 15px;
            border: 1px solid var(--border-color);
        }}

        .annotated-query pre {{
            margin: 0;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 13px;
            line-height: 1.7;
        }}

        .annotated-query .comment {{
            color: var(--syn-comment);
            font-style: italic;
        }}

        .annotated-query .stage-keyword {{
            color: var(--syn-keyword);
            font-weight: 600;
        }}

        .annotated-query .function {{
            color: var(--syn-function);
        }}

        .annotated-query .string {{
            color: var(--syn-string);
        }}

        .annotated-query .operator {{
            color: var(--syn-operator);
            font-weight: 500;
        }}

        /* XQL Example blocks in tips */
        .xql-example {{
            margin-top: 8px;
        }}

        .xql-example summary {{
            cursor: pointer;
            color: var(--accent-teal);
            font-size: 12px;
            padding: 4px 0;
        }}

        .xql-example summary:hover {{
            color: var(--accent-blue);
        }}

        .xql-code {{
            background: var(--bg-code);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px;
            margin: 8px 0;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 12px;
            line-height: 1.5;
            overflow-x: auto;
            white-space: pre;
            color: var(--text-primary);
        }}

        .copy-btn {{
            background: var(--accent-blue);
            color: var(--bg-primary);
            border: none;
            border-radius: 4px;
            padding: 4px 12px;
            font-size: 11px;
            cursor: pointer;
            transition: background 0.2s;
        }}

        .copy-btn:hover {{
            background: var(--accent-teal);
        }}

        .copy-btn.copied {{
            background: var(--accent-green);
        }}

        .tip-text, .step-text, .query-name {{
            font-weight: 500;
            display: block;
            margin-bottom: 4px;
        }}

        .step-note {{
            color: var(--accent-yellow);
            font-size: 13px;
            font-style: italic;
            margin-bottom: 12px;
            padding: 8px 12px;
            background: rgba(210, 153, 34, 0.1);
            border-radius: 4px;
            border-left: 3px solid var(--accent-yellow);
        }}

        .next-steps ol {{
            padding-left: 20px;
        }}

        .next-steps li {{
            margin-bottom: 16px;
        }}

        .related-queries li {{
            margin-bottom: 12px;
        }}

        /* Explanation sections */
        .explanation-section {{
            margin-bottom: 20px;
        }}

        .explanation-content {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            line-height: 1.8;
            font-size: 14px;
        }}

        .explanation-content strong {{
            color: var(--accent-blue);
        }}

        .query-explanation {{
            border-left: 3px solid var(--accent-blue);
        }}

        .threat-explanation {{
            border-left: 3px solid var(--accent-red);
        }}

        .explanation-content ul, .explanation-content ol {{
            margin: 10px 0 10px 20px;
        }}

        .explanation-content li {{
            margin-bottom: 6px;
        }}

        /* Collapsible sections */
        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}

        .collapsible::before {{
            content: '▶ ';
            display: inline-block;
            transition: transform 0.3s ease;
        }}

        .collapsible.active::before {{
            transform: rotate(90deg);
        }}

        .collapsible-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }}

        .collapsible-content.show {{
            max-height: 2000px;
        }}

        footer {{
            text-align: center;
            color: var(--text-secondary);
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid var(--border-color);
        }}

        footer a {{
            color: var(--accent-blue);
            text-decoration: none;
        }}

        footer a:hover {{
            text-decoration: underline;
        }}

        @media (max-width: 768px) {{
            .meta {{
                flex-direction: column;
                gap: 10px;
            }}

            .issues-table {{
                font-size: 14px;
            }}

            .issues-table th,
            .issues-table td {{
                padding: 8px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{html.escape(metadata.title or 'XQL Detection Query')}</h1>
            <div class="meta">
                <span><strong>Category:</strong> {html.escape(purpose['category'])}</span>
                <span><strong>Severity:</strong> {html.escape(metadata.severity)}</span>
                {f'<span><strong>File:</strong> {html.escape(file_path)}</span>' if file_path else ''}
                <span><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
            </div>
            <div class="status-badge {status_class}">{status_text}</div>
        </header>

        <div class="card">
            <h2>Query Analysis</h2>

            <h3 class="collapsible active">Syntax Highlighted Query</h3>
            <div class="collapsible-content show">
                <div class="annotated-query">
                    <pre id="highlighted-query">{syntax_highlight_query(query)}</pre>
                    <button class="copy-btn" style="margin-top: 12px;" onclick="copyHighlightedQuery()">Copy Query</button>
                </div>
            </div>

            <h3 class="collapsible">Auto-Commented Query</h3>
            <div class="collapsible-content">
                <div class="annotated-query">
                    <pre>{syntax_highlight_query(generate_annotated_query(query))}</pre>
                </div>
            </div>

            {build_pipeline_html(query)}
        </div>

        <div class="card">
            <h2>Validation Results</h2>
            <div class="summary-stats">
                <div class="stat-card errors">
                    <div class="number">{error_count}</div>
                    <div>Errors</div>
                </div>
                <div class="stat-card warnings">
                    <div class="number">{warning_count}</div>
                    <div>Warnings</div>
                </div>
                <div class="stat-card info">
                    <div class="number">{info_count}</div>
                    <div>Info</div>
                </div>
            </div>
            {issues_html}
        </div>

        {f'''
        <div class="card">
            <h2>Detection Guidance</h2>

            {query_explanation_html if query_explanation_html else f'<div class="purpose-section"><p>{html.escape(purpose["description"])}</p></div>'}

            {threat_explanation_html}

            {mitre_html}
        </div>

        <div class="card">
            <h2>Response Playbook</h2>
            {next_steps_html}
            {related_html}
        </div>
        ''' if include_guidance else ''}

        <footer>
            <p>Generated by XQL Validator - <a href="https://github.com/ai-for-the-win" target="_blank">AI for the Win</a></p>
            <p>Created by Raymond DePalma | For security research and education</p>
        </footer>
    </div>

    <script>
        // Collapsible sections
        document.querySelectorAll('.collapsible').forEach(function(elem) {{
            elem.addEventListener('click', function() {{
                this.classList.toggle('active');
                var content = this.nextElementSibling;
                content.classList.toggle('show');
            }});
        }});

        // Pipeline stage interaction
        document.querySelectorAll('.pipeline-stage').forEach(function(stage) {{
            stage.addEventListener('click', function() {{
                // Hide all details
                document.querySelectorAll('.pipeline-detail').forEach(function(d) {{
                    d.classList.remove('active');
                }});
                // Remove active from all stages
                document.querySelectorAll('.pipeline-stage').forEach(function(s) {{
                    s.style.borderColor = 'var(--border-color)';
                }});

                // Show selected detail
                var idx = this.getAttribute('data-stage');
                var detail = document.getElementById('stage-detail-' + idx);
                if (detail) {{
                    detail.classList.add('active');
                    this.style.borderColor = 'var(--accent-blue)';
                }}
            }});
        }});

        // Click first stage by default to show its detail
        var firstStage = document.querySelector('.pipeline-stage');
        if (firstStage) {{
            firstStage.click();
        }}

        // Copy XQL code from tips section
        function copyXQL(btn) {{
            var pre = btn.previousElementSibling;
            var text = pre.textContent || pre.innerText;
            navigator.clipboard.writeText(text).then(function() {{
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(function() {{
                    btn.textContent = 'Copy';
                    btn.classList.remove('copied');
                }}, 2000);
            }});
        }}

        // Copy syntax-highlighted query (strips HTML tags)
        function copyHighlightedQuery() {{
            var pre = document.getElementById('highlighted-query');
            var text = pre.textContent || pre.innerText;
            var btn = pre.nextElementSibling;
            navigator.clipboard.writeText(text).then(function() {{
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(function() {{
                    btn.textContent = 'Copy Query';
                    btn.classList.remove('copied');
                }}, 2000);
            }});
        }}
    </script>
</body>
</html>
"""

    return html_content


def generate_report_file(
    query: str,
    output_path: str | Path,
    include_guidance: bool = True
) -> tuple[bool, str]:
    """
    Generate an HTML report file for an XQL query.

    Args:
        query: The XQL query to validate and report on
        output_path: Path to write the HTML report
        include_guidance: Include detection guidance and MITRE mapping

    Returns:
        Tuple of (is_valid, output_path)
    """
    is_valid, issues = validate_query(query)
    html_content = generate_html_report(query, issues, include_guidance=include_guidance)

    output_path = Path(output_path)
    output_path.write_text(html_content, encoding="utf-8")

    return is_valid, str(output_path)


if __name__ == "__main__":
    # Example usage
    test_query = """
// Title: LSASS Memory Dump Detection
// Description: Detects credential dumping via comsvcs.dll or procdump
// MITRE ATT&CK: T1003.001
// Severity: Critical
// Author: Security Team

config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter (
    (actor_process_image_name ~= "rundll32.exe"
     and actor_process_command_line contains "comsvcs"
     and actor_process_command_line contains "minidump")
    or
    (actor_process_image_name in ("procdump.exe", "procdump64.exe")
     and actor_process_command_line contains "lsass")
)
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line
| sort desc _time
| limit 100
    """

    is_valid, output_file = generate_report_file(test_query, "xql_report.html")
    print(f"Report generated: {output_file}")
    print(f"Query valid: {is_valid}")
