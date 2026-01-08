// =============================================================================
// XQL Threat Hunting Query Library
// Cortex XDR - Validated January 2026
// =============================================================================

// -----------------------------------------------------------------------------
// PROCESS HUNTING
// -----------------------------------------------------------------------------

// Suspicious PowerShell - Encoded Commands
config case_sensitive = false
config timeframe between "2025-01-01 00:00:00 +0000" and "2025-01-07 23:59:59 +0000"
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter actor_process_image_name ~= "powershell\.exe"
| filter actor_process_command_line contains "-enc"
    or actor_process_command_line contains "-encodedcommand"
    or actor_process_command_line contains "frombase64"
    or actor_process_command_line contains "downloadstring"
    or actor_process_command_line contains "invoke-expression"
| fields _time, agent_hostname, actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// -----------------------------------------------------------------------------

// LOLBins with Network Activity
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter action_process_image_name in (
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wmic.exe", "cscript.exe", "wscript.exe"
)
| filter actor_process_command_line contains "http"
    or actor_process_command_line contains "//"
| fields _time, agent_hostname, action_process_image_name, actor_process_command_line
| sort desc _time

// -----------------------------------------------------------------------------

// Execution from Suspicious Paths
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 1
| filter action_process_image_path contains "\\temp\\"
    or action_process_image_path contains "\\downloads\\"
    or action_process_image_path contains "\\appdata\\local\\"
    or action_process_image_path contains "\\public\\"
| fields _time, agent_hostname, action_process_image_path, action_process_image_sha256, actor_process_image_name
| dedup action_process_image_sha256
| limit 50

// -----------------------------------------------------------------------------
// PERSISTENCE
// -----------------------------------------------------------------------------

// Registry Run Key Modifications
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter action_registry_key_name contains "CurrentVersion\\Run"
    or action_registry_key_name contains "Winlogon\\Shell"
    or action_registry_key_name contains "Image File Execution Options"
| fields _time, agent_hostname, actor_process_image_name, action_registry_key_name, action_registry_data
| sort desc _time

// -----------------------------------------------------------------------------

// Scheduled Task Creation
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name = "schtasks.exe"
| filter actor_process_command_line contains "/create"
| fields _time, agent_hostname, actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// -----------------------------------------------------------------------------
// LATERAL MOVEMENT
// -----------------------------------------------------------------------------

// Remote Execution Tools
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter action_process_image_name in ("psexec.exe", "psexec64.exe", "paexec.exe")
    or action_process_image_path contains "\\admin$\\"
    or action_process_image_path contains "\\c$\\"
| fields _time, agent_hostname, action_process_image_name, action_process_command_line
| sort desc _time

// -----------------------------------------------------------------------------

// WMI Remote Execution
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name = "wmiprvse.exe"
| filter action_process_command_line != null
| fields _time, agent_hostname, action_process_image_name, action_process_command_line
| sort desc _time

// -----------------------------------------------------------------------------
// CREDENTIAL ACCESS
// -----------------------------------------------------------------------------

// LSASS Memory Access
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter action_process_image_name = "lsass.exe"
| filter event_sub_type = ENUM.PROCESS_OPEN
| filter actor_process_image_name not in ("svchost.exe", "csrss.exe", "wininit.exe", "MsMpEng.exe")
| fields _time, agent_hostname, actor_process_image_path, actor_process_image_sha256
| limit 50

// -----------------------------------------------------------------------------

// Credential Dumping Tool Indicators
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_command_line contains "sekurlsa"
    or actor_process_command_line contains "lsadump"
    or actor_process_command_line contains "privilege::debug"
    or (actor_process_command_line contains "procdump" and actor_process_command_line contains "lsass")
    or (actor_process_command_line contains "comsvcs" and actor_process_command_line contains "minidump")
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line
| sort desc _time

// -----------------------------------------------------------------------------
// NETWORK / C2
// -----------------------------------------------------------------------------

// Connections to Unusual Ports
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 1
| filter action_remote_port not in (80, 443, 53, 22, 21, 25, 3389, 445, 139)
| filter action_remote_ip != null
| fields _time, agent_hostname, actor_process_image_name, action_remote_ip, action_remote_port
| comp count() as conn_count by actor_process_image_name, action_remote_port
| sort desc conn_count
| limit 50

// -----------------------------------------------------------------------------

// Long DNS Queries (Possible Tunneling)
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 1
| filter dns_query_name != null
| filter strlen(dns_query_name) > 50
| fields _time, agent_hostname, actor_process_image_name, dns_query_name
| comp count() as query_count by agent_hostname, dns_query_name
| filter query_count > 10
| sort desc query_count

// -----------------------------------------------------------------------------
// RANSOMWARE
// -----------------------------------------------------------------------------

// Mass File Operations
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.FILE
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 1
| comp count() as file_count by agent_hostname, actor_process_image_name
| filter file_count > 100
| sort desc file_count

// -----------------------------------------------------------------------------

// Shadow Copy Deletion
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter (action_process_image_name = "vssadmin.exe" and actor_process_command_line contains "delete")
    or (actor_process_command_line contains "shadowcopy" and actor_process_command_line contains "delete")
    or (action_process_image_name = "bcdedit.exe" and actor_process_command_line contains "recoveryenabled")
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line
| sort desc _time

// -----------------------------------------------------------------------------
// INVESTIGATION HELPERS
// -----------------------------------------------------------------------------

// Process Tree for Specific Host
config case_sensitive = false
config timeframe between "2025-01-15 00:00:00 +0000" and "2025-01-15 23:59:59 +0000"
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter agent_hostname = "WORKSTATION-001"
| fields _time, causality_actor_process_image_name, actor_process_image_name, action_process_image_name, actor_process_command_line
| sort asc _time

// -----------------------------------------------------------------------------

// IOC Search - IP Address
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 30
| filter action_remote_ip in ("192.168.1.100", "10.0.0.50")
| fields _time, agent_hostname, actor_process_image_name, action_remote_ip, action_remote_port
| sort desc _time

// -----------------------------------------------------------------------------

// IOC Search - File Hash
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 30
| filter action_process_image_sha256 = "abc123def456789..."
| fields _time, agent_hostname, action_process_image_path, action_process_image_sha256
| dedup agent_hostname
| sort desc _time

// -----------------------------------------------------------------------------

// Rare Process Detection (Potential Malware)
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| comp count() as total_exec, count_distinct(agent_hostname) as unique_hosts by action_process_image_sha256, action_process_image_name
| filter unique_hosts <= 3
| sort asc unique_hosts
| limit 50
