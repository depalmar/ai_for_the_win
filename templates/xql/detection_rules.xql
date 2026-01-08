// =============================================================================
// XQL Detection Rule Templates
// Cortex XDR BIOC-style detections for common threats
// =============================================================================

// -----------------------------------------------------------------------------
// CREDENTIAL ACCESS
// -----------------------------------------------------------------------------

// Detection: LSASS Memory Dump Attempt
// MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
// Severity: Critical
// Note: Detects credential dumping via command line patterns and known tools
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter (
    // Mimikatz command patterns
    actor_process_command_line ~= "sekurlsa|lsadump|privilege::debug|mimikatz"
    or
    // Procdump targeting LSASS
    (actor_process_image_name ~= "procdump" and actor_process_command_line ~= "lsass")
    or
    // Comsvcs.dll MiniDump
    (actor_process_command_line ~= "comsvcs" and actor_process_command_line ~= "minidump")
    or
    // Task Manager LSASS dump
    (actor_process_command_line ~= "taskmgr" and actor_process_command_line ~= "lsass")
    or
    // Suspicious process spawning with LSASS in command line
    (causality_actor_process_image_name ~= "powershell|cmd|wscript|cscript" and
     actor_process_command_line ~= "lsass")
)
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, action_process_image_name,
         causality_actor_process_image_name
| sort desc _time
| limit 100

// -----------------------------------------------------------------------------
// EXECUTION
// -----------------------------------------------------------------------------

// Detection: Encoded PowerShell Command Execution
// MITRE ATT&CK: T1059.001 - PowerShell
// Severity: High
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name ~= "powershell\.exe|pwsh\.exe"
| filter actor_process_command_line ~= "-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,}"
| filter actor_process_command_line not contains "Windows Defender"
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, causality_actor_process_image_name,
         causality_actor_process_command_line
| sort desc _time
| limit 100

// Detection: LOLBAS Execution - CertUtil Download
// MITRE ATT&CK: T1218, T1105
// Severity: High
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name ~= "certutil\.exe"
| filter actor_process_command_line ~= "urlcache|verifyctl|decode|encode"
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// Detection: MSHTA Executing Remote Content
// MITRE ATT&CK: T1218.005 - System Binary Proxy Execution: Mshta
// Severity: High
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name ~= "mshta\.exe"
| filter actor_process_command_line ~= "http://|https://|javascript:|vbscript:"
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// -----------------------------------------------------------------------------
// PERSISTENCE
// -----------------------------------------------------------------------------

// Detection: Registry Run Key Modification
// MITRE ATT&CK: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
// Severity: Medium
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter action_registry_key_name ~= "CurrentVersion\\\\Run|RunOnce|RunServices"
| filter actor_process_image_name not in ("msiexec.exe", "setup.exe", "explorer.exe")
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         action_registry_key_name, action_registry_value_name,
         action_registry_data
| sort desc _time
| limit 100

// Detection: Scheduled Task Created for Persistence
// MITRE ATT&CK: T1053.005 - Scheduled Task/Job: Scheduled Task
// Severity: Medium
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name ~= "schtasks\.exe"
| filter actor_process_command_line ~= "/create"
| filter actor_process_command_line not contains "Microsoft\\Windows"
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// -----------------------------------------------------------------------------
// LATERAL MOVEMENT
// -----------------------------------------------------------------------------

// Detection: PsExec or Similar Tool Execution
// MITRE ATT&CK: T1021.002 - SMB/Windows Admin Shares
// Severity: High
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter (
    actor_process_image_name ~= "psexec|paexec|remcom|csexec"
    or
    (actor_process_command_line ~= "\\\\\\\\.*\\\\admin\$|\\\\\\\\.*\\\\c\$|\\\\\\\\.*\\\\ipc\$" and
     actor_process_image_name ~= "cmd\.exe|powershell\.exe")
)
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, action_process_image_name,
         causality_actor_process_image_name
| sort desc _time
| limit 100

// Detection: WMI Remote Execution
// MITRE ATT&CK: T1047 - Windows Management Instrumentation
// Severity: Medium
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name ~= "wmic\.exe"
| filter actor_process_command_line ~= "/node:|process call create"
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// -----------------------------------------------------------------------------
// DEFENSE EVASION
// -----------------------------------------------------------------------------

// Detection: Windows Defender Tampering
// MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
// Severity: High
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter (
    // PowerShell disabling Defender
    (actor_process_image_name ~= "powershell\.exe" and
     actor_process_command_line ~= "Set-MpPreference.*-Disable|DisableRealtimeMonitoring")
    or
    // Command line disabling Defender
    actor_process_command_line ~= "sc stop WinDefend|sc delete WinDefend|net stop WinDefend"
)
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// Detection: Event Log Clearing
// MITRE ATT&CK: T1070.001 - Indicator Removal: Clear Windows Event Logs
// Severity: High
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter (
    actor_process_command_line ~= "wevtutil.*cl|Clear-EventLog|Remove-EventLog"
    or
    (actor_process_image_name ~= "wevtutil\.exe" and
     actor_process_command_line contains " cl ")
)
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------

// Detection: Ransomware - Shadow Copy Deletion
// MITRE ATT&CK: T1490 - Inhibit System Recovery
// Severity: Critical
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter (
    // VSSAdmin shadow deletion
    (actor_process_image_name ~= "vssadmin\.exe" and
     actor_process_command_line ~= "delete shadows|resize shadowstorage")
    or
    // WMIC shadow deletion
    (actor_process_image_name ~= "wmic\.exe" and
     actor_process_command_line ~= "shadowcopy delete")
    or
    // BCDEdit disabling recovery
    (actor_process_image_name ~= "bcdedit\.exe" and
     actor_process_command_line ~= "recoveryenabled.*no|bootstatuspolicy.*ignoreallfailures")
)
| fields _time, agent_hostname, agent_ip_addresses, actor_process_image_name,
         actor_process_command_line, causality_actor_process_image_name
| sort desc _time
| limit 100

// -----------------------------------------------------------------------------
// DISCOVERY
// -----------------------------------------------------------------------------

// Detection: Reconnaissance Commands Burst
// MITRE ATT&CK: T1082, T1083, T1016 - System/File/Network Discovery
// Severity: Medium
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name in ("whoami.exe", "hostname.exe", "ipconfig.exe",
                                       "net.exe", "systeminfo.exe", "nltest.exe",
                                       "quser.exe", "query.exe", "nslookup.exe")
| comp count() as recon_count by agent_hostname, causality_actor_process_image_name
| filter recon_count >= 5
| sort desc recon_count
| limit 50
