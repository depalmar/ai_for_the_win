# Windows Internals Quick Reference

A quick reference for Windows internals concepts needed for memory forensics and threat hunting labs.

---

## Who This Guide is For

If you're taking Lab 13 (Memory Forensics) or other DFIR labs and don't have a Windows internals background, this guide covers the essential concepts you need.

---

## Processes and Threads

### What is a Process?

A **process** is a running instance of a program. When you double-click notepad.exe, Windows creates a notepad process.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PROCESS ANATOMY                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   PROCESS (notepad.exe - PID 1234)                                         │
│   ├── Virtual Memory Space (unique to this process)                        │
│   │   ├── Code (.text) - The executable instructions                       │
│   │   ├── Data (.data) - Global variables                                  │
│   │   ├── Heap - Dynamic memory allocation                                 │
│   │   └── Stack - Function call data                                       │
│   ├── Loaded DLLs (kernel32.dll, ntdll.dll, etc.)                         │
│   ├── Handles (files, registry keys, network connections)                  │
│   └── Threads (1 or more - actual execution units)                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Process Properties

| Property | What It Is | Security Relevance |
|----------|------------|-------------------|
| **PID** | Process ID (unique number) | Track specific processes |
| **PPID** | Parent Process ID | Shows what started this process |
| **Image Path** | Where the .exe lives on disk | Spot processes from unusual locations |
| **Command Line** | Full command used to start | See arguments, spot encoded commands |
| **User** | Account running the process | SYSTEM processes are highest privilege |
| **Integrity** | Low/Medium/High/System | Higher = more privileges |

### What is a Thread?

A **thread** is the actual unit of execution. A process is a container; threads do the work.

```
Process (chrome.exe)
├── Thread 1: Handling UI
├── Thread 2: Network requests
├── Thread 3: JavaScript execution
├── Thread 4: Rendering
└── ...
```

**Security Note**: Malware often injects malicious threads into legitimate processes.

---

## Critical Windows Processes

These are processes you'll always see on a healthy Windows system. Knowing what's normal helps you spot what's not.

### Essential System Processes

| Process | Normal Path | Normal Parent | Function |
|---------|-------------|---------------|----------|
| **System** | N/A (kernel) | None (PID 0) | The Windows kernel |
| **smss.exe** | `\SystemRoot\System32\` | System | Session Manager |
| **csrss.exe** | `\SystemRoot\System32\` | smss.exe | Client/Server Runtime |
| **wininit.exe** | `\SystemRoot\System32\` | smss.exe | Windows Initialization |
| **services.exe** | `\SystemRoot\System32\` | wininit.exe | Service Control Manager |
| **lsass.exe** | `\SystemRoot\System32\` | wininit.exe | Local Security Authority |
| **svchost.exe** | `\SystemRoot\System32\` | services.exe | Service Host (many instances) |
| **explorer.exe** | `\Windows\` | userinit.exe | Windows Shell |

### What's Suspicious?

```
✅ NORMAL: svchost.exe running from C:\Windows\System32\
❌ SUSPICIOUS: svchost.exe running from C:\Users\Public\
❌ SUSPICIOUS: svchost.exe with no parent (orphaned)
❌ SUSPICIOUS: Multiple lsass.exe processes (should only be one)
❌ SUSPICIOUS: csrss.exe spawned by something other than smss.exe
```

### The "Hunt Evil" Principle

SANS's famous "Hunt Evil" poster teaches this method:

1. **Know what normal looks like** for each critical process
2. **Check path** - Is it running from the expected location?
3. **Check parent** - Was it started by the expected process?
4. **Check user** - Is it running as the expected account?
5. **Check command line** - Are there unexpected arguments?

---

## DLLs (Dynamic Link Libraries)

### What is a DLL?

A DLL is a library of code that multiple programs can share. Instead of every program having its own copy of common functions, they load them from DLLs.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DLL LOADING                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   notepad.exe loads:                                                        │
│   ├── ntdll.dll      - Low-level Windows functions                         │
│   ├── kernel32.dll   - Core Windows API                                    │
│   ├── user32.dll     - User interface functions                            │
│   ├── gdi32.dll      - Graphics functions                                  │
│   └── ...                                                                   │
│                                                                             │
│   Security Issue: DLL Injection                                             │
│   ─────────────────────────────────                                        │
│   Attacker loads MALICIOUS.DLL into legitimate process                     │
│   → Malicious code runs in context of trusted process                      │
│   → Harder to detect, bypasses some security controls                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key DLLs to Know

| DLL | Purpose | Why Attackers Care |
|-----|---------|-------------------|
| **ntdll.dll** | Native API (lowest level) | Syscall hooking, evasion |
| **kernel32.dll** | Core Windows functions | Process/thread creation |
| **advapi32.dll** | Security, registry, services | Credential access |
| **ws2_32.dll** | Network sockets | C2 communication |
| **wininet.dll** | HTTP functions | Downloading payloads |
| **crypt32.dll** | Cryptography | Ransomware encryption |

---

## Memory Regions

### Virtual Memory Layout

Every Windows process has its own virtual address space:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROCESS VIRTUAL MEMORY (Simplified)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   High Addresses (Kernel Space - off limits to user code)                  │
│   ─────────────────────────────────────────────────────────                │
│   0xFFFF...    │ Kernel memory (not accessible to process)                 │
│                │                                                            │
│   ─────────────┼────────────────────────────────────────────               │
│                │                                                            │
│   User Space   │ Stack (grows down) - local variables, return addresses    │
│                │   ↓                                                        │
│                │                                                            │
│                │ (unallocated space)                                       │
│                │                                                            │
│                │   ↑                                                        │
│                │ Heap (grows up) - dynamic allocations (malloc)            │
│                │                                                            │
│                │ DLLs - loaded libraries                                   │
│                │                                                            │
│                │ .data - initialized global variables                       │
│                │                                                            │
│   0x0040...   │ .text - executable code                                    │
│                │                                                            │
│   Low Addresses                                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Memory Protection Flags

| Flag | Meaning | Security Relevance |
|------|---------|-------------------|
| **PAGE_EXECUTE_READWRITE (RWX)** | Read + Write + Execute | Suspicious! Rarely needed legitimately |
| **PAGE_EXECUTE_READ** | Read + Execute | Normal for code sections |
| **PAGE_READWRITE** | Read + Write | Normal for data/heap |
| **PAGE_READONLY** | Read only | Normal for constants |

**Red Flag**: Memory regions with RWX permissions are often malicious - legitimate code rarely needs to write and execute in the same region.

---

## Windows Registry

### What is the Registry?

The Windows Registry is a hierarchical database storing system and application configuration.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REGISTRY STRUCTURE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   HKEY_LOCAL_MACHINE (HKLM) - System-wide settings                         │
│   ├── SOFTWARE     - Installed applications                                │
│   ├── SYSTEM       - Hardware, drivers, services                           │
│   ├── SECURITY     - Security policies                                     │
│   └── SAM          - User account database                                 │
│                                                                             │
│   HKEY_CURRENT_USER (HKCU) - Current user settings                         │
│   ├── SOFTWARE     - User application settings                             │
│   ├── Environment  - User environment variables                            │
│   └── ...                                                                   │
│                                                                             │
│   HKEY_USERS (HKU) - All user profiles                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Common Persistence Locations

Attackers often use these registry keys for persistence (surviving reboot):

| Key | Purpose | ATT&CK |
|-----|---------|--------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Programs run at startup (all users) | T1547.001 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Programs run at startup (current user) | T1547.001 |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Windows services | T1543.003 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` | Shell replacement | T1547.004 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | Debugger hijacking | T1546.012 |

---

## Windows Services

### What is a Service?

A Windows Service is a program that runs in the background, often starting at boot.

```
SERVICE CHARACTERISTICS:
• Run without user login
• Run as SYSTEM (usually)
• Start automatically or on-demand
• Managed by services.exe
```

### Viewing Services

```powershell
# List all services
Get-Service

# Get detailed info
Get-WmiObject Win32_Service | Select Name, PathName, StartMode, State

# Look for suspicious services
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*System32*"}
```

### Suspicious Service Indicators

```
❌ Service binary in unusual location (user folders, temp)
❌ Service running as SYSTEM with write-accessible binary
❌ Service with misspelled name similar to legitimate service
❌ Service with no description
❌ Service created recently (check creation timestamp)
```

---

## Windows Event Logs

### Key Log Channels

| Log | Location | Key Events |
|-----|----------|------------|
| **Security** | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | Logons, privilege use, audit |
| **System** | `%SystemRoot%\System32\winevt\Logs\System.evtx` | Service changes, shutdowns |
| **Application** | `%SystemRoot%\System32\winevt\Logs\Application.evtx` | Application errors |
| **PowerShell** | `Microsoft-Windows-PowerShell/Operational` | Script execution |
| **Sysmon** | `Microsoft-Windows-Sysmon/Operational` | Detailed process/network logging |

### Critical Event IDs

| Event ID | Log | Meaning |
|----------|-----|---------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential use (runas) |
| 4672 | Security | Special privileges assigned |
| 4688 | Security | Process creation |
| 4697 | Security | Service installed |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 7045 | System | Service installed |
| 1102 | Security | Audit log cleared |

---

## Handles and Objects

### What is a Handle?

A handle is a reference to a Windows object (file, process, registry key, etc.). Think of it like a file descriptor in Linux.

```python
# When you open a file in Python:
f = open("secret.txt")  # f is like a handle

# Windows equivalent:
# CreateFile() returns a HANDLE to the file
# The process has a handle table tracking all open objects
```

### Why Handles Matter for Forensics

- **Which files does a process have open?**
- **Is a process accessing another process's memory?** (handle to process)
- **What registry keys is malware reading?**
- **Network connections** (socket handles)

---

## Common Attack Techniques

### Process Injection (T1055)

Injecting code into another process:

```
1. DLL Injection
   - Force target to load malicious DLL
   
2. Process Hollowing
   - Start legitimate process suspended
   - Replace its memory with malicious code
   - Resume execution
   
3. Thread Injection
   - Create new thread in target process
   - Thread executes malicious code

Detection: Look for:
- Unusual DLLs in processes
- Processes with memory from unusual locations
- RWX memory regions
```

### Credential Dumping (T1003)

Stealing credentials from memory:

```
Primary Target: lsass.exe (Local Security Authority)
- Contains cached credentials
- NTLM hashes
- Kerberos tickets

Tools: mimikatz, procdump, comsvcs.dll

Detection:
- Processes accessing lsass.exe
- lsass.exe memory dumps
- Unusual tools reading lsass memory
```

---

## Quick Reference Commands

### PowerShell Process Investigation

```powershell
# List processes with path
Get-Process | Select-Object Name, Id, Path | Sort-Object Name

# Get parent process
Get-WmiObject Win32_Process | Select Name, ProcessId, ParentProcessId, CommandLine

# Find processes with specific name
Get-Process -Name "svchost" | Format-List *

# Check loaded modules (DLLs)
Get-Process notepad | Select-Object -ExpandProperty Modules
```

### Command Prompt

```cmd
# List processes
tasklist /v

# Process tree
wmic process get processid,parentprocessid,commandline

# Services
sc query

# Network connections
netstat -ano
```

---

## SANS Resources

- **[Hunt Evil Poster](https://www.sans.org/posters/hunt-evil/)** - Normal vs. suspicious process behaviors
- **[Windows Forensic Analysis Poster](https://www.sans.org/posters/windows-forensic-analysis/)** - Artifact locations
- **[Know Normal, Find Evil](https://www.sans.org/white-papers/)** - Search in Reading Room

---

## Learn More

- Lab 13: Memory Forensics AI
- Lab 10b: DFIR Fundamentals
- [Windows Internals Book](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals) (Microsoft)
- [Sysinternals Tools](https://docs.microsoft.com/en-us/sysinternals/) (Process Explorer, Autoruns, etc.)
