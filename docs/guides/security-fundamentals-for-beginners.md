# Security Fundamentals for Beginners

A quick introduction to cybersecurity concepts for data scientists, developers, and ML practitioners who are new to security.

---

## Who This Guide Is For

If you're a:
- Data scientist wanting to apply ML to security problems
- Developer curious about security automation
- ML engineer exploring security use cases
- Student learning about AI in cybersecurity

...but you've never worked in security, this guide will help you understand the key concepts used throughout this course.

---

## Table of Contents

1. [What is Cybersecurity?](#what-is-cybersecurity)
2. [The Security Operations Center (SOC)](#the-security-operations-center-soc)
3. [Threats and Attacks](#threats-and-attacks)
4. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
5. [MITRE ATT&CK Framework](#mitre-attck-framework)
6. [Security Logs and Events](#security-logs-and-events)
7. [Incident Response (IR)](#incident-response-ir)
8. [Common Security Tools](#common-security-tools)
9. [Security Terminology Quick Reference](#security-terminology-quick-reference)

---

## What is Cybersecurity?

**Cybersecurity** is the practice of protecting systems, networks, and data from digital attacks. Think of it as the immune system for computers and organizations.

### The CIA Triad

Security focuses on protecting three things:

```
                    ┌─────────────────┐
                    │ CONFIDENTIALITY │
                    │   (Secrets stay │
                    │    secret)      │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              │              ▼
    ┌─────────────────┐      │      ┌─────────────────┐
    │   INTEGRITY     │◄─────┴─────►│  AVAILABILITY   │
    │   (Data isn't   │             │  (Systems work  │
    │    tampered)    │             │   when needed)  │
    └─────────────────┘             └─────────────────┘
```

| Property | Meaning | Threat Example |
|----------|---------|----------------|
| **Confidentiality** | Only authorized people can access data | Hacker steals customer database |
| **Integrity** | Data hasn't been tampered with | Attacker modifies financial records |
| **Availability** | Systems are accessible when needed | Ransomware encrypts all files |

---

## The Security Operations Center (SOC)

A **SOC** is a team of security analysts who monitor an organization's systems for threats 24/7.

### What SOC Analysts Do

```
┌─────────────────────────────────────────────────────────────┐
│                    SOC WORKFLOW                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ALERT        TRIAGE         INVESTIGATE      RESPOND      │
│   ─────        ──────         ───────────      ───────      │
│                                                             │
│   Tool         Analyst        Analyst          Analyst +    │
│   generates    reviews:       digs deeper:     Tools:       │
│   alert        Real? Fake?    What happened?   Contain,     │
│                How bad?       Who's affected?  remediate    │
│                                                             │
│   10,000+      ~1,000         ~100             ~10          │
│   /day         reviewed       investigated     incidents    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### SOC Tiers

| Tier | Role | What They Do |
|------|------|--------------|
| **Tier 1** | Alert Triage | Review alerts, filter false positives, escalate real threats |
| **Tier 2** | Investigation | Deep dive into incidents, correlate events |
| **Tier 3** | Threat Hunting | Proactively search for hidden threats, advanced analysis |

**Why AI Helps**: SOCs are overwhelmed with alerts (thousands per day). AI can help filter noise, prioritize threats, and speed up investigations.

---

## Threats and Attacks

### Common Threat Types

| Threat | What It Is | Example |
|--------|------------|---------|
| **Phishing** | Fake emails/websites to steal credentials | "Your bank account needs verification" email |
| **Malware** | Malicious software | Virus, trojan, worm, spyware |
| **Ransomware** | Malware that encrypts files and demands payment | WannaCry, LockBit, BlackCat |
| **Brute Force** | Guessing passwords repeatedly | Trying millions of password combinations |
| **Data Exfiltration** | Stealing data from a network | Sending company secrets to external server |
| **Lateral Movement** | Attacker spreads through network after initial access | Moving from one computer to others |
| **Command & Control (C2)** | Attacker controlling compromised systems remotely | Malware "calling home" for instructions |

### The Attack Lifecycle

Most attacks follow a pattern:

```
1. RECON           2. INITIAL ACCESS      3. ESTABLISH FOOTHOLD
   ─────────          ──────────────         ─────────────────
   Research target    Phishing email,        Install malware,
   Find weaknesses    exploit vulnerability  create backdoor

        │                    │                       │
        └────────────────────┴───────────────────────┘
                             │
                             ▼

4. ESCALATE         5. LATERAL MOVEMENT    6. OBJECTIVE
   ────────────        ────────────────       ─────────
   Get admin           Spread to other        Steal data,
   privileges          systems                deploy ransomware
```

---

## Indicators of Compromise (IOCs)

An **IOC** is a piece of evidence that indicates a potential security breach. Think of them as "fingerprints" left by attackers.

### Types of IOCs

| IOC Type | What It Is | Example |
|----------|------------|---------|
| **IP Address** | Network address of attacker/C2 server | `185.220.101.5` |
| **Domain** | Malicious website or C2 domain | `evil-domain.xyz` |
| **File Hash** | Unique fingerprint of a malicious file | `5d41402abc4b2a76b9719d911017c592` (MD5) |
| **File Path** | Location where malware drops files | `C:\Windows\Temp\malware.exe` |
| **URL** | Specific malicious link | `hxxp://evil.com/payload.exe` |
| **Email Address** | Sender of phishing emails | `support@paypall-verify.com` |
| **Registry Key** | Windows registry persistence | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |

### Defanging IOCs

When sharing IOCs, we "defang" them to prevent accidental clicks:

```
Original:        Defanged:
http://         hxxp://
https://        hxxps://
evil.com        evil[.]com
192.168.1.1     192[.]168[.]1[.]1
```

### Why IOCs Matter for ML

IOC extraction is a common ML/NLP task:
- **Lab 04**: Extract IOCs from logs using LLMs
- **Lab 05**: Build agents that look up IOC reputation
- **Lab 06**: Create RAG systems for IOC knowledge bases

---

## MITRE ATT&CK Framework

**ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) is a knowledge base of attacker behaviors. It's the "common language" security professionals use to describe attacks.

### Understanding the Structure

```
TACTIC (Why)              TECHNIQUE (How)           SUB-TECHNIQUE
────────────              ───────────────           ─────────────
What the attacker         Specific method           More specific
wants to achieve          to achieve it             variant

Example:
Execution                 Command and Scripting     PowerShell
(Run malicious code)      Interpreter (T1059)       (T1059.001)
```

### Key Tactics (The "Why")

| Tactic | Goal | Example Techniques |
|--------|------|-------------------|
| **Initial Access** | Get into the network | Phishing, exploit public app |
| **Execution** | Run malicious code | PowerShell, command line |
| **Persistence** | Stay in the network | Registry run keys, scheduled tasks |
| **Privilege Escalation** | Get admin rights | Exploit vulnerability, steal credentials |
| **Defense Evasion** | Avoid detection | Disable antivirus, obfuscate code |
| **Credential Access** | Steal passwords | Dump LSASS memory, keylogger |
| **Discovery** | Learn about network | Scan network, list processes |
| **Lateral Movement** | Move to other systems | Remote desktop, PsExec |
| **Collection** | Gather target data | Screenshot, keylogger |
| **Exfiltration** | Steal data | Upload to cloud, DNS tunneling |
| **Impact** | Damage the target | Encrypt files (ransomware), wipe data |

### Reading ATT&CK IDs

```
T1059.001
│ │    │
│ │    └── Sub-technique number (001 = PowerShell)
│ └─────── Technique number (1059 = Command and Scripting Interpreter)
└───────── "T" for Technique
```

Common IDs you'll see:
- **T1566**: Phishing
- **T1059.001**: PowerShell
- **T1055**: Process Injection
- **T1003.001**: LSASS Memory (credential dumping)
- **T1486**: Data Encrypted for Impact (ransomware)

### Why ATT&CK Matters for AI

- Labs map findings to ATT&CK techniques
- LLMs can help identify techniques from logs
- Detection rules often reference ATT&CK IDs

**Learn More**: [attack.mitre.org](https://attack.mitre.org/)

---

## Security Logs and Events

Security tools generate **logs** - records of what happened on systems and networks. Analysts (and AI) analyze these logs to find threats.

### Common Log Types

| Log Type | What It Contains | Example Source |
|----------|------------------|----------------|
| **Authentication Logs** | Login attempts (success/failure) | Windows Security, SSH, Active Directory |
| **Firewall Logs** | Network connections allowed/blocked | Cisco, Fortinet, iptables |
| **Proxy Logs** | Web traffic (URLs visited) | Zscaler, Squid, Blue Coat |
| **Endpoint Logs** | Process execution, file changes | CrowdStrike, Carbon Black, Sysmon |
| **DNS Logs** | Domain name lookups | DNS server, Zeek |
| **Email Logs** | Email metadata, attachments | Exchange, Proofpoint |

### Windows Event IDs

Windows logs specific events with numeric IDs. Key ones for security:

| Event ID | Log | Meaning |
|----------|-----|---------|
| **4624** | Security | Successful login |
| **4625** | Security | Failed login |
| **4688** | Security | New process created |
| **4697** | Security | Service installed |
| **4720** | Security | User account created |
| **7045** | System | Service installed |
| **1102** | Security | Audit log cleared (suspicious!) |

### Log Formats

Logs come in various formats:

```
# Syslog (traditional)
Jan 15 10:30:00 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22

# JSON (modern, structured)
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "authentication",
  "result": "failure",
  "user": "admin",
  "source_ip": "192.168.1.100"
}

# CEF (Common Event Format)
CEF:0|Security|Firewall|1.0|BLOCK|Blocked connection|5|src=192.168.1.100 dst=10.0.0.1
```

---

## Incident Response (IR)

**Incident Response** is the process of handling security incidents (breaches, attacks, etc.).

### The IR Lifecycle

```
┌───────────────────────────────────────────────────────────────┐
│                   INCIDENT RESPONSE LIFECYCLE                  │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│   1. PREPARATION       2. IDENTIFICATION      3. CONTAINMENT  │
│      ───────────          ──────────────         ───────────  │
│      Have playbooks,      Detect incident,       Stop the     │
│      tools ready          assess scope           bleeding     │
│                                                               │
│           │                     │                     │       │
│           └─────────────────────┴─────────────────────┘       │
│                                 │                             │
│                                 ▼                             │
│                                                               │
│   6. LESSONS LEARNED   5. RECOVERY          4. ERADICATION    │
│      ───────────────      ────────             ───────────    │
│      What can we          Restore              Remove the     │
│      do better?           operations           threat         │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

### Key IR Concepts

| Term | Meaning |
|------|---------|
| **Containment** | Stop the attack from spreading (e.g., isolate infected computer) |
| **Eradication** | Remove the threat (e.g., delete malware, patch vulnerability) |
| **Recovery** | Return to normal operations |
| **Forensics** | Investigate what happened and how |
| **Chain of Custody** | Document who handled evidence and when |

**Lab Connection**: Lab 10b (DFIR Fundamentals) covers this in depth.

---

## Common Security Tools

### Tool Categories

| Category | Purpose | Examples |
|----------|---------|----------|
| **SIEM** | Collect and analyze logs | Splunk, Elastic, Microsoft Sentinel, IBM QRadar |
| **EDR** | Monitor endpoints (computers) | CrowdStrike, SentinelOne, Carbon Black |
| **Firewall** | Block/allow network traffic | Cisco, Fortinet, Check Point |
| **IDS/IPS** | Detect/prevent intrusions | Snort, Suricata, Zeek |
| **SOAR** | Automate response | Splunk SOAR, Swimlane, Tines |
| **Sandbox** | Safely run suspicious files | Any.Run, Joe Sandbox, Cuckoo |
| **Threat Intel** | Information about threats | VirusTotal, MISP, ThreatFox |

### What These Tools Produce

- **SIEM**: Alerts, dashboards, correlated events
- **EDR**: Process trees, file changes, network connections
- **Firewall**: Allowed/blocked connections, threat signatures
- **IDS**: Alert when suspicious traffic detected

**Why This Matters**: AI tools often integrate with these systems to automate analysis.

---

## Security Terminology Quick Reference

| Term | Meaning |
|------|---------|
| **Alert** | Notification that something suspicious happened |
| **False Positive** | Alert that looks bad but is actually normal |
| **True Positive** | Alert for a real threat |
| **False Negative** | Missed threat (no alert when there should be) |
| **Threat Actor** | Person or group conducting attacks |
| **APT** | Advanced Persistent Threat - sophisticated, long-term attackers |
| **TTPs** | Tactics, Techniques, and Procedures - how attackers operate |
| **Payload** | The malicious part of an attack |
| **Exploit** | Code that takes advantage of a vulnerability |
| **Vulnerability** | Weakness in software that can be exploited |
| **CVE** | Common Vulnerabilities and Exposures - standardized vulnerability IDs |
| **Zero-Day** | Vulnerability with no patch available |
| **Beaconing** | Malware regularly "calling home" to C2 server |
| **DLP** | Data Loss Prevention - stopping data from leaving |
| **MFA** | Multi-Factor Authentication - requiring multiple proofs of identity |

---

## How This Connects to the Labs

| Concept | Where You'll Use It |
|---------|---------------------|
| **IOCs** | Labs 04, 05, 06 - Extract and enrich IOCs |
| **ATT&CK** | Labs 04, 10b, 11 - Map findings to techniques |
| **Log Analysis** | Labs 04, 09 - Parse and analyze security logs |
| **Threat Types** | Labs 01-03 - Detect phishing, malware, anomalies |
| **IR Process** | Labs 10, 10b, 11 - Build IR copilots and tools |
| **SOC Workflow** | Lab 00d, 09, 10 - Understand where AI fits |

---

## Resources to Learn More

### SANS Free Resources (Highly Recommended)

SANS is one of the most respected cybersecurity training organizations. Their free resources are excellent for beginners:

| Resource | What It Is | Link |
|----------|------------|------|
| **SANS Reading Room** | 3,500+ free security white papers | [sans.org/white-papers](https://www.sans.org/white-papers/) |
| **SANS Posters** | Visual reference guides (print-worthy!) | [sans.org/posters](https://www.sans.org/posters/) |
| **SANS Webcasts** | Free security webinars | [sans.org/webcasts](https://www.sans.org/webcasts/) |
| **SANS Cyber Aces** | Free intro cybersecurity course | [cyberaces.org](https://www.cyberaces.org/) |
| **Internet Storm Center** | Daily security news & diaries | [isc.sans.edu](https://isc.sans.edu/) |
| **GIAC Papers** | Research from certified professionals | [giac.org/paper](https://www.giac.org/paper) |

### Must-Have SANS Posters for Your Wall

These reference posters are gold - download and print them:

| Poster | What It Covers | Best For |
|--------|----------------|----------|
| **Intrusion Discovery Cheat Sheet** | Windows/Linux evidence artifacts | Finding attacker traces |
| **Windows Forensic Analysis** | Registry, event logs, artifacts | Windows DFIR |
| **DFIR Memory Forensics** | Memory analysis techniques | Volatility, live response |
| **Hunt Evil** | Attacker behaviors to look for | Threat hunting |
| **Network Forensics** | Packet analysis, protocols | Network investigation |
| **Cloud Security** | AWS/Azure/GCP security | Cloud incidents |

> 💡 **Tip**: The "Hunt Evil" poster is especially valuable - it shows what normal vs. suspicious looks like for common Windows processes.

### Other Free Resources

- [MITRE ATT&CK](https://attack.mitre.org/) - The adversary tactics framework
- [CyberDefenders](https://cyberdefenders.org/) - Free DFIR challenges
- [LetsDefend](https://letsdefend.io/) - SOC analyst training
- [Blue Team Labs Online](https://blueteamlabs.online/) - Defensive security challenges
- [TryHackMe](https://tryhackme.com/) - Beginner-friendly security paths (SOC Level 1 is excellent)

### In This Course

- **Lab 00d**: AI in Security Operations - conceptual overview
- **Lab 10b**: DFIR Fundamentals - incident response basics
- **Glossary**: [security-to-ai-glossary.md](../../resources/security-to-ai-glossary.md) - AI terms explained for security folks

---

## Next Steps

Now that you understand the basics:

1. **Lab 00d**: Read about AI's role in security operations
2. **Lab 01**: Build your first security ML tool (phishing classifier)
3. **Lab 04**: Use LLMs to analyze security logs

You don't need to be a security expert to complete these labs - the README for each lab explains the security context. This guide gives you the foundation to understand what you're building and why it matters.

---

*Welcome to security! It's a fascinating field where you'll never stop learning.*
