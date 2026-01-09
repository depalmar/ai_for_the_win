# Ransomware Incident Response Playbook

## Overview
This playbook provides step-by-step guidance for responding to a ransomware incident. Time is critical in ransomware incidents - faster response limits encryption spread.

## Severity: CRITICAL
## Estimated Time: 4-24 hours for containment

---

## Phase 1: Detection & Initial Assessment (0-30 minutes)

### 1.1 Confirm the Incident
- [ ] Verify ransomware indicators (ransom note, encrypted files, unusual extensions)
- [ ] Document the ransom note contents and any provided contact information
- [ ] Identify the ransomware variant if possible (check ID Ransomware)
- [ ] Screenshot all evidence before taking any action

### 1.2 Initial Scoping
- [ ] Identify the first known affected system (Patient Zero)
- [ ] Determine the approximate time of initial infection
- [ ] List all known affected systems and shares
- [ ] Identify critical business systems at risk

### 1.3 Activate Incident Response
- [ ] Notify the incident response team lead
- [ ] Activate the incident response communication channel
- [ ] Begin incident documentation log
- [ ] Prepare to brief executive leadership

---

## Phase 2: Containment (30 minutes - 4 hours)

### 2.1 Immediate Network Isolation
- [ ] Disconnect affected systems from the network (unplug, not shutdown)
- [ ] Disable Wi-Fi on affected systems
- [ ] Block lateral movement ports (445, 135-139, 3389) between segments
- [ ] Consider full network segmentation if spread is extensive

### 2.2 Preserve Evidence
- [ ] Do NOT turn off affected systems (volatile memory evidence)
- [ ] Capture memory dumps from key affected systems
- [ ] Take disk images of Patient Zero if possible
- [ ] Preserve network logs, EDR data, and authentication logs

### 2.3 Stop the Spread
- [ ] Identify the propagation mechanism (SMB, RDP, phishing)
- [ ] Block malicious IPs and domains at firewall
- [ ] Disable compromised accounts
- [ ] Deploy emergency EDR rules to block ransomware behaviors

### 2.4 Protect Backups
- [ ] Verify backup systems are isolated and unaffected
- [ ] Disconnect backup systems from network if connected
- [ ] Verify integrity of recent backups
- [ ] Identify the last known good backup date

---

## Phase 3: Eradication (4-24 hours)

### 3.1 Identify Root Cause
- [ ] Determine initial access vector (phishing, RDP, vulnerability)
- [ ] Identify all compromised accounts and credentials
- [ ] Map the attacker's lateral movement path
- [ ] Identify persistence mechanisms

### 3.2 Remove Threat
- [ ] Remove ransomware executables and related malware
- [ ] Clear identified persistence mechanisms (scheduled tasks, services)
- [ ] Reset all potentially compromised credentials
- [ ] Patch the exploited vulnerability if applicable

### 3.3 Validate Eradication
- [ ] Run full antimalware scans on all systems
- [ ] Verify no ransomware remnants in startup locations
- [ ] Check for ongoing C2 communications
- [ ] Confirm all IOCs are blocked

---

## Phase 4: Recovery (24-72 hours)

### 4.1 Recovery Planning
- [ ] Prioritize systems for recovery based on business criticality
- [ ] Determine recovery method (rebuild, restore, decrypt)
- [ ] Check for available decryption tools (No More Ransom project)
- [ ] Prepare clean installation media

### 4.2 System Recovery
- [ ] Rebuild critical systems from known good images
- [ ] Restore data from verified clean backups
- [ ] Apply all security patches before reconnecting
- [ ] Implement additional security controls

### 4.3 Validation
- [ ] Verify recovered systems are functioning correctly
- [ ] Confirm data integrity after restoration
- [ ] Test critical business processes
- [ ] Monitor recovered systems for signs of reinfection

---

## Phase 5: Post-Incident (1-2 weeks)

### 5.1 Documentation
- [ ] Complete detailed incident timeline
- [ ] Document all affected systems and data
- [ ] Record all response actions taken
- [ ] Calculate business impact and costs

### 5.2 Lessons Learned
- [ ] Conduct post-incident review meeting
- [ ] Identify gaps in detection and response
- [ ] Document recommendations for improvement
- [ ] Update incident response procedures

### 5.3 Improvements
- [ ] Implement enhanced backup procedures
- [ ] Deploy additional detection capabilities
- [ ] Conduct user awareness training
- [ ] Test incident response procedures

---

## Key Contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| IR Lead | [Name] | [Phone] | [Email] |
| IT Director | [Name] | [Phone] | [Email] |
| Legal Counsel | [Name] | [Phone] | [Email] |
| External IR Firm | [Name] | [Phone] | [Email] |
| Cyber Insurance | [Name] | [Phone] | [Email] |

---

## Do NOT:
- Pay the ransom without consulting legal and executive leadership
- Communicate with attackers without proper preparation
- Turn off affected systems (destroys volatile evidence)
- Restore from backups until threat is fully eradicated
- Announce the incident publicly before coordinating with PR/Legal

---

## References
- CISA Ransomware Guide: https://www.cisa.gov/ransomware
- No More Ransom Project: https://www.nomoreransom.org
- ID Ransomware: https://id-ransomware.malwarehunterteam.com
