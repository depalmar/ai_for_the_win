# Sigma Rule Creator

Generate a Sigma detection rule from a description, IOCs, log sample, or MITRE technique.

## Usage

```
/sigma-create "PowerShell encoded command execution"
/sigma-create --from-log <file>          # Infer rule from a log sample
/sigma-create --mitre T1059.001          # Generate based on a MITRE technique
/sigma-create --iocs iocs.json           # Build a rule that fires on supplied IOCs
```

## Instructions

When the user invokes this command:

1. **Load Sigma syntax reference** from `.claude/knowledge/sigma-rules.md` for current schema (field modifiers, condition syntax, level taxonomy).

2. **Determine inputs**:
   - Plain description → ask Claude to map to log source + selection
   - `--from-log` → parse the log via `/log-parser` first, then derive selection criteria
   - `--mitre` → pull tactic/technique context from `.claude/knowledge/mitre-attack.md`
   - `--iocs` → build a `selection` block matching those values

3. **Generate the rule** with all required fields:
   ```yaml
   title: <short, action-oriented>
   id: <generate UUID v4>
   status: experimental
   description: <what it detects and why it matters>
   author: AI for the Win
   date: <today, YYYY/MM/DD>
   references:
     - <urls>
   tags:
     - attack.<tactic>
     - attack.<technique>
   logsource:
     product: <windows|linux|...>
     category: <process_creation|...>
   detection:
     selection:
       <field>: <value>
     condition: selection
   falsepositives:
     - <list>
   level: <low|medium|high|critical>
   ```

4. **Validate** before returning:
   - YAML parses cleanly
   - All required fields present
   - Field modifiers are valid (`|contains`, `|startswith`, `|re`, `|all`, etc.)
   - At least one condition evaluates the selection
   - MITRE tags use the `attack.txxxx` format

5. **Offer next steps**:
   - Convert to a different backend with `/sigma-convert`
   - Drop into `labs/labXX/data/rules/` for testing
   - Run against a sample log via the lab19 / lab23 pipeline

## Open-Source Policy

This project targets open backends only — write rules so they convert cleanly to **EQL**, **ES|QL**, **KQL (Kibana)**, or **OpenSearch**. Avoid vendor-only field names (use the canonical Sysmon/ECS field names).

## Related

- Knowledge: `.claude/knowledge/sigma-rules.md`, `.claude/knowledge/mitre-attack.md`
- Convert: `/sigma-convert`
- Labs: lab19 (Detection Engineering), lab23 (Detection Pipeline), lab28 (Hunting)
