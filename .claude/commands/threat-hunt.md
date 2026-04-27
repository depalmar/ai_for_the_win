# Threat Hunt Query Builder

Construct hypothesis-driven threat hunting queries from an idea, MITRE technique, or known IOC set.

## Usage

```
/threat-hunt "Suspicious WMI persistence on Windows endpoints"
/threat-hunt --mitre T1546.003                 # Hunt by MITRE technique
/threat-hunt --iocs iocs.json --backend eql    # Hunt for known IOCs
/threat-hunt --backend esql|kql|opensearch     # Pick query language
```

## Instructions

When the user invokes this command:

1. **Frame the hypothesis** explicitly before writing any query:
   - **Hypothesis**: "Adversary is using X technique on Y data source"
   - **Data sources required**: process_creation, network, dns, registry, etc.
   - **Time window**: e.g., last 7 days
   - **Expected hit rate**: high-volume (broad, needs filtering) vs. rare (sharp)

2. **Pull MITRE context** from `.claude/knowledge/mitre-attack.md`:
   - Tactic + technique IDs
   - Common procedures (T-numbers)
   - Known data source mappings (DS####)
   - Detection guidance from ATT&CK

3. **Write the query** in the requested backend (default EQL). Use ECS / Sysmon canonical fields. Example shape:
   ```eql
   sequence by host.id with maxspan=10m
     [process where process.name == "wmiprvse.exe"]
     [registry where registry.path : "*\\Software\\Classes\\CLSID\\*"]
   ```

4. **Add false-positive filters** explicitly — comment each filter so an analyst can tune:
   ```
   // Exclude legitimate SCCM agents
   and not process.parent.name == "ccmexec.exe"
   ```

5. **Output a runnable hunt package**:
   - Query (in chosen backend)
   - Required fields / data sources
   - Suggested time range
   - Triage steps for any hit (what to validate, who to contact)
   - Pivot queries (e.g., "if hit, also check ___")

6. **Open-source backends only**: EQL, ES|QL, KQL, OpenSearch DSL. Convert to/from Sigma via `/sigma-convert` for portability.

## Hunt Methodology Reference

Follow the **PEAK** model (Prepare, Execute, Act, Knowledge):
1. **Prepare** — hypothesis, data check, success criteria
2. **Execute** — run query, iterate
3. **Act** — escalate hits, document benign findings
4. **Knowledge** — convert successful hunts to Sigma rules via `/sigma-create`

## Related

- Knowledge: `.claude/knowledge/mitre-attack.md`, `.claude/knowledge/sigma-rules.md`
- Convert hunt → detection: `/sigma-create`
- Labs: lab23 (Detection Pipeline), lab35 (Lateral Movement Detection), lab36 (Threat Actor Profiling)
