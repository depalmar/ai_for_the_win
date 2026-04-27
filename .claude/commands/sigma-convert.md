# Sigma Rule Converter

Convert a Sigma rule to an open-source backend query language.

## Usage

```
/sigma-convert <rule.yml>                    # Default: convert to EQL
/sigma-convert <rule.yml> --target eql       # Elastic EQL
/sigma-convert <rule.yml> --target esql      # ES|QL (Elasticsearch piped query)
/sigma-convert <rule.yml> --target kql       # Kibana KQL
/sigma-convert <rule.yml> --target opensearch
```

## Instructions

When the user invokes this command:

1. **Load Sigma syntax** from `.claude/knowledge/sigma-rules.md` to understand the source rule's selectors, modifiers, and condition tree.

2. **Read and validate** the input rule:
   - YAML parses cleanly
   - `logsource`, `detection`, `condition` exist
   - All field modifiers are recognized (`|contains`, `|startswith`, `|endswith`, `|re`, `|all`, `|cidr`, etc.)

3. **Map fields** to the target backend's schema (ECS, Sysmon, Windows event channels). Reject the conversion if a field has no equivalent and explain why.

4. **Translate the condition tree**:
   - `selection` → backend-native equality / contains operator
   - `selection and not filter` → AND NOT composition
   - `1 of selection_*` / `all of selection_*` → expanded boolean
   - `count() by ...` → aggregation if supported, else flag as unsupported

5. **Emit output**:

   ````
   ## Converted: <rule title>

   **Source**: Sigma → **Target**: EQL

   ```eql
   process where process.name == "powershell.exe" and process.command_line : "*-enc*"
   ```

   **Notes**:
   - Field `Image` mapped to `process.executable` (ECS)
   - Modifier `|contains` → `:` (case-insensitive wildcard match)
   ````

6. **Verify round-trip semantics** when possible — describe edge cases where the translation is approximate.

## Supported Targets

| Target | Backend | Status |
|--------|---------|--------|
| `eql` | Elastic EQL | Recommended |
| `esql` | Elasticsearch ES\|QL | Recommended |
| `kql` | Kibana KQL | Recommended |
| `opensearch` | OpenSearch DSL | Supported |

## Open-Source Policy

Targets are limited to open-source / openly-documented query languages. Proprietary backends are intentionally not supported — see `LICENSE` and `docs/SOURCES.md`.

## Related

- Create rules: `/sigma-create`
- Knowledge: `.claude/knowledge/sigma-rules.md`
- Labs: lab19 (Detection Engineering), lab23 (Detection Pipeline)
