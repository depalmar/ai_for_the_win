# XQL Query Templates

Pre-built XQL query templates for Cortex XDR threat hunting, detection, and investigation.

## Files

| File | Description |
|------|-------------|
| `xql_templates.py` | Python library for generating XQL queries programmatically |
| `hunting_queries.xql` | Ready-to-use threat hunting queries |
| `detection_rules.xql` | BIOC/Analytics rule templates |

## Usage

### Python Library

```python
from xql_templates import XQLBuilder

# Build a PowerShell hunting query
query = XQLBuilder.powershell_hunting(
    days=7,
    case_sensitive=False
)
print(query)
```

### Direct XQL Queries

Copy queries from `.xql` files directly into Cortex XDR Query Builder.

## Query Categories

- **Process Hunting**: PowerShell, LOLBins, suspicious paths
- **Persistence**: Registry, scheduled tasks, services
- **Lateral Movement**: PsExec, WMI, SMB
- **Credential Access**: LSASS, Mimikatz patterns
- **Network**: Beaconing, DNS tunneling, unusual ports
- **Ransomware**: Mass file operations, shadow deletion

## References

- [XQL Guide](../../docs/guides/xql-guide.md) - Comprehensive XQL documentation
- [Cortex XDR Docs](https://docs.paloaltonetworks.com/cortex/cortex-xdr) - Official reference
