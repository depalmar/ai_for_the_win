# MCP Server Templates

Model Context Protocol (MCP) servers for integrating threat intelligence APIs with Claude Code, Cursor, and other MCP-compatible AI tools.

> ⚠️ **DISCLAIMER**: These are example templates for educational purposes. Configure API keys and test before production use.

## Available Servers

| Server | Description | APIs Used |
|--------|-------------|-----------|
| [VirusTotal](#virustotal-mcp-server) | File/IP/domain/URL reputation lookups | VirusTotal API v3 |
| [Threat Intel](#threat-intel-mcp-server) | Aggregated threat intelligence | AbuseIPDB, AlienVault OTX |

---

## VirusTotal MCP Server

Provides file hash, IP, domain, and URL reputation lookups via VirusTotal.

### Tools

| Tool | Description |
|------|-------------|
| `lookup_hash` | Look up MD5/SHA1/SHA256 file hashes |
| `lookup_ip` | Check IP address reputation |
| `lookup_domain` | Check domain reputation |
| `lookup_url` | Check URL reputation |
| `get_file_behavior` | Get sandbox behavioral analysis |

### Setup

```bash
# Install dependencies
pip install mcp httpx python-dotenv

# Set API key
export VT_API_KEY="your-virustotal-api-key"

# Run server
python virustotal-mcp-server.py
```

### Configuration (Claude Code / Cursor)

Add to `.claude/mcp_servers.json` or Cursor MCP settings:

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "python",
      "args": ["path/to/virustotal-mcp-server.py"],
      "env": {
        "VT_API_KEY": "${env:VT_API_KEY}"
      }
    }
  }
}
```

---

## Threat Intel MCP Server

Aggregates threat intelligence from multiple sources with local caching and MITRE ATT&CK mapping.

### Tools

| Tool | Description |
|------|-------------|
| `lookup_ip_reputation` | Aggregate IP reputation from AbuseIPDB + OTX |
| `lookup_domain_reputation` | Check domain against OTX |
| `add_local_ioc` | Add IOC to local SQLite database |
| `search_local_iocs` | Search local IOC database |
| `get_threat_summary` | Batch lookup multiple IOCs |

### Features

- **Multi-source aggregation**: Combines AbuseIPDB and AlienVault OTX
- **Local caching**: SQLite database with 24-hour cache
- **MITRE ATT&CK mapping**: Automatic technique mapping from tags
- **Threat scoring**: Combined threat score calculation

### Setup

```bash
# Install dependencies
pip install mcp httpx python-dotenv aiosqlite

# Set API keys
export ABUSEIPDB_API_KEY="your-abuseipdb-key"
export OTX_API_KEY="your-otx-key"

# Optional: Custom database path
export THREAT_DB_PATH="./my_threat_intel.db"

# Run server
python threat-intel-mcp-server.py
```

### Configuration

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "python",
      "args": ["path/to/threat-intel-mcp-server.py"],
      "env": {
        "ABUSEIPDB_API_KEY": "${env:ABUSEIPDB_API_KEY}",
        "OTX_API_KEY": "${env:OTX_API_KEY}"
      }
    }
  }
}
```

---

## Usage Examples

### With Claude Code

Once configured, you can ask Claude:

```
"Look up the reputation of IP 8.8.8.8"
"Check if this hash is malicious: abc123..."
"What threat intel do we have on evil.com?"
```

### With Cursor

The MCP tools appear in the tool list. Claude will automatically use them when relevant to your security analysis tasks.

---

## API Key Sources

| Service | Get API Key |
|---------|-------------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | https://www.abuseipdb.com/account/api |
| AlienVault OTX | https://otx.alienvault.com/api |

---

## Extending

To add a new MCP server:

1. Copy an existing server as a template
2. Implement your API integration
3. Add `@server.tool()` decorated functions
4. Update this README with the new server

See the [MCP documentation](https://modelcontextprotocol.io/) for more details.
