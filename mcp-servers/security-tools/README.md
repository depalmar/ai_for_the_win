# Security Tools MCP Server

Model Context Protocol (MCP) server providing AI agents with access to security tools and threat intelligence APIs.

## Features

| Tool | API | Description |
|------|-----|-------------|
| `virustotal_hash` | VirusTotal | Analyze file hashes for malware |
| `virustotal_url` | VirusTotal | Check URLs for malicious content |
| `virustotal_ip` | VirusTotal | IP reputation and threat data |
| `virustotal_domain` | VirusTotal | Domain analysis and categorization |
| `shodan_ip` | Shodan | Open ports, services, vulnerabilities |
| `shodan_search` | Shodan | Search internet-connected devices |
| `abuseipdb_check` | AbuseIPDB | IP abuse reports and reputation |
| `misp_search` | MISP | Threat intelligence IOC lookup |

## Setup

### 1. Install Dependencies

```bash
pip install httpx mcp
```

### 2. Configure API Keys

```bash
export VIRUSTOTAL_API_KEY="your_vt_key"
export SHODAN_API_KEY="your_shodan_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export MISP_URL="https://your-misp-instance"
export MISP_API_KEY="your_misp_key"
```

### 3. Add to Claude Code

Add to your `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-tools": {
      "command": "python",
      "args": ["/path/to/mcp-servers/security-tools/server.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_key",
        "SHODAN_API_KEY": "your_key"
      }
    }
  }
}
```

## Usage Examples

### Analyze a File Hash

```
Analyze this hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

Claude will use `virustotal_hash` to check the file against 70+ antivirus engines.

### Check IP Reputation

```
Is this IP malicious? 185.220.101.1
```

Claude will check VirusTotal, Shodan, and AbuseIPDB for threat intelligence.

### Search for Vulnerable Devices

```
Find devices running Apache 2.4.49 (CVE-2021-41773)
```

Claude will use Shodan to search for potentially vulnerable systems.

## API Response Examples

### VirusTotal Hash Response

```json
{
  "hash": "275a021...",
  "type": "EICAR test file",
  "detection_stats": {
    "malicious": 62,
    "suspicious": 0,
    "undetected": 10,
    "total": 72
  },
  "reputation": -100,
  "tags": ["eicar", "test-file"]
}
```

### Shodan IP Response

```json
{
  "ip": "8.8.8.8",
  "hostnames": ["dns.google"],
  "country": "United States",
  "org": "Google LLC",
  "ports": [53, 443],
  "services": [
    {"port": 53, "product": "Google DNS"},
    {"port": 443, "product": "nginx"}
  ]
}
```

## Security Considerations

- Store API keys securely (environment variables, secrets manager)
- Rate limit API calls to avoid quota exhaustion
- Cache responses where appropriate
- Validate inputs before API calls
- Handle errors gracefully

## Free API Tiers

| Service | Free Tier |
|---------|-----------|
| VirusTotal | 4 requests/min, 500/day |
| Shodan | 1 credit for IP lookup |
| AbuseIPDB | 1,000 checks/day |
| MISP | Depends on instance |
