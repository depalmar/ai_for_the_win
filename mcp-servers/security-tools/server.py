#!/usr/bin/env python3
"""
MCP Server for Security Tools

Provides AI agents with access to security tools:
- VirusTotal: File/URL/IP analysis
- Shodan: Internet-connected device search
- MISP: Threat intelligence platform
- AbuseIPDB: IP reputation
- URLScan: URL analysis
"""

import os
import json
import hashlib
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
import httpx

# MCP SDK imports (when available)
try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    print("MCP SDK not installed. Install with: pip install mcp")


@dataclass
class SecurityToolConfig:
    """Configuration for security tool APIs."""
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    misp_url: str = ""
    misp_api_key: str = ""
    abuseipdb_api_key: str = ""
    urlscan_api_key: str = ""

    @classmethod
    def from_env(cls) -> "SecurityToolConfig":
        """Load configuration from environment variables."""
        return cls(
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
            shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
            misp_url=os.getenv("MISP_URL", ""),
            misp_api_key=os.getenv("MISP_API_KEY", ""),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            urlscan_api_key=os.getenv("URLSCAN_API_KEY", ""),
        )


class VirusTotalClient:
    """VirusTotal API client."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    async def analyze_hash(self, file_hash: str) -> Dict[str, Any]:
        """Analyze a file by hash (MD5, SHA1, or SHA256)."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=self.headers
            )

            if response.status_code == 200:
                data = response.json()["data"]
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                return {
                    "hash": file_hash,
                    "type": attrs.get("type_description", "Unknown"),
                    "size": attrs.get("size", 0),
                    "names": attrs.get("names", [])[:5],
                    "detection_stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "total": sum(stats.values())
                    },
                    "reputation": attrs.get("reputation", 0),
                    "tags": attrs.get("tags", []),
                    "first_seen": attrs.get("first_submission_date"),
                    "last_seen": attrs.get("last_analysis_date"),
                }
            elif response.status_code == 404:
                return {"hash": file_hash, "status": "not_found", "message": "Hash not found in VirusTotal"}
            else:
                return {"error": f"API error: {response.status_code}"}

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a URL."""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self.headers
            )

            if response.status_code == 200:
                data = response.json()["data"]
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                return {
                    "url": url,
                    "detection_stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0),
                    },
                    "categories": attrs.get("categories", {}),
                    "reputation": attrs.get("reputation", 0),
                    "last_analysis": attrs.get("last_analysis_date"),
                }
            else:
                return {"url": url, "status": "not_found"}

    async def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze an IP address."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self.headers
            )

            if response.status_code == 200:
                data = response.json()["data"]
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                return {
                    "ip": ip,
                    "country": attrs.get("country", "Unknown"),
                    "asn": attrs.get("asn", 0),
                    "as_owner": attrs.get("as_owner", "Unknown"),
                    "detection_stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0),
                    },
                    "reputation": attrs.get("reputation", 0),
                    "tags": attrs.get("tags", []),
                }
            else:
                return {"ip": ip, "status": "not_found"}

    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze a domain."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self.headers
            )

            if response.status_code == 200:
                data = response.json()["data"]
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                return {
                    "domain": domain,
                    "registrar": attrs.get("registrar", "Unknown"),
                    "creation_date": attrs.get("creation_date"),
                    "detection_stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0),
                    },
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                    "tags": attrs.get("tags", []),
                }
            else:
                return {"domain": domain, "status": "not_found"}


class ShodanClient:
    """Shodan API client."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up information about an IP address."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params={"key": self.api_key}
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "ip": ip,
                    "hostnames": data.get("hostnames", []),
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("asn", "Unknown"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                    "last_update": data.get("last_update"),
                    "services": [
                        {
                            "port": s.get("port"),
                            "transport": s.get("transport"),
                            "product": s.get("product", "Unknown"),
                            "version": s.get("version", ""),
                        }
                        for s in data.get("data", [])[:10]
                    ]
                }
            elif response.status_code == 404:
                return {"ip": ip, "status": "not_found", "message": "IP not found in Shodan"}
            else:
                return {"error": f"API error: {response.status_code}"}

    async def search(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search Shodan for devices matching the query."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/shodan/host/search",
                params={"key": self.api_key, "query": query}
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "query": query,
                    "total": data.get("total", 0),
                    "results": [
                        {
                            "ip": r.get("ip_str"),
                            "port": r.get("port"),
                            "org": r.get("org"),
                            "product": r.get("product"),
                            "country": r.get("location", {}).get("country_name"),
                        }
                        for r in data.get("matches", [])[:limit]
                    ]
                }
            else:
                return {"error": f"API error: {response.status_code}"}


class AbuseIPDBClient:
    """AbuseIPDB API client."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"Key": api_key, "Accept": "application/json"}

    async def check_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """Check an IP address for abuse reports."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/check",
                headers=self.headers,
                params={"ipAddress": ip, "maxAgeInDays": max_age_days}
            )

            if response.status_code == 200:
                data = response.json()["data"]
                return {
                    "ip": ip,
                    "is_public": data.get("isPublic", True),
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "country": data.get("countryCode", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", ""),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported": data.get("lastReportedAt"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "usage_type": data.get("usageType", "Unknown"),
                }
            else:
                return {"error": f"API error: {response.status_code}"}


class MISPClient:
    """MISP (Malware Information Sharing Platform) client."""

    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    async def search_ioc(self, value: str, ioc_type: str = None) -> Dict[str, Any]:
        """Search for an IOC in MISP."""
        async with httpx.AsyncClient(verify=False) as client:
            search_body = {"value": value}
            if ioc_type:
                search_body["type"] = ioc_type

            response = await client.post(
                f"{self.url}/attributes/restSearch",
                headers=self.headers,
                json=search_body
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("response", {}).get("Attribute", [])

                return {
                    "query": value,
                    "total_results": len(attributes),
                    "attributes": [
                        {
                            "type": a.get("type"),
                            "value": a.get("value"),
                            "category": a.get("category"),
                            "event_id": a.get("event_id"),
                            "timestamp": a.get("timestamp"),
                            "comment": a.get("comment", ""),
                        }
                        for a in attributes[:20]
                    ]
                }
            else:
                return {"error": f"API error: {response.status_code}"}

    async def get_event(self, event_id: str) -> Dict[str, Any]:
        """Get details of a MISP event."""
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{self.url}/events/view/{event_id}",
                headers=self.headers
            )

            if response.status_code == 200:
                event = response.json().get("Event", {})
                return {
                    "id": event.get("id"),
                    "info": event.get("info"),
                    "date": event.get("date"),
                    "threat_level": event.get("threat_level_id"),
                    "analysis": event.get("analysis"),
                    "org": event.get("Org", {}).get("name"),
                    "tags": [t.get("name") for t in event.get("Tag", [])],
                    "attribute_count": event.get("attribute_count", 0),
                }
            else:
                return {"error": f"API error: {response.status_code}"}


# =============================================================================
# MCP Server Definition
# =============================================================================

SECURITY_TOOLS = [
    {
        "name": "virustotal_hash",
        "description": "Analyze a file hash (MD5, SHA1, SHA256) using VirusTotal to check for malware detections",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "File hash (MD5, SHA1, or SHA256)"}
            },
            "required": ["hash"]
        }
    },
    {
        "name": "virustotal_url",
        "description": "Analyze a URL using VirusTotal to check if it's malicious",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to analyze"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "virustotal_ip",
        "description": "Analyze an IP address using VirusTotal for reputation and threat data",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to analyze"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "virustotal_domain",
        "description": "Analyze a domain using VirusTotal for reputation and threat data",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to analyze"}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "shodan_ip",
        "description": "Look up an IP address in Shodan for open ports, services, and vulnerabilities",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "shodan_search",
        "description": "Search Shodan for devices matching a query (e.g., 'apache', 'port:22')",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Shodan search query"},
                "limit": {"type": "integer", "description": "Max results to return", "default": 10}
            },
            "required": ["query"]
        }
    },
    {
        "name": "abuseipdb_check",
        "description": "Check an IP address for abuse reports using AbuseIPDB",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check"},
                "max_age_days": {"type": "integer", "description": "Max age of reports in days", "default": 90}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "misp_search",
        "description": "Search for an IOC in MISP threat intelligence platform",
        "inputSchema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "IOC value to search for"},
                "type": {"type": "string", "description": "IOC type (ip-dst, domain, md5, sha256, url)"}
            },
            "required": ["value"]
        }
    }
]


async def handle_tool_call(tool_name: str, arguments: Dict[str, Any], config: SecurityToolConfig) -> str:
    """Handle a tool call and return the result."""
    try:
        if tool_name == "virustotal_hash":
            client = VirusTotalClient(config.virustotal_api_key)
            result = await client.analyze_hash(arguments["hash"])

        elif tool_name == "virustotal_url":
            client = VirusTotalClient(config.virustotal_api_key)
            result = await client.analyze_url(arguments["url"])

        elif tool_name == "virustotal_ip":
            client = VirusTotalClient(config.virustotal_api_key)
            result = await client.analyze_ip(arguments["ip"])

        elif tool_name == "virustotal_domain":
            client = VirusTotalClient(config.virustotal_api_key)
            result = await client.analyze_domain(arguments["domain"])

        elif tool_name == "shodan_ip":
            client = ShodanClient(config.shodan_api_key)
            result = await client.lookup_ip(arguments["ip"])

        elif tool_name == "shodan_search":
            client = ShodanClient(config.shodan_api_key)
            result = await client.search(
                arguments["query"],
                arguments.get("limit", 10)
            )

        elif tool_name == "abuseipdb_check":
            client = AbuseIPDBClient(config.abuseipdb_api_key)
            result = await client.check_ip(
                arguments["ip"],
                arguments.get("max_age_days", 90)
            )

        elif tool_name == "misp_search":
            client = MISPClient(config.misp_url, config.misp_api_key)
            result = await client.search_ioc(
                arguments["value"],
                arguments.get("type")
            )

        else:
            result = {"error": f"Unknown tool: {tool_name}"}

        return json.dumps(result, indent=2, default=str)

    except Exception as e:
        return json.dumps({"error": str(e)})


# =============================================================================
# Standalone Demo (without MCP)
# =============================================================================

async def demo():
    """Demo the security tools (requires API keys)."""
    print("=" * 60)
    print("Security Tools MCP Server Demo")
    print("=" * 60)

    config = SecurityToolConfig.from_env()

    if not config.virustotal_api_key:
        print("\n[!] Set VIRUSTOTAL_API_KEY to test VirusTotal")
        print("[!] Set SHODAN_API_KEY to test Shodan")
        print("[!] Set ABUSEIPDB_API_KEY to test AbuseIPDB")
        print("\nExample usage with API keys:")
        print("  export VIRUSTOTAL_API_KEY=your_key_here")
        print("  python server.py")
        return

    # Demo VirusTotal hash lookup
    print("\n[1] VirusTotal Hash Lookup (EICAR test file):")
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = await handle_tool_call("virustotal_hash", {"hash": eicar_hash}, config)
    print(result)

    print("\n[+] Available tools:")
    for tool in SECURITY_TOOLS:
        print(f"  - {tool['name']}: {tool['description'][:60]}...")


if __name__ == "__main__":
    asyncio.run(demo())
