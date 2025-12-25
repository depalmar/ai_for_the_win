#!/usr/bin/env python3
"""
VirusTotal MCP Server Template

A Model Context Protocol server for integrating VirusTotal
with Claude Code, Cursor, or other MCP-compatible tools.

Setup:
    pip install mcp httpx python-dotenv

Usage:
    # Set environment variable
    export VT_API_KEY="your-api-key"

    # Run server
    python virustotal-mcp-server.py

Configuration in Claude Code (.claude/mcp_servers.json):
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
"""

import asyncio
import json
import os
import re
from datetime import datetime
from typing import Any

import httpx
from mcp import Server, Tool
from mcp.server.stdio import stdio_server

# Configuration
VT_API_KEY = os.environ.get("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 30.0

# Initialize server
server = Server("virustotal-mcp")


def validate_hash(hash_value: str) -> tuple[bool, str]:
    """Validate hash format and return type."""
    hash_value = hash_value.strip().lower()

    if re.match(r"^[a-f0-9]{32}$", hash_value):
        return True, "md5"
    elif re.match(r"^[a-f0-9]{40}$", hash_value):
        return True, "sha1"
    elif re.match(r"^[a-f0-9]{64}$", hash_value):
        return True, "sha256"
    else:
        return False, "unknown"


def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(pattern, ip.strip()))


def validate_domain(domain: str) -> bool:
    """Validate domain format."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain.strip()))


async def make_vt_request(endpoint: str, method: str = "GET", data: dict = None) -> dict:
    """Make authenticated request to VirusTotal API."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY environment variable not set"}

    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        try:
            if method == "GET":
                response = await client.get(f"{VT_BASE_URL}{endpoint}", headers=headers)
            elif method == "POST":
                response = await client.post(f"{VT_BASE_URL}{endpoint}", headers=headers, data=data)
            else:
                return {"error": f"Unsupported method: {method}"}

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "Not found in VirusTotal database"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded. Please wait and try again."}
            elif response.status_code == 401:
                return {"error": "Invalid API key"}
            else:
                return {"error": f"API error: {response.status_code}"}

        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": f"Request failed: {str(e)}"}


@server.tool()
async def lookup_hash(file_hash: str) -> str:
    """
    Look up a file hash (MD5, SHA1, or SHA256) in VirusTotal.

    Returns detection statistics, file metadata, and threat classification.
    """
    # Validate hash
    is_valid, hash_type = validate_hash(file_hash)
    if not is_valid:
        return json.dumps(
            {
                "error": "Invalid hash format. Provide MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars)."
            }
        )

    # Make API request
    result = await make_vt_request(f"/files/{file_hash.strip().lower()}")

    if "error" in result:
        return json.dumps(result)

    # Parse response
    try:
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        response = {
            "hash": file_hash,
            "hash_type": hash_type,
            "detection": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
            },
            "file_info": {
                "type": attrs.get("type_description", "Unknown"),
                "size": attrs.get("size", 0),
                "names": attrs.get("names", [])[:5],  # First 5 names
                "first_seen": attrs.get("first_submission_date"),
                "last_seen": attrs.get("last_analysis_date"),
            },
            "threat_classification": {
                "category": attrs.get("popular_threat_classification", {}).get(
                    "suggested_threat_label"
                ),
                "family": attrs.get("popular_threat_classification", {}).get(
                    "popular_threat_name", []
                ),
            },
            "tags": attrs.get("tags", [])[:10],
            "vt_link": f"https://www.virustotal.com/gui/file/{file_hash}",
        }

        return json.dumps(response, indent=2, default=str)

    except Exception as e:
        return json.dumps({"error": f"Failed to parse response: {str(e)}"})


@server.tool()
async def lookup_ip(ip_address: str) -> str:
    """
    Look up an IP address in VirusTotal.

    Returns reputation data, associated URLs, and detection statistics.
    """
    if not validate_ip(ip_address):
        return json.dumps({"error": "Invalid IPv4 address format"})

    result = await make_vt_request(f"/ip_addresses/{ip_address.strip()}")

    if "error" in result:
        return json.dumps(result)

    try:
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        response = {
            "ip": ip_address,
            "detection": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
            },
            "network_info": {
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "asn": attrs.get("asn"),
                "network": attrs.get("network"),
            },
            "reputation": attrs.get("reputation", 0),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "tags": attrs.get("tags", []),
            "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip_address}",
        }

        return json.dumps(response, indent=2, default=str)

    except Exception as e:
        return json.dumps({"error": f"Failed to parse response: {str(e)}"})


@server.tool()
async def lookup_domain(domain: str) -> str:
    """
    Look up a domain in VirusTotal.

    Returns reputation data, DNS records, and detection statistics.
    """
    domain = domain.strip().lower()

    # Remove protocol if present
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]  # Remove path

    if not validate_domain(domain):
        return json.dumps({"error": "Invalid domain format"})

    result = await make_vt_request(f"/domains/{domain}")

    if "error" in result:
        return json.dumps(result)

    try:
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        response = {
            "domain": domain,
            "detection": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
            },
            "categories": attrs.get("categories", {}),
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "last_dns_records": attrs.get("last_dns_records", [])[:5],
            "tags": attrs.get("tags", []),
            "vt_link": f"https://www.virustotal.com/gui/domain/{domain}",
        }

        return json.dumps(response, indent=2, default=str)

    except Exception as e:
        return json.dumps({"error": f"Failed to parse response: {str(e)}"})


@server.tool()
async def lookup_url(url: str) -> str:
    """
    Look up a URL in VirusTotal.

    Returns scan results and threat information.
    """
    import base64

    # Encode URL for API
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    result = await make_vt_request(f"/urls/{url_id}")

    if "error" in result:
        # URL might not be in database, try to get basic info
        return json.dumps(
            {
                "url": url,
                "status": "not_found",
                "message": "URL not found in VirusTotal database. Consider submitting for scanning.",
            }
        )

    try:
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        response = {
            "url": url,
            "detection": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
            },
            "final_url": attrs.get("last_final_url"),
            "title": attrs.get("title"),
            "categories": attrs.get("categories", {}),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "threat_names": attrs.get("threat_names", []),
            "tags": attrs.get("tags", []),
        }

        return json.dumps(response, indent=2, default=str)

    except Exception as e:
        return json.dumps({"error": f"Failed to parse response: {str(e)}"})


@server.tool()
async def get_file_behavior(file_hash: str) -> str:
    """
    Get behavioral analysis results for a file.

    Returns sandbox execution details, network activity, and process information.
    """
    is_valid, _ = validate_hash(file_hash)
    if not is_valid:
        return json.dumps({"error": "Invalid hash format"})

    result = await make_vt_request(f"/files/{file_hash.strip().lower()}/behaviours")

    if "error" in result:
        return json.dumps(result)

    try:
        behaviors = []
        for item in result.get("data", [])[:3]:  # Limit to 3 sandbox results
            attrs = item.get("attributes", {})
            behaviors.append(
                {
                    "sandbox": attrs.get("sandbox_name"),
                    "processes_created": attrs.get("processes_created", [])[:5],
                    "files_written": attrs.get("files_written", [])[:5],
                    "registry_keys_set": attrs.get("registry_keys_set", [])[:5],
                    "dns_lookups": attrs.get("dns_lookups", [])[:5],
                    "ip_traffic": attrs.get("ip_traffic", [])[:5],
                    "http_conversations": attrs.get("http_conversations", [])[:3],
                    "mitre_attack_techniques": attrs.get("mitre_attack_techniques", []),
                }
            )

        return json.dumps({"hash": file_hash, "behaviors": behaviors}, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Failed to parse response: {str(e)}"})


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)


if __name__ == "__main__":
    asyncio.run(main())
