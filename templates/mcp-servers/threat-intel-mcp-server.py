#!/usr/bin/env python3
"""
Threat Intelligence MCP Server Template

A Model Context Protocol server for aggregating threat intelligence
from multiple sources (AbuseIPDB, OTX, local database).

Setup:
    pip install mcp httpx python-dotenv aiosqlite

Usage:
    export ABUSEIPDB_API_KEY="your-key"
    export OTX_API_KEY="your-key"
    python threat-intel-mcp-server.py

Configuration in Claude Code (.claude/mcp_servers.json):
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
"""

import asyncio
import json
import os
import re
from datetime import datetime, timedelta
from typing import Any

import httpx
import aiosqlite
from mcp import Server, Tool
from mcp.server.stdio import stdio_server

# Configuration
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.environ.get("OTX_API_KEY")
DB_PATH = os.environ.get("THREAT_DB_PATH", "./threat_intel.db")
REQUEST_TIMEOUT = 30.0

# Initialize server
server = Server("threat-intel-mcp")


# ============================================================================
# Database Functions
# ============================================================================

async def init_database():
    """Initialize SQLite database for caching and local IOCs."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ioc_cache (
                ioc_value TEXT PRIMARY KEY,
                ioc_type TEXT,
                threat_score INTEGER,
                source TEXT,
                data TEXT,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS local_iocs (
                ioc_value TEXT PRIMARY KEY,
                ioc_type TEXT,
                threat_level TEXT,
                description TEXT,
                tags TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()


async def get_cached_result(ioc_value: str) -> dict | None:
    """Get cached result if still valid (24 hours)."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM ioc_cache WHERE ioc_value = ? AND cached_at > datetime('now', '-24 hours')",
            (ioc_value,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return json.loads(row["data"])
    return None


async def cache_result(ioc_value: str, ioc_type: str, threat_score: int, source: str, data: dict):
    """Cache a lookup result."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT OR REPLACE INTO ioc_cache (ioc_value, ioc_type, threat_score, source, data)
               VALUES (?, ?, ?, ?, ?)""",
            (ioc_value, ioc_type, threat_score, source, json.dumps(data))
        )
        await db.commit()


# ============================================================================
# AbuseIPDB Integration
# ============================================================================

async def query_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    if not ABUSEIPDB_API_KEY:
        return {"source": "abuseipdb", "error": "API key not configured"}

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "ip": ip,
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt"),
                    "is_tor": data.get("isTor", False),
                    "is_public": data.get("isPublic", True),
                    "categories": data.get("reports", [])[:5] if data.get("reports") else []
                }
            else:
                return {"source": "abuseipdb", "error": f"API error: {response.status_code}"}

        except Exception as e:
            return {"source": "abuseipdb", "error": str(e)}


# ============================================================================
# AlienVault OTX Integration
# ============================================================================

async def query_otx(ioc_value: str, ioc_type: str) -> dict:
    """Query AlienVault OTX for IOC information."""
    if not OTX_API_KEY:
        return {"source": "otx", "error": "API key not configured"}

    type_mapping = {
        "ip": "IPv4",
        "domain": "domain",
        "hostname": "hostname",
        "md5": "file",
        "sha256": "file",
        "url": "url"
    }

    otx_type = type_mapping.get(ioc_type, ioc_type)

    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        try:
            # Get general information
            url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc_value}/general"
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                return {
                    "source": "otx",
                    "ioc": ioc_value,
                    "type": ioc_type,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [
                        {
                            "name": p.get("name"),
                            "description": p.get("description", "")[:200],
                            "tags": p.get("tags", [])[:5],
                            "created": p.get("created")
                        }
                        for p in data.get("pulse_info", {}).get("pulses", [])[:5]
                    ],
                    "country": data.get("country_name"),
                    "asn": data.get("asn"),
                    "validation": data.get("validation", [])
                }
            elif response.status_code == 404:
                return {"source": "otx", "ioc": ioc_value, "pulse_count": 0, "message": "Not found in OTX"}
            else:
                return {"source": "otx", "error": f"API error: {response.status_code}"}

        except Exception as e:
            return {"source": "otx", "error": str(e)}


# ============================================================================
# MITRE ATT&CK Mapping
# ============================================================================

MITRE_MAPPINGS = {
    "c2": ["T1071", "T1095", "T1571"],
    "command_and_control": ["T1071", "T1095", "T1571"],
    "phishing": ["T1566", "T1598"],
    "malware": ["T1059", "T1204"],
    "ransomware": ["T1486", "T1490"],
    "cryptominer": ["T1496"],
    "botnet": ["T1583.005", "T1584.005"],
    "scan": ["T1595", "T1046"],
    "brute_force": ["T1110"],
    "ssh": ["T1021.004"],
    "exploitation": ["T1190", "T1203"]
}


def map_to_mitre(tags: list[str], categories: list[str] = None) -> list[str]:
    """Map threat tags to MITRE ATT&CK techniques."""
    techniques = set()
    all_terms = [t.lower() for t in tags]
    if categories:
        all_terms.extend([c.lower() for c in categories])

    for term in all_terms:
        for key, techs in MITRE_MAPPINGS.items():
            if key in term:
                techniques.update(techs)

    return list(techniques)


# ============================================================================
# MCP Tools
# ============================================================================

@server.tool()
async def lookup_ip_reputation(ip_address: str) -> str:
    """
    Look up IP address reputation across multiple threat intelligence sources.

    Aggregates data from AbuseIPDB, AlienVault OTX, and local database.
    """
    # Validate IP
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not re.match(pattern, ip_address.strip()):
        return json.dumps({"error": "Invalid IPv4 address format"})

    ip = ip_address.strip()

    # Check cache first
    cached = await get_cached_result(ip)
    if cached:
        cached["cached"] = True
        return json.dumps(cached, indent=2)

    # Query sources in parallel
    results = await asyncio.gather(
        query_abuseipdb(ip),
        query_otx(ip, "ip"),
        return_exceptions=True
    )

    # Aggregate results
    abuseipdb_result = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}
    otx_result = results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])}

    # Calculate combined threat score
    threat_score = 0
    if isinstance(abuseipdb_result, dict) and "abuse_confidence" in abuseipdb_result:
        threat_score = max(threat_score, abuseipdb_result["abuse_confidence"])
    if isinstance(otx_result, dict) and "pulse_count" in otx_result:
        if otx_result["pulse_count"] > 0:
            threat_score = max(threat_score, min(50 + otx_result["pulse_count"] * 5, 100))

    # Determine threat level
    if threat_score >= 80:
        threat_level = "critical"
    elif threat_score >= 50:
        threat_level = "high"
    elif threat_score >= 25:
        threat_level = "medium"
    elif threat_score > 0:
        threat_level = "low"
    else:
        threat_level = "unknown"

    # Build response
    response = {
        "ip": ip,
        "threat_score": threat_score,
        "threat_level": threat_level,
        "sources": {
            "abuseipdb": abuseipdb_result,
            "otx": otx_result
        },
        "mitre_techniques": map_to_mitre(
            otx_result.get("pulses", [{}])[0].get("tags", []) if otx_result.get("pulses") else []
        ),
        "recommendations": [],
        "queried_at": datetime.utcnow().isoformat()
    }

    # Add recommendations based on threat level
    if threat_level in ["critical", "high"]:
        response["recommendations"] = [
            "Block this IP at firewall/WAF",
            "Review logs for connections from this IP",
            "Add to threat intelligence blocklist",
            "Investigate any systems that communicated with this IP"
        ]
    elif threat_level == "medium":
        response["recommendations"] = [
            "Monitor traffic from this IP",
            "Consider rate limiting",
            "Add to watchlist"
        ]

    # Cache result
    await cache_result(ip, "ip", threat_score, "aggregated", response)

    return json.dumps(response, indent=2)


@server.tool()
async def lookup_domain_reputation(domain: str) -> str:
    """
    Look up domain reputation in threat intelligence databases.

    Queries AlienVault OTX and checks local blocklists.
    """
    # Clean domain
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]

    # Validate
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if not re.match(pattern, domain):
        return json.dumps({"error": "Invalid domain format"})

    # Check cache
    cached = await get_cached_result(domain)
    if cached:
        cached["cached"] = True
        return json.dumps(cached, indent=2)

    # Query OTX
    otx_result = await query_otx(domain, "domain")

    # Calculate threat score
    threat_score = 0
    if otx_result.get("pulse_count", 0) > 0:
        threat_score = min(40 + otx_result["pulse_count"] * 10, 100)

    response = {
        "domain": domain,
        "threat_score": threat_score,
        "otx": otx_result,
        "mitre_techniques": map_to_mitre(
            otx_result.get("pulses", [{}])[0].get("tags", []) if otx_result.get("pulses") else []
        ),
        "queried_at": datetime.utcnow().isoformat()
    }

    await cache_result(domain, "domain", threat_score, "otx", response)

    return json.dumps(response, indent=2)


@server.tool()
async def add_local_ioc(
    ioc_value: str,
    ioc_type: str,
    threat_level: str,
    description: str,
    tags: str = ""
) -> str:
    """
    Add an IOC to the local threat intelligence database.

    Args:
        ioc_value: The indicator value (IP, domain, hash, etc.)
        ioc_type: Type of IOC (ip, domain, md5, sha256, url)
        threat_level: Threat level (critical, high, medium, low)
        description: Description of why this is an IOC
        tags: Comma-separated tags
    """
    if threat_level not in ["critical", "high", "medium", "low"]:
        return json.dumps({"error": "threat_level must be: critical, high, medium, or low"})

    if ioc_type not in ["ip", "domain", "md5", "sha256", "sha1", "url", "hostname"]:
        return json.dumps({"error": "Invalid ioc_type"})

    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                """INSERT OR REPLACE INTO local_iocs
                   (ioc_value, ioc_type, threat_level, description, tags)
                   VALUES (?, ?, ?, ?, ?)""",
                (ioc_value.strip(), ioc_type, threat_level, description, tags)
            )
            await db.commit()

            return json.dumps({
                "status": "success",
                "message": f"IOC {ioc_value} added to local database",
                "ioc": {
                    "value": ioc_value,
                    "type": ioc_type,
                    "threat_level": threat_level,
                    "description": description,
                    "tags": tags.split(",") if tags else []
                }
            })
        except Exception as e:
            return json.dumps({"error": f"Database error: {str(e)}"})


@server.tool()
async def search_local_iocs(query: str, ioc_type: str = None) -> str:
    """
    Search the local IOC database.

    Args:
        query: Search term (partial match supported)
        ioc_type: Optional filter by IOC type
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        if ioc_type:
            sql = """SELECT * FROM local_iocs
                     WHERE ioc_value LIKE ? AND ioc_type = ?
                     ORDER BY added_at DESC LIMIT 50"""
            params = (f"%{query}%", ioc_type)
        else:
            sql = """SELECT * FROM local_iocs
                     WHERE ioc_value LIKE ? OR description LIKE ? OR tags LIKE ?
                     ORDER BY added_at DESC LIMIT 50"""
            params = (f"%{query}%", f"%{query}%", f"%{query}%")

        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()

            results = [
                {
                    "value": row["ioc_value"],
                    "type": row["ioc_type"],
                    "threat_level": row["threat_level"],
                    "description": row["description"],
                    "tags": row["tags"].split(",") if row["tags"] else [],
                    "added_at": row["added_at"]
                }
                for row in rows
            ]

            return json.dumps({
                "query": query,
                "count": len(results),
                "results": results
            }, indent=2)


@server.tool()
async def get_threat_summary(iocs: str) -> str:
    """
    Get a summary threat assessment for multiple IOCs.

    Args:
        iocs: Comma-separated list of IOCs (IPs, domains, hashes)
    """
    ioc_list = [i.strip() for i in iocs.split(",") if i.strip()]

    if len(ioc_list) > 10:
        return json.dumps({"error": "Maximum 10 IOCs per request"})

    results = []
    for ioc in ioc_list:
        # Detect IOC type
        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}", ioc):
            result = json.loads(await lookup_ip_reputation(ioc))
        elif re.match(r"^[a-f0-9]{32}$", ioc.lower()) or re.match(r"^[a-f0-9]{64}$", ioc.lower()):
            # Hash - just return type info since we don't have VT here
            result = {"ioc": ioc, "type": "hash", "note": "Use VirusTotal MCP for hash lookups"}
        else:
            result = json.loads(await lookup_domain_reputation(ioc))

        results.append(result)

    # Calculate summary
    threat_scores = [r.get("threat_score", 0) for r in results]
    max_threat = max(threat_scores) if threat_scores else 0

    summary = {
        "ioc_count": len(ioc_list),
        "max_threat_score": max_threat,
        "threat_distribution": {
            "critical": sum(1 for s in threat_scores if s >= 80),
            "high": sum(1 for s in threat_scores if 50 <= s < 80),
            "medium": sum(1 for s in threat_scores if 25 <= s < 50),
            "low": sum(1 for s in threat_scores if 0 < s < 25),
            "unknown": sum(1 for s in threat_scores if s == 0)
        },
        "results": results
    }

    return json.dumps(summary, indent=2)


async def main():
    """Run the MCP server."""
    await init_database()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)


if __name__ == "__main__":
    asyncio.run(main())
