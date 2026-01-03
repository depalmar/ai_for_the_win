#!/usr/bin/env python3
"""
CTF Data Generator

Generates realistic CTF challenge data based on threat actor TTP profiles.
Uses the threat-actor-ttps database to create authentic attack scenarios.

Usage:
    python generate_ctf_data.py --actor apt29 --scenario c2_beacon --output challenge_data.json
    python generate_ctf_data.py --list-actors
    python generate_ctf_data.py --list-scenarios
"""

import argparse
import json
import random
import hashlib
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional


# Path to TTP database
TTP_DATABASE = Path(__file__).parent.parent / "data" / "threat-actor-ttps"


def load_actor(actor_id: str) -> Dict[str, Any]:
    """Load a threat actor profile from the TTP database."""
    actor_file = TTP_DATABASE / "actors" / f"{actor_id}.json"
    if not actor_file.exists():
        raise ValueError(f"Actor '{actor_id}' not found. Use --list-actors to see available actors.")
    
    with open(actor_file, 'r') as f:
        return json.load(f)


def load_campaign(campaign_id: str) -> Dict[str, Any]:
    """Load a campaign profile from the TTP database."""
    campaign_file = TTP_DATABASE / "campaigns" / f"{campaign_id}.json"
    if not campaign_file.exists():
        raise ValueError(f"Campaign '{campaign_id}' not found.")
    
    with open(campaign_file, 'r') as f:
        return json.load(f)


def load_attack_chain(chain_id: str) -> Dict[str, Any]:
    """Load an attack chain template from the TTP database."""
    chain_file = TTP_DATABASE / "attack-chains" / f"{chain_id}.json"
    if not chain_file.exists():
        raise ValueError(f"Attack chain '{chain_id}' not found.")
    
    with open(chain_file, 'r') as f:
        return json.load(f)


def list_available_actors() -> List[str]:
    """List all available threat actors in the TTP database."""
    actors_dir = TTP_DATABASE / "actors"
    if not actors_dir.exists():
        return []
    return [f.stem for f in actors_dir.glob("*.json")]


def list_available_campaigns() -> List[str]:
    """List all available campaigns in the TTP database."""
    campaigns_dir = TTP_DATABASE / "campaigns"
    if not campaigns_dir.exists():
        return []
    return [f.stem for f in campaigns_dir.glob("*.json")]


def list_available_attack_chains() -> List[str]:
    """List all available attack chains in the TTP database."""
    chains_dir = TTP_DATABASE / "attack-chains"
    if not chains_dir.exists():
        return []
    return [f.stem for f in chains_dir.glob("*.json")]


def generate_random_ip(internal: bool = False) -> str:
    """Generate a random IP address."""
    if internal:
        return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    else:
        # Avoid reserved ranges
        first_octet = random.choice([45, 91, 185, 193, 203, 212])
        return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_random_hash(hash_type: str = "sha256") -> str:
    """Generate a random hash value."""
    random_bytes = random.randbytes(32)
    if hash_type == "sha256":
        return hashlib.sha256(random_bytes).hexdigest()
    elif hash_type == "md5":
        return hashlib.md5(random_bytes).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(random_bytes).hexdigest()
    return hashlib.sha256(random_bytes).hexdigest()


def generate_timestamp(base_time: datetime = None, offset_minutes: int = 0) -> str:
    """Generate an ISO format timestamp."""
    if base_time is None:
        base_time = datetime.now()
    actual_time = base_time + timedelta(minutes=offset_minutes)
    return actual_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_beacon_traffic(
    actor: Dict[str, Any],
    num_beacons: int = 50,
    beacon_interval: int = 60,
    jitter_percent: float = 0.1,
    flag: str = None
) -> Dict[str, Any]:
    """
    Generate C2 beacon traffic based on threat actor profile.
    
    Args:
        actor: Threat actor profile
        num_beacons: Number of beacon connections to generate
        beacon_interval: Base interval between beacons in seconds
        jitter_percent: Randomness in beacon timing (0.0-1.0)
        flag: Optional flag to embed in the data
    
    Returns:
        Dictionary containing beacon traffic and DNS queries
    """
    c2_ip = generate_random_ip(internal=False)
    victim_ip = generate_random_ip(internal=True)
    base_time = datetime(2024, 3, 15, 8, 0, 0)
    
    connections = []
    dns_queries = []
    current_offset = 0
    
    # Get C2 patterns from actor profile
    c2_patterns = actor.get("infrastructure", {}).get("c2_patterns", ["HTTPS beaconing"])
    
    for i in range(num_beacons):
        # Add jitter to beacon interval
        jitter = random.uniform(-jitter_percent, jitter_percent)
        actual_interval = int(beacon_interval * (1 + jitter))
        current_offset += actual_interval
        
        # Generate beacon connection
        connections.append({
            "src_ip": victim_ip,
            "dst_ip": c2_ip,
            "dst_port": 443,
            "timestamp": int(base_time.timestamp()) + current_offset,
            "protocol": "TCP",
            "bytes_sent": random.randint(500, 600),
            "bytes_recv": random.randint(1000, 1100)
        })
        
        # Add some legitimate traffic to create noise
        if random.random() < 0.3:
            legitimate_ips = ["8.8.8.8", "142.250.185.206", "151.101.1.140", "104.18.32.68"]
            connections.append({
                "src_ip": victim_ip,
                "dst_ip": random.choice(legitimate_ips),
                "dst_port": random.choice([53, 443, 80]),
                "timestamp": int(base_time.timestamp()) + current_offset + random.randint(5, 30),
                "protocol": random.choice(["TCP", "UDP"]),
                "bytes_sent": random.randint(100, 5000),
                "bytes_recv": random.randint(500, 20000)
            })
    
    # Generate DNS queries including tunneling attempts
    tunnel_domain = "data-sync.evil-tunnel.net"
    legitimate_domains = [
        "www.google.com", "mail.google.com", "github.com", "api.github.com",
        "www.microsoft.com", "login.microsoftonline.com", "outlook.office365.com",
        "slack.com", "zoom.us", "dropbox.com"
    ]
    
    # Embed flag in DNS queries if provided
    if flag:
        # Split flag into base64-encoded parts for DNS subdomains
        flag_parts = [
            base64.b64encode(flag[i:i+10].encode()).decode()
            for i in range(0, len(flag), 10)
        ]
    else:
        flag_parts = []
    
    dns_offset = 0
    for i in range(num_beacons):
        dns_offset += random.randint(30, 120)
        
        # Add legitimate DNS queries
        dns_queries.append({
            "timestamp": generate_timestamp(base_time, dns_offset // 60),
            "query": random.choice(legitimate_domains),
            "type": "A",
            "response": generate_random_ip()
        })
        
        # Add tunneling DNS queries (suspicious)
        if random.random() < 0.4:
            if flag_parts and len(dns_queries) // 3 < len(flag_parts):
                subdomain = flag_parts[len(dns_queries) // 3]
            else:
                subdomain = base64.b64encode(random.randbytes(16)).decode().rstrip('=')
            
            dns_queries.append({
                "timestamp": generate_timestamp(base_time, dns_offset // 60 + 1),
                "query": f"{subdomain}.{tunnel_domain}",
                "type": random.choice(["TXT", "A"]),
                "response": "TXT 'ok'" if random.random() < 0.5 else "127.0.0.1"
            })
    
    return {
        "connections": sorted(connections, key=lambda x: x["timestamp"]),
        "dns": dns_queries,
        "metadata": {
            "actor": actor.get("name", "Unknown"),
            "c2_ip": c2_ip,
            "victim_ip": victim_ip,
            "beacon_interval_seconds": beacon_interval,
            "jitter_percent": jitter_percent,
            "tunnel_domain": tunnel_domain
        }
    }


def generate_auth_logs(
    actor: Dict[str, Any],
    num_events: int = 100,
    include_brute_force: bool = True,
    flag: str = None
) -> Dict[str, Any]:
    """
    Generate authentication logs with attack patterns.
    
    Args:
        actor: Threat actor profile
        num_events: Total number of events to generate
        include_brute_force: Whether to include a brute force attack
        flag: Optional flag to embed
    
    Returns:
        Dictionary containing auth log events
    """
    base_time = datetime(2024, 3, 15, 0, 0, 0)
    events = []
    
    # Legitimate users
    legitimate_users = [
        "alice.johnson", "bob.smith", "charlie.davis", "diana.wilson",
        "eve.martin", "frank.brown", "grace.lee", "henry.kim"
    ]
    
    # Attack usernames from actor TTPs
    attack_usernames = [
        "admin", "administrator", "root", "guest", "test", "user",
        "webadmin", "sysadmin", "support", "backup", "oracle", "mysql",
        "postgres", "ftpuser", "www-data", "apache", "nginx"
    ]
    
    attacker_ip = generate_random_ip(internal=False)
    compromised_user = "backup_admin"
    
    # Generate legitimate activity throughout the day
    for i in range(num_events - 30):  # Reserve space for attack
        offset_minutes = random.randint(0, 1440)  # Spread across 24 hours
        user = random.choice(legitimate_users)
        internal_ip = generate_random_ip(internal=True)
        
        event_type = random.choice(["login_success", "login_success", "login_success", "logout"])
        
        event = {
            "timestamp": generate_timestamp(base_time, offset_minutes),
            "event": event_type,
            "username": user,
            "source_ip": internal_ip,
            "method": random.choice(["password", "ssh_key", "mfa"])
        }
        
        if event_type == "login_success":
            event["session_id"] = f"sess_{generate_random_hash('md5')[:8]}"
        
        events.append(event)
    
    # Generate brute force attack
    if include_brute_force:
        attack_start = 120  # 2:00 AM
        
        # Failed login attempts
        for i, username in enumerate(attack_usernames):
            events.append({
                "timestamp": generate_timestamp(base_time, attack_start + (i * 2 / 60)),
                "event": "login_failure",
                "username": username,
                "source_ip": attacker_ip,
                "method": "password",
                "reason": "invalid_password" if username in ["admin", "root", "backup"] else "invalid_user"
            })
        
        # Multiple attempts on discovered valid account
        for i in range(3):
            events.append({
                "timestamp": generate_timestamp(base_time, attack_start + 0.9 + (i * 2 / 60)),
                "event": "login_failure",
                "username": compromised_user,
                "source_ip": attacker_ip,
                "method": "password",
                "reason": "invalid_password"
            })
        
        # Successful compromise
        session_id = "sess_mal1c10us"
        events.append({
            "timestamp": generate_timestamp(base_time, attack_start + 1),
            "event": "login_success",
            "username": compromised_user,
            "source_ip": attacker_ip,
            "method": "password",
            "session_id": session_id
        })
        
        # Post-exploitation commands
        post_exploit_commands = [
            "whoami", "cat /etc/passwd", "cat /etc/shadow",
            "netstat -tulpn", "ps aux"
        ]
        
        for i, cmd in enumerate(post_exploit_commands):
            events.append({
                "timestamp": generate_timestamp(base_time, attack_start + 1.2 + (i * 0.3)),
                "event": "command_executed",
                "username": compromised_user,
                "source_ip": attacker_ip,
                "command": cmd,
                "session_id": session_id
            })
        
        # File access
        events.append({
            "timestamp": generate_timestamp(base_time, attack_start + 2),
            "event": "file_access",
            "username": compromised_user,
            "source_ip": attacker_ip,
            "file": "/home/admin/.ssh/id_rsa",
            "action": "read",
            "session_id": session_id
        })
    
    # Sort events by timestamp
    events.sort(key=lambda x: x["timestamp"])
    
    return {
        "events": events,
        "metadata": {
            "source": "auth.log",
            "collection_period": f"{base_time.date()} 00:00:00 to 23:59:59",
            "timezone": "UTC"
        },
        "analysis_hints": {
            "attacker_ip": attacker_ip,
            "attack_type": "brute_force",
            "compromised_user": compromised_user,
            "flag_hint": flag if flag else "FLAG{IP_last_octet + attack_hour + compromised_username}"
        }
    }


def generate_malware_samples(
    actor: Dict[str, Any],
    num_samples: int = 10,
    malicious_ratio: float = 0.5
) -> List[Dict[str, Any]]:
    """
    Generate malware sample metadata based on threat actor malware families.
    
    Args:
        actor: Threat actor profile
        num_samples: Number of samples to generate
        malicious_ratio: Ratio of malicious samples (0.0-1.0)
    
    Returns:
        List of malware sample metadata
    """
    malware_families = actor.get("malware_families", ["Unknown"])
    samples = []
    
    # Benign filenames
    benign_names = [
        "notepad.exe", "calc.exe", "chrome.exe", "firefox.exe",
        "python.exe", "vscode.exe", "explorer.exe", "svchost.exe"
    ]
    
    # Malicious filenames
    malicious_names = [
        "invoice_doc.exe", "update_installer.exe", "flashplayer_update.exe",
        "driver_update.exe", "document_viewer.exe", "system_helper.exe"
    ]
    
    for i in range(num_samples):
        is_malicious = random.random() < malicious_ratio
        
        if is_malicious:
            sample = {
                "sha256": generate_random_hash("sha256"),
                "filename": random.choice(malicious_names),
                "family": random.choice(malware_families),
                "entropy": round(random.uniform(7.5, 7.99), 2),
                "file_size": random.randint(200000, 600000),
                "section_count": random.randint(5, 8),
                "import_count": random.randint(100, 250),
                "export_count": random.randint(0, 5),
                "suspicious_imports": random.sample([
                    "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
                    "NtCreateThreadEx", "RtlCreateUserThread", "VirtualAllocEx",
                    "HttpOpenRequest", "InternetReadFile", "CryptEncrypt"
                ], k=random.randint(2, 5)),
                "packer_detected": random.choice([None, "UPX", "Themida", "VMProtect", "MPRESS"]),
                "compile_timestamp": generate_timestamp(datetime(2024, random.randint(1, 12), random.randint(1, 28))),
                "strings_count": random.randint(50, 200),
                "suspicious_strings": random.sample([
                    "http://", "cmd.exe", "powershell", "beacon", "sleep",
                    "jitter", "HKEY_", "RegSetValueEx", "schtasks"
                ], k=random.randint(2, 4)),
                "label": "malicious"
            }
        else:
            sample = {
                "sha256": generate_random_hash("sha256"),
                "filename": random.choice(benign_names),
                "family": None,
                "entropy": round(random.uniform(4.5, 6.5), 2),
                "file_size": random.randint(20000, 2500000),
                "section_count": random.randint(3, 5),
                "import_count": random.randint(20, 150),
                "export_count": random.randint(0, 20),
                "suspicious_imports": [],
                "packer_detected": None,
                "compile_timestamp": generate_timestamp(datetime(2023, random.randint(1, 12), random.randint(1, 28))),
                "strings_count": random.randint(500, 5000),
                "suspicious_strings": [],
                "label": "benign"
            }
        
        samples.append(sample)
    
    return samples


def generate_incident_timeline(
    actor: Dict[str, Any],
    attack_chain: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate a full incident timeline based on actor TTPs and attack chain.
    
    Args:
        actor: Threat actor profile
        attack_chain: Attack chain template
    
    Returns:
        Dictionary containing incident timeline
    """
    base_time = datetime(2024, 1, 14, 9, 0, 0)
    events = []
    
    # Get phases from attack chain
    phases = attack_chain.get("phases", [])
    
    current_offset = 0
    for phase in phases:
        phase_name = phase.get("name", "Unknown Phase")
        techniques = phase.get("techniques", [])
        
        # Generate events for this phase
        for i, technique in enumerate(techniques[:3]):  # Limit to 3 techniques per phase
            tech_id = technique.get("id", "T0000")
            tech_name = technique.get("name", "Unknown Technique")
            
            events.append({
                "time": generate_timestamp(base_time, current_offset),
                "phase": phase_name,
                "technique_id": tech_id,
                "technique_name": tech_name,
                "event": f"{tech_name} observed",
                "host": f"HOST-{random.randint(1, 10):02d}",
                "user": random.choice(["SYSTEM", "admin", "user1", "svc_account"]),
                "details": f"MITRE ATT&CK: {tech_id}"
            })
            
            current_offset += random.randint(30, 180)  # 30 min to 3 hours between events
    
    return {
        "incident_id": f"INC-{datetime.now().year}-{random.randint(1000, 9999)}",
        "threat_actor": actor.get("name", "Unknown"),
        "events": events,
        "techniques_observed": [t.get("id") for phase in phases for t in phase.get("techniques", [])[:3]]
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate CTF challenge data from threat actor TTPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # List available threat actors
    python generate_ctf_data.py --list-actors
    
    # Generate C2 beacon traffic for APT29
    python generate_ctf_data.py --actor apt29 --scenario beacon --output c2_traffic.json
    
    # Generate auth logs with brute force attack
    python generate_ctf_data.py --actor apt28 --scenario auth_logs --output auth_logs.json
    
    # Generate malware samples metadata
    python generate_ctf_data.py --actor lazarus --scenario malware --output samples.json
        """
    )
    
    parser.add_argument("--list-actors", action="store_true", help="List available threat actors")
    parser.add_argument("--list-campaigns", action="store_true", help="List available campaigns")
    parser.add_argument("--list-scenarios", action="store_true", help="List available scenarios")
    parser.add_argument("--actor", type=str, help="Threat actor ID (e.g., apt29, lazarus)")
    parser.add_argument("--scenario", type=str, choices=["beacon", "auth_logs", "malware", "incident"],
                        help="Scenario type to generate")
    parser.add_argument("--output", type=str, help="Output file path")
    parser.add_argument("--flag", type=str, help="Flag to embed in the data")
    parser.add_argument("--num-events", type=int, default=100, help="Number of events to generate")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    
    args = parser.parse_args()
    
    # Handle list commands
    if args.list_actors:
        print("Available Threat Actors:")
        print("-" * 40)
        for actor in list_available_actors():
            profile = load_actor(actor)
            print(f"  {actor}: {profile.get('name', 'Unknown')} ({profile.get('country', 'Unknown')})")
        return
    
    if args.list_campaigns:
        print("Available Campaigns:")
        print("-" * 40)
        for campaign in list_available_campaigns():
            print(f"  {campaign}")
        return
    
    if args.list_scenarios:
        print("Available Scenarios:")
        print("-" * 40)
        print("  beacon      - C2 beacon traffic with DNS tunneling")
        print("  auth_logs   - Authentication logs with brute force attack")
        print("  malware     - Malware sample metadata")
        print("  incident    - Full incident timeline")
        return
    
    # Validate required arguments
    if not args.actor or not args.scenario:
        parser.error("--actor and --scenario are required for data generation")
    
    # Load actor profile
    try:
        actor = load_actor(args.actor)
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    print(f"Generating {args.scenario} data for {actor.get('name', args.actor)}...")
    
    # Generate data based on scenario
    if args.scenario == "beacon":
        data = generate_beacon_traffic(actor, num_beacons=args.num_events, flag=args.flag)
    elif args.scenario == "auth_logs":
        data = generate_auth_logs(actor, num_events=args.num_events, flag=args.flag)
    elif args.scenario == "malware":
        data = generate_malware_samples(actor, num_samples=args.num_events)
    elif args.scenario == "incident":
        attack_chain = load_attack_chain("double_extortion")
        data = generate_incident_timeline(actor, attack_chain)
    else:
        print(f"Error: Unknown scenario '{args.scenario}'")
        return
    
    # Output data
    indent = 2 if args.pretty else None
    json_output = json.dumps(data, indent=indent, default=str)
    
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(json_output)
        print(f"Data written to {output_path}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
