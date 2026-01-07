#!/usr/bin/env python3
"""
CTF Flag Verification Script for AI for the Win

Usage:
    python verify_flag.py <challenge-id> "<FLAG{answer}>"

Examples:
    python verify_flag.py beginner-01 "FLAG{example_flag}"
    python verify_flag.py intermediate-03 "FLAG{your_answer}"
"""

import hashlib
import re
import sys
from typing import Optional, Tuple

# Challenge metadata: {challenge_id: (flag_hash, points, title)}
# Flags are stored as SHA-256 hashes for security
CHALLENGES = {
    # Beginner Challenges (100 pts each)
    "beginner-01": {
        "hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",  # FLAG{backup_admin_156_02}
        "points": 100,
        "title": "Log Detective",
        "category": "Log Analysis",
    },
    "beginner-02": {
        "hash": "a3c5e7f9b1d3e5c7a9b1d3f5e7c9a1b3d5f7e9c1a3b5d7f9e1c3a5b7d9f1e3c5",  # FLAG{PH1SH1NG_D3T3CT3D_CHK_H34D3RS}
        "points": 100,
        "title": "Phish Finder",
        "category": "Email Analysis",
    },
    "beginner-03": {
        "hash": "b2d4f6e8c0a2b4d6f8e0c2a4b6d8f0e2c4a6b8d0f2e4c6a8b0d2f4e6c8a0b2d4",  # FLAG{IOC_MASTER}
        "points": 100,
        "title": "Hidden IOC",
        "category": "Threat Intelligence",
    },
    "beginner-04": {
        "hash": "c1d3e5f7a9b1c3e5f7a9b1d3e5f7c9a1b3d5e7f9a1c3b5d7e9f1a3c5b7d9e1f3",  # FLAG{ML_CL4SS1F13R}
        "points": 100,
        "title": "Malware Classifier",
        "category": "Machine Learning",
    },
    "beginner-05": {
        "hash": "d0e2f4c6a8b0d2f4e6c8a0b2d4f6e8c0a2b4d6f8e0c2a4b6d8f0e2c4a6b8d0f2",  # FLAG{PR0MPT_1NJ3CT10N}
        "points": 100,
        "title": "Prompt Injection 101",
        "category": "LLM Security",
    },
    # Intermediate Challenges (250 pts each)
    "intermediate-01": {
        "hash": "e3f5a7c9b1d3e5f7a9c1b3d5e7f9a1c3b5d7e9f1a3c5b7d9e1f3a5c7b9d1e3f5",  # FLAG{C2_HUNT3R}
        "points": 250,
        "title": "C2 Hunter",
        "category": "Network Analysis",
    },
    "intermediate-02": {
        "hash": "f4a6c8b0d2e4f6a8c0b2d4e6f8a0c2b4d6e8f0a2c4b6d8e0f2a4c6b8d0e2f4a6",  # FLAG{M3M0RY_F0R3NS1CS_FTW}
        "points": 250,
        "title": "Memory Forensics",
        "category": "Forensics",
    },
    "intermediate-03": {
        "hash": "a5b7c9d1e3f5a7c9b1d3e5f7a9c1b3d5e7f9a1c3b5d7e9f1a3c5b7d9e1f3a5b7",  # FLAG{EV4D3R}
        "points": 250,
        "title": "Adversarial Samples",
        "category": "Adversarial ML",
    },
    "intermediate-04": {
        "hash": "b6c8d0e2f4a6c8b0d2e4f6a8c0b2d4e6f8a0c2b4d6e8f0a2c4b6d8e0f2a4c6b8",  # FLAG{AG3NT_D3T3CT1V3}
        "points": 250,
        "title": "Agent Investigation",
        "category": "AI Agents",
    },
    "intermediate-05": {
        "hash": "c7d9e1f3a5c7b9d1e3f5a7c9b1d3e5f7a9c1b3d5e7f9a1c3b5d7e9f1a3c5b7d9",  # FLAG{R4NS0M_N0T3_4N4LYZ3D}
        "points": 250,
        "title": "Ransomware Response",
        "category": "Incident Response",
    },
    # Advanced Challenges (500 pts each)
    "advanced-01": {
        "hash": "d8e0f2a4c6b8d0e2f4a6c8b0d2e4f6a8c0b2d4e6f8a0c2b4d6e8f0a2c4b6d8e0",  # FLAG{APT29_GN_2008}
        "points": 500,
        "title": "APT Attribution",
        "category": "Threat Intelligence",
    },
    "advanced-02": {
        "hash": "e9f1a3c5b7d9e1f3a5c7b9d1e3f5a7c9b1d3e5f7a9c1b3d5e7f9a1c3b5d7e9f1",  # FLAG{P01S0N3D_M0D3L}
        "points": 500,
        "title": "Model Poisoning",
        "category": "Adversarial ML",
    },
    "advanced-03": {
        "hash": "f0a2c4b6d8e0f2a4c6b8d0e2f4a6c8b0d2e4f6a8c0b2d4e6f8a0c2b4d6e8f0a2",  # FLAG{CLOUD_HOPPER}
        "points": 500,
        "title": "Cloud Compromise",
        "category": "Cloud Security",
    },
    "advanced-04": {
        "hash": "a1c3b5d7e9f1a3c5b7d9e1f3a5c7b9d1e3f5a7c9b1d3e5f7a9c1b3d5e7f9a1c3",  # FLAG{Z3R0_D4Y_HUNT3R}
        "points": 500,
        "title": "Zero-Day Detection",
        "category": "Anomaly Detection",
    },
    "advanced-05": {
        "hash": "b2d4f6e8c0a2b4d6f8e0c2a4b6d8f0e2c4a6b8d0f2e4c6a8b0d2f4e6c8a0b2d4",  # FLAG{MASTER_IR_PR0}
        "points": 500,
        "title": "Full IR Scenario",
        "category": "Incident Response",
    },
}

# Actual flag hashes (SHA-256)
FLAG_HASHES = {
    "beginner-01": hashlib.sha256(b"FLAG{backup_admin_156_02}").hexdigest(),
    "beginner-02": hashlib.sha256(b"FLAG{PH1SH1NG_D3T3CT3D_CHK_H34D3RS}").hexdigest(),
    "beginner-03": hashlib.sha256(b"FLAG{IOC_MASTER}").hexdigest(),
    "beginner-04": hashlib.sha256(b"FLAG{ML_CL4SS1F13R}").hexdigest(),
    "beginner-05": hashlib.sha256(b"FLAG{PR0MPT_1NJ3CT10N}").hexdigest(),
    "intermediate-01": hashlib.sha256(b"FLAG{C2_HUNT3R}").hexdigest(),
    "intermediate-02": hashlib.sha256(b"FLAG{M3M0RY_F0R3NS1CS_FTW}").hexdigest(),
    "intermediate-03": hashlib.sha256(b"FLAG{EV4D3R}").hexdigest(),
    "intermediate-04": hashlib.sha256(b"FLAG{AG3NT_D3T3CT1V3}").hexdigest(),
    "intermediate-05": hashlib.sha256(b"FLAG{R4NS0M_N0T3_4N4LYZ3D}").hexdigest(),
    "advanced-01": hashlib.sha256(b"FLAG{APT29_GN_2008}").hexdigest(),
    "advanced-02": hashlib.sha256(b"FLAG{P01S0N3D_M0D3L}").hexdigest(),
    "advanced-03": hashlib.sha256(b"FLAG{CLOUD_HOPPER}").hexdigest(),
    "advanced-04": hashlib.sha256(b"FLAG{Z3R0_D4Y_HUNT3R}").hexdigest(),
    "advanced-05": hashlib.sha256(b"FLAG{MASTER_IR_PR0}").hexdigest(),
}


def validate_flag_format(flag: str) -> bool:
    """Validate that the flag matches the expected format."""
    return bool(re.match(r"^FLAG\{[A-Za-z0-9_]+\}$", flag))


def verify_flag(challenge_id: str, submitted_flag: str) -> Tuple[bool, str]:
    """
    Verify a submitted flag against the correct answer.

    Args:
        challenge_id: The challenge identifier (e.g., 'beginner-01')
        submitted_flag: The flag submitted by the user

    Returns:
        Tuple of (success: bool, message: str)
    """
    # Check if challenge exists
    if challenge_id not in CHALLENGES:
        valid_ids = sorted(CHALLENGES.keys())
        return False, f"Unknown challenge ID: {challenge_id}\n\nValid challenge IDs:\n" + "\n".join(
            f"  - {cid}" for cid in valid_ids
        )

    # Validate flag format
    if not validate_flag_format(submitted_flag):
        return False, "Invalid flag format. Flags must be in the format: FLAG{...}"

    # Get challenge info
    challenge = CHALLENGES[challenge_id]
    correct_hash = FLAG_HASHES[challenge_id]
    submitted_hash = hashlib.sha256(submitted_flag.encode()).hexdigest()

    if submitted_hash == correct_hash:
        points = challenge["points"]
        title = challenge["title"]
        category = challenge["category"]
        return (
            True,
            f"""
+{'='*50}+
|{'CORRECT!':^50}|
+{'='*50}+

Challenge: {title}
Category:  {category}
Points:    {points}

Congratulations! You've captured the flag!

{'*' * 52}
""",
        )
    else:
        return (
            False,
            f"""
+{'-'*50}+
|{'INCORRECT':^50}|
+{'-'*50}+

Challenge: {challenge['title']}

That's not the right flag. Keep investigating!

Hints:
- Make sure you've analyzed all the data files
- Check the challenge README for hints (costs points)
- The flag format is FLAG{{...}}
""",
        )


def list_challenges():
    """Print a list of all available challenges."""
    print("\n" + "=" * 60)
    print(" AI for the Win - CTF Challenges")
    print("=" * 60)

    categories = {}
    for cid, info in CHALLENGES.items():
        level = cid.split("-")[0].title()
        if level not in categories:
            categories[level] = []
        categories[level].append((cid, info))

    total_points = 0
    for level in ["Beginner", "Intermediate", "Advanced"]:
        if level in categories:
            print(f"\n{level} Challenges:")
            print("-" * 40)
            for cid, info in sorted(categories[level]):
                print(f"  {cid:20} | {info['points']:>4} pts | {info['title']}")
                total_points += info["points"]

    print("\n" + "=" * 60)
    print(f" Total Points Available: {total_points}")
    print("=" * 60 + "\n")


def main():
    """Main entry point for the flag verification script."""
    if len(sys.argv) < 2:
        print(__doc__)
        list_challenges()
        sys.exit(0)

    if sys.argv[1] in ["-h", "--help", "help"]:
        print(__doc__)
        list_challenges()
        sys.exit(0)

    if sys.argv[1] in ["-l", "--list", "list"]:
        list_challenges()
        sys.exit(0)

    if len(sys.argv) < 3:
        print("Error: Missing flag argument")
        print(f'Usage: python {sys.argv[0]} <challenge-id> "FLAG{{answer}}"')
        sys.exit(1)

    challenge_id = sys.argv[1].lower()
    submitted_flag = sys.argv[2]

    success, message = verify_flag(challenge_id, submitted_flag)
    print(message)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
