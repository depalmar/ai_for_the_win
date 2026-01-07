# Challenge 06: Linux Persistence Hunter

**Category:** Linux DFIR
**Points:** 100
**Difficulty:** Beginner

## Description

A Linux web server was compromised. The attacker established persistence to maintain access after reboots. The incident response team has collected key system artifacts.

Your mission: Analyze the Linux persistence mechanisms to find evidence of the attacker's backdoor and extract the flag.

## Objective

1. Analyze crontab entries for suspicious scheduled tasks
2. Examine systemd service files for malicious services
3. Check SSH authorized_keys for unauthorized access
4. Identify the persistence mechanism and find the flag

## Files

- `crontabs.json` - Collected crontab entries from all users
- `systemd_services.json` - Custom systemd service files
- `ssh_keys.json` - SSH authorized_keys entries
- `bash_profiles.json` - User bash profile/rc files

## Background

Linux persistence mechanisms include:
- **Cron jobs**: Scheduled tasks that run periodically
- **Systemd services**: Services that start on boot
- **SSH keys**: Authorized keys for passwordless access
- **Shell profiles**: Scripts that run on user login

Attackers often hide in plain sight by using legitimate-looking names.

## Rules

- Analyze all provided artifacts
- The flag format is `FLAG{...}`
- AI can help identify anomalies in Linux configurations

## Hints

<details>
<summary>Hint 1 (costs 10 pts)</summary>

One of the cron jobs runs a script from an unusual location - /dev/shm is a red flag.

</details>

<details>
<summary>Hint 2 (costs 20 pts)</summary>

Check the systemd service descriptions - attackers sometimes hide messages there.

</details>

<details>
<summary>Hint 3 (costs 30 pts)</summary>

The flag is embedded in a systemd service file's description field.

</details>

## Skills Tested

- Linux system administration
- Persistence mechanism identification
- Configuration file analysis
- AI-assisted anomaly detection

## Submission

```bash
python ../../../scripts/verify_flag.py beginner-06 "FLAG{your_answer}"
```

Hunt down that backdoor! 🐧
