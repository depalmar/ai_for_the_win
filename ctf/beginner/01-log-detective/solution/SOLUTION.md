# Solution: Log Detective

**Flag:** `FLAG{L0G_D3T3CT1V3}`

## Solution Steps

1. **Examine the log files** - Look for unusual patterns or anomalies

2. **Find the encoded data** - In `system.log`, line 14:
   ```
   2025-01-07 23:45:00 DEBUG internal_check: status=ok marker=RkxBR3tMMGdfRDNUM0NUMFY0fQ==
   ```

   The `marker` field contains a base64-encoded string.

3. **Decode the flag**:
   ```python
   import base64
   encoded = "RkxBR3tMMGdfRDNUM0NUMFY0fQ=="
   decoded = base64.b64decode(encoded).decode()
   print(decoded)  # FLAG{L0G_D3T3CT1V3}
   ```

## Alternative Discovery Paths

- Search for base64 patterns: strings ending in `=` or `==`
- Search for "FLAG" in all files (won't find it directly since it's encoded)
- Analyze the timeline and notice the DEBUG entry at the same time as suspicious activity

## Key Learning Points

1. **Attackers hide data in logs** - The "internal_check" entry was inserted by the attacker
2. **Base64 is common for obfuscation** - Easy to spot by the character set and padding
3. **Timeline correlation matters** - The encoded data appears right when suspicious activity occurs
4. **Check all log levels** - DEBUG entries often contain overlooked information

## Attack Timeline Summary

1. 09:00 - Initial brute force attempt from 10.0.0.99
2. 23:45 - Successful login with compromised service_account
3. 23:45 - Attacker left marker (flag) in DEBUG log
4. 23:45-23:46 - Download of malicious script and C2 connection attempt
