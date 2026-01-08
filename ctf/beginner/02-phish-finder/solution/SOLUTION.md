# Solution: Phish Finder

**Flag:** `FLAG{PH1SH_F0UND_1T}`

## Solution Steps

1. **Identify the phishing emails** - Look for indicators:
   - Spoofed/lookalike domains (c0mpany, cornpany, company-verify.net)
   - Urgent language
   - Suspicious links
   - Grammar issues
   - Requests for sensitive actions

2. **Phishing emails identified:**
   - Email #2: `admin@c0mpany-secure.com` (domain: c0mpany-secure.com)
   - Email #4: `helpdesk@cornpany.com` (domain: cornpany.com - 'rn' looks like 'm')
   - Email #6: `security@company-verify.net` (domain: company-verify.net)
   - Email #8: `ceo@c0mpany.biz` (domain: c0mpany.biz - classic CEO fraud)

3. **Extract subdomains from phishing URLs** (in timestamp order):
   - #2 (09:15): `https://flag.c0mpany-secure.com/...` → `flag`
   - #4 (11:45): `https://ph1sh.cornpany.com/...` → `ph1sh`
   - #6 (14:20): `https://f0und.company-verify.net/...` → `f0und`
   - #8 (16:30): `https://1t.c0mpany.biz/...` → `1t`

4. **Combine subdomains in order:**
   - flag + ph1sh + f0und + 1t = `FLAG{PH1SH_F0UND_1T}`

## Phishing Indicators Summary

| Email | Red Flags |
|-------|-----------|
| #2 | Lookalike domain (c0mpany), urgency, password reset |
| #4 | Lookalike domain (cornpany), urgency, account verification |
| #6 | External security domain, fear tactics, urgency |
| #8 | Lookalike domain, CEO fraud, confidentiality request, wire transfer |

## Key Learning Points

1. **Domain spoofing techniques:**
   - Character substitution (0 for o, 1 for l)
   - Visual confusion (rn vs m)
   - Similar-looking domains (.biz, -secure.com, -verify.net)

2. **Social engineering tactics:**
   - Urgency and time pressure
   - Fear (account compromise)
   - Authority (CEO impersonation)
   - Confidentiality requests

3. **URL analysis:**
   - Always check the actual domain, not just the display text
   - Subdomains can be used to hide malicious intent
   - Legitimate companies don't use lookalike domains
