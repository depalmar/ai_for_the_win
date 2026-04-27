# IOC Extractor

Extract Indicators of Compromise (IOCs) from logs, threat reports, emails, or any unstructured text.

## Usage

```
/ioc-extractor                    # Extract from clipboard / pasted text
/ioc-extractor <file>             # Extract from a file
/ioc-extractor <file> --defang    # Defang IOCs in output (e.g., 1.2.3[.]4)
/ioc-extractor <file> --type ip   # Limit to one type: ip, domain, url, hash, email
```

## Instructions

When the user invokes this command:

1. **Load IOC patterns** from `.claude/knowledge/ioc-patterns.md` to ensure correct regex (IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256, emails, CVEs, MITRE technique IDs).

2. **Read the input** (file path argument, or ask the user to paste content if none provided).

3. **Extract and de-duplicate** matches per category:
   - **IPs**: IPv4 + IPv6 (skip RFC1918 unless `--include-private` is set)
   - **Domains**: full FQDNs (skip whitelisted: microsoft.com, google.com, github.com, etc.)
   - **URLs**: http/https/ftp
   - **Hashes**: MD5 (32), SHA1 (40), SHA256 (64)
   - **Emails**
   - **CVEs**
   - **MITRE technique IDs** (T1234, T1234.001)

4. **Refang first** (convert `1.2.3[.]4` → `1.2.3.4`, `hxxp://` → `http://`) before matching, then optionally re-defang the output if `--defang`.

5. **Validate** each IOC:
   - Discard obvious false positives (version strings like `1.0.0.0`, internal RFC1918 IPs by default)
   - Validate hash hex-only and correct length

6. **Output** as a markdown table grouped by type, with a count summary. Offer to:
   - Save to `iocs.json` / `iocs.csv`
   - Pass to `/threat-intel` for enrichment
   - Generate a Sigma rule via `/sigma-create`

## Example Output

```
## Extracted IOCs (12 unique)

### IPs (3)
| IOC | Defanged | Source Line |
|-----|----------|-------------|
| 198.51.100.42 | 198.51.100[.]42 | line 14 |
| 203.0.113.7 | 203.0.113[.]7 | line 22 |

### Domains (2)
| IOC | Defanged |
|-----|----------|
| evil-c2.example | evil-c2[.]example |

### Hashes (5 SHA256, 2 MD5)
...
```

## Related

- Knowledge: `.claude/knowledge/ioc-patterns.md`
- Labs: lab16 (Threat Intel Agent), lab23 (Detection Pipeline)
- Shared utility: `shared/ioc_utils.py`
