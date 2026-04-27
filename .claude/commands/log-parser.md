# Log Parser

Parse, normalize, and structure common security log formats into JSON for downstream analysis.

## Usage

```
/log-parser <file>                       # Auto-detect format
/log-parser <file> --format syslog       # Force a format
/log-parser <file> --output parsed.json  # Save normalized output
/log-parser <file> --extract-iocs        # Pipe results into /ioc-extractor
```

## Instructions

When the user invokes this command:

1. **Load format reference** from `.claude/knowledge/log-formats.md` for field mappings.

2. **Auto-detect format** if not specified, by sampling the first 20 lines:
   - **Syslog** (RFC 5424 / 3164)
   - **CEF** (`CEF:0|...`)
   - **LEEF** (`LEEF:1.0|...`)
   - **JSON** (one object per line)
   - **Windows Event** (XML or evtx-export JSON)
   - **Apache/Nginx access** (combined / common)
   - **AWS CloudTrail** (JSON records)
   - **Sysmon** (XML or normalized JSON)
   - **Zeek/Bro** (TSV)
   - **Suricata EVE** (JSON)

3. **Normalize to ECS** (Elastic Common Schema) field names where possible, so output is portable across backends:
   - `@timestamp` (ISO 8601 UTC)
   - `event.action`, `event.category`, `event.outcome`
   - `source.ip`, `source.port`, `destination.ip`, `destination.port`
   - `user.name`, `host.name`
   - `process.name`, `process.command_line`, `process.pid`

4. **Output** structured records (one JSON object per event) plus a summary table:
   - Total events
   - Time range
   - Distinct hosts / users / source IPs
   - Top 10 event actions

5. **Offer follow-ups**:
   - `/ioc-extractor` on the parsed values
   - `/timeline-viz` to chart events over time
   - `/sigma-create --from-log` to draft a detection
   - `/threat-hunt` to build a hunting query for any anomaly

## Error Handling

- Skip malformed lines but report count + line numbers in summary
- For unknown formats, offer the user a regex template to map fields manually
- Never silently drop fields — unknown fields go under `_unmapped.<original_name>`

## Related

- Knowledge: `.claude/knowledge/log-formats.md`
- Labs: lab15 (LLM Log Analysis), lab23 (Detection Pipeline), lab27 (Forensics)
