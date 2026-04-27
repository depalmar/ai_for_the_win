# Timeline Visualizer

Generate visual timelines from security events, IR cases, or log data.

## Usage

```
/timeline-viz <events.json>                 # Auto-pick chart type
/timeline-viz <events.csv> --type swimlane  # Chart type: swimlane | gantt | scatter | heatmap
/timeline-viz <events.json> --group-by host.name
/timeline-viz <events.json> --output timeline.html
```

## Instructions

When the user invokes this command:

1. **Load events** from JSON / CSV / log file (route through `/log-parser` if not yet structured).

2. **Validate the schema** — at minimum each record needs:
   - `@timestamp` (ISO 8601, UTC)
   - `event.action` or `event.type`
   - At least one entity field (`host.name`, `user.name`, `source.ip`)

3. **Pick a sensible chart type** if not specified:
   - **Swimlane** — multi-entity activity over time (default for IR cases)
   - **Gantt** — phased adversary actions / kill-chain progression
   - **Scatter** — high-volume event density (anomaly spotting)
   - **Heatmap** — hour-of-day vs. day-of-week patterns

4. **Generate using Plotly** (per project tech stack — `docs/CLAUDE.md`). Output an interactive HTML file plus a static PNG for reports.

5. **Annotate key moments** automatically:
   - First/last event per entity
   - Severity spikes (if `event.severity` present)
   - MITRE tactic transitions (if tagged)
   - Gaps > 1h (potential dwell time)

6. **Output package**:
   - `timeline.html` (interactive, shareable)
   - `timeline.png` (for reports)
   - Markdown summary with: time range, entity count, event count, key annotations
   - Suggestion to feed into `/dfir-analyze` case report

## Style Guidelines

- Use a sequential colorscale for time, qualitative for categories
- Y-axis = entities (sorted by activity volume), X-axis = time
- Tooltip on each point: timestamp, action, source IP, user, full event JSON

## Related

- Pre-process logs: `/log-parser`
- Use in case work: `/dfir-analyze`
- Labs: lab12 (Anomaly Detection), lab27 (Forensics), lab29 (IR Copilot)
