# AI Security Training - Quick Reference

> **Where to start?** See the [README](../README.md#-pick-your-starting-point) for 3 simple entry points.

---

## ML vs LLM: When to Use Which

| Security Task | Best Approach | Why |
|--------------|---------------|-----|
| **Malware classification** | ML | Fast, interpretable, structured features |
| **Phishing detection** | ML + LLM hybrid | ML for volume, LLM for sophisticated cases |
| **Log anomaly detection** | ML | High volume, real-time |
| **Threat report analysis** | LLM | Natural language understanding |
| **IOC extraction** | LLM | Flexible parsing |
| **YARA/Sigma rules** | LLM | Code generation |
| **Network intrusion** | ML | Speed, numerical features |
| **Incident summarization** | LLM | Language generation |

### Quick Decision

```
Structured data (logs, flows, metrics) → Use ML (Labs 01-03)
Unstructured text (reports, emails)   → Use LLM (Labs 04-07)
Both / need reasoning                 → Use Hybrid or Agents (Lab 23, 05)
```

### Cost Comparison

| Factor | ML | LLM |
|--------|-----|-----|
| Per-prediction cost | ~$0.000001 | ~$0.001-0.01 |
| 1M predictions | ~$1 | ~$1,000-10,000 |
| Latency | 1-10ms | 100-2000ms |

---

## Lab Quick Reference

Each lab tells you what's next. Just follow the path:

- **Labs 01-03**: ML fundamentals (no API key needed)
- **Labs 04-07**: LLM basics (needs API key)
- **Labs 08-10**: Pipelines and automation
- **Labs 11+**: DFIR and advanced topics

---

## Getting Help

1. **Stuck?** Check [walkthroughs](./walkthroughs/) or the solution file
2. **API errors?** Verify your `.env` file
3. **Questions?** Open a GitHub Discussion
