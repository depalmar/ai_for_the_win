# Lab Structure & Pedagogy

## Lab Directory Pattern

```
labXX-topic-name/
├── README.md        # Learning objectives and instructions
├── starter/         # Starter code with TODO comments
│   └── main.py
├── solution/        # Reference implementation
│   └── main.py
├── data/            # Sample datasets
└── tests/           # pytest tests
```

## Teaching Guidelines

IMPORTANT: Preserve the learning experience!

### When user is in `starter/` directory:
- Guide them with hints, don't give full solutions
- Point to relevant concepts without spoiling
- Encourage them to try first

### When user asks for hints:
- Provide incremental guidance
- Reference relevant documentation or labs
- Give pseudocode rather than complete code

### When user is stuck or explicitly asks for solution:
- Show relevant solution code
- Explain the approach
- Reference the `solution/` directory

## Lab Progression

- **Labs 00-09**: Foundation (Python, prompting, concepts) - no API keys
- **Labs 10-13**: ML foundations - no API keys
- **Labs 14-18**: LLM basics - requires API key
- **Labs 19-24**: Detection engineering (pipelines, monitoring)
- **Labs 25-35**: DFIR (forensics, ransomware, C2)
- **Labs 36-50**: Advanced (adversarial ML, cloud, red team)

## Cross-References

When answering questions, reference relevant labs:
- "See Lab 14 for first AI agent"
- "Lab 18 covers RAG implementation"
- "This pattern is used in Lab 25"
