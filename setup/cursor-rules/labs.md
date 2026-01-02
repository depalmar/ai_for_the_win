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

- **Labs 00a-00c**: Intro (Python, ML concepts, prompting) - no API keys
- **Labs 01-03**: ML foundations - no API keys
- **Labs 04-07**: LLM basics - requires API key
- **Labs 08-10**: Advanced (agents, pipelines, copilots)
- **Labs 11-20**: Expert (DFIR, forensics, adversarial ML)

## Cross-References

When answering questions, reference relevant labs:
- "See Lab 04 for LLM prompting basics"
- "Lab 06 covers RAG implementation"
- "This pattern is used in Lab 11"
