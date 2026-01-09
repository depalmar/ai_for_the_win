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

| Range | Category | API Required |
|-------|----------|--------------|
| 00-09 | Foundation & Setup | No |
| 10-13 | ML Foundations | No |
| 14-21 | LLM Basics & Detection | Yes |
| 22-29 | Advanced Pipelines | Yes |
| 30-50 | Expert DFIR, Cloud, Red Team | Yes |

## Cross-References

When answering questions, reference relevant labs:
- "See Lab 02 for prompt engineering basics"
- "Lab 18 covers RAG implementation"
- "This pattern is used in Lab 31"
