# Security Project .cursorrules Template

Copy this file to your project root as `.cursorrules` and customize for your needs.

---

```markdown
# Security Tool Development Rules

## Project Context
This is a security analysis toolkit for [threat detection/incident response/malware analysis/etc.].
Primary focus: [describe your project's main security function]

## Technology Stack
- Python 3.11+
- LLM Framework: [LangChain/Google ADK/CrewAI]
- Vector DB: [ChromaDB/Pinecone/etc.]
- APIs: [VirusTotal/MISP/Shodan/etc.]

## Code Style Requirements
- Use Python 3.10+ with full type hints (PEP 484)
- Follow PEP 8 style guidelines
- Follow PEP 257 docstring conventions
- Use async/await for all I/O operations
- Implement comprehensive error handling with custom exceptions
- Use Pydantic models for data validation
- Prefer composition over inheritance

## Security Requirements (CRITICAL)

### Data Handling
- NEVER log sensitive data (passwords, API keys, PII, credentials, tokens)
- NEVER store secrets in code - use environment variables or secret managers
- NEVER commit .env files, credentials, or API keys
- ALWAYS sanitize log output before writing
- ALWAYS encrypt sensitive data at rest

### Input Validation
- ALWAYS validate and sanitize ALL external inputs
- ALWAYS use parameterized queries for databases (no string formatting)
- ALWAYS escape output in web contexts (XSS prevention)
- ALWAYS validate file paths to prevent path traversal
- NEVER trust user-provided file names or paths

### Command Execution
- NEVER use shell=True with subprocess when user input is involved
- ALWAYS use shlex.quote() for shell arguments if shell is required
- PREFER subprocess with argument lists over shell commands
- VALIDATE all command arguments before execution

### Network Security
- NEVER disable SSL certificate verification in production
- ALWAYS use HTTPS for external API calls
- ALWAYS implement rate limiting on API endpoints
- ALWAYS set reasonable timeouts on network requests
- USE connection pooling for repeated requests

### Authentication & Authorization
- ALWAYS check authentication before authorization
- IMPLEMENT proper session management
- USE secure password hashing (bcrypt, argon2)
- NEVER store plaintext passwords
- IMPLEMENT account lockout after failed attempts

## Malware Analysis Guidelines
When analyzing potentially malicious code:
1. Explain what the code does in detail
2. Identify malicious capabilities and techniques
3. Map findings to MITRE ATT&CK framework
4. Extract all IOCs (indicators of compromise)
5. Provide detection recommendations
6. NEVER enhance, improve, or weaponize malicious functionality
7. ALWAYS defang URLs, IPs, and domains in output

## Preferred Libraries

### Core
- pydantic: Data validation and settings management
- httpx: Async HTTP client (preferred over requests)
- loguru: Logging with automatic PII filtering
- tenacity: Retry logic with exponential backoff

### LLM/AI
- langchain / langchain-anthropic: LLM operations
- chromadb: Vector storage for RAG
- tiktoken: Token counting

### Security
- yara-python: Pattern matching for malware detection
- pefile: PE file analysis
- volatility3: Memory forensics
- python-magic: File type detection
- hashlib: Cryptographic hashing

### Testing
- pytest: Test framework
- pytest-asyncio: Async test support
- pytest-cov: Coverage reporting
- responses / respx: HTTP mocking

## Output Formatting Standards

### Security References
- Include MITRE ATT&CK IDs: T1059.001, T1055, etc.
- Reference CVE IDs for vulnerabilities: CVE-2024-1234
- Use CWE classifications for code weaknesses: CWE-89
- Link to relevant documentation when applicable

### IOC Formatting
- Defang URLs: hxxp:// or hxxps://
- Defang domains: example[.]com
- Defang IPs: 192[.]168[.]1[.]1
- Include hash type: MD5, SHA1, SHA256
- Use consistent JSON schema for IOC output

## File Organization
```
project/
├── src/
│   ├── agents/         # LLM-powered agents
│   ├── analyzers/      # Analysis modules
│   ├── detectors/      # Detection logic
│   ├── integrations/   # External API clients
│   ├── models/         # Pydantic models
│   ├── parsers/        # Log and file parsers
│   └── utils/          # Shared utilities
├── tests/
│   ├── unit/           # Unit tests
│   ├── integration/    # Integration tests
│   └── fixtures/       # Test data
├── rules/
│   ├── yara/           # YARA rules
│   └── sigma/          # Sigma rules
├── config/
│   └── settings.py     # Configuration
└── docs/
    └── security.md     # Security documentation
```

## Testing Requirements
- Unit tests for all public functions
- Integration tests for external APIs (mocked)
- Security-focused test cases:
  - SQL injection attempts
  - Command injection attempts
  - Path traversal attacks
  - Invalid/malformed inputs
  - Authentication bypass attempts
- Minimum 80% code coverage
- All tests must pass before commit

## Documentation Requirements
- README with setup instructions
- API documentation for all public interfaces
- Security considerations documented
- MITRE ATT&CK coverage documented
- Example usage for all major features

## Error Handling
- Use custom exception hierarchy
- Never expose internal errors to users
- Log full error details internally
- Return sanitized error messages externally
- Include correlation IDs for debugging

## Performance Guidelines
- Use async/await for I/O-bound operations
- Implement caching for expensive operations
- Use connection pooling for database/API clients
- Set appropriate timeouts on all external calls
- Profile before optimizing
```

---

## Customization Tips

1. **Adjust for your tech stack**: Update the preferred libraries section
2. **Add project-specific rules**: Include any unique requirements
3. **Define output formats**: Specify exact JSON schemas if needed
4. **Include team conventions**: Add code review requirements, PR templates
5. **Reference internal docs**: Link to your security policies
