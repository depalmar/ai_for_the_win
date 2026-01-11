# Curriculum Check

Comprehensive curriculum validation with optional web search for up-to-date content.

## Usage

```
/curriculum-check              # Run full curriculum validation
/curriculum-check quick        # Quick structural check only
/curriculum-check models       # Check if model references are current
/curriculum-check packages     # Check if package versions are current
/curriculum-check links        # Validate all internal links
```

## Instructions

When the user invokes this command:

### 1. Quick Check (default or "quick")

Run structural validation without web searches:

```bash
pytest tests/test_curriculum_integrity.py -v --tb=short
```

Report:
- Lab header/folder mismatches
- Broken internal references
- Missing README files
- CTF achievement counts

### 2. Model Version Check ("models")

**Use web search to verify model names are current:**

1. Search: "Anthropic Claude latest models [current year]"
2. Search: "OpenAI GPT latest models [current year]"
3. Search: "Google Gemini latest models [current year]"

Compare with model references in:
- `shared/llm_config.py`
- `docs/guides/llm-provider-comparison.md`
- Lab README files

Flag any outdated references:
- Old model names (e.g., claude-3 instead of claude-4)
- Deprecated models
- Missing newer model options

### 3. Package Version Check ("packages")

**Use web search to verify package versions:**

1. Search: "anthropic python package latest version pypi [current year]"
2. Search: "langchain latest version [current year]"
3. Search: "chromadb latest version [current year]"

Compare with version pins in:
- `requirements.txt`
- `docs/guides/dev-environment-setup.md`
- `docs/guides/quickstart-guide.md`

Flag packages more than 2 major versions behind.

### 4. Link Validation ("links")

Check all internal links:
- Lab cross-references (Next Lab, Prerequisites)
- Walkthrough references
- Notebook Colab links
- Guide cross-references

For each broken link, report:
- Source file and line number
- Broken reference
- Suggested fix (if determinable)

### 5. Full Check (no argument)

Run all checks in sequence:
1. Quick structural check
2. Model version check (with web search)
3. Package version check (with web search)
4. Link validation

## Output Format

```
## Curriculum Health Report

### Structure
- Labs: 51/51 with valid README
- Headers: 51/51 matching folder numbers
- CTF: 18 challenges, achievements aligned

### Models (Web Search: 2024-01-11)
- claude-sonnet-4-20250514: CURRENT
- gpt-4-turbo: UPDATE AVAILABLE (gpt-4o recommended)

### Packages (Web Search: 2024-01-11)
- anthropic>=0.40.0: CURRENT (latest: 0.42.0)
- langchain>=0.3.0: CURRENT (latest: 0.3.5)

### Links
- 0 broken internal references
- 0 broken Colab links

### Recommendations
1. Update OpenAI model reference to gpt-4o
2. Consider updating langchain to 0.3.5
```

## When to Run

Run this check:
- Before major releases
- Monthly for package/model updates
- After adding new labs
- When updating documentation

## Auto-Update Guidelines

When issues are found:

1. **Model Updates**: Update `shared/llm_config.py` with new model names
2. **Package Updates**: Update version pins in guides and requirements
3. **Broken Links**: Fix references in source files
4. **Run tests**: `pytest tests/test_curriculum_integrity.py -v`
5. **Commit**: Include "chore: curriculum update" in message

## Web Search Best Practices

For accurate results:
- Include current year in searches
- Use official sources (PyPI, Anthropic docs, OpenAI docs)
- Cross-reference multiple sources
- Note search date in reports
