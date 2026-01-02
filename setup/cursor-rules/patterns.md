# Preferred Code Patterns

## Pydantic for Data Models

```python
from pydantic import BaseModel, Field

class ThreatIndicator(BaseModel):
    """Structured threat indicator."""
    
    indicator_type: str = Field(..., description="Type: ip, domain, hash, url")
    value: str = Field(..., description="The indicator value (defanged)")
    confidence: float = Field(ge=0, le=1, description="Confidence score 0-1")
    mitre_techniques: list[str] = Field(default_factory=list)
```

## LangChain Agent Pattern

```python
from langchain.agents import create_react_agent
from langchain_anthropic import ChatAnthropic

def create_security_agent(tools: list) -> AgentExecutor:
    """Create a security-focused ReAct agent."""
    llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
    # ... setup with proper error handling
```

## Async for I/O Operations

Use async for API calls, file reads, network operations:

```python
async def enrich_ioc(ioc: str) -> EnrichmentResult:
    """Enrich an IOC with threat intelligence."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{API_URL}/lookup", params={"ioc": ioc})
        return EnrichmentResult(**response.json())
```

## ChromaDB for RAG

```python
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)
vectorstore = Chroma(
    collection_name="security_docs",
    embedding_function=embeddings,
    persist_directory="./chroma_db",
)
```

## Structured Output with Instructor

```python
import instructor
from pydantic import BaseModel

class ThreatAnalysis(BaseModel):
    threat_type: str
    confidence: float
    mitre_techniques: list[str]

client = instructor.from_anthropic(Anthropic())
result = client.chat.completions.create(
    model="claude-sonnet-4-20250514",
    response_model=ThreatAnalysis,
    messages=[{"role": "user", "content": f"Analyze: {data}"}],
)
```

## Error Handling

Always handle errors gracefully:

```python
try:
    result = await analyze_sample(data)
except ValidationError as e:
    logger.error(f"Invalid input: {e}")
    raise
except APIError as e:
    logger.warning(f"API unavailable: {e}, using cached data")
    result = get_cached_result(data)
```
