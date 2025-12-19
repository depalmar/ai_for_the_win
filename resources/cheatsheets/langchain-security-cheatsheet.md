# LangChain Security Cheat Sheet

Quick reference for building security tools with LangChain.

---

## Setup

```bash
pip install langchain langchain-anthropic chromadb
```

```python
from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain.memory import ConversationBufferMemory
```

---

## Initialize Claude

```python
llm = ChatAnthropic(
    model="claude-sonnet-4-20250514",
    temperature=0.1,  # Low for security analysis
    max_tokens=4096
)
```

---

## Quick Tool Definition

```python
from langchain.tools import Tool

def extract_iocs(text: str) -> str:
    """Extract indicators of compromise."""
    # Your implementation
    return json.dumps({"ips": [], "domains": [], "hashes": []})

ioc_tool = Tool(
    name="extract_iocs",
    func=extract_iocs,
    description="Extract IOCs from text. Input: text containing IOCs"
)
```

---

## Structured Tool (Pydantic)

```python
from langchain.tools import StructuredTool
from pydantic import BaseModel, Field

class HashLookupInput(BaseModel):
    hash_value: str = Field(description="MD5, SHA1, or SHA256 hash")
    hash_type: str = Field(default="auto", description="Hash type")

def lookup_hash(hash_value: str, hash_type: str = "auto") -> str:
    # Implementation
    return result

hash_tool = StructuredTool.from_function(
    func=lookup_hash,
    name="lookup_hash",
    description="Look up file hash in threat intelligence",
    args_schema=HashLookupInput
)
```

---

## Create Agent

```python
from langchain.prompts import PromptTemplate

prompt = PromptTemplate.from_template("""
You are a security analyst assistant.

Tools: {tools}
Tool names: {tool_names}

Question: {input}
{agent_scratchpad}
""")

agent = create_react_agent(llm, tools, prompt)

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    max_iterations=10,
    handle_parsing_errors=True
)

# Run
result = executor.invoke({"input": "Analyze this IP: 192.168.1.100"})
```

---

## Memory

```python
# Conversation memory
memory = ConversationBufferMemory(
    memory_key="chat_history",
    return_messages=True
)

# With window
from langchain.memory import ConversationBufferWindowMemory
memory = ConversationBufferWindowMemory(k=10)

# Summary memory (for long conversations)
from langchain.memory import ConversationSummaryMemory
memory = ConversationSummaryMemory(llm=llm)
```

---

## RAG for Threat Intel

```python
from langchain_community.vectorstores import Chroma
from langchain_anthropic import AnthropicEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter

# Split documents
splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=200
)
chunks = splitter.split_documents(docs)

# Create vector store
vectorstore = Chroma.from_documents(
    chunks,
    AnthropicEmbeddings(),
    persist_directory="./threat_intel_db"
)

# Query
retriever = vectorstore.as_retriever(search_kwargs={"k": 5})
docs = retriever.get_relevant_documents("APT29 techniques")
```

---

## Chains

```python
from langchain.chains import LLMChain

# Simple chain
chain = LLMChain(llm=llm, prompt=prompt)
result = chain.invoke({"input": query})

# Sequential chain
from langchain.chains import SequentialChain

analysis_chain = SequentialChain(
    chains=[extract_chain, assess_chain, report_chain],
    input_variables=["raw_data"],
    output_variables=["final_report"]
)
```

---

## Output Parsing

```python
from langchain.output_parsers import PydanticOutputParser

class ThreatAssessment(BaseModel):
    threat_level: str
    confidence: float
    iocs: list[str]
    recommendations: list[str]

parser = PydanticOutputParser(pydantic_object=ThreatAssessment)

prompt = PromptTemplate(
    template="Assess this threat:\n{input}\n{format_instructions}",
    input_variables=["input"],
    partial_variables={"format_instructions": parser.get_format_instructions()}
)
```

---

## Error Handling

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
def safe_llm_call(query: str) -> str:
    try:
        return llm.invoke(query)
    except Exception as e:
        logging.error(f"LLM call failed: {e}")
        raise
```

---

## Common Patterns

### IOC Extraction Agent
```python
tools = [
    extract_iocs_tool,
    defang_tool,
    lookup_hash_tool,
    check_ip_tool
]
```

### Threat Assessment Agent
```python
tools = [
    analyze_malware_tool,
    search_mitre_tool,
    query_threat_intel_tool,
    generate_report_tool
]
```

### Log Analysis Agent
```python
tools = [
    parse_logs_tool,
    detect_anomalies_tool,
    correlate_events_tool,
    create_timeline_tool
]
```
