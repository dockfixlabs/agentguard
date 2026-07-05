"""Tests for Agent Memory Poisoning detection (ASI-MEMORY-POISON)."""
import tempfile, os
from agentguard.scanner import scan_file


def _tmp_file(content, ext=".py"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_chroma_add_unsanitized():
    """Untrusted user_input -> chroma.add() without sanitization."""
    code = """
import chromadb
client = chromadb.Client()
collection = client.create_collection("docs")

def ingest(user_input):
    collection.add(documents=[user_input], ids=["doc1"])
"""
    p = _tmp_file(code)
    try:
        findings = scan_file(p)
        mem = [f for f in findings if f.rule_id == "ASI-MEMORY-POISON"]
        assert len(mem) >= 1
        assert "user_input" in mem[0].description.lower()
    finally:
        os.unlink(p)


def test_langchain_memory_unsanitized():
    """Untrusted data saved to LangChain conversation memory."""
    code = """
from langchain.memory import ConversationBufferMemory
memory = ConversationBufferMemory()

def chat(user_message):
    response = agent.run(user_message)
    memory.save_context({"input": user_message}, {"output": response})
"""
    p = _tmp_file(code)
    try:
        findings = scan_file(p)
        mem = [f for f in findings if f.rule_id == "ASI-MEMORY-POISON"]
        assert len(mem) >= 1
    finally:
        os.unlink(p)


def test_pinecone_upsert_unsanitized():
    """Tainted data -> Pinecone upsert without validation."""
    code = """
import pinecone
index = pinecone.Index("my-index")

def index_results(search_result):
    vectors = embed(search_result)
    index.upsert(vectors=vectors)
"""
    p = _tmp_file(code)
    try:
        findings = scan_file(p)
        mem = [f for f in findings if f.rule_id == "ASI-MEMORY-POISON"]
        assert len(mem) >= 1
    finally:
        os.unlink(p)


def test_rag_ingestion_unsanitized():
    """RAG document ingestion from webhook without sanitization."""
    code = """
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import Chroma

splitter = RecursiveCharacterTextSplitter(chunk_size=1000)
vectorstore = Chroma()

def process_webhook(webhook):
    docs = splitter.split_text(webhook)
    vectorstore.add_documents(docs)
"""
    p = _tmp_file(code)
    try:
        findings = scan_file(p)
        mem = [f for f in findings if f.rule_id == "ASI-MEMORY-POISON"]
        assert len(mem) >= 1
    finally:
        os.unlink(p)


def test_sanitized_memory_write_safe():
    """Sanitized data -> memory write should NOT flag."""
    code = """
import chromadb, bleach
client = chromadb.Client()
collection = client.create_collection("safe")

def ingest(user_input):
    safe = bleach.clean(user_input)
    collection.add(documents=[safe], ids=["safe"])
"""
    p = _tmp_file(code)
    try:
        findings = scan_file(p)
        mem = [f for f in findings if f.rule_id == "ASI-MEMORY-POISON"]
        assert len(mem) == 0
    finally:
        os.unlink(p)


def test_memory_write_no_taint_safe():
    """Memory write with safe data should NOT flag."""
    code = """
import chromadb
client = chromadb.Client()
collection = client.create_collection("docs")

def store_config():
    config = {"version": "1.0", "model": "gpt-4"}
    collection.add(documents=[str(config)], ids=["config"])
"""
    p = _tmp_file(code)
    try:
        findings = scan_file(p)
        mem = [f for f in findings if f.rule_id == "ASI-MEMORY-POISON"]
        assert len(mem) == 0
    finally:
        os.unlink(p)


def test_js_memory_store():
    """JavaScript: Pinecone upsert with user input."""
    code = """
const pinecone = new PineconeClient();
const index = pinecone.Index("my-index");

async function storeUserData(userInput) {
    const embedding = await embed(userInput);
    await index.upsert([{id: "user1", values: embedding, metadata: {text: userInput}}]);
}
"""
    p = _tmp_file(code, ".js")
    try:
        findings = scan_file(p)
        mem = [f for f in findings if f.rule_id == "ASI-MEMORY-POISON"]
        assert len(mem) >= 1
    finally:
        os.unlink(p)


def test_agent_framework_memory():
    """CrewAI/AutoGen-style memory poisoning."""
    code = """
class Agent:
    def update_memory(self, tool_output):
        self.memory_store.add(tool_output)
        self.memory_store.persist()

agent = Agent()
def on_tool_result(tool_result):
    agent.update_memory(tool_result)
"""
    p = _tmp_file(code)
    try:
        findings = scan_file(p)
        mem = [f for f in findings if f.rule_id == "ASI-MEMORY-POISON"]
        assert len(mem) >= 1
    finally:
        os.unlink(p)
