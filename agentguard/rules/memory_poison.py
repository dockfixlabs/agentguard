"""Agent Memory Poisoning (ASI-MEMORY-POISON)

Detects code patterns that allow untrusted data to corrupt
agent memory systems -- vector databases, RAG knowledge bases,
LangChain memory, conversation history, and tool output stores.

This is a novel attack vector beyond OWASP ASI Top 10:
attackers inject persistent malicious content into the agent's
long-term memory, which then influences ALL future decisions.
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


class MemoryPoisoningRule(Rule):
    """Detects unvalidated writes to agent memory/knowledge systems.

    Unlike prompt injection (single-turn), memory poisoning is PERSISTENT.
    Once malicious content enters the vector store or conversation memory,
    it poisons every subsequent agent decision until the store is purged.
    """
    rule_id = "ASI-MEMORY-POISON"
    rule_name = "Agent Memory Poisoning"
    severity = Severity.CRITICAL

    MEMORY_WRITE_RE = re.compile(
        rb"\.add\s*\(.*documents?\s*[:=]|\.add_documents?\s*\(|\.add_texts?\s*\(|"
        rb"\.upsert\s*\(|\.insert\s*\(|\.index\s*\(|\.ingest\s*\(|"
        rb"chroma\.add\s*\(|chromadb\.add\s*\(|new ChromaClient|\.add_to_collection\s*\(|"
        rb"pinecone\.|new PineconeClient|"
        rb"weaviate\.batch\.add_data_object|client\.batch\.add_data_object|"
        rb"qdrant_client\.upsert\s*\(|\.upload_points\s*\(|"
        rb"faiss\.write_index\s*\(|\.add_with_ids\s*\(|"
        rb"milvus\.insert\s*\(|collection\.insert\s*\(|"
        rb"ConversationBufferMemory|ConversationSummaryMemory|ConversationKGMemory|"
        rb"VectorStoreRetrieverMemory|"
        rb"\.save_context\s*\(|\.chat_memory\.add_message|\.chat_memory\.add_[a-z]+_message|"
        rb"\.from_documents\s*\(|RecursiveCharacterTextSplitter|\.load_and_split\s*\(|"
        rb"knowledge_base\.add\s*\(|\.store\s*\(|\.persist\s*\(|\.save_to_disk\s*\(|"
        rb"\.update_memory\s*\(|\.set_memory\s*\(|\.remember\s*\(|Memory\.create\s*\(|\.add_to_memory\s*\(",
        re.IGNORECASE
    )

    TAINT_RE = re.compile(
        rb"user[_]?input|user[_]?message|user[_]?query|"
        rb"request\.(body|data|json|form|args)|request\.get\(|"
        rb"req\.(body|data|json|form|args)|"
        rb"webhook|api[_]?callback|external[_]?data|untrusted_|"
        rb"raw[_]?input|unsanitized_|"
        rb"search[_]?result|scraped[_]?content|"
        rb"tool[_]?output|tool[_]?result|agent[_]?response",
        re.IGNORECASE
    )

    SANITIZE_RE = re.compile(
        rb"\.sanitize\s*\(|\.validate\s*\(|\.clean\s*\(|\.escape\s*\(|"
        rb"bleach\.clean|html\.escape|re\.sub\s*\(.*<|"
        rb"\.strip_tags\s*\(|InputValidator|ContentFilter|"
        rb"sanitize_|validated_|cleaned_|escaped_",
        re.IGNORECASE
    )

    def scan_line(self, line, line_num, file):
        return []

    def scan_content(self, content, file):
        ext = file.rsplit(".", 1)[-1] if "." in file else ""
        if ext not in ("py", "js", "ts", "jsx", "tsx"):
            return []

        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            encoded = line.encode("utf-8", errors="ignore")
            if not self.MEMORY_WRITE_RE.search(encoded):
                continue

            # Check nearby context for taint sources
            ctx_start = max(0, i - 5)
            ctx_end = min(len(lines), i + 2)
            context = " ".join(lines[ctx_start:ctx_end])
            ctx_encoded = context.encode("utf-8", errors="ignore")

            taint_m = self.TAINT_RE.search(ctx_encoded)
            if not taint_m:
                continue

            # Check for sanitization
            if self.SANITIZE_RE.search(ctx_encoded):
                continue

            taint_str = taint_m.group(0).decode("utf-8", errors="ignore")
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                file=file,
                line=i,
                snippet=line.strip()[:120],
                description="Untrusted data (%s) written to agent memory store without sanitization -- persistent knowledge base poisoning" % taint_str,
                recommendation="Validate and sanitize ALL data before writing to vector stores, RAG databases, or agent memory. Use content filtering, input validation, and origin verification.",
                confidence=0.85,
            ))

        return findings
