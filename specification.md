# AgentGuard Security Specification v0.6.8
## The Standard for AI Agent Code Security

**Status:** Reference Implementation
**Coverage:** OWASP ASI Top 10 (2026) + 6 Novel Attack Vectors
**Authority:** Dockfix Labs, open-source MIT license

---

## 1. OWASP ASI Top 10 Coverage

### ASI01 — Prompt Injection
- **CWE:** CWE-77 (Command Injection)
- **Detection:** User-controlled data reaching LLM prompt construction without sanitization
- **Severity:** CRITICAL
- **Interprocedural:** Tracks taint through function calls and imports
- **Languages:** Python, JavaScript, TypeScript

### ASI02 — Tool & API Abuse
- **CWE:** CWE-78 (OS Command Injection), CWE-94 (Code Injection)
- **Detection:** Agent tools with dangerous system capabilities (subprocess, os.system, eval)
- **Severity:** CRITICAL
- **Guard:** `subprocess.run(..., shell=True)`, `os.system()`, `eval()` in tool code

### ASI03 — Data Exfiltration
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Detection:** Secrets, API keys, credentials in log statements
- **Severity:** HIGH
- **Patterns:** `logging.info()` with credential variables, `print()` of secrets

### ASI04 — Excessive Agency
- **CWE:** CWE-250 (Execution with Unnecessary Privileges)
- **Detection:** Tools with capabilities beyond declared purpose
- **Severity:** HIGH
- **Indicators:** File write, network access, process execution in read-only tools

### ASI05 — Supply Chain
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components)
- **Detection:** Unpinned dependencies, remote code loading
- **Severity:** HIGH
- **Patterns:** `pip install` without version pin, `exec(requests.get(url).text)`

### ASI06 — Insecure Output Handling
- **CWE:** CWE-79 (Cross-Site Scripting)
- **Detection:** Unsanitized agent output rendered as HTML/markdown
- **Severity:** HIGH
- **Guard:** `innerHTML`, `dangerouslySetInnerHTML`, unescaped template rendering

### ASI07 — Credential Exposure
- **CWE:** CWE-798 (Hardcoded Credentials)
- **Detection:** API keys, tokens, passwords in source code
- **Severity:** CRITICAL
- **Patterns:** 100+ known credential patterns (AWS, OpenAI, GitHub, etc.)

### ASI08 — Context Manipulation
- **CWE:** CWE-349 (Acceptance of Extraneous Untrusted Data)
- **Detection:** Agent state modified by unvalidated external input
- **Severity:** HIGH

### ASI09 — Agent Loop Exploitation
- **CWE:** CWE-835 (Uncontrolled Loop)
- **Detection:** Unbounded agent loops without circuit breakers
- **Severity:** HIGH

### ASI10 — Trust Boundary Violation
- **CWE:** CWE-501 (Trust Boundary Violation)
- **Detection:** Agent can modify its own code, configuration, or system files
- **Severity:** CRITICAL

---

## 2. Novel Attack Vectors (Beyond OWASP)

### ASI-MEMORY-POISON (v0.6.0)
- **Technique:** Corrupting vector databases and agent memory stores
- **Detection:** 26 vector DB + agent memory sink patterns
- **Severity:** CRITICAL
- **Sinks:** Chroma, Pinecone, Weaviate, FAISS, LangChain memory, agent_results

### ASI-TOOL-TRUST (v0.6.1)
- **Technique:** Blind agent trust in unvalidated tool outputs
- **Detection:** Tool output used as command or code input without validation
- **Severity:** CRITICAL

### ASI-CHAIN-AMPLIFY (v0.6.2)
- **Technique:** Destructive operations in unbounded agent loops
- **Detection:** File delete/write operations inside while-true loops
- **Severity:** CRITICAL

### ASI-AGENT-COLLUSION (v0.6.3)
- **Technique:** Multi-agent conspiracy through shared mutable state
- **Detection:** Shared memory without access controls between agents
- **Severity:** MEDIUM

### ASI-PROMPT-TEMPLATE (v0.6.7)
- **Technique:** Attacker controls prompt STRUCTURE, not just content
- **Detection:** Jinja2/f-string building message role/content objects
- **Severity:** CRITICAL
- **CWE:** CWE-74 (Improper Neutralization of Special Elements in Output)

### ASI-STEGANO-INJECT (v0.6.8)
- **Technique:** Hidden commands in encoded data (base64, hex, rot13)
- **Detection:** Decode-then-execute chains with tainted source
- **Severity:** CRITICAL
- **CWE:** CWE-506 (Embedded Malicious Code)

---

## 3. Standard Taint Tracking Rules

### ASI-TAINT-TRACK
- **Technique:** User input reaching dangerous sinks across function boundaries
- **Sources:** Function parameters named `user_input`, `request`, `query`, `prompt`
- **Sinks:** `os.system`, `subprocess`, `eval`, `exec`, LLM calls
- **Languages:** Python (v0.5.0), JavaScript (v0.5.2)

### ASI-INTERPROCEDURAL
- **Technique:** Cross-function and cross-file taint propagation
- **Phase 1 (v0.5.5):** Same-file function call chain analysis
- **Phase 2 (v0.5.7):** Cross-file import resolution
- **Phase 3 (planned):** Class method dispatch

---

## 4. Comparison Scope

AgentGuard comparisons with traditional SAST tools must note:

1. **Semgrep** — general-purpose pattern matching. No OWASP ASI rules exist.
2. **CodeQL** — deep semantic analysis. No OWASP ASI query pack exists.
3. **Bandit** — Python security linter. 2/10 ASI categories partially covered.

AgentGuard is the **first and only** scanner with dedicated OWASP ASI rules.
No scanner currently detects the 6 novel vectors.

---

## 5. Compliance

| Standard | Coverage |
|----------|----------|
| OWASP ASI Top 10 (2026) | 10/10 (full) |
| CWE Top 25 | 12/25 (agent-relevant subset) |
| MITRE ATLAS | Agent-specific attack techniques |
| NIST AI 600-1 | Secure AI system development |

---

**Version:** 0.6.8
**Date:** 2026-07-05
**License:** MIT — Fork, modify, contribute. The standard is open.
**Repository:** https://github.com/dockfixlabs/agentguard
