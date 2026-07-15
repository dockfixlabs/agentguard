# AgentGuard — Security Specification

**Version:** 0.8.1  
**License:** GNU Lesser General Public License v3 (LGPL v3)  
**OWASP ASI Reference:** <https://genai.owasp.org/>

---

## 1. Overview

AgentGuard is a static-analysis security scanner purpose-built for **AI-agent codebases**.  
It detects 22 categories of vulnerabilities across OWASP ASI Top 10 (Agentic Security Initiative) and novel agent‑specific attack vectors, using regex‑pattern matching, AST‑based taint tracking, and interprocedural cross‑file analysis.

All rules are defined in `agentguard/rules/` and registered in `agentguard/rules/__init__.py`.

---

## 2. OWASP ASI Top 10 Coverage

These 10 rules map directly to the OWASP Agentic Security Initiative Top 10 (2026).

| # | Rule ID | Rule Name | ASI | Default Severity | CWE | CVSS | Detection Method |
|---|---------|-----------|-----|------------------|-----|------|------------------|
| 1 | `ASI01-PROMPT-INJECTION` | Prompt Injection | ASI01 | CRITICAL | — | — | Regex patterns on prompt construction, f‑strings, `.format()`, message‑array assembly, and system‑prompt override patterns. |
| 2 | `ASI02-TOOL-ABUSE` | Unrestricted Tool Access | ASI02 | HIGH | — | — | Regex patterns for `os.system`, `subprocess` calls, wildcard tool registrations, and missing rate‑limits. |
| 3 | `ASI03-DATA-EXFIL` | Data Exfiltration Risk | ASI03 | HIGH | — | — | Multi‑pass regex: URL assignments, HTTP/fetch/axios/websocket calls, secret‑logging, DNS exfiltration, and cross‑line secret→network correlation. |
| 4 | `ASI04-EXCESSIVE-AGENCY` | Excessive Agency | ASI04 | HIGH | — | — | Regex patterns for write/delete permissions, privilege escalation (`sudo`, `chmod`), auto‑confirm destructive actions, cross‑agent resource access, and unrestricted API endpoints. |
| 5 | `ASI05-SUPPLY-CHAIN` | Supply Chain Risk | ASI05 | MEDIUM | — | — | Regex patterns for untrusted package sources (`pip git+`, `npm git+`), remote‑code execution, unverified deserialization, and unpinned Docker `:latest` tags. |
| 6 | `ASI06-UNSAFE-EVAL` | Unsafe Code Execution | ASI06 | CRITICAL | — | — | Regex patterns for `eval`, `exec`, `__import__`, `compile`, `subprocess shell=True`, `pickle.load`, `yaml.load`, and insecure LLM‑output rendering (`innerHTML`, `dangerouslySetInnerHTML`). |
| 7 | `ASI07-CREDENTIAL-LEAK` | Credential Exposure | ASI07 | CRITICAL | — | — | Regex patterns for API keys (`sk-*`, GitHub tokens, AWS keys, Slack tokens), private keys, connection strings with credentials, wallet keys, and hardcoded passwords — with placeholder false‑positive filtering. |
| 8 | `ASI08-CONTEXT-MANIPULATION` | Context Window Manipulation | ASI08 | MEDIUM | — | — | Regex patterns for missing token limits, unbounded context accumulation, and file‑content loaded directly into LLM context. |
| 9 | `ASI09-AGENT-LOOP` | Agent Loop Exploitation | ASI09 | MEDIUM | — | — | Multi‑pass analysis: recursive function detection, `while True` loops without break, missing `max_iterations`, missing budget limits, and agent self‑invocation patterns. |
| 10 | `ASI10-TRUST-BOUNDARY` | Trust Boundary Violation | ASI10 | HIGH | — | — | Regex patterns for privileged execution (`root`/`admin`), disabled sandboxing, host‑filesystem mounts, agent self‑modification, and direct database access with user input — with false‑positive exclusions. |

> **Note:** CWE/CVSS values are not embedded in the ASI rule classes in the current codebase.  
> Refer to <https://genai.owasp.org/> for the authoritative CWE‑to‑ASI mapping.

---

## 3. Additional Detection Rules (Beyond OWASP ASI Top 10)

These 12 rules address novel agent‑specific attack vectors not covered by the OWASP ASI Top 10.

| # | Rule ID | Rule Name | Default Severity | CWE | CVSS | Detection Method |
|---|---------|-----------|------------------|-----|------|------------------|
| 11 | `ASI01-TAINT-TRACK` | Prompt Injection (Taint Tracked) | CRITICAL | — | — | Python AST‑based taint tracking: propagates taint from user‑input sources through assignments to LLM‑sink variables and API calls (`openai.chat.completions.create`, `anthropic.messages.create`, etc.). |
| 12 | `ASI01-JS-TAINT` | JS Taint Tracking | CRITICAL | — | — | Structural regex‑based taint tracking for JS/TS: tracks taint from `req.body`, `ctx.message`, `process.argv` through assignments to LLM sinks and template literals. |
| 13 | `ASI01-INTERPROCEDURAL` | Cross‑Function Taint Flow | CRITICAL | — | — | AST‑based interprocedural analysis: tracks taint across Python function calls; Phase 2 resolves imports (`from utils import call_llm`) for cross‑file taint propagation. |
| 14 | `ASI-MEMORY-POISON` | Agent Memory Poisoning | CRITICAL | — | — | Regex detection of unvalidated writes to vector databases (Chroma, Pinecone, Qdrant, FAISS, Milvus), LangChain memory stores, and RAG indexes when the source is a taint variable — with sanitization exemption. |
| 15 | `ASI-TOOL-TRUST` | Tool Output Trust | CRITICAL | — | — | Two‑phase regex: (1) identifies tool‑output variable assignments; (2) detects unvalidated use of those variables in dangerous operations (`os.system`, `eval`, `pickle.load`, `shutil.rmtree`) without schema validation. |
| 16 | `ASI-CHAIN-AMPLIFY` | Action Chain Amplification | CRITICAL | — | — | Context‑aware regex: destructive operations (`.delete`, `.send`, `.charge`) inside unbounded loops or batch executors with tainted data sources, checked for absence of safety patterns (rate‑limits, checkpoints, approval gates). |
| 17 | `ASI-AGENT-COLLUSION` | Multi‑Agent Collusion | CRITICAL | — | — | Regex patterns for inter‑agent communication, shared state between agents, and agent output→input chaining — severity downgraded if trust‑verification patterns (message signing, nonce, audit logging) are present in the file. |
| 18 | `ASI-PROMPT-TEMPLATE` | Prompt Template Injection | CRITICAL | — | — | Regex patterns for Jinja2 template injection in prompts, f‑string message‑structure construction, and conversation‑structure manipulation with user‑controlled data. |
| 19 | `ASI-STEGANO-INJECT` | Steganographic Command Injection | CRITICAL | — | — | Multi‑line context analysis: detects decode‑then‑execute chains (`base64.decode` → `os.system`) when the encoded source is a taint variable, bypassing content‑based sanitizers. |
| 20 | `ASI-MOUNT-EXPOSURE` | Host Filesystem Mount Exposure | HIGH | **CWE‑732** | **8.6** | Multi‑pass analysis across Python, JS/TS, YAML, and Dockerfiles: detects `DockerCommandLineCodeExecutor` without `read_only=True`, `‑v` with sensitive host paths, bind‑mount sources of `/etc`, `/root`, `/proc`, and `Mount(type='bind')` with sensitive paths. |
| 21 | `ASI-MEMORY-CLASS-CONFUSION` | Agent Memory Class Confusion | HIGH | **CWE‑863** | **7.8** | Regex patterns for `self.tools`, `self.config`, `self.permissions`, `self.system_prompt`, `self.instructions`, `self.capabilities` mutations, and `memory.update` / `context.update` calls — checks for absence of authorization guards and function context (`__init__` vs. runtime). |
| 22 | `ASI-DOCKERFILE-SECURITY` | Dockerfile Security | HIGH | — | — | Dockerfile‑specific regex: `USER root`, missing `USER` directive, `EXPOSE` without TLS context, `ENV` secrets, `ADD` from remote URLs, `curl | bash`, `chmod 777`, and unpinned package installs. |

---

## 4. Severity Mapping

AgentGuard uses five severity levels:

| Severity | Meaning | Example Rules |
|----------|---------|---------------|
| **CRITICAL** | Immediate risk of compromise — remote code execution, credential exposure, prompt injection leading to data breach | `ASI01-PROMPT-INJECTION`, `ASI07-CREDENTIAL-LEAK`, `ASI-STEGANO-INJECT` |
| **HIGH** | Easily exploitable by attackers — excessive agency, trust boundary bypass, tool output blind‑trust | `ASI02-TOOL-ABUSE`, `ASI04-EXCESSIVE-AGENCY`, `ASI10-TRUST-BOUNDARY` |
| **MEDIUM** | Defense‑in‑depth issues — missing limits, potential resource exhaustion, unpinned dependencies | `ASI05-SUPPLY-CHAIN`, `ASI08-CONTEXT-MANIPULATION`, `ASI09-AGENT-LOOP` |
| **LOW** | Best‑practice deviations without direct exploit path — unpinned package installs in Dockerfiles | `ASI-DOCKERFILE-SECURITY` (sub‑rule) |
| **INFO** | Informational findings — not used by any current rule, reserved for future use | — |

Each finding includes a **confidence score** (0.0–1.0) indicating the likelihood of a true positive:
- **0.90–0.99**: High‑confidence match (e.g., `PRIVATE_KEY`, API key format, `eval()`)
- **0.70–0.89**: Strong heuristic match (e.g., `os.system()`, `curl | bash`)
- **0.50–0.69**: Moderate match requiring review (e.g., unpinned Docker images, webhook URLs)

---

## 5. Detection Methodology

### 5.1 Scan Pipeline

```
Project files → File‑type routing → Per‑rule scanning → Finding aggregation → ScanResult
```

1. **File Discovery** — Recursively walks the target directory, applying include/exclude glob patterns.
2. **File‑Type Routing** — Each rule declares which file extensions it handles: Python (`.py`), JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`), YAML (`.yaml`, `.yml`), or Dockerfile.
3. **Per‑Rule Scanning** — Rules implement one or both of:
   - `scan_line(line, line_num, file)` — line‑by‑line regex matching (used by 12 rules)
   - `scan_content(content, file)` — whole‑file analysis with multi‑line context, AST parsing, or cross‑line correlation (used by 10 rules)
4. **Finding Aggregation** — All findings are collected into a `ScanResult` with severity counts.

### 5.2 Analysis Techniques

| Technique | Rules | Description |
|-----------|-------|-------------|
| **Regex Pattern Matching** | 1–10, 14–22 | Regex patterns with false‑positive filters (comments, string literals, placeholder values, whitelist patterns). |
| **AST‑Based Taint Tracking** | 11, 13 | Parses Python source into AST; walks assignments, function calls, and expressions to track data flow from taint sources to LLM sinks. |
| **Structural JS/TS Analysis** | 12 | Regex‑based taint tracking for JavaScript/TypeScript without a parser dependency, modeling variable assignments, function parameters, and template literals. |
| **Multi‑Pass Context Analysis** | 3, 9, 14–19, 21 | Scans wider context windows (5–20 lines) to correlate assignments with usage, detect loops around destructive operations, or find sanitization/safety patterns. |
| **Cross‑File Import Resolution** | 13 | Resolves Python `from X import Y` statements to track taint across module boundaries. |
| **YAML/Dockerfile Parsing** | 20, 22 | Line‑by‑line structural analysis with indentation‑aware parsing for compose files and Dockerfiles. |

### 5.3 False‑Positive Mitigation

All rules implement false‑positive filters:
- **Comment skipping** — Lines starting with `#`, `//`, or `/*` are excluded.
- **Placeholder filtering** — CredentialLeakRule checks matched values against known placeholders (`your‑*`, `example`, `test`, `changeme`).
- **Whitelist patterns** — MemoryClassConfusionRule exempts `self.tools = []` (initialization) and `__init__` contexts.
- **Sanitization detection** — MemoryPoisoningRule and ToolOutputTrustRule check for validation/sanitization functions in nearby context.
- **Trust‑verification presence** — AgentCollusionRule downgrades severity when message‑signing or audit patterns are detected elsewhere in the file.

---

## 6. Compliance

AgentGuard maps findings to the **OWASP Agentic Security Initiative (ASI) Top 10 (2026)**.  
The `OWASP_ASI` enum in `agentguard/models.py` provides the authoritative mapping:

```python
class OWASP_ASI(str, Enum):
    ASI01 = "ASI01"  # Prompt Injection
    ASI02 = "ASI02"  # Tool Abuse / Unintended Tool Use
    ASI03 = "ASI03"  # Data Exfiltration / Sensitive Data Leakage
    ASI04 = "ASI04"  # Unauthorized Actions / Excessive Agency
    ASI05 = "ASI05"  # Supply Chain / Untrusted Components
    ASI06 = "ASI06"  # Insecure Output Handling
    ASI07 = "ASI07"  # Credential / Secret Exposure
    ASI08 = "ASI08"  # Context Window Manipulation
    ASI09 = "ASI09"  # Agent Loop Exploitation
    ASI10 = "ASI10"  # Trust Boundary Violation
```

Two rules include CWE mappings directly in the code:

| Rule | CWE | CVSS | Description |
|------|-----|------|-------------|
| Mount Exposure | CWE‑732 | 8.6 | Incorrect Permission Assignment for Critical Resource |
| Memory Class Confusion | CWE‑863 | 7.8 | Incorrect Authorization |

All severity levels are defined in the `Severity` enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

---

## 7. License

AgentGuard is licensed under the **GNU Lesser General Public License v3 (LGPL v3)**.

```
AgentGuard — Static analysis security scanner for AI agent codebases.
Copyright (C) 2026  AgentGuard Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.
```

---

## 8. References

- **OWASP Agentic Security Initiative (ASI):** <https://genai.owasp.org/>
- **OWASP ASI Top 10 for LLM Applications:** <https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/>
- **CWE‑732 — Incorrect Permission Assignment for Critical Resource:** <https://cwe.mitre.org/data/definitions/732.html>
- **CWE‑863 — Incorrect Authorization:** <https://cwe.mitre.org/data/definitions/863.html>
- **AutoGen Docker Code Executor (Issue #7917):** Filesystem mount exposure analysis basis
- **AutoGen Memory Self‑Modification (Issue #7918):** Class confusion / privilege escalation analysis basis
