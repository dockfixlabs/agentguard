# Why AI Agents Need SAST: 951 Findings in 7 Frameworks

**Draft v2 — Sanitized — Pending Owner Approval**

---

## TL;DR

We scanned 7 major AI agent frameworks (9,000 Python files) using AgentGuard, a static analysis tool built specifically for OWASP ASI Top 10. Result: 951 confirmed security findings with 88% precision on independent validation. Existing SAST tools (Bandit, Semgrep, CodeQL) miss these entirely because they weren't designed for agent-specific attack vectors.

## The Problem

AI agents are deployed in production at scale — coding assistants, customer support, trading bots, autonomous systems. They have unique attack surfaces that traditional SAST tools don't cover:

- **Prompt injection** — user input flows into LLM system prompts
- **Tool abuse** — agents with `os.system()` or `subprocess` access
- **Data exfiltration** — agents sending data to external endpoints
- **Excessive agency** — agents with unrestricted tool registration
- **Trust boundary violations** — runtime self-modification of agent behavior

Traditional tools scan for SQL injection, XSS, hardcoded secrets. None of them detect when `user_input` flows into an LLM prompt template.

## What We Did

Built AgentGuard — a Python SAST tool with 22 rules covering all 10 OWASP ASI categories. Scanned:

| Framework | Files | CONFIRMED Findings |
|-----------|-------|--------------------|
| Dify | 2,030 | 216 |
| LlamaIndex | 2,951 | 294 |
| CrewAI | 1,042 | 99 |
| LangChain | 1,831 | 132 |
| AutoGen | 553 | 98 |
| CAMEL | 355 | 62 |
| Qwen-Agent | 238 | 50 |
| **Total** | **9,000** | **951** |

## Precision Validation

We measured precision honestly:

1. **Development sample** (50 findings): 36% → 100% after rule fixes
2. **Independent sample** (50 new findings, zero overlap): **88%** (44 TP / 6 FP)

The 100% on the development sample was overfitting. The 88% on the independent sample is the real number. We're publishing 88%, not 100%, because honesty builds trust.

The 6 remaining false positives were all from one pattern: `def _update_prompts(self, ...)` being flagged as runtime self-modification. Fixed in v0.8.1.

## What We Found (No Exploit Details)

We found vulnerabilities across all 7 frameworks spanning all 10 OWASP ASI categories. The most common patterns:

1. **Unrestricted tool access** — agents with direct `os.system()` or `subprocess` calls that accept user-controlled input
2. **Credential exposure in source** — real-looking API keys committed in example files
3. **Missing trust boundaries** — agent code that can modify its own runtime behavior

Several findings have been reported privately via GitHub Security Advisories. We won't disclose specifics until the responsible disclosure window closes.

## Why Existing Tools Miss This

| Vulnerability | Bandit | Semgrep | CodeQL | AgentGuard |
|---------------|--------|---------|--------|------------|
| Prompt injection | No | No | No | Yes |
| Tool abuse (agent context) | Partial | No | No | Yes |
| Excessive agency | No | No | No | Yes |
| Trust boundary | No | No | No | Yes |
| AST taint tracking (agent) | No | No | No | Yes |

## How to Use AgentGuard

```bash
pip install dfx-agentguard
agentguard scan ./your-agent-code
```

Outputs Markdown, JSON, or SARIF for GitHub Code Scanning integration.

## Honest Limitations

- 88% precision means ~1 in 8 findings is a false positive
- Only Python is supported (JavaScript partial)
- No data flow across function boundaries (intra-procedural only)
- 951 findings on 9,000 files = 10.6% density — some frameworks are noisy

## Links

- GitHub: <https://github.com/dockfixlabs/agentguard>
- PyPI: <https://pypi.org/project/dfx-agentguard/>
- OWASP ASI: <https://owasp.org/www-project-agentic-security-initiative/>

---

**This is a draft. No external posting without owner approval.**
