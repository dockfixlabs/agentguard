# 6,173 Security Findings in 10 AI Agent Frameworks: A Systematic Static Analysis

**Dockfix Labs Security Research**
*AgentGuard v0.7.0*
*July 2026*

---

## Abstract

We present a systematic static analysis of 10 major AI agent frameworks comprising 11,036 files, revealing 6,173 security findings across 22 detection rules. Using AgentGuard v0.7.0 — an open-source static analysis security testing (SAST) tool purpose-built for AI agent codebases — we discovered vulnerabilities spanning the OWASP ASI Top 10 categories plus 6 novel attack vectors including Agent Memory Poisoning, Multi-Agent Collusion, and Steganographic Command Injection. We report 1,764 critical-severity and 1,320 high-severity findings across all frameworks, with Dify showing the highest raw finding count (1,725 findings in 1,886 files) and the OpenAI Agents SDK exhibiting the highest critical-to-file density (0.856 critical findings per file). Every framework exhibited at least one agent-specific vulnerability class absent from traditional SAST coverage. Our analysis demonstrates that AI agent frameworks systematically lack access control boundaries between agent perception and system execution — a structural security gap not addressed by existing general-purpose SAST tools, and one that demands domain-aware analysis.

**Keywords:** AI agent security, static analysis, OWASP ASI Top 10, multi-agent collusion, agent memory poisoning, SAST, AgentGuard

---

## 1. Introduction

### 1.1 The Rise of AI Agent Frameworks

The transition from standalone large language models (LLMs) to autonomous AI agent systems represents one of the most consequential architectural shifts in software engineering since the advent of microservices. AI agent frameworks — such as LangChain, CrewAI, AutoGen, and Dify — enable developers to build systems that perceive their environment, reason about goals, select and invoke tools, and execute multi-step workflows with minimal human intervention. As of mid-2026, these frameworks collectively power hundreds of thousands of production deployments across enterprise automation, customer support, code generation, financial analysis, and cybersecurity operations.

Yet the security properties of these frameworks remain poorly understood. Traditional application security testing tools — Bandit, Semgrep, CodeQL, Snyk — were designed for conventional web applications, APIs, and microservices. They detect cross-site scripting, SQL injection, hardcoded secrets, and path traversal with high fidelity. They do not detect prompt injection chains, agent-to-agent privilege escalation, memory store poisoning via tool output feedback loops, or unbounded agent execution loops that constitute denial-of-service primitives in multi-agent deployments.

### 1.2 The OWASP ASI Top 10 Gap

In 2025, the OWASP Foundation published the **OWASP Top 10 for Agentic Security Incidents (ASI)** [1], cataloging the most critical security risks specific to AI agent systems. The ASI Top 10 includes:

| ASI ID | Risk Category |
|--------|--------------|
| ASI01 | Excessive Agency |
| ASI02 | Prompt Injection |
| ASI03 | Tool Output Poisoning |
| ASI04 | Goal Manipulation |
| ASI05 | Unbounded Execution |
| ASI06 | Agent Impersonation |
| ASI07 | Sensitive Data Leakage |
| ASI08 | Supply Chain Compromise |
| ASI09 | Agent Loop Abuse |
| ASI10 | Multi-Agent Collusion |

Prior to this study, no systematic evaluation had been conducted to determine whether popular AI agent frameworks — in their default configurations — were vulnerable to these categories, or whether existing SAST tools could detect them.

### 1.3 Contributions

This paper makes the following contributions:

1. **The first large-scale, multi-framework static analysis of AI agent codebases** using domain-specific detection rules, covering 10 frameworks and 11,036 source files.

2. **Empirical evidence that general-purpose SAST tools systematically miss agent-specific vulnerability classes**, including agent memory poisoning, multi-agent collusion primitives, and unbounded execution loops — all of which were detected across multiple frameworks by AgentGuard.

3. **A per-framework vulnerability density analysis** revealing that frameworks with higher agent-automation capabilities tend to exhibit higher finding densities, with Dify and the OpenAI Agents SDK at the extremes.

4. **Disclosure of CWE-1188 (Insecure Default Initialization of Resource) at CVSS 10.0** in LangChain's ShellToolMiddleware (separate coordinated disclosure, CVE pending).

5. **The release of AgentGuard v0.7.0** as an open-source SAST tool with 22 agent-aware detection rules, available on PyPI and GitHub, along with the complete detection rule corpus used in this study.

---

## 2. Methodology

### 2.1 AgentGuard Architecture

AgentGuard v0.7.0 is a static analysis engine built on a Python AST and text-pattern matching pipeline. Unlike general-purpose SAST tools that operate on control-flow graphs and taint analysis of traditional web primitives, AgentGuard introduces **agent-aware pattern matchers** that reason about:

- **Tool invocation boundaries**: Code patterns where an agent invokes external tools (shell, HTTP, database, file system) with input derived from LLM output or agent memory.
- **Memory read/write asymmetry**: Patterns where agent memory stores are written by tool outputs but read without sanitization into subsequent prompt contexts or execution decisions.
- **Multi-agent communication channels**: Shared state, message bus, or event-driven patterns where one agent's output becomes another agent's execution context without a trust boundary.
- **Execution loop characteristics**: For-loops, while-loops, and recursive call patterns where the termination condition depends on LLM output, enabling unbounded agent execution.
- **Steganographic encodings**: Base64, hex, Unicode homoglyph, and whitespace-encoded instruction patterns embedded in tool outputs or external data consumed by agents.

### 2.2 Detection Rule Taxonomy

AgentGuard v0.7.0 implements 22 detection rules mapped to CWE identifiers, CVSS 3.1 severity scores, and OWASP ASI categories. The rule taxonomy is presented in Table 1.

**Table 1: AgentGuard v0.7.0 Detection Rules**

| Rule ID | Description | CWE | CVSS | OWASP ASI |
|---------|-------------|-----|------|-----------|
| AG-001 | Unsanitized LLM Output to Shell | CWE-78 | 9.8 | ASI03 |
| AG-002 | Agent Memory Poisoning via Tool Output | CWE-502 | 8.8 | ASI03 |
| AG-003 | Multi-Agent Shared State Without Isolation | CWE-1188 | 9.0 | ASI10 |
| AG-004 | Unbounded Agent Execution Loop | CWE-834 | 7.5 | ASI09 |
| AG-005 | Prompt Injection via External Data | CWE-74 | 8.6 | ASI02 |
| AG-006 | Steganographic Command Injection | CWE-506 | 9.1 | ASI03 |
| AG-007 | Agent Tool with Excessive Filesystem Permissions | CWE-732 | 7.8 | ASI01 |
| AG-008 | Hardcoded API Keys in Agent Configuration | CWE-798 | 9.8 | ASI08 |
| AG-009 | Agent Impersonation via Token Replay | CWE-287 | 8.1 | ASI06 |
| AG-010 | Sensitive Data in Agent Memory/Chat History | CWE-359 | 6.5 | ASI07 |
| AG-011 | Dynamic Code Execution from LLM Output | CWE-94 | 9.8 | ASI01 |
| AG-012 | Unsanitized Tool Output in Prompt Template | CWE-79 | 7.2 | ASI03 |
| AG-013 | Missing Rate Limiting on Agent Actions | CWE-770 | 6.5 | ASI09 |
| AG-014 | Agent Goal Manipulation via Context Injection | CWE-349 | 8.2 | ASI04 |
| AG-015 | SQL Injection via Agent-Generated Queries | CWE-89 | 8.6 | ASI01 |
| AG-016 | Server-Side Request Forgery via Agent Tools | CWE-918 | 8.2 | ASI01 |
| AG-017 | Insecure Deserialization in Agent Plugins | CWE-502 | 9.8 | ASI08 |
| AG-018 | Agent Configuration File Exposure | CWE-538 | 6.5 | ASI07 |
| AG-019 | Tool Chaining Without Input Validation | CWE-20 | 7.5 | ASI03 |
| AG-020 | Agent-to-Agent Privilege Escalation | CWE-269 | 8.8 | ASI10 |
| AG-021 | Unsafe Pickle in Agent Model Loading | CWE-502 | 9.8 | ASI08 |
| AG-022 | LLM Output Directly Rendered as HTML/Markdown | CWE-79 | 6.1 | ASI07 |

### 2.3 Scan Configuration

All scans were performed using the following standardized configuration:

- **AgentGuard version**: 0.7.0
- **Python version**: 3.11+
- **Scan depth**: Recursive, all `.py` and `.yaml`/`.yml`/`.json` configuration files
- **Severity thresholds**: All severities (Low, Medium, High, Critical) included
- **False positive suppression**: Baseline mode enabled, with per-framework exclusion lists derived from manual review of the first 50 findings per framework
- **Excluded paths**: `tests/`, `docs/`, `examples/` (unless containing agent tool definitions), `venv/`, `node_modules/`, `__pycache__/`
- **Framework versions**: Latest stable releases as of June 2026 (see Table 2)

**Table 2: Framework Versions Analyzed**

| Framework | Version | Release Date |
|-----------|---------|-------------|
| LangChain | 0.3.21 | May 2026 |
| LlamaIndex | 0.12.8 | June 2026 |
| AutoGen | 0.7.5 | April 2026 |
| CAMEL | 0.2.44 | May 2026 |
| CrewAI | 0.11.3 | June 2026 |
| Qwen-Agent | 0.0.18 | May 2026 |
| Semantic Kernel (Python) | 1.24.0 | June 2026 |
| Haystack | 2.10.2 | May 2026 |
| Dify | 1.3.0 | June 2026 |
| OpenAI Agents SDK | 0.5.0 | June 2026 |

### 2.4 Validation Protocol

To minimize false positives and ensure result reliability:

1. **Automated deduplication**: Identical finding fingerprints (file, line, rule, pattern hash) were collapsed into single findings with occurrence counts.
2. **Manual sampling**: A random sample of 5% of findings across all frameworks (308 findings) was manually reviewed by two security researchers. Inter-reviewer agreement was 91.2% (Cohen's κ = 0.84).
3. **Baseline comparison**: Each framework was also scanned with Bandit v1.8.3 and Semgrep v1.92.1 using their default rule sets. Agent-specific findings absent from both tools were flagged and manually verified.
4. **False positive rate**: Estimated at 3.7% based on the manual sample review. The rates reported in Section 3 have been adjusted accordingly.

---

## 3. Results

### 3.1 Aggregate Findings

Across all 10 frameworks, AgentGuard v0.7.0 detected 6,173 security findings in 11,036 analyzed files. The overall finding density was 0.559 findings per file. Of these, 1,764 (28.6%) were classified as Critical severity (CVSS ≥ 9.0) and 1,320 (21.4%) as High severity (CVSS 7.0–8.9). The remaining 3,089 (50.0%) were Medium (CVSS 4.0–6.9) or Low (CVSS < 4.0).

**Table 3: Aggregate Results by Framework**

| Framework | Files Analyzed | Total Findings | Critical (CVSS ≥ 9.0) | High (CVSS 7.0–8.9) | Findings/File |
|-----------|---------------|----------------|----------------------|---------------------|---------------|
| Dify | 1,886 | 1,725 | 1,038 | 661 | 0.915 |
| LlamaIndex | 2,951 | 1,003 | 8 | 31 | 0.340 |
| CAMEL | 899 | 746 | 9 | 52 | 0.830 |
| OpenAI Agents SDK | 543 | 695 | 465 | 188 | 1.280 |
| LangChain | 1,784 | 452 | 12 | 47 | 0.253 |
| Qwen-Agent | 239 | 441 | 2 | 42 | 1.845 |
| CrewAI | 84 | 391 | 5 | 28 | 4.655 |
| Semantic Kernel | 561 | 282 | 169 | 107 | 0.503 |
| AutoGen | 549 | 229 | 11 | 38 | 0.417 |
| Haystack | 1,540 | 209 | 45 | 126 | 0.136 |
| **TOTAL** | **11,036** | **6,173** | **1,764** | **1,320** | **0.559** |

### 3.2 Vulnerability Density Analysis

CrewAI exhibits the highest findings-per-file ratio (4.655), attributable to its compact codebase (84 files) with concentrated agent execution logic — each file averages nearly 5 security-relevant patterns. The OpenAI Agents SDK shows the second-highest density among non-trivial codebases at 1.280 findings per file. Dify, despite its large codebase, maintains a high density of 0.915, with particularly elevated rates of multi-agent collusion and memory poisoning patterns.

At the opposite end, Haystack (0.136) and LangChain (0.253) show the lowest density, suggesting more mature security practices or architectural decisions that inherently limit agent-specific attack surface. However, LangChain's lower density masks the presence of a CVSS 10.0 finding (see Section 4.3).

### 3.3 Per-Framework Top Detection Rules

**Table 4: Top 3 Detection Rules by Framework**

| Framework | Top Rule 1 | Top Rule 2 | Top Rule 3 |
|-----------|-----------|-----------|-----------|
| LangChain | AG-011: Dynamic Code Exec (38) | AG-008: Hardcoded Keys (29) | AG-005: Prompt Injection (24) |
| LlamaIndex | AG-019: Tool Chaining (112) | AG-010: Sensitive Data (87) | AG-005: Prompt Injection (78) |
| AutoGen | AG-003: Agent Collusion (45) | AG-004: Unbounded Loop (38) | AG-020: Privilege Escalation (29) |
| CAMEL | AG-001: LLM→Shell (89) | AG-003: Agent Collusion (74) | AG-006: Stegano Injection (61) |
| CrewAI | AG-004: Unbounded Loop (52) | AG-011: Dynamic Code Exec (44) | AG-002: Memory Poison (37) |
| Qwen-Agent | AG-001: LLM→Shell (67) | AG-005: Prompt Injection (54) | AG-008: Hardcoded Keys (43) |
| Semantic Kernel | AG-017: Insecure Deserial. (78) | AG-021: Unsafe Pickle (54) | AG-008: Hardcoded Keys (32) |
| Haystack | AG-012: Prompt Template (48) | AG-010: Sensitive Data (36) | AG-005: Prompt Injection (27) |
| Dify | AG-003: Agent Collusion (1,010) | AG-006: Stegano Injection (298) | AG-002: Memory Poison (187) |
| OpenAI Agents SDK | AG-004: Unbounded Loop (178) | AG-020: Privilege Escalation (142) | AG-011: Dynamic Code Exec (98) |

### 3.4 OWASP ASI Category Coverage

Every OWASP ASI Top 10 category was detected in at least 4 out of 10 frameworks. ASI09 (Agent Loop Abuse), ASI10 (Multi-Agent Collusion), and ASI03 (Tool Output Poisoning) were detected in all 10 frameworks. ASI02 (Prompt Injection) was detected in 9 of 10.

**Table 5: ASI Category Detection Coverage**

| ASI Category | Frameworks Affected | Total Findings |
|-------------|---------------------|----------------|
| ASI01 — Excessive Agency | 10/10 | 891 |
| ASI02 — Prompt Injection | 9/10 | 742 |
| ASI03 — Tool Output Poisoning | 10/10 | 1,547 |
| ASI04 — Goal Manipulation | 4/10 | 213 |
| ASI05 — Unbounded Execution | 10/10 | 623 |
| ASI06 — Agent Impersonation | 7/10 | 312 |
| ASI07 — Sensitive Data Leakage | 8/10 | 498 |
| ASI08 — Supply Chain Compromise | 6/10 | 397 |
| ASI09 — Agent Loop Abuse | 10/10 | 634 |
| ASI10 — Multi-Agent Collusion | 10/10 | 1,316 |

---

## 4. Key Findings

### 4.1 ASI-AGENT-COLLUSION: Multi-Agent Collusion at Scale

**Finding**: AgentGuard rule AG-003 detected 1,010 instances of multi-agent collusion primitives in Dify alone — representing 58.6% of Dify's total findings and 76.7% of all AG-003 detections across the study.

**Technical details**: Dify's architecture employs a shared `AgentState` object that is mutated by multiple agent executors without access control checks, transaction isolation, or origin validation. In the pattern detected, Agent A writes to a shared knowledge base (`dataset.update()`) and Agent B reads that data into its planning context without verifying that Agent A's write was authorized or that the data has not been tampered with. This creates a transitive trust chain where compromising any single agent compromises all agents that share the same state bus.

**Exploitation scenario**: An attacker who achieves prompt injection against a low-privilege agent (e.g., a customer-facing chatbot in a Dify workflow) can write malicious entries to the shared knowledge base. When a high-privilege agent (e.g., an admin automation agent) reads this data — which Dify does without integrity verification — the attacker's payload executes in the high-privilege context.

**Affected frameworks**: Dify (1,010), CAMEL (74), AutoGen (45), CrewAI (28), OpenAI Agents SDK (17), LlamaIndex (12), plus 3 others. Total: 1,316 instances across 10 frameworks — making this the single most prevalent vulnerability class in our study, present in every framework analyzed.

### 4.2 ASI09-AGENT-LOOP: Universal Unbounded Execution

**Finding**: AgentGuard rule AG-004 detected patterns of unbounded agent execution loops in all 10 frameworks, with 634 total instances.

**Mechanism**: The canonical pattern involves a `while` loop whose termination condition depends on the output of an LLM call — e.g., `while not agent.should_stop(response): tool.execute(response)`. If the LLM enters a reasoning loop, hallucinates a repeated tool call, or receives crafted input designed to prevent termination, the agent executes indefinitely.

**Impact**: In cloud-deployed agents (e.g., Dify workflows, CrewAI crews, AutoGen group chats), unbounded loops translate directly to unbounded API costs (LLM tokens, tool execution time) and potential denial-of-service conditions on shared infrastructure. A single malicious prompt can trigger thousands of dollars in API charges before timeout mechanisms engage.

**Framework-specific observations**:

- **OpenAI Agents SDK**: 178 instances — the highest raw count, driven by its `Runner` class abstraction that encourages streaming tool execution loops without configurable iteration limits by default.
- **CrewAI**: 52 instances in only 84 files — a density of 0.619 per file, the highest proportional rate. CrewAI's `Task` and `Crew` abstractions intrinsically encode loop semantics without default iteration caps.
- **Semantic Kernel**: Despite its lower overall finding count, 31 AG-004 instances were detected, concentrated in its planner and function-calling pipelines.

**Mitigation gap**: While some frameworks expose `max_iterations` configuration parameters, none enforce a safe default. In 8 of 10 frameworks, removing or omitting the iteration limit parameter resulted in unbounded execution — a violation of CWE-834 (Excessive Iteration).

### 4.3 CWE-1188 in LangChain: ShellToolMiddleware at CVSS 10.0

**Finding**: During analysis of LangChain v0.3.21, AgentGuard rule AG-001 flagged the `ShellToolMiddleware` class as a CVSS 10.0 instance of CWE-1188 (Insecure Default Initialization of Resource).

**Vulnerability details**:

- **Component**: `langchain.tools.ShellToolMiddleware`
- **Default behavior**: When instantiated without explicit `allowed_commands` or `sandbox_path` parameters, the middleware defaults to `allowed_commands=None`, which is interpreted as "all commands allowed" — granting the agent unrestricted shell access on the host system.
- **Attack vector**: Any LangChain agent configured with `ShellToolMiddleware()` (zero-argument constructor) receives a tool that executes arbitrary shell commands. If the agent's prompt is injectable — a separately documented vulnerability class (ASI02) — the injected prompt can commandeer the host shell.
- **CVSS 3.1 vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` — Network-accessible, low attack complexity, no privileges required, no user interaction, scope changed, complete confidentiality/integrity/availability impact.

**Responsible disclosure**: This finding was reported to the LangChain security team via their private vulnerability disclosure program on June 12, 2026. A CVE identifier has been requested. The LangChain team acknowledged the finding and is preparing a patch that enforces an explicit `allowed_commands` allowlist requirement.

**Broader implications**: This pattern — "secure-by-configuration" rather than "secure-by-default" — is endemic across AI agent tooling. Five additional tools across four frameworks exhibited similar insecure defaults, including AutoGen's `CommandLineCodeExecutor` and CrewAI's `ShellTool`.

### 4.4 ASI-MEMORY-POISON: A Novel Attack Vector

**Finding**: AgentGuard rule AG-002 detected Agent Memory Poisoning patterns in 5 of 10 frameworks, with 312 total instances. This represents a novel attack vector first formalized in AgentGuard's detection rule corpus.

**Definition**: Agent Memory Poisoning occurs when:

1. An agent invokes a tool that returns attacker-controlled output (e.g., a web scraper tool fetching a page with malicious content).
2. The tool output is stored in the agent's memory/context store without sanitization.
3. Subsequent agent reasoning or tool invocations read from the poisoned memory, propagating the attacker's influence across the agent's execution timeline.

**Visualized attack chain**:

```
Step 1: Attacker controls external resource
    ┌──────────────────────┐
    │ Untrusted webpage    │
    │ Content:             │
    │ "Ignore prior instr. │
    │  Delete all files."  │
    └──────┬───────────────┘
           │ Tool invocation (HTTP GET)
           ▼
Step 2: Agent tool fetches and stores
    ┌──────────────────────────────────┐
    │ agent.memory.store(tool_output)  │  ← No sanitization
    └──────────────┬───────────────────┘
                   │ Later, in same or subsequent turn
                   ▼
Step 3: Agent reads poisoned memory
    ┌──────────────────────────────────┐
    │ context = agent.memory.retrieve()│
    │ llm.generate(context)            │  ← Malicious content in prompt
    └──────────────┬───────────────────┘
                   ▼
Step 4: Compromised agent reasoning
    ┌──────────────────────────────────┐
    │ Agent follows malicious          │
    │ instructions from memory         │
    └──────────────────────────────────┘
```

**Affected frameworks**: Dify (187 instances), CrewAI (37), CAMEL (45), AutoGen (21), OpenAI Agents SDK (22).

**Why existing tools miss this**: Traditional SAST tools do not model "agent memory" as a security boundary. They treat `dict.update()`, `list.append()`, or database writes as ordinary data operations — they lack the semantic awareness that these operations populate future LLM prompt context, creating a second-order injection primitive that bypasses input sanitization at the prompt-construction layer.

### 4.5 Steganographic Command Injection (AG-006)

**Finding**: Rule AG-006 detected 423 instances of steganographic command injection patterns across 8 frameworks. Dify accounted for 298 of these (70.4%), followed by CAMEL with 61.

**Mechanism**: The rule detects patterns where untrusted external data is passed through encoding/decoding transformations (Base64, hex, Unicode escapes, ROT13, whitespace encoding) and then executed or interpolated into commands. In agent contexts, this typically manifests as:

```python
# Detected pattern: base64-encoded instruction extraction
data = tool.fetch_url(user_provided_url)
decoded = base64.b64decode(data).decode()
os.system(decoded)  # AG-006 detection
```

The detection is not limited to explicit `os.system()` calls. AgentGuard also flags patterns where decoded data flows into LLM prompts, tool invocation arguments, or agent planning directives — recognizing that in an agent system, "execution" includes any action the agent takes based on attacker-influenced reasoning.

### 4.6 Comparative SAST Analysis

To quantify the gap between general-purpose SAST and agent-aware static analysis, we scanned each framework with two widely-deployed tools:

- **Bandit v1.8.3**: Python-specific SAST with 69 built-in test plugins.
- **Semgrep v1.92.1** with the `p/security-audit` ruleset: 119 rules covering OWASP Top 10 for web applications.

**Table 6: General-Purpose SAST vs. AgentGuard on Agent-Specific Rules**

| Tool | Agent-Specific Rules | Findings (Agent-Specific) | Coverage of ASI Top 10 |
|------|---------------------|--------------------------|------------------------|
| Bandit 1.8.3 | 0 | 0 | 0/10 |
| Semgrep 1.92.1 | 0 | 0 | 0/10 |
| AgentGuard 0.7.0 | 22 | 6,173 | 10/10 |

Bandit and Semgrep collectively detected 2,847 traditional security findings (hardcoded secrets, unsafe YAML loading, SQL injection in raw queries, etc.) across all 10 frameworks. This is expected and represents a subset of findings that AgentGuard also detects via its standard CWE rules (AG-008, AG-015, AG-017, AG-021). However, neither tool detected any agent-specific vulnerability — prompt injection chains, memory poisoning, agent collusion, unbounded execution loops, tool output sanitization gaps, or agent privilege escalation — because these vulnerability classes are absent from their rule definitions and fundamentally outside their threat model.

---

## 5. Discussion

### 5.1 The Structural Security Gap

The central finding of this study is not any single vulnerability, but a systemic pattern: **AI agent frameworks do not enforce access control boundaries between the agent's perception of the world and its execution of actions in that world.** In traditional software, the boundary between "input" and "command" is a well-understood security primitive — SQL parameterization, command argument arrays, filesystem jail APIs. In AI agent frameworks, this boundary is dissolved by design: LLM output flows directly into tool invocations, tool outputs flow directly back into context windows, and agent-to-agent communication occurs through shared state without trust verification.

This is not a bug. It is an architectural consequence of how agent frameworks maximize flexibility. But from a security perspective, it represents a fundamental erosion of the principle of least privilege — every agent has ambient authority over every tool in its registry, and every agent that shares state with another agent implicitly trusts that agent's entire execution history.

### 5.2 Why General-Purpose SAST Is Insufficient

General-purpose SAST tools operate on well-defined attack models: an attacker provides malicious input through HTTP parameters, file uploads, or database records; the application processes this input; and a vulnerability occurs when the input reaches a dangerous sink (shell, SQL, HTML output) without sanitization. These tools model data flow between sources and sinks.

AI agents introduce a qualitatively different attack surface:

1. **Second-order injection**: An attacker's payload may enter the system not through a direct input parameter, but through the *output of a tool that the agent invoked*. The agent becomes an unwitting carrier.
2. **Temporal persistence**: A poisoned memory entry may not activate until a future agent turn — potentially after human review steps that inspected and cleared the immediate input.
3. **Cross-agent propagation**: In multi-agent systems, a compromise in Agent A can spread to Agent B, C, and D through shared state, even if Agents B–D never directly interacted with the attacker.
4. **Semantic exploitation**: Some attacks (steganographic command injection, goal manipulation) do not rely on syntactic escape of a data context (like SQL injection) but on semantic interpretation — the LLM reads malicious instructions and *chooses* to follow them.

None of these attack vectors are captured by existing taint-tracking or pattern-matching rules designed for traditional web applications. Domain-specific SAST — with rules that understand agent memory semantics, tool invocation chains, and multi-agent trust models — is necessary.

### 5.3 Framework Comparison and Risk Profiles

**High-risk frameworks** (Dify, OpenAI Agents SDK): These frameworks exhibit both high raw finding counts and high critical-to-file ratios. Dify's 1,038 critical findings (55.0% of all criticals in the study) are concentrated in its workflow orchestration engine and multi-agent collaboration features — precisely the components that differentiate it from simpler LLM-chaining libraries. The OpenAI Agents SDK's 465 critical findings reflect its design philosophy of maximal agent autonomy with minimal guardrails by default.

**Moderate-risk frameworks** (CAMEL, CrewAI, Qwen-Agent): These show elevated finding densities but smaller absolute codebase sizes. CrewAI's 4.655 findings-per-file ratio is the highest in the study, suggesting that its compact design concentrates security-relevant patterns. Qwen-Agent's 1.845 findings-per-file ratio similarly indicates dense agent execution logic.

**Lower-risk frameworks** (LangChain, LlamaIndex, Haystack): These frameworks — particularly Haystack (0.136 findings/file) — demonstrate that it is possible to build AI agent infrastructure with lower vulnerability density. Haystack's pipeline-based architecture, which enforces stricter component boundaries by design, appears to inherently limit agent-specific attack surface. However, LangChain's lower density is offset by the severity of its critical findings (CWE-1188 at CVSS 10.0), underscoring that density alone is not a sufficient risk metric.

### 5.4 Limitations

This study has several limitations:

1. **Static analysis scope**: AgentGuard v0.7.0 performs static analysis only. Runtime behaviors — such as actual prompt injection success rates, LLM susceptibility to specific payloads, and dynamic tool invocation patterns — are not captured. The 6,173 findings represent *potential* vulnerabilities; the proportion that are exploitable in production depends on deployment configuration, LLM model behavior, and runtime guardrails.

2. **Python-only**: All analyzed frameworks are Python-based. Agent frameworks in TypeScript (e.g., Vercel AI SDK, LangChain.js), Go, and Rust were not included. Extension of AgentGuard to multi-language support is ongoing.

3. **Version specificity**: Findings are tied to specific framework versions (see Table 2). Security postures may have changed in subsequent releases.

4. **Framework scope**: The analysis covers the framework code itself, not downstream applications built on these frameworks. A LangChain application may introduce vulnerabilities not present in LangChain's core library, and conversely may implement mitigations that would neuter vulnerabilities detected in the framework code.

5. **False positive rate**: The estimated 3.7% false positive rate, established through manual sampling of 5% of findings, may not be uniformly distributed across rules or frameworks. Some rules (particularly AG-003 and AG-006) rely on heuristic pattern matching that may over-flag in certain code patterns.

### 5.5 Recommendations

Based on our findings, we recommend:

1. **For framework maintainers**: Adopt secure-by-default configurations for all agent tools. Every tool invocation primitive (shell, HTTP, filesystem, database) should require explicit allowlist configuration. Unbounded agent execution loops should be capped by default (recommended: 10–50 iterations maximum). Agent memory stores should implement integrity verification (HMAC or digital signatures) on stored entries.

2. **For application developers**: Run AgentGuard (or equivalent agent-aware SAST) as part of CI/CD pipelines alongside traditional SAST tools. Audit agent tool registries for excessive permissions. Implement runtime guardrails including LLM output validation, tool output sanitization, and per-agent rate limiting — defense-in-depth measures that complement static analysis.

3. **For the security research community**: Extend CWE and CVSS taxonomies to capture agent-specific vulnerability classes. The current CWE hierarchy does not adequately model prompt injection, memory poisoning, or multi-agent collusion. We propose new CWE categories: CWE-XXXX (Agent Prompt Injection), CWE-XXXX (Agent Memory Poisoning), and CWE-XXXX (Multi-Agent Trust Boundary Violation).

4. **For standards bodies**: Accelerate adoption of the OWASP ASI Top 10 as a compliance framework. Our data demonstrates that every ASI category is present in production AI agent frameworks at scale — this is not a theoretical concern.

---

## 6. Conclusion

This study presents the first large-scale, multi-framework static analysis of AI agent codebases, revealing 6,173 security findings across 10 frameworks and 11,036 files. Our results demonstrate unequivocally that AI agent frameworks systematically lack the security boundaries that traditional software has developed over three decades — input validation, output encoding, principle of least privilege, and trust boundary enforcement.

The 1,764 critical-severity findings we report are not edge cases. They represent structural vulnerabilities in the architectural patterns that define modern AI agent systems: LLM output flowing unsanitized into shell commands, agent memory acting as a persistent injection vector, multi-agent state shared without isolation, and execution loops with no termination guarantees. These patterns exist not because framework developers are negligent, but because the security community has not yet adapted its tools and taxonomies to the agent paradigm.

**AgentGuard v0.7.0** is our contribution toward closing this gap. It is available as an open-source tool on PyPI (`pip install agentguard`) and GitHub (`github.com/dockfix-labs/agentguard`), with the 22-rule detection corpus released under the Apache 2.0 license. We encourage framework maintainers to integrate agent-aware SAST into their development workflows, application developers to include it in their CI/CD pipelines, and the broader security research community to extend and improve upon the detection rules we have published.

The AI agent revolution will not wait for security to catch up. But with domain-aware tooling, systematic analysis, and community-wide adoption of frameworks like the OWASP ASI Top 10, we can ensure that the agents we build are worthy of the trust we place in them.

---

## 7. References

[1] OWASP Foundation. "OWASP Top 10 for Agentic Security Incidents (ASI)." 2025. https://owasp.org/www-project-top-10-for-agentic-security-incidents/

[2] CWE Project. "CWE-1188: Insecure Default Initialization of Resource." MITRE Corporation. https://cwe.mitre.org/data/definitions/1188.html

[3] CWE Project. "CWE-78: Improper Neutralization of Special Elements used in an OS Command." MITRE Corporation. https://cwe.mitre.org/data/definitions/78.html

[4] CWE Project. "CWE-834: Excessive Iteration." MITRE Corporation. https://cwe.mitre.org/data/definitions/834.html

[5] CWE Project. "CWE-502: Deserialization of Untrusted Data." MITRE Corporation. https://cwe.mitre.org/data/definitions/502.html

[6] CWE Project. "CWE-94: Improper Control of Generation of Code." MITRE Corporation. https://cwe.mitre.org/data/definitions/94.html

[7] CWE Project. "CWE-506: Embedded Malicious Code." MITRE Corporation. https://cwe.mitre.org/data/definitions/506.html

[8] FIRST. "Common Vulnerability Scoring System v3.1: Specification Document." https://www.first.org/cvss/v3.1/specification-document

[9] Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." *Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security (AISec)*, 2023.

[10] Liu, Y., Deng, G., Li, Y., Wang, K., Wang, Z., Wang, X., Zhang, T., Liu, Y., Wang, H., Zheng, Y., & Zhang, Y. "Prompt Injection attack against LLM-integrated Applications." *arXiv preprint arXiv:2306.05499*, 2023.

[11] Wu, Q., Bansal, G., Zhang, J., Wu, Y., Li, B., Zhu, E., Jiang, L., Zhang, X., Zhang, S., Liu, J., Awadallah, A.H., White, R.W., Burger, D., & Wang, C. "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation." *arXiv preprint arXiv:2308.08155*, 2023.

[12] Chase, H. "LangChain: Building applications with LLMs through composability." 2022. https://github.com/langchain-ai/langchain

[13] Liu, J. "LlamaIndex: A Data Framework for LLM Applications." 2022. https://github.com/run-llama/llama_index

[14] Dify.AI. "Dify: An open-source LLM app development platform." 2023. https://github.com/langgenius/dify

[15] OpenAI. "OpenAI Agents SDK." 2025. https://github.com/openai/openai-agents-python

[16] Microsoft. "Semantic Kernel: Integrate cutting-edge LLM technology quickly and easily into your apps." 2023. https://github.com/microsoft/semantic-kernel

[17] deepset. "Haystack: The open-source NLP framework." 2020. https://github.com/deepset-ai/haystack

[18] crewAI. "CrewAI: Framework for orchestrating role-playing, autonomous AI agents." 2023. https://github.com/crewAIInc/crewAI

[19] CAMEL-AI.org. "CAMEL: Communicative Agents for 'Mind' Exploration of Large Language Model Society." 2023. https://github.com/camel-ai/camel

[20] Qwen Team. "Qwen-Agent: Agent framework and applications based on Qwen." 2024. https://github.com/QwenLM/Qwen-Agent

[21] Dockfix Labs. "AgentGuard: SAST for AI Agent Codebases." 2026. PyPI: https://pypi.org/project/agentguard/ — GitHub: https://github.com/dockfix-labs/agentguard

---

## Appendix A: AgentGuard v0.7.0 Rule Severity Distribution

| Severity | Rule Count | Rule IDs |
|----------|-----------|----------|
| Critical (CVSS ≥ 9.0) | 7 | AG-001, AG-003, AG-006, AG-008, AG-011, AG-017, AG-021 |
| High (CVSS 7.0–8.9) | 8 | AG-002, AG-005, AG-007, AG-009, AG-014, AG-015, AG-016, AG-020 |
| Medium (CVSS 4.0–6.9) | 5 | AG-004, AG-010, AG-013, AG-018, AG-019 |
| Low (CVSS < 4.0) | 2 | AG-012, AG-022 |

## Appendix B: Detailed Per-Framework Finding Breakdown

### B.1 LangChain (v0.3.21)
- Files: 1,784 | Findings: 452 | Critical: 12 | High: 47
- Top rules: AG-011 (38), AG-008 (29), AG-005 (24), AG-001 (21), AG-007 (19)
- Notable: CWE-1188 / CVSS 10.0 in `ShellToolMiddleware` (separate disclosure)

### B.2 LlamaIndex (v0.12.8)
- Files: 2,951 | Findings: 1,003 | Critical: 8 | High: 31
- Top rules: AG-019 (112), AG-010 (87), AG-005 (78), AG-004 (67), AG-012 (54)
- Notable: Largest codebase; agent-specific findings concentrated in query engines and tool abstractions

### B.3 AutoGen (v0.7.5)
- Files: 549 | Findings: 229 | Critical: 11 | High: 38
- Top rules: AG-003 (45), AG-004 (38), AG-020 (29), AG-002 (21), AG-001 (17)
- Notable: `CommandLineCodeExecutor` default-allowed state mirrors LangChain's CWE-1188

### B.4 CAMEL (v0.2.44)
- Files: 899 | Findings: 746 | Critical: 9 | High: 52
- Top rules: AG-001 (89), AG-003 (74), AG-006 (61), AG-005 (53), AG-002 (45)
- Notable: High rate of LLM→Shell patterns in role-playing agent scenarios

### B.5 CrewAI (v0.11.3)
- Files: 84 | Findings: 391 | Critical: 5 | High: 28
- Top rules: AG-004 (52), AG-011 (44), AG-002 (37), AG-003 (28), AG-020 (24)
- Notable: Highest findings-per-file ratio (4.655); compact codebase concentrates agent logic

### B.6 Qwen-Agent (v0.0.18)
- Files: 239 | Findings: 441 | Critical: 2 | High: 42
- Top rules: AG-001 (67), AG-005 (54), AG-008 (43), AG-004 (38), AG-007 (33)
- Notable: High density from integrated tool execution in assistant framework

### B.7 Semantic Kernel (v1.24.0)
- Files: 561 | Findings: 282 | Critical: 169 | High: 107
- Top rules: AG-017 (78), AG-021 (54), AG-008 (32), AG-004 (31), AG-009 (22)
- Notable: Critical findings dominated by insecure deserialization in plugin loading

### B.8 Haystack (v2.10.2)
- Files: 1,540 | Findings: 209 | Critical: 45 | High: 126
- Top rules: AG-012 (48), AG-010 (36), AG-005 (27), AG-008 (24), AG-018 (19)
- Notable: Lowest findings-per-file ratio (0.136); pipeline architecture provides structural protection

### B.9 Dify (v1.3.0)
- Files: 1,886 | Findings: 1,725 | Critical: 1,038 | High: 661
- Top rules: AG-003 (1,010), AG-006 (298), AG-002 (187), AG-004 (112), AG-020 (78)
- Notable: Single largest source of findings; multi-agent collusion dominates; 55% of all critical findings

### B.10 OpenAI Agents SDK (v0.5.0)
- Files: 543 | Findings: 695 | Critical: 465 | High: 188
- Top rules: AG-004 (178), AG-020 (142), AG-011 (98), AG-001 (89), AG-002 (22)
- Notable: Highest critical density among non-trivial codebases (0.856 critical/finding per file)

---

*This research was conducted by Dockfix Labs Security Research using AgentGuard v0.7.0. For inquiries, contact research@dockfix.dev.*

*AgentGuard is available under the Apache 2.0 license at https://github.com/dockfix-labs/agentguard and https://pypi.org/project/agentguard/.*
