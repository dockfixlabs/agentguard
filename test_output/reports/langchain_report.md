# AgentGuard Security Audit Report

**Tool:** AgentGuard v0.8.0 | **Date:** 2026-07-08 19:42 UTC
**Target:** `../langchain-audit` | **Files scanned:** 1831
**Scan duration:** 69937ms

## Executive Summary

| Metric | Value |
|--------|-------|
| Total findings | 436 |
| CRITICAL | 127 |
| HIGH | 255 |
| MEDIUM | 54 |
| LOW | 0 |
| INFO | 0 |
| Risk Score | 2653 |
| Health | **CRITICAL — Large number of critical findings requiring immediate attention** |

## Classification

| Category | Count | Description |
|----------|-------|-------------|
| CONFIRMED | 132 | Actionable, high-confidence vulnerabilities |
| INVESTIGATE | 51 | Needs human review |
| BEST_PRACTICE | 27 | Security pattern, not exploitable |
| LIKELY_FP | 226 | Probable false positive |
| FP Removed | 15 | Auto-filtered false positives |
| FP Downgraded | 0 | Severity reduced |

## Top Detection Rules

| Rule | Count | Severity |
|------|-------|----------|
| Agent Loop Exploitation | 226 | HIGH |
| Trust Boundary Violation | 43 | CRITICAL |
| Unrestricted Tool Access | 31 | CRITICAL |
| Data Exfiltration Risk | 29 | CRITICAL |
| Agent Memory Class Confusion | 24 | CRITICAL |
| Prompt Injection | 20 | CRITICAL |
| Action Chain Amplification | 18 | CRITICAL |
| Unsafe Code Execution | 15 | CRITICAL |
| Multi-Agent Collusion | 11 | CRITICAL |
| Excessive Agency | 4 | CRITICAL |

## Most Affected Files

| File | Findings |
|------|----------|
| .../runnables/base.py | 20 |
| .../agents/factory.py | 15 |
| .../prompts/chat.py | 13 |
| .../integration_tests/chat_models.py | 12 |
| .../language_models/chat_model_stream.py | 11 |
| .../middleware/_execution.py | 8 |
| .../middleware/anthropic_tools.py | 8 |
| .../language_models/chat_models.py | 8 |
| .../chat_models/azure.py | 8 |
| .../langchain_openai/chatgpt_oauth.py | 7 |

## OWASP ASI Coverage

| Category | Findings |
|----------|----------|
| ASI09 | 226 |
| ASI10 | 43 |
| ASI02 | 31 |
| ASI03 | 29 |
| ASI01 | 27 |
| ASI06 | 15 |
| ASI04 | 4 |
| ASI08 | 4 |

## Critical & High Findings

### [!] Unrestricted Tool Access — `.../middleware/bash.py:16`

**Confidence:** 95% | **OWASP:** ASI02

> [CONFIRMED] Shell/terminal tool exposed to agent — arbitrary code execution

**Snippet:**
```
BASH_TOOL_NAME = "bash"
```

**Recommendation:** Never expose shell access to AI agents. Use restricted, purpose-built tools instead.

### [!] Action Chain Amplification — `.../output_parsers/string.py:27`

**Confidence:** 85% | **OWASP:** N/A

> [CONFIRMED] Destructive operation inside unbounded loop without rate limiting or checkpoint -- single trigger can amplify into mass destruction

**Snippet:**
```
result = parser.invoke(message)
```

**Recommendation:** Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.

### [!] Prompt Template Injection — `.../flare/prompts.py:29`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Jinja2 template rendering with user-controlled data -- template injection enables structural prompt manipulation

**Snippet:**
```
PROMPT = PromptTemplate(
```

**Recommendation:** Never pass user data directly to template.render(). Use whitelist-based template variables. Escape all user inputs before template rendering.

### [!] Unrestricted Tool Access — `.../middleware/_execution.py:34`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
) -> subprocess.Popen[str]:
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../middleware/_execution.py:35`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
return subprocess.Popen(  # noqa: S603
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Prompt Template Injection — `.../flare/prompts.py:43`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Jinja2 template rendering with user-controlled data -- template injection enables structural prompt manipulation

**Snippet:**
```
QUESTION_GENERATOR_PROMPT = PromptTemplate(
```

**Recommendation:** Never pass user data directly to template.render(). Use whitelist-based template variables. Escape all user inputs before template rendering.

### [!] Trust Boundary Violation — `.../integration_tests/cache.py:56`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def test_update_cache(self, cache: BaseCache) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../langchain_ollama/embeddings.py:65`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
View the Ollama documentation for more commands.
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Trust Boundary Violation — `.../tracers/root_listeners.py:67`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _on_run_update(self, run: Run) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../middleware/shell_tool.py:68`

**Confidence:** 95% | **OWASP:** ASI02

> [CONFIRMED] Shell/terminal tool exposed to agent — arbitrary code execution

**Snippet:**
```
SHELL_TOOL_NAME = "shell"
```

**Recommendation:** Never expose shell access to AI agents. Use restricted, purpose-built tools instead.

### [!] Unrestricted Tool Access — `.../workflows/close_unchecked_issues.yml:69`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
const headingMatch = headingRe.exec(body);
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../workflows/close_unchecked_issues.yml:69`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] exec() -- arbitrary code execution

**Snippet:**
```
const headingMatch = headingRe.exec(body);
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Trust Boundary Violation — `.../langchain_core/caches.py:73`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def update(self, prompt: str, llm_string: str, return_val: RETURN_VAL_TYPE) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../middleware/_execution.py:87`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
) -> subprocess.Popen[str]:
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Trust Boundary Violation — `.../integration_tests/indexer.py:93`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def test_upsert_overwrites(self, index: DocumentIndex) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Excessive Agency — `.../storage/file_system.py:93`

**Confidence:** 90% | **OWASP:** ASI04

> [CONFIRMED] Agent can escalate privileges — sudo/chmod/setuid access

**Snippet:**
```
whereas the explicit `os.chmod()` used here is not.
```

**Recommendation:** Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.

### [!] Trust Boundary Violation — `.../integration_tests/cache.py:97`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def test_update_cache_with_multiple_generations(self, cache: BaseCache) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Data Exfiltration Risk — `.../scripts/record_codex_cassettes.sh:97`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Multi-Agent Collusion — `.../router/base.py:100`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
route = self.router_chain.route(inputs, callbacks=callbacks)
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Excessive Agency — `.../storage/file_system.py:102`

**Confidence:** 90% | **OWASP:** ASI04

> [CONFIRMED] Agent can escalate privileges — sudo/chmod/setuid access

**Snippet:**
```
dir_path.chmod(self.chmod_dir)
```

**Recommendation:** Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.

### [!] Trust Boundary Violation — `.../combine_documents/map_rerank.py:105`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
schema.update(dict.fromkeys(self.metadata_keys, (Any, None)))
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../load/_validation.py:119`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
secrets.update(this.lc_secrets)
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../tracers/root_listeners.py:122`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
async def _on_run_update(self, run: Run) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Prompt Injection — `.../middleware/model_fallback.py:123`

**Confidence:** 90% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input concatenated into prompt -- prompt injection vector

**Snippet:**
```
messages = _sanitize_messages(request.messages)
```

**Recommendation:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.

### [!] Unrestricted Tool Access — `.../middleware/_execution.py:137`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
) -> subprocess.Popen[str]:
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Prompt Injection (Taint Tracked) — `.../middleware/tool_emulator.py:138`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'prompt' without sanitization

**Snippet:**
```
prompt = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Trust Boundary Violation — `.../agents/agent_iterator.py:138`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def update_iterations(self) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Excessive Agency — `.../storage/file_system.py:138`

**Confidence:** 90% | **OWASP:** ASI04

> [CONFIRMED] Agent can escalate privileges — sudo/chmod/setuid access

**Snippet:**
```
full_path.chmod(self.chmod_file)
```

**Recommendation:** Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.

### [!] Unrestricted Tool Access — `.../middleware/shell_tool.py:139`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
self._process: subprocess.Popen[str] | None = None
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Action Chain Amplification — `.../flare/base.py:145`

**Confidence:** 85% | **OWASP:** N/A

> [CONFIRMED] Destructive operation inside unbounded loop without rate limiting or checkpoint -- single trigger can amplify into mass destruction

**Snippet:**
```
docs.extend(self.retriever.invoke(question))
```

**Recommendation:** Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.

*... and 352 more critical/high findings*

## Top Recommendations

- **Unrestricted Tool Access:** Never expose shell access to AI agents. Use restricted, purpose-built tools instead.
- **Action Chain Amplification:** Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.
- **Prompt Template Injection:** Never pass user data directly to template.render(). Use whitelist-based template variables. Escape all user inputs before template rendering.
- **Trust Boundary Violation:** Make agent code immutable at runtime. Use code signing and integrity checks.
- **Unsafe Code Execution:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.
- **Excessive Agency:** Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.
- **Data Exfiltration Risk:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.
- **Multi-Agent Collusion:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.
- **Prompt Injection:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.
- **Prompt Injection (Taint Tracked):** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.
- **Agent Memory Class Confusion:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.
- **Tool Output Trust:** Validate all tool outputs before use. Apply Pydantic models, JSON Schema, type checking, and content filtering. Never treat tool results as executable commands or file paths.
- **Cross-Function Taint Flow:** Sanitize data before passing to LLM-interacting functions.
- **Agent Loop Exploitation:** Add recursion depth limit (e.g., if depth > MAX_DEPTH: return). Use iteration with explicit bounds instead of recursion for agent loops.
- **Context Window Manipulation:** Set explicit max_tokens and max_input_length. Truncate or summarize long inputs before sending to LLM.

---
*Report generated by [AgentGuard](https://github.com/dockfixlabs/agentguard) v0.8.0 — AI Agent Security Scanner*
*OWASP ASI Top 10 coverage | 22+ detection rules | Static analysis for AI agent codebases*