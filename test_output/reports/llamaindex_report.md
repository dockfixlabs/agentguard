# AgentGuard Security Audit Report

**Tool:** AgentGuard v0.8.0 | **Date:** 2026-07-08 19:48 UTC
**Target:** `../llama-index-audit` | **Files scanned:** 2951
**Scan duration:** 273444ms

## Executive Summary

| Metric | Value |
|--------|-------|
| Total findings | 1080 |
| CRITICAL | 307 |
| HIGH | 575 |
| MEDIUM | 198 |
| LOW | 0 |
| INFO | 0 |
| Risk Score | 6341 |
| Health | **CRITICAL — Large number of critical findings requiring immediate attention** |

## Classification

| Category | Count | Description |
|----------|-------|-------------|
| CONFIRMED | 294 | Actionable, high-confidence vulnerabilities |
| INVESTIGATE | 212 | Needs human review |
| BEST_PRACTICE | 136 | Security pattern, not exploitable |
| LIKELY_FP | 438 | Probable false positive |
| FP Removed | 22 | Auto-filtered false positives |
| FP Downgraded | 0 | Severity reduced |

## Top Detection Rules

| Rule | Count | Severity |
|------|-------|----------|
| Agent Loop Exploitation | 438 | HIGH |
| Data Exfiltration Risk | 172 | CRITICAL |
| Trust Boundary Violation | 141 | CRITICAL |
| Prompt Injection | 88 | CRITICAL |
| Unsafe Code Execution | 46 | CRITICAL |
| Multi-Agent Collusion | 45 | CRITICAL |
| Agent Memory Class Confusion | 43 | CRITICAL |
| Credential Exposure | 31 | CRITICAL |
| Unrestricted Tool Access | 25 | CRITICAL |
| Prompt Injection (Taint Tracked) | 15 | CRITICAL |

## Most Affected Files

| File | Findings |
|------|----------|
| .../javascript/algolia.js | 25 |
| .../js/algolia.js | 25 |
| .../discord_dumps/help_channel_dump_06_02_23.json | 17 |
| .../discord_dumps/help_channel_dump_05_25_23.json | 16 |
| .../mem0/base.py | 15 |
| .../jaguar/base.py | 15 |
| .../nebula/nebula_graph_store.py | 15 |
| .../readability_web/Readability.js | 14 |
| .../finance/base.py | 13 |
| .../llms/function_calling.py | 11 |

## OWASP ASI Coverage

| Category | Findings |
|----------|----------|
| ASI09 | 438 |
| ASI03 | 172 |
| ASI10 | 141 |
| ASI01 | 115 |
| ASI06 | 46 |
| ASI07 | 31 |
| ASI02 | 25 |
| ASI05 | 6 |
| ASI08 | 4 |

## Critical & High Findings

### [!] Trust Boundary Violation — `.../response_synthesizers/context_only.py:15`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_prompts(self, prompts: PromptDictType) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../response_synthesizers/no_text.py:15`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_prompts(self, prompts: PromptDictType) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../release/changelog.py:15`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
def _run_command(command: str) -> str:
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Trust Boundary Violation — `.../postprocessor/types.py:23`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_prompts(self, prompts: PromptDictType) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Data Exfiltration Risk — `.../you/base.py:24`

**Confidence:** 90% | **OWASP:** ASI03

> [CONFIRMED] Secret accessed then sent to external URL -- active exfiltration

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Isolate secret access from network code. Use secret managers that do not expose values to agent context.

### [!] Unrestricted Tool Access — `.../release/changelog.py:26`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
return _run_command('git describe --tags --match "v[0-9]*" --abbrev=0')
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Credential Exposure — `.../modelslab/base.py:31`

**Confidence:** 95% | **OWASP:** ASI07

> [CONFIRMED] Hardcoded API key detected -- credential in source code

**Snippet:**
```
api_key="****REDACTED****",
```

**Recommendation:** Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.

### [!] Unrestricted Tool Access — `.../release/changelog.py:31`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
log_output = _run_command(f'git log {latest_tag}..HEAD --pretty="format:%H %s"')
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../query_transform/feedback_transform.py:33`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
eval(Evaluation): An evaluation object.
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../query_transform/feedback_transform.py:33`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] eval() -- arbitrary code execution from string

**Snippet:**
```
eval(Evaluation): An evaluation object.
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Trust Boundary Violation — `.../workflow/agent_context.py:34`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def write_event_to_stream(self, event: Any) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../base/base_query_engine.py:35`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_prompts(self, prompts: PromptDictType) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../docarray/base.py:39`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_ref_docs(self, docs) -> None:  # type: ignore[no-untyped-def]
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Credential Exposure — `.../perplexity/base.py:40`

**Confidence:** 95% | **OWASP:** ASI07

> [CONFIRMED] Hardcoded API key detected -- credential in source code

**Snippet:**
```
pplx_api_key = "****REDACTED****"
```

**Recommendation:** Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.

### [!] Credential Exposure — `.../timescalevector/base.py:41`

**Confidence:** 90% | **OWASP:** ASI07

> [CONFIRMED] Connection string with embedded credentials -- password in URL

**Snippet:**
```
TIMESCALE_SERVICE_URL = "postgres://tsdbadmin:<password>@<id>.tsdb.cloud.timescale.com:<port>/tsdb?sslmode=require"
```

**Recommendation:** Use separate host, user, and password parameters from environment variables. Never embed credentials in connection URLs.

### [!] Trust Boundary Violation — `.../client/sync.py:43`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
session.headers.update(self._headers)
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../kvstore/simple_kvstore.py:45`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
f.write(json.dumps(self._collections_mappings))
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Agent Memory Class Confusion — `.../whisper/base.py:47`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Agent class mutates system_prompt/instructions — governance bypass via prompt self-modification

**Snippet:**
```
self.prompt = prompt
```

**Recommendation:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.

### [!] Credential Exposure — `.../azure_openai/responses.py:47`

**Confidence:** 95% | **OWASP:** ASI07

> [CONFIRMED] Hardcoded API key detected -- credential in source code

**Snippet:**
```
aoai_api_key = "****REDACTED****"
```

**Recommendation:** Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.

### [!] Agent Memory Class Confusion — `.../azure_foundry_agent/base.py:48`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Agent class mutates system_prompt/instructions — governance bypass via prompt self-modification

**Snippet:**
```
self._instructions = instructions
```

**Recommendation:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.

### [!] Trust Boundary Violation — `.../selectors/embedding_selectors.py:48`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_prompts(self, prompts: PromptDictType) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../events/embedding.py:49`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
singledispatch (e.g. openinference-instrumentation-llama-index) route this
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../release/changelog.py:49`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
pr_json_str = _run_command(f"gh pr view {pr_number} --json number,title,url,files")
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../colpali_rerank/base.py:51`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
).eval()
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../colpali_rerank/base.py:51`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] eval() -- arbitrary code execution from string

**Snippet:**
```
).eval()
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Credential Exposure — `.../azure_openai/base.py:51`

**Confidence:** 95% | **OWASP:** ASI07

> [CONFIRMED] Hardcoded API key detected -- credential in source code

**Snippet:**
```
aoai_api_key = "****REDACTED****"
```

**Recommendation:** Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.

### [!] Credential Exposure — `.../supabase/base.py:52`

**Confidence:** 90% | **OWASP:** ASI07

> [CONFIRMED] Connection string with embedded credentials -- password in URL

**Snippet:**
```
postgres_connection_string="postgresql://<user>:<password>@<host>:<port>/<db_name>",
```

**Recommendation:** Use separate host, user, and password parameters from environment variables. Never embed credentials in connection URLs.

### [!] Credential Exposure — `.../nile/base.py:52`

**Confidence:** 90% | **OWASP:** ASI07

> [CONFIRMED] Connection string with embedded credentials -- password in URL

**Snippet:**
```
service_url="postgresql://user:****REDACTED****@us-west-2.db.thenile.dev:5432/niledb",
```

**Recommendation:** Use separate host, user, and password parameters from environment variables. Never embed credentials in connection URLs.

### [!] Trust Boundary Violation — `.../response_synthesizers/simple_summarize.py:52`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_prompts(self, prompts: PromptDictType) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Action Chain Amplification — `.../ingestion/cache.py:53`

**Confidence:** 85% | **OWASP:** N/A

> [CONFIRMED] Destructive operation inside unbounded loop without rate limiting or checkpoint -- single trigger can amplify into mass destruction

**Snippet:**
```
self.cache.delete(key, collection=collection)
```

**Recommendation:** Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.

*... and 852 more critical/high findings*

## Top Recommendations

- **Trust Boundary Violation:** Make agent code immutable at runtime. Use code signing and integrity checks.
- **Unrestricted Tool Access:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.
- **Data Exfiltration Risk:** Isolate secret access from network code. Use secret managers that do not expose values to agent context.
- **Credential Exposure:** Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.
- **Unsafe Code Execution:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.
- **Agent Memory Class Confusion:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.
- **Action Chain Amplification:** Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.
- **Prompt Injection (Taint Tracked):** Sanitize user input before passing to LLM APIs. Use structured message arrays. Validate and filter all user-controlled data.
- **Multi-Agent Collusion:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.
- **Prompt Injection:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.
- **Cross-Function Taint Flow:** Sanitize data before passing to LLM-interacting functions.
- **Agent Memory Poisoning:** Validate and sanitize ALL data before writing to vector stores, RAG databases, or agent memory. Use content filtering, input validation, and origin verification.
- **Agent Loop Exploitation:** Add recursion depth limit (e.g., if depth > MAX_DEPTH: return). Use iteration with explicit bounds instead of recursion for agent loops.
- **Supply Chain Risk:** Only install from PyPI/npm registry. Pin versions. Use hash verification (--require-hashes).
- **Host Filesystem Mount Exposure:** Ensure volume mounts are read-only and never expose sensitive host paths (/etc, /root, /home, /var/run/docker.sock).
- **Prompt Template Injection:** Validate message structure before appending to conversation. Sanitize role fields. Use typed message objects.
- **Context Window Manipulation:** Set explicit max_tokens and max_input_length. Truncate or summarize long inputs before sending to LLM.

---
*Report generated by [AgentGuard](https://github.com/dockfixlabs/agentguard) v0.8.0 — AI Agent Security Scanner*
*OWASP ASI Top 10 coverage | 22+ detection rules | Static analysis for AI agent codebases*