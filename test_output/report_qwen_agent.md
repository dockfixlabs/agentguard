# AgentGuard Security Audit Report

**Tool:** AgentGuard v0.7.3 | **Date:** 2026-07-08 19:37 UTC
**Target:** `../qwen-agent` | **Files scanned:** 239
**Scan duration:** 16659ms

## Executive Summary

| Metric | Value |
|--------|-------|
| Total findings | 302 |
| CRITICAL | 107 |
| HIGH | 155 |
| MEDIUM | 40 |
| LOW | 0 |
| INFO | 0 |
| Risk Score | 1925 |
| Health | **CRITICAL — Large number of critical findings requiring immediate attention** |

## Classification

| Category | Count | Description |
|----------|-------|-------------|
| CONFIRMED | 50 | Actionable, high-confidence vulnerabilities |
| INVESTIGATE | 52 | Needs human review |
| BEST_PRACTICE | 12 | Security pattern, not exploitable |
| LIKELY_FP | 188 | Probable false positive |
| FP Removed | 12 | Auto-filtered false positives |
| FP Downgraded | 0 | Severity reduced |

## Top Detection Rules

| Rule | Count | Severity |
|------|-------|----------|
| Agent Loop Exploitation | 128 | HIGH |
| Credential Exposure | 60 | CRITICAL |
| Unrestricted Tool Access | 20 | CRITICAL |
| Multi-Agent Collusion | 20 | MEDIUM |
| Trust Boundary Violation | 14 | CRITICAL |
| Unsafe Code Execution | 12 | CRITICAL |
| Prompt Injection (Taint Tracked) | 12 | CRITICAL |
| Prompt Injection | 12 | CRITICAL |
| Data Exfiltration Risk | 12 | MEDIUM |
| Agent Memory Class Confusion | 7 | CRITICAL |

## Most Affected Files

| File | Findings |
|------|----------|
| .../website/package-lock.json | 60 |
| ..\qwen-agent\examples\group_chat_demo.py | 9 |
| ..\qwen-agent\qwen_agent\agents\group_chat.py | 9 |
| .../code_interpreter/code_interpreter.py | 7 |
| .../examples/qwen2vl_assistant_tooluse.py | 7 |
| ..\qwen-agent\qwen_agent\tools\python_executor.py | 6 |
| .../metrics/code_execution.py | 6 |
| ..\qwen-agent\examples\group_chat_chess.py | 6 |
| .../code_interpreter/inference_and_execute.py | 5 |
| ..\qwen-agent\qwen_server\workstation_server.py | 5 |

## OWASP ASI Coverage

| Category | Findings |
|----------|----------|
| ASI09 | 128 |
| ASI07 | 60 |
| ASI01 | 24 |
| ASI02 | 20 |
| ASI10 | 14 |
| ASI06 | 12 |
| ASI03 | 12 |

## Critical & High Findings

### [!] Unrestricted Tool Access — `.../models/base.py:12`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
low_cpu_mem_usage=True).eval()
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../models/base.py:12`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] eval() -- arbitrary code execution from string

**Snippet:**
```
low_cpu_mem_usage=True).eval()
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Agent Memory Class Confusion — `.../prompt/llama_react.py:18`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Agent class mutates system_prompt/instructions — governance bypass via prompt self-modification

**Snippet:**
```
self.prompt = planning_prompt
```

**Recommendation:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.

### [!] Unrestricted Tool Access — `.../code_interpreter/inference_and_execute.py:26`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
os.system(f'cp -r upload_file_clean {WORK_DIR}/upload_file')
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../code_interpreter/inference_and_execute.py:27`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
os.system('cp -r upload_file_clean ./upload_file')
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../metrics/gsm8k.py:27`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
return eval(last_digit)
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../metrics/gsm8k.py:27`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] eval() -- arbitrary code execution from string

**Snippet:**
```
return eval(last_digit)
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Trust Boundary Violation — `.../agents/write_from_scratch.py:34`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
class WriteFromScratch(Agent):
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Prompt Injection (Taint Tracked) — `..\qwen-agent\examples\virtual_memory_qa.py:41`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'messages' without sanitization

**Snippet:**
```
messages = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Prompt Injection (Taint Tracked) — `..\qwen-agent\examples\tir_math.py:45`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'messages' without sanitization

**Snippet:**
```
messages = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Trust Boundary Violation — `..\qwen-agent\qwen_agent\agents\article_agent.py:45`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
writing_agent = WriteFromScratch(llm=self.llm)
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Prompt Injection (Taint Tracked) — `..\qwen-agent\examples\assistant_qwen3vl.py:48`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'messages' without sanitization

**Snippet:**
```
messages = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Unrestricted Tool Access — `..\qwen-agent\qwen_agent\tools\python_executor.py:49`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
exec(code_piece, self._global_vars)
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `..\qwen-agent\qwen_agent\tools\python_executor.py:49`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] exec() -- arbitrary code execution

**Snippet:**
```
exec(code_piece, self._global_vars)
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Unrestricted Tool Access — `.../metrics/code_execution.py:50`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
exec(text, locals())
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../metrics/code_execution.py:50`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] exec() -- arbitrary code execution

**Snippet:**
```
exec(text, locals())
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Agent Memory Class Confusion — `.../prompt/qwen_react.py:50`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Agent class mutates system_prompt/instructions — governance bypass via prompt self-modification

**Snippet:**
```
self.prompt = prompt
```

**Recommendation:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.

### [!] Agent Memory Class Confusion — `.../prompt/react.py:51`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Agent class mutates system_prompt/instructions — governance bypass via prompt self-modification

**Snippet:**
```
self.prompt = ''
```

**Recommendation:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.

### [!] Unrestricted Tool Access — `..\qwen-agent\qwen_agent\tools\python_executor.py:52`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
return eval(expr, self._global_vars)
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `..\qwen-agent\qwen_agent\tools\python_executor.py:52`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] eval() -- arbitrary code execution from string

**Snippet:**
```
return eval(expr, self._global_vars)
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Prompt Injection — `.../agents/write_from_scratch.py:57`

**Confidence:** 90% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input concatenated into prompt -- prompt injection vector

**Snippet:**
```
res_sum = sum_agent.run(messages=[Message(USER, user_request)], knowledge=knowledge, lang=lang)
```

**Recommendation:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.

### [!] Trust Boundary Violation — `..\qwen-agent\qwen_agent\tools\mcp_manager.py:57`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def monkey_patch_mcp_create_platform_compatible_process(self):
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../metrics/code_execution.py:57`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
exec(text, locals())
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../metrics/code_execution.py:57`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] exec() -- arbitrary code execution

**Snippet:**
```
exec(text, locals())
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Prompt Injection (Taint Tracked) — `..\qwen-agent\examples\assistant_qwq.py:58`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'messages' without sanitization

**Snippet:**
```
messages = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Prompt Injection (Taint Tracked) — `..\qwen-agent\examples\group_chat_chess.py:58`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'messages' without sanitization

**Snippet:**
```
messages = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Unrestricted Tool Access — `.../code_interpreter/code_interpreter.py:59`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
kernel_process = subprocess.Popen([
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Agent Memory Class Confusion — `.../prompt/react.py:61`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Agent class mutates system_prompt/instructions — governance bypass via prompt self-modification

**Snippet:**
```
self.prompt = planning_prompt
```

**Recommendation:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.

### [!] Prompt Injection (Taint Tracked) — `.../examples/assistant_add_custom_tool.py:77`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'messages' without sanitization

**Snippet:**
```
messages = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Trust Boundary Violation — `.../tools/delete_product_from_cart.py:77`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_summary(self):
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

*... and 232 more critical/high findings*

## Top Recommendations

- **Unrestricted Tool Access:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.
- **Unsafe Code Execution:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.
- **Agent Memory Class Confusion:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.
- **Trust Boundary Violation:** Make agent code immutable at runtime. Use code signing and integrity checks.
- **Prompt Injection (Taint Tracked):** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.
- **Prompt Injection:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.
- **Action Chain Amplification:** Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.
- **Credential Exposure:** Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.
- **Agent Loop Exploitation:** Add recursion depth limit (e.g., if depth > MAX_DEPTH: return). Use iteration with explicit bounds instead of recursion for agent loops.
- **Prompt Template Injection:** Validate message structure before appending to conversation. Sanitize role fields. Use typed message objects.
- **Multi-Agent Collusion:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.
- **Data Exfiltration Risk:** Validate all external URLs against an allowlist. Ensure URLs are not constructed from user input.

---
*Report generated by [AgentGuard](https://github.com/dockfixlabs/agentguard) v0.7.3 — AI Agent Security Scanner*
*OWASP ASI Top 10 coverage | 22+ detection rules | Static analysis for AI agent codebases*