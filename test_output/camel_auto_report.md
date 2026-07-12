# AgentGuard Security Audit Report

**Tool:** AgentGuard v0.7.3 | **Date:** 2026-07-08 19:36 UTC
**Target:** `../camel` | **Files scanned:** 355
**Scan duration:** 12131ms

## Executive Summary

| Metric | Value |
|--------|-------|
| Total findings | 147 |
| CRITICAL | 71 |
| HIGH | 28 |
| MEDIUM | 48 |
| LOW | 0 |
| INFO | 0 |
| Risk Score | 946 |
| Health | **CRITICAL — Large number of critical findings requiring immediate attention** |

## Classification

| Category | Count | Description |
|----------|-------|-------------|
| CONFIRMED | 62 | Actionable, high-confidence vulnerabilities |
| INVESTIGATE | 30 | Needs human review |
| BEST_PRACTICE | 39 | Security pattern, not exploitable |
| LIKELY_FP | 16 | Probable false positive |
| FP Removed | 22 | Auto-filtered false positives |
| FP Downgraded | 0 | Severity reduced |

## Top Detection Rules

| Rule | Count | Severity |
|------|-------|----------|
| Data Exfiltration Risk | 54 | CRITICAL |
| Unrestricted Tool Access | 38 | CRITICAL |
| Multi-Agent Collusion | 19 | CRITICAL |
| Agent Loop Exploitation | 16 | HIGH |
| Prompt Injection | 6 | CRITICAL |
| Unsafe Code Execution | 6 | CRITICAL |
| Trust Boundary Violation | 4 | CRITICAL |
| Prompt Injection (Taint Tracked) | 1 | CRITICAL |
| Agent Memory Poisoning | 1 | CRITICAL |
| Excessive Agency | 1 | HIGH |

## Most Affected Files

| File | Findings |
|------|----------|
| ..\camel\examples\toolkits\terminal_toolkit.py | 15 |
| .../workforce/workforce_shared_memory_validation.py | 12 |
| ..\camel\examples\toolkits\file_toolkit.py | 9 |
| .../runtimes/shared_runtime_multi_toolkit.py | 8 |
| ..\camel\examples\debug\eigent.py | 8 |
| .../codeforces_question_solver/app.py | 6 |
| ..\camel\examples\workforce\eigent.py | 5 |
| ..\camel\examples\models\nemotron_model_example.py | 4 |
| .../self_improving_cot/self_improving_cot_example_with_r1.py | 4 |
| ..\camel\examples\models\claude_model_example.py | 3 |

## OWASP ASI Coverage

| Category | Findings |
|----------|----------|
| ASI03 | 54 |
| ASI02 | 38 |
| ASI09 | 16 |
| ASI01 | 7 |
| ASI06 | 6 |
| ASI10 | 4 |
| ASI04 | 1 |

## Critical & High Findings

### [!] Data Exfiltration Risk — `..\camel\examples\models\nemotron_model_example.py:35`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Data Exfiltration Risk — `..\camel\examples\models\nemotron_model_example.py:36`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Data Exfiltration Risk — `..\camel\examples\models\nemotron_model_example.py:39`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Data Exfiltration Risk — `..\camel\examples\models\nemotron_model_example.py:40`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Unrestricted Tool Access — `.../toolkits/terminal_toolkit_runtimes.py:47`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
"Python scripts. Use the terminal tools to execute commands."
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Prompt Injection — `..\camel\examples\models\aihubmix_model_example.py:55`

**Confidence:** 85% | **OWASP:** ASI01

> [CONFIRMED] f-string prompt with user-controlled variable -- prompt injection via format string

**Snippet:**
```
print(f"User message: {user_msg}")
```

**Recommendation:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.

### [!] Unrestricted Tool Access — `.../runtimes/docker_runtime_with_tasks.py:55`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
"Your code will be executed using eval()."
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../runtimes/docker_runtime_with_tasks.py:55`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] eval() -- arbitrary code execution from string

**Snippet:**
```
"Your code will be executed using eval()."
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Unrestricted Tool Access — `.../runtimes/shared_runtime_multi_toolkit.py:59`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
shell_exec = next(
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../runtimes/shared_runtime_multi_toolkit.py:60`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
(t for t in tools if t.get_function_name() == "shell_exec"), None
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Multi-Agent Collusion — `..\camel\examples\toolkits\file_toolkit.py:63`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
Tool calls: [ToolCallingRecord(tool_name='write_to_file', args={'content': 'from flask import Flask\n\napp = Flask(__nam
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Trust Boundary Violation — `.../workforce/workforce_workflow_memory_example.py:65`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def create_writer_agent() -> ChatAgent:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../runtimes/shared_runtime_multi_toolkit.py:66`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
if not shell_exec or not execute_code:
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `..\camel\examples\toolkits\terminal_toolkit.py:68`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
[ToolCallingRecord(tool_name='shell_exec', args={'id': 'session1', 'exec_dir':
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `..\camel\examples\toolkits\terminal_toolkit.py:71`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
(tool_name='shell_exec', args={'id': 'session2', 'exec_dir': '/Users/enrei/
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../runtimes/shared_runtime_multi_toolkit.py:72`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
result = shell_exec.func(
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../runtimes/shared_runtime_multi_toolkit.py:81`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
result = shell_exec.func(
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Prompt Injection — `..\camel\examples\models\aihubmix_model_example.py:85`

**Confidence:** 85% | **OWASP:** ASI01

> [CONFIRMED] f-string prompt with user-controlled variable -- prompt injection via format string

**Snippet:**
```
print(f"User message: {user_msg}")
```

**Recommendation:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.

### [!] Prompt Injection — `..\camel\examples\usecases\chat_with_github\app.py:89`

**Confidence:** 85% | **OWASP:** ASI01

> [CONFIRMED] User-controlled variable in messages array -- prompt injection via LLM messages

**Snippet:**
```
{'role': 'user', 'content': user_input}
```

**Recommendation:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.

### [!] Unrestricted Tool Access — `..\camel\examples\toolkits\terminal_toolkit.py:91`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
[ToolCallingRecord(tool_name='shell_exec', args={'id': 'create_log_file',
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Prompt Injection (Taint Tracked) — `.../chat_with_github/demo_git_ingest.py:91`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'prompt' without sanitization

**Snippet:**
```
prompt = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Unrestricted Tool Access — `..\camel\examples\toolkits\terminal_toolkit.py:95`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
(tool_name='shell_exec', args={'id': 'show_log_file_content', 'exec_dir': '/
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unrestricted Tool Access — `.../runtimes/shared_runtime_multi_toolkit.py:110`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
result = shell_exec.func(
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Data Exfiltration Risk — `.../workforce/workforce_shared_memory_validation.py:115`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Data Exfiltration Risk — `..\camel\examples\models\claude_model_example.py:119`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Agent Memory Poisoning — `..\camel\examples\memories\agent_memory_example.py:125`

**Confidence:** 85% | **OWASP:** N/A

> [CONFIRMED] Untrusted data (user_message) written to agent memory store without sanitization -- persistent knowledge base poisoning

**Snippet:**
```
another_agent.update_memory(
```

**Recommendation:** Validate and sanitize ALL data before writing to vector stores, RAG databases, or agent memory. Use content filtering, input validation, and origin verification.

### [!] Prompt Injection — `..\camel\examples\models\claude_model_example.py:125`

**Confidence:** 85% | **OWASP:** ASI01

> [CONFIRMED] f-string prompt with user-controlled variable -- prompt injection via format string

**Snippet:**
```
print(f"\nUser: {user_msg}")
```

**Recommendation:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.

### [!] Unrestricted Tool Access — `..\camel\examples\toolkits\terminal_toolkit.py:132`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
[ToolCallingRecord(tool_name='shell_exec', args={'id': 'remove_logs',
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Multi-Agent Collusion — `.../toolkits/message_agent_toolkit.py:134`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
manual_result = msg_toolkit.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Data Exfiltration Risk — `.../workforce/workforce_shared_memory_validation.py:136`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

*... and 69 more critical/high findings*

## Top Recommendations

- **Data Exfiltration Risk:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.
- **Unrestricted Tool Access:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.
- **Prompt Injection:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.
- **Unsafe Code Execution:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.
- **Multi-Agent Collusion:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.
- **Trust Boundary Violation:** Make agent code immutable at runtime. Use code signing and integrity checks.
- **Prompt Injection (Taint Tracked):** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.
- **Agent Memory Poisoning:** Validate and sanitize ALL data before writing to vector stores, RAG databases, or agent memory. Use content filtering, input validation, and origin verification.
- **Agent Loop Exploitation:** Add recursion depth limit (e.g., if depth > MAX_DEPTH: return). Use iteration with explicit bounds instead of recursion for agent loops.
- **Excessive Agency:** Isolate agent resources. Each agent should only access its own state and workspace.
- **Agent Memory Class Confusion:** All memory updates must be guarded by authorization checks. Implement immutable memory with append-only logs and cryptographic verification.

---
*Report generated by [AgentGuard](https://github.com/dockfixlabs/agentguard) v0.7.3 — AI Agent Security Scanner*
*OWASP ASI Top 10 coverage | 22+ detection rules | Static analysis for AI agent codebases*