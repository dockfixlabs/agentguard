# AgentGuard Security Audit Report

**Tool:** AgentGuard v0.8.0 | **Date:** 2026-07-08 19:44 UTC
**Target:** `../autogen-audit` | **Files scanned:** 553
**Scan duration:** 43224ms

## Executive Summary

| Metric | Value |
|--------|-------|
| Total findings | 696 |
| CRITICAL | 115 |
| HIGH | 128 |
| MEDIUM | 453 |
| LOW | 0 |
| INFO | 0 |
| Risk Score | 2696 |
| Health | **CRITICAL — Large number of critical findings requiring immediate attention** |

## Classification

| Category | Count | Description |
|----------|-------|-------------|
| CONFIRMED | 98 | Actionable, high-confidence vulnerabilities |
| INVESTIGATE | 379 | Needs human review |
| BEST_PRACTICE | 32 | Security pattern, not exploitable |
| LIKELY_FP | 187 | Probable false positive |
| FP Removed | 63 | Auto-filtered false positives |
| FP Downgraded | 0 | Severity reduced |

## Top Detection Rules

| Rule | Count | Severity |
|------|-------|----------|
| Multi-Agent Collusion | 441 | CRITICAL |
| Agent Loop Exploitation | 69 | HIGH |
| Trust Boundary Violation | 44 | CRITICAL |
| Data Exfiltration Risk | 35 | CRITICAL |
| Prompt Injection | 29 | CRITICAL |
| Unrestricted Tool Access | 18 | CRITICAL |
| Unsafe Code Execution | 18 | CRITICAL |
| Agent Memory Class Confusion | 14 | CRITICAL |
| Prompt Template Injection | 11 | HIGH |
| Host Filesystem Mount Exposure | 10 | CRITICAL |

## Most Affected Files

| File | Findings |
|------|----------|
| .../_group_chat/_base_group_chat.py | 69 |
| .../_magentic_one/_magentic_one_orchestrator.py | 54 |
| .../_group_chat/_round_robin_group_chat.py | 36 |
| .../_group_chat/_selector_group_chat.py | 34 |
| .../_group_chat/_base_group_chat_manager.py | 34 |
| .../_magentic_one/_magentic_one_group_chat.py | 30 |
| .../_group_chat/_chat_agent_container.py | 27 |
| .../_group_chat/_swarm_group_chat.py | 15 |
| .../database/db_manager.py | 14 |
| .../_graph/_digraph_group_chat.py | 14 |

## OWASP ASI Coverage

| Category | Findings |
|----------|----------|
| ASI09 | 69 |
| ASI10 | 44 |
| ASI03 | 35 |
| ASI01 | 33 |
| ASI02 | 18 |
| ASI06 | 18 |
| ASI04 | 2 |
| ASI07 | 1 |

## Critical & High Findings

### [!] Host Filesystem Mount Exposure — `..\autogen-audit\.devcontainer\docker-compose.yml:11`

**Confidence:** 92% | **OWASP:** N/A

> [CONFIRMED] docker-compose volume mount exposes sensitive host path: /var/run/docker.sock

**Snippet:**
```
- /var/run/docker.sock:/var/run/docker-host.sock
```

**Recommendation:** Remove mount to sensitive path. Use named Docker volumes or restrict to app-specific directories with read_only access.

### [!] Unrestricted Tool Access — `.../fields/tool-fields.tsx:19`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
* - FunctionTool uses exec() to execute user-provided Python code
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../fields/tool-fields.tsx:19`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] exec() -- arbitrary code execution

**Snippet:**
```
* - FunctionTool uses exec() to execute user-provided Python code
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Trust Boundary Violation — `.../auth/middleware.py:23`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../canvas/_canvas.py:32`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def add_or_update_file(self, filename: str, new_content: Union[str, bytes, Any]) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Multi-Agent Collusion — `.../autogen_core/_agent_proxy.py:38`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
return await self._runtime.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../mcp/wsbridge.py:39`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
await self.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Trust Boundary Violation — `.../_host/_elicitation.py:39`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _write(self, text: str) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../canvas/_canvas.py:46`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def apply_patch(self, filename: str, patch_data: Union[str, bytes, Any]) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Multi-Agent Collusion — `.../mcp/wsbridge.py:49`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
await self.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../tool_agent/_caller_loop.py:50`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
caller.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Trust Boundary Violation — `.../_extension/code_lint.py:52`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def write_doc(self, docname: str, doctree: nodes.Node) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Multi-Agent Collusion — `.../mcp/wsbridge.py:59`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
await self.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Prompt Injection — `.../task_centric_memory/_prompter.py:63`

**Confidence:** 90% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input concatenated into prompt -- prompt injection vector

**Snippet:**
```
input_messages = [system_message] + self._chat_history + [user_message]
```

**Recommendation:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.

### [!] Multi-Agent Collusion — `.../mcp/wsbridge.py:69`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
await self.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Trust Boundary Violation — `.../database/schema_manager.py:72`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _update_configuration(self) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Multi-Agent Collusion — `.../autogen_core/_agent_instantiation.py:75`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
await runtime.send_message(TestMessage(content="Hello, world!"), AgentId("test_agent", "default"))
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../mcp/wsbridge.py:81`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
await self.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Host Filesystem Mount Exposure — `.../docker/_docker_code_executor.py:85`

**Confidence:** 95% | **OWASP:** N/A

> [CONFIRMED] DockerCommandLineCodeExecutor without read_only=True — container has unrestricted host filesystem write access

**Snippet:**
```
class DockerCommandLineCodeExecutor(CodeExecutor, Component[DockerCommandLineCodeExecutorConfig]):
```

**Recommendation:** Always set read_only=True on DockerCommandLineCodeExecutor. Use volume mounts with explicit read-only options for any required host paths.

### [!] Data Exfiltration Risk — `.../replay/_replay_chat_completion_client.py:87`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Data Exfiltration Risk — `.../replay/_replay_chat_completion_client.py:90`

**Confidence:** 85% | **OWASP:** ASI03

> [CONFIRMED] Secret/credential value being logged -- credential exposure in logs

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.

### [!] Prompt Injection — `.../utils/grader.py:94`

**Confidence:** 90% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input concatenated into prompt -- prompt injection vector

**Snippet:**
```
input_messages = [system_message] + self._chat_history + [user_message]
```

**Recommendation:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.

### [!] Trust Boundary Violation — `.../gallery/builder.py:102`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
self.agents.append(self._update_component_metadata(agent, label, description))
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../canvas/_text_canvas.py:108`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def add_or_update_file(self, filename: str, new_content: Union[str, bytes, Any]) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Prompt Injection (Taint Tracked) — `.../eval/judges.py:110`

**Confidence:** 92% | **OWASP:** ASI01

> [CONFIRMED] Untrusted input flows into LLM sink variable 'prompt' without sanitization

**Snippet:**
```
prompt = <tainted expression>
```

**Recommendation:** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### [!] Host Filesystem Mount Exposure — `.../magentic_one_cli/_m1.py:113`

**Confidence:** 95% | **OWASP:** N/A

> [CONFIRMED] DockerCommandLineCodeExecutor without read_only=True — container has unrestricted host filesystem write access

**Snippet:**
```
async with DockerCommandLineCodeExecutor(work_dir=os.getcwd()) as code_executor:
```

**Recommendation:** Always set read_only=True on DockerCommandLineCodeExecutor. Use volume mounts with explicit read-only options for any required host paths.

### [!] Multi-Agent Collusion — `.../mcp/wsbridge.py:114`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.send_message() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
await self.send_message(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Trust Boundary Violation — `.../_magentic_one/_magentic_one_orchestrator.py:119`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _get_task_ledger_facts_update_prompt(self, task: str, facts: str) -> str:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Host Filesystem Mount Exposure — `.../teams/magentic_one.py:122`

**Confidence:** 95% | **OWASP:** N/A

> [CONFIRMED] DockerCommandLineCodeExecutor without read_only=True — container has unrestricted host filesystem write access

**Snippet:**
```
async with DockerCommandLineCodeExecutor() as code_executor:
```

**Recommendation:** Always set read_only=True on DockerCommandLineCodeExecutor. Use volume mounts with explicit read-only options for any required host paths.

### [!] Trust Boundary Violation — `.../_magentic_one/_magentic_one_orchestrator.py:122`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _get_task_ledger_plan_update_prompt(self, team: str) -> str:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

*... and 213 more critical/high findings*

## Top Recommendations

- **Host Filesystem Mount Exposure:** Remove mount to sensitive path. Use named Docker volumes or restrict to app-specific directories with read_only access.
- **Unrestricted Tool Access:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.
- **Unsafe Code Execution:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.
- **Trust Boundary Violation:** Make agent code immutable at runtime. Use code signing and integrity checks.
- **Multi-Agent Collusion:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.
- **Prompt Injection:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.
- **Data Exfiltration Risk:** Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.
- **Prompt Injection (Taint Tracked):** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.
- **Credential Exposure:** Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.
- **Agent Memory Class Confusion:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.
- **Excessive Agency:** Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.
- **Agent Loop Exploitation:** Add recursion depth limit (e.g., if depth > MAX_DEPTH: return). Use iteration with explicit bounds instead of recursion for agent loops.
- **Prompt Template Injection:** Validate message structure before appending to conversation. Sanitize role fields. Use typed message objects.

---
*Report generated by [AgentGuard](https://github.com/dockfixlabs/agentguard) v0.8.0 — AI Agent Security Scanner*
*OWASP ASI Top 10 coverage | 22+ detection rules | Static analysis for AI agent codebases*