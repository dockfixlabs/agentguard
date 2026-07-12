# AgentGuard Security Audit Report

**Tool:** AgentGuard v0.8.0 | **Date:** 2026-07-08 19:43 UTC
**Target:** `../crewai-audit` | **Files scanned:** 1042
**Scan duration:** 96190ms

## Executive Summary

| Metric | Value |
|--------|-------|
| Total findings | 1317 |
| CRITICAL | 358 |
| HIGH | 311 |
| MEDIUM | 609 |
| LOW | 39 |
| INFO | 0 |
| Risk Score | 6392 |
| Health | **CRITICAL — Large number of critical findings requiring immediate attention** |

## Classification

| Category | Count | Description |
|----------|-------|-------------|
| CONFIRMED | 99 | Actionable, high-confidence vulnerabilities |
| INVESTIGATE | 300 | Needs human review |
| BEST_PRACTICE | 559 | Security pattern, not exploitable |
| LIKELY_FP | 359 | Probable false positive |
| FP Removed | 59 | Auto-filtered false positives |
| FP Downgraded | 39 | Severity reduced |

## Top Detection Rules

| Rule | Count | Severity |
|------|-------|----------|
| Data Exfiltration Risk | 560 | CRITICAL |
| Multi-Agent Collusion | 285 | CRITICAL |
| Agent Loop Exploitation | 252 | HIGH |
| Unrestricted Tool Access | 77 | CRITICAL |
| Trust Boundary Violation | 45 | CRITICAL |
| Unsafe Code Execution | 37 | CRITICAL |
| Agent Memory Class Confusion | 32 | CRITICAL |
| Excessive Agency | 10 | CRITICAL |
| Prompt Injection (Taint Tracked) | 6 | CRITICAL |
| Prompt Injection | 6 | CRITICAL |

## Most Affected Files

| File | Findings |
|------|----------|
| .../crewai_devtools/cli.py | 69 |
| .../agent/core.py | 34 |
| .../experimental/agent_executor.py | 21 |
| .../tools/tool_usage.py | 16 |
| .../memory/unified_memory.py | 15 |
| ..\crewai-audit\lib\crewai\src\crewai\crew.py | 15 |
| .../state/runtime.py | 13 |
| ..\crewai-audit\lib\crewai\src\crewai\llm.py | 13 |
| .../utilities/agent_utils.py | 12 |
| .../streaming/handler.py | 11 |

## OWASP ASI Coverage

| Category | Findings |
|----------|----------|
| ASI03 | 560 |
| ASI09 | 252 |
| ASI02 | 77 |
| ASI10 | 45 |
| ASI06 | 37 |
| ASI01 | 15 |
| ASI04 | 10 |
| ASI07 | 1 |

## Critical & High Findings

### [!] Trust Boundary Violation — `.../content_crew/content_crew.py:23`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def writer(self) -> Agent:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../utilities/task_output_storage_handler.py:29`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def update(self, task_index: int, log: dict[str, Any]) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../content_crew/content_crew.py:29`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def editor(self) -> Agent:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Multi-Agent Collusion — `.../utilities/env.py:33`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.emit() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
crewai_event_bus.emit(None, CCEnvEvent())
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../utilities/env.py:35`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.emit() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
crewai_event_bus.emit(None, CodexEnvEvent())
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../utilities/env.py:37`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.emit() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
crewai_event_bus.emit(None, CursorEnvEvent())
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../utilities/env.py:39`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.emit() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
crewai_event_bus.emit(None, DefaultEnvEvent())
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Excessive Agency — `.../crewai_core/settings.py:41`

**Confidence:** 90% | **OWASP:** ASI04

> [CONFIRMED] Agent can escalate privileges — sudo/chmod/setuid access

**Snippet:**
```
directory.chmod(0o700)
```

**Recommendation:** Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.

### [!] Trust Boundary Violation — `.../crews/crew_output.py:43`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
output_dict.update(self.json_dict)
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../crews/crew_output.py:45`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
output_dict.update(self.pydantic.model_dump())
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../daytona_sandbox_tool/daytona_exec_tool.py:47`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
response = sandbox.process.exec(
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Unsafe Code Execution — `.../daytona_sandbox_tool/daytona_exec_tool.py:47`

**Confidence:** 95% | **OWASP:** ASI06

> [CONFIRMED] exec() -- arbitrary code execution

**Snippet:**
```
response = sandbox.process.exec(
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Trust Boundary Violation — `.../content_crew/content_crew.py:47`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def editing_task(self) -> Task:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Data Exfiltration Risk — `.../contextualai_query_tool/contextual_query_tool.py:48`

**Confidence:** 90% | **OWASP:** ASI03

> [CONFIRMED] Secret accessed then sent to external URL -- active exfiltration

**Snippet:**
```
***REDACTED***
```

**Recommendation:** Isolate secret access from network code. Use secret managers that do not expose values to agent context.

### [!] Trust Boundary Violation — `.../flow/main.py:50`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
f.write(self.state.final_post)
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../e2b_sandbox_tool/e2b_exec_tool.py:54`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
result = sandbox.commands.run(command, **run_kwargs)
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Excessive Agency — `.../crewai_core/settings.py:58`

**Confidence:** 90% | **OWASP:** ASI04

> [CONFIRMED] Agent can escalate privileges — sudo/chmod/setuid access

**Snippet:**
```
os.chmod(tmp, 0o600)
```

**Recommendation:** Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.

### [!] Trust Boundary Violation — `.../utils/console_formatter.py:59`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def _show_version_update_message_if_needed(self) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Multi-Agent Collusion — `.../skills/loader.py:60`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.emit() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
crewai_event_bus.emit(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Unrestricted Tool Access — `.../transports/stdio.py:61`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
self._process: subprocess.Popen[bytes] | None = None
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Trust Boundary Violation — `.../transports/base.py:62`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def write_stream(self) -> MCPWriteStream:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../crewai_core/token_manager.py:63`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
self._atomic_write_secure_file(self.file_path, encrypted_data)
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `.../crewai_devtools/cli.py:65`

**Confidence:** 27% | **OWASP:** ASI02

> [LIKELY_FP] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
def run_command(cmd: list[str], cwd: Path | None = None) -> str:
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Trust Boundary Violation — `.../cache/metrics.py:65`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
result.update(self.metadata)
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Trust Boundary Violation — `.../flow/flow_wrappers.py:65`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
functools.update_wrapper(self, meth, updated=[])
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Agent Memory Class Confusion — `.../processing/processor.py:68`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Agent class mutates system_prompt/instructions — governance bypass via prompt self-modification

**Snippet:**
```
self.constraints = resolved
```

**Recommendation:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.

### [!] Agent Memory Class Confusion — `.../processing/processor.py:70`

**Confidence:** 90% | **OWASP:** N/A

> [CONFIRMED] Agent class mutates system_prompt/instructions — governance bypass via prompt self-modification

**Snippet:**
```
self.constraints = constraints
```

**Recommendation:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.

### [!] Multi-Agent Collusion — `.../skills/loader.py:78`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.emit() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
crewai_event_bus.emit(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../push_notifications/handler.py:81`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.emit() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
crewai_event_bus.emit(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../evaluators/task_evaluator.py:82`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.emit() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
crewai_event_bus.emit(
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

*... and 639 more critical/high findings*

## Top Recommendations

- **Trust Boundary Violation:** Make agent code immutable at runtime. Use code signing and integrity checks.
- **Multi-Agent Collusion:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.
- **Excessive Agency:** Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.
- **Unrestricted Tool Access:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.
- **Unsafe Code Execution:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.
- **Data Exfiltration Risk:** Isolate secret access from network code. Use secret managers that do not expose values to agent context.
- **Agent Memory Class Confusion:** System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.
- **Prompt Injection (Taint Tracked):** Sanitize user input before passing to LLM APIs. Use structured message arrays. Validate and filter all user-controlled data.
- **Credential Exposure:** Remove immediately. Rotate the key. Use secret manager or HSM for private keys.
- **Prompt Injection:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.
- **Cross-Function Taint Flow:** Sanitize data before passing to LLM-interacting functions.
- **Action Chain Amplification:** Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.
- **Agent Memory Poisoning:** Validate and sanitize ALL data before writing to vector stores, RAG databases, or agent memory. Use content filtering, input validation, and origin verification.
- **Agent Loop Exploitation:** Add recursion depth limit (e.g., if depth > MAX_DEPTH: return). Use iteration with explicit bounds instead of recursion for agent loops.
- **Prompt Template Injection:** Validate message structure before appending to conversation. Sanitize role fields. Use typed message objects.

---
*Report generated by [AgentGuard](https://github.com/dockfixlabs/agentguard) v0.8.0 — AI Agent Security Scanner*
*OWASP ASI Top 10 coverage | 22+ detection rules | Static analysis for AI agent codebases*