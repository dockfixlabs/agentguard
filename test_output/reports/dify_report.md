# AgentGuard Security Audit Report

**Tool:** AgentGuard v0.8.0 | **Date:** 2026-07-08 19:59 UTC
**Target:** `../dify-audit` | **Files scanned:** 2030
**Scan duration:** 0ms

## Executive Summary

| Metric | Value |
|--------|-------|
| Total findings | 1687 |
| CRITICAL | 955 |
| HIGH | 561 |
| MEDIUM | 44 |
| LOW | 127 |
| INFO | 0 |
| Risk Score | 12570 |
| Health | **CRITICAL — Large number of critical findings requiring immediate attention** |

## Classification

| Category | Count | Description |
|----------|-------|-------------|
| CONFIRMED | 216 | Actionable, high-confidence vulnerabilities |
| INVESTIGATE | 868 | Needs human review |
| BEST_PRACTICE | 17 | Security pattern, not exploitable |
| LIKELY_FP | 586 | Probable false positive |

## Top Detection Rules

| Rule | Count | Severity |
|------|-------|----------|
| Multi-Agent Collusion | 918 | CRITICAL |
| Agent Loop Exploitation | 459 | HIGH |
| Trust Boundary Violation | 134 | CRITICAL |
| Unsafe Code Execution | 38 | CRITICAL |
| Agent Memory Class Confusion | 33 | CRITICAL |
| Prompt Injection | 33 | CRITICAL |
| Unrestricted Tool Access | 31 | CRITICAL |
| Data Exfiltration Risk | 17 | HIGH |
| Action Chain Amplification | 8 | CRITICAL |
| Credential Exposure | 6 | CRITICAL |

## Most Affected Files

| File | Findings |
|------|----------|
| .../workspace/tool_providers.py | 38 |
| .../workspace/rbac.py | 34 |
| .../workspace/plugin.py | 31 |
| .../rag_pipeline/rag_pipeline_workflow.py | 28 |
| .../app/workflow.py | 28 |
| .../app/agent_config_inspector.py | 26 |
| .../datasets/datasets_document.py | 24 |
| .../agent/roster.py | 20 |
| .../workspace/account.py | 19 |
| ..\dify-audit\api\extensions\ext_redis.py | 18 |

## OWASP ASI Coverage

| Category | Findings |
|----------|----------|
| ASI09 | 459 |
| ASI10 | 134 |
| ASI06 | 38 |
| ASI01 | 34 |
| ASI02 | 31 |
| ASI03 | 17 |
| ASI07 | 6 |
| ASI08 | 5 |
| ASI05 | 1 |

## Critical & High Findings

### [!] Unsafe Code Execution — `.../utils/prompt_template_parser.py:4`

**Confidence:** 85% | **OWASP:** ASI06

> [CONFIRMED] compile() with user input -- code compilation from untrusted data

**Snippet:**
```
REGEX = re.compile(r"\{\{([a-zA-Z_][a-zA-Z0-9_]{0,29}|#histories#|#query#|#context#)\}\}")
```

**Recommendation:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.

### [!] Unrestricted Tool Access — `.../shell/configs.py:7`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
Agent Stub drive ref used by shell-visible drive commands.
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\openapi\index.py:8`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@openapi_ns.route("/_health")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Unrestricted Tool Access — `..\dify-audit\api\commands\data_migrate.py:10`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
from commands.rbac import migrate_dataset_permissions_to_rbac
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\web\feature.py:10`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@web_ns.route("/system-features")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\service_api\index.py:11`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@service_api_ns.route("/")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Trust Boundary Violation — `.../services/conversation_variable_updater.py:16`

**Confidence:** 85% | **OWASP:** ASI10

> [CONFIRMED] Agent can modify its own code -- self-modification attack vector

**Snippet:**
```
def update(self, conversation_id: str, variable: VariableBase) -> None:
```

**Recommendation:** Make agent code immutable at runtime. Use code signing and integrity checks.

### [!] Unrestricted Tool Access — `..\dify-audit\api\core\helper\csv_sanitizer.py:16`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
in a spreadsheet application, potentially executing malicious commands.
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\openapi\_meta.py:16`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@openapi_ns.route("/_version")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../app/site.py:16`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@service_api_ns.route("/site")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../end_user/end_user.py:16`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@service_api_ns.route("/end-users/<uuid:end_user_id>")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\trigger\trigger.py:17`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@bp.route("/plugin/<string:endpoint_id>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../dataset/hit_testing.py:17`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@service_api_ns.route("/datasets/<uuid:dataset_id>/hit-testing", "/datasets/<uuid:dataset_id>/retrieve")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `..\dify-audit\api\extensions\ext_app_metrics.py:20`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@app.route("/health")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Agent Memory Class Confusion — `.../telemetry/id_generator.py:22`

**Confidence:** 88% | **OWASP:** N/A

> [CONFIRMED] Memory/context/state update without authorization check — untrusted code can modify agent execution state

**Snippet:**
```
_correlation_id_context.set(correlation_id)
```

**Recommendation:** All memory updates must be guarded by authorization checks. Implement immutable memory with append-only logs and cryptographic verification.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\web\files.py:22`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@web_ns.route("/files/upload")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\openapi\app_dsl.py:23`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@openapi_ns.route("/workspaces/<string:workspace_id>/apps/imports")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\web\saved_message.py:23`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@web_ns.route("/saved-messages")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Supply Chain Risk — `.../services/recommended_app_service.py:25`

**Confidence:** 95% | **OWASP:** ASI05

> [CONFIRMED] Executing code downloaded from network — remote code execution

**Snippet:**
```
RecommendAppRetrievalFactory.get_buildin_recommend_app_retrieval().fetch_recommended_apps_from_builtin(
```

**Recommendation:** Never execute downloaded code. Verify integrity with hashes. Use signed packages only.

### [!] Multi-Agent Collusion — `.../app/file.py:25`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@service_api_ns.route("/files/upload")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../workspace/models.py:26`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@service_api_ns.route("/workspaces/current/models/model-types/<string:model_type>")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../explore/saved_message.py:26`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@console_ns.route("/installed-apps/<uuid:installed_app_id>/saved-messages", endpoint="installed_app_saved_messages")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\console\spec.py:27`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@console_ns.route("/spec/schema-definitions")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../explore/parameter.py:27`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@console_ns.route("/installed-apps/<uuid:installed_app_id>/parameters", endpoint="installed_app_parameters")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../rag_pipeline/datasource_content_preview.py:27`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@console_ns.route("/rag/pipelines/<uuid:pipeline_id>/workflows/published/datasource/nodes/<string:node_id>/preview")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `..\dify-audit\api\extensions\ext_app_metrics.py:28`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@app.route("/threads")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Unrestricted Tool Access — `.../workflow/command_channels.py:29`

**Confidence:** 90% | **OWASP:** ASI02

> [CONFIRMED] Dangerous system-level tool accessible to agent — code execution capability

**Snippet:**
```
commands.extend(channel.fetch_commands())
```

**Recommendation:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.

### [!] Multi-Agent Collusion — `..\dify-audit\api\controllers\openapi\files.py:29`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@openapi_ns.route("/apps/<string:app_id>/files/upload")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../workspace/workspace.py:29`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@inner_api_ns.route("/enterprise/workspace")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

### [!] Multi-Agent Collusion — `.../datasets/hit_testing.py:30`

**Confidence:** 80% | **OWASP:** N/A

> [INVESTIGATE] Inter-agent communication (.route() without trust verification -- agents can collude through unvalidated messages

**Snippet:**
```
@console_ns.route("/datasets/<uuid:dataset_id>/hit-testing")
```

**Recommendation:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.

*... and 1486 more critical/high findings*

## Top Recommendations

- **Unsafe Code Execution:** Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.
- **Unrestricted Tool Access:** Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.
- **Multi-Agent Collusion:** Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.
- **Trust Boundary Violation:** Make agent code immutable at runtime. Use code signing and integrity checks.
- **Agent Memory Class Confusion:** All memory updates must be guarded by authorization checks. Implement immutable memory with append-only logs and cryptographic verification.
- **Supply Chain Risk:** Never execute downloaded code. Verify integrity with hashes. Use signed packages only.
- **Credential Exposure:** Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.
- **Action Chain Amplification:** Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.
- **Prompt Injection:** Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.
- **Prompt Injection (Taint Tracked):** Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.
- **Agent Memory Poisoning:** Validate and sanitize ALL data before writing to vector stores, RAG databases, or agent memory. Use content filtering, input validation, and origin verification.
- **Agent Loop Exploitation:** Add recursion depth limit (e.g., if depth > MAX_DEPTH: return). Use iteration with explicit bounds instead of recursion for agent loops.
- **Data Exfiltration Risk:** Whitelist allowed domains. Proxy all external requests through a filtering layer. Log and alert on unexpected outbound traffic.
- **Prompt Template Injection:** Validate message structure before appending to conversation. Sanitize role fields. Use typed message objects.
- **Context Window Manipulation:** Set explicit max_tokens and max_input_length. Truncate or summarize long inputs before sending to LLM.

---
*Report generated by [AgentGuard](https://github.com/dockfixlabs/agentguard) v0.8.0 — AI Agent Security Scanner*
*OWASP ASI Top 10 coverage | 22+ detection rules | Static analysis for AI agent codebases*