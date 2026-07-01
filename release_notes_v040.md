## v0.4.0 - Semantic Detection + Adversarial Hardening

### Headline

**7/7 real-world attack patterns detected, 0 false positives.** AgentGuard now catches threats that regex alone missed.

### New Detection Capabilities

- **ASI06 Insecure Output Handling**: Detects LLM output rendered as HTML (XSS via prompt injection), innerHTML assignments, document.write with agent output, markdown rendering without sanitization.
- **ASI09 Agent Loop Exploitation**: Detects recursive function calls without depth limits (indent-aware scope tracking eliminates false positives on non-recursive calls).
- **ASI01 Tool Description Poisoning**: Detects prompt injection payloads embedded in MCP tool descriptions ("Ignore previous instructions", "Always call this tool first").
- **ASI01 Context Stuffing**: Detects padding attacks that push out system prompts (e.g., "A" * 100000).

### Adversarial Test Suite

Added 8 real-world attack patterns beyond the benchmark:

| Pattern | Detected |
|---------|----------|
| Indirect prompt injection (DB -> prompt) | YES (3 findings) |
| Tool description poisoning | YES (2 findings) |
| Gradual data exfiltration (chunked) | YES |
| Recursive agent loop (no depth limit) | YES |
| Runtime supply chain (__import__) | YES |
| Context window stuffing | YES |
| Output injection (HTML f-string) | YES (3 findings) |
| Safe env var access (negative test) | Correctly skipped |

### Improved

- **ASI09 recursion detection**: Now uses indent-aware scope tracking. Only flags functions that call themselves within their own body. Eliminates false positives where function A calls function B.
- **ASI06 output patterns**: 6 new regex patterns for HTML/JSX/DOM injection via LLM output.
- **Tests**: 32 tests (up from 26). Added adversarial real-world pattern tests.

### Benchmark Results

```
ASI01: 6/6 (100%)    ASI02: 5/5 (100%)    ASI03: 4/4 (100%)
ASI07: 6/6 (100%)    ASI10: 5/5 (100%)    clean: 0 FP
Detection rate: 100%  False positives: 0
```

### Install

```bash
pip install --upgrade dfx-agentguard
agentguard . --format text
```
