# SPECIFICATION.md — AgentGuard Detection Rules

## Overview

AgentGuard implements 22 detection rules mapped to CWE and CVSS, covering OWASP ASI Top 10 plus 6 novel attack vectors discovered during framework auditing.

## Rule Table

| Rule ID | Name | OWASP ASI | CWE | Default CVSS | Description |
|---------|------|-----------|-----|--------------|-------------|
| ASI01 | Prompt Injection | ASI01 | CWE-74 | 8.8 | User input flows into LLM prompts without sanitization (f-strings, concat, templates) |
| ASI02 | Tool Abuse | ASI02 | CWE-94 | 9.0 | Unrestricted `os.system()`, `subprocess.run()`, `eval()` on untrusted input |
| ASI03 | Tool Output Trust | ASI03 | CWE-345 | 8.6 | Agents consuming tool results without validation |
| ASI04 | Goal Manipulation | ASI04 | CWE-642 | 7.5 | Agent goal/objective modified via external input |
| ASI05 | Chain Amplification | ASI05 | CWE-834 | 7.5 | Destructive operations inside unbounded loops |
| ASI06 | Agent Impersonation | ASI06 | CWE-290 | 6.5 | Agent identity spoofing via output injection |
| ASI07 | Credential Leak | ASI07 | CWE-798 | 9.8 | Hardcoded API keys, tokens, secrets in source code |
| ASI08 | Supply Chain | ASI08 | CWE-506 | 8.6 | Unpinned dependencies, unsigned packages |
| ASI09 | Agent Loop Abuse | ASI09 | CWE-835 | 7.5 | Infinite retry/recursion without rate limits |
| ASI10 | Agent Collusion | ASI10 | CWE-265 | 6.8 | Shared mutable state between agents without access controls |
| NOVEL-1 | Memory Poisoning | — | CWE-502 | 8.2 | Untrusted data written to vector DBs without validation |
| NOVEL-2 | Memory Class Confusion | — | CWE-863 | 7.8 | Agent memory type confusion enabling privilege escalation |
| NOVEL-3 | Prompt Template Injection | — | CWE-74 | 8.8 | Jinja2/f-string injection in prompt construction BEFORE LLM |
| NOVEL-4 | Steganographic Injection | — | CWE-506 | 9.0 | base64/hex/ROT13-encoded commands in tool parameters |
| NOVEL-5 | Mount Exposure | — | CWE-732 | 8.6 | Docker executor exposing host filesystem |
| NOVEL-6 | Excessive Agency | — | CWE-269 | 9.0 | Agent granted unnecessary system privileges |
| — | Unsafe Eval | — | CWE-95 | 9.8 | Dynamic code execution via `eval()`, `exec()`, `compile()` |
| — | Data Exfiltration | — | CWE-200 | 7.5 | Agent sending data to external endpoints |
| — | Trust Boundary | — | CWE-250 | 8.1 | Execution with unnecessary privileges |
| — | Context Manipulation | — | CWE-349 | 7.5 | Agent context/state modified by untrusted input |
| — | Dockerfile Security | — | CWE-269 | 7.8 | Insecure Docker configurations for agent containers |
| — | Taint Tracking | — | CWE-79 | 7.5 | Untrusted data flowing to sensitive sinks |

## Severity Mapping

| Severity | CVSS Range | Description |
|----------|------------|-------------|
| CRITICAL | ≥ 9.0 | Direct system compromise |
| HIGH | 7.0–8.9 | Significant security impact |
| MEDIUM | 4.0–6.9 | Limited impact, requires conditions |
| LOW | 0.1–3.9 | Minor security concern |

## Detection Methodology

AgentGuard uses static code analysis with abstract syntax tree (AST) pattern matching. Each rule defines:

1. **Regex patterns**: String-level detection for known-dangerous patterns
2. **AST visitors**: Tree-level detection for structural vulnerabilities
3. **Cross-file analysis**: Inter-procedural and cross-module taint tracking

## Compliance

- **OWASP ASI Top 10 2025**: Full coverage of all 10 categories
- **CWE Compatibility**: All rules mapped to CWE identifiers
- **CVSS v3.1**: Severity scoring per NVD standards
- **MIT License**: Open source, no restrictions

## References

- [OWASP Agentic Security Initiative Top 10](https://owasp.org/ASI/)
- [NVD CVSS v3.1 Specification](https://www.first.org/cvss/v3-1/)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)
