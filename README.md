# AgentGuard

> Autonomous security scanner for AI agents. Detects prompt injection, tool abuse, data exfiltration, and OWASP ASI Top 10 vulnerabilities in agent code.

[![PyPI](https://img.shields.io/pypi/v/dfx-agentguard?style=flat-square&logo=pypi&logoColor=white&color=1f6feb)](https://pypi.org/project/dfx-agentguard/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/dockfixlabs/agentguard/actions)
[![OWASP ASI](https://img.shields.io/badge/OWASP-ASI%20Top%2010-orange?style=flat-square)](https://genai.owasp.org/)

---

## Why AgentGuard?

AI agents are being deployed at scale -- in coding tools, customer support, trading bots, and autonomous systems. Nobody is scanning their code for security vulnerabilities.

Existing tools (Bandit, Semgrep, CodeQL) scan for traditional vulnerabilities. AgentGuard scans for **agent-specific** attack vectors that traditional SAST tools miss.

### Comparison

| Feature | AgentGuard | Semgrep | CodeQL | Bandit |
|---------|-----------|---------|--------|--------|
| Prompt Injection (ASI01) | Yes + AST taint | No | No | No |
| Tool Abuse (ASI02) | Yes | No | No | Partial |
| Data Exfiltration (ASI03) | Yes | No | No | No |
| Excessive Agency (ASI04) | Yes | No | No | No |
| Supply Chain (ASI05) | Yes | No | No | No |
| Insecure Output (ASI06) | Yes | No | No | No |
| Credential Exposure (ASI07) | Yes | Partial | Partial | Yes |
| Context Manipulation (ASI08) | Yes | No | No | No |
| Agent Loop Exploitation (ASI09) | Yes | No | No | No |
| Trust Boundary (ASI10) | Yes | No | No | No |
| AST Taint Tracking | Yes | No | No | No |
| OWASP ASI Top 10 Coverage | 10/10 | 1/10 | 1/10 | 2/10 |
| MCP Server Mode | Yes | No | No | No |
| SARIF Output | Yes | Yes | Yes | No |
| Pre-commit Hook | Yes | Yes | No | No |
| GitHub Action | Yes | Yes | Yes | No |

*Comparison based on author's assessment of default rule sets (v0.8.1 vs Semgrep OSS v1.x, CodeQL default queries, Bandit v1.7). "Partial" indicates some coverage via general-purpose rules but no agent-specific detection.*

## Live Demo

See AgentGuard in action on the [demo repo](https://github.com/dockfixlabs/agentguard-demo). The CI runs AgentGuard on every push, and findings appear in GitHub Code Scanning.



## Precision & Validation

AgentGuard's precision has been independently measured:

| Metric | Value |
|--------|-------|
| **Precision (independent sample)** | **88%** (44 TP / 6 FP) |
| Sample size | 50 CONFIRMED findings |
| Frameworks covered | 7 (CAMEL, Qwen-Agent, LangChain, CrewAI, AutoGen, LlamaIndex, Dify) |
| Validation method | Manual source code inspection at each reported line |
| FP filter effectiveness | 32 systematic FP patterns eliminated (from 36% to 88%) |
| License | LGPL v3 — free for individuals and OSS, paid for enterprise |

**All 6 remaining FPs fixed in v0.8.1** (single pattern: `def _update_prompts`).

**Methodology:** 50 findings were randomly sampled from 951 CONFIRMED results, 
completely disjoint from the development/fix sample. Each finding was verified by 
reading the actual source code at the reported line with surrounding context.


## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full 2026–2027 roadmap. Current phase: **Phase 1 — Prove Technical Value** (complete). Next: **Phase 2 — Build Audience**.


## Sovereign Security Audit 2026

AgentGuard was deployed against 7 major AI agent frameworks:

| Framework | Files | Findings | CONFIRMED | Risk Score |
|-----------|-------|----------|-----------|------------|
| Dify | 2,030 | 1,687 | 216 | 12,570 |
| LlamaIndex | 2,951 | 1,080 | 294 | 6,341 |
| CrewAI | 1,042 | 1,317 | 99 | 6,392 |
| LangChain | 1,831 | 436 | 132 | 2,653 |
| AutoGen | 553 | 696 | 98 | 2,696 |
| CAMEL | 355 | 147 | 62 | 946 |
| Qwen-Agent | 238 | 242 | 50 | 1,325 |
| **TOTAL** | **9,000** | **5,605** | **951** | **32,923** |

**Full report:** [AUDIT_REPORT_2026.md](AUDIT_REPORT_2026.md)

AgentGuard is the **first and only** static analysis tool with dedicated OWASP ASI Top 10 rules.
Traditional SAST tools (Semgrep, CodeQL, Bandit) lack agent-specific detection rules --
they were designed for traditional vulnerabilities, not AI agent attack vectors.

[Benchmark Dashboard](https://dockfixlabs.github.io/agentguard-benchmark/)


**Security Specification:** [specification.md](specification.md) — the formal standard for AI agent code security.

## Quick Start

```bash
pip install dfx-agentguard

# Scan a directory
agentguard .

# JSON output for CI/CD
agentguard src/ --format json

# SARIF for GitHub Code Scanning
agentguard . --format sarif > results.sarif

# Only show HIGH and above
agentguard . --min-severity HIGH

# Include test files in scan
agentguard . --include-tests
```

## CLI Usage

```
agentguard [OPTIONS] [TARGET]

Arguments:
  TARGET                   Directory or file to scan (default: current directory)

Options:
  --format [text|json|sarif]   Output format (default: text)
  --exit-code / --no-exit-code  Exit non-zero if findings found (default: on)
  --min-severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]  Minimum severity to report
  --include-tests               Include test files in scan (default: skip)
  --no-fp-filter                Disable false positive filtering
  --no-classify                 Disable finding classification
  --auto-report PATH            Generate auto Markdown audit report
  --ci                          CI/CD concise output mode
  --help                        Show help
```

## OWASP ASI Top 10 Coverage

| ID | Vulnerability | Status | Detection Method |
|----|--------------|--------|-----------------|
| ASI01 | Prompt Injection | Detected | f-string, .format(), messages array, context stuffing, tool description poisoning |
| ASI02 | Tool Abuse / Unintended Tool Use | Detected | os.system, subprocess, shell tools, unrestricted registration |
| ASI03 | Data Exfiltration | Detected | External URLs, variable URL correlation, fetch/axios, subprocess curl, DNS exfil |
| ASI04 | Unauthorized Actions / Excessive Agency | Detected | Auto-execute, no confirmation, autonomous actions |
| ASI05 | Supply Chain / Untrusted Components | Detected | Dynamic import, unpinned deps, untrusted pip install |
| ASI06 | Insecure Output Handling | Detected | LLM output in HTML/JSX/DOM, innerHTML, document.write, markdown.render |
| ASI07 | Credential / Secret Exposure | Detected | API keys (sk-, ghp_, AKIA, AIza, xox), private keys, passwords, connection strings |
| ASI08 | Context Window Manipulation | Detected | Unbounded context, token stuffing, missing limits |
| ASI09 | Agent Loop Exploitation | Detected | Recursive calls without depth limit, while True, no max iterations |
| ASI10 | Trust Boundary Violation | Detected | Root access, host filesystem mounts, no sandbox, self-modification |

## CI/CD Integration

### Docker — Run Anywhere

```bash
docker run --rm -v $(pwd):/workspace ghcr.io/dockfixlabs/agentguard .
```

Works in any CI/CD pipeline. No Python needed.

### GitHub Action

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  agentguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install dfx-agentguard
      - run: agentguard . --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Drop-in GitHub Action

```yaml
- uses: dockfixlabs/agentguard@v0.8.1
  with:
    path: src/
    format: sarif
```

### Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/dockfixlabs/agentguard
    rev: v0.8.1
    hooks:
      - id: agentguard
        args: ["--min-severity", "HIGH"]
```

## Programmatic Usage

```python
from agentguard.scanner import scan_directory

result = scan_directory("src/")

print(f"Found {len(result.findings)} issues")
print(f"Critical: {result.critical_count}")
print(f"High: {result.high_count}")

for finding in result.findings:
    print(f"  [{finding.severity}] {finding.rule_name} at {finding.file}:{finding.line}")
```

## MCP Server Mode

Scan agent code directly from Claude Code, Cursor, or any MCP-compatible client:

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "python3",
      "args": ["-m", "agentguard.mcp_server"]
    }
  }
}
```

Then ask Claude: "Scan my agent code for security vulnerabilities"

## Benchmark Results

Tested against 28 vulnerable code samples + 8 real-world attack patterns:

```
Category      Total   Detected     Coverage
ASI01             6          6    Covered
ASI02             5          5    Covered
ASI03             4          4     Covered
ASI07             6          6     Covered
ASI10             5          5     Covered
clean             2          0    Verified clean
TOTAL            28         26    —
```

The complete [benchmark suite](https://github.com/dockfixlabs/agentguard-benchmark) contains 56 hand-crafted samples covering all detection rules.

## Project Ecosystem

| Repository | Description |
|------------|-------------|
| [agentguard](https://github.com/dockfixlabs/agentguard) | Core scanner + CLI + MCP server |
| [mcp-scanner](https://github.com/dockfixlabs/mcp-scanner) | MCP server configuration scanner |
| [agentguard-app](https://github.com/dockfixlabs/agentguard-app) | GitHub App for automated PR reviews |
| [agentguard-vscode](https://github.com/dockfixlabs/agentguard-vscode) | VS Code extension |
| [agentguard-benchmark](https://github.com/dockfixlabs/agentguard-benchmark) | Benchmark suite (56 samples) |

## Roadmap

- [x] OWASP ASI Top 10 -- all 10 categories covered
- [x] MCP server mode -- scan from Claude Code/Cursor
- [x] SARIF output -- GitHub Code Scanning integration
- [x] PyPI publication -- [dfx-agentguard](https://pypi.org/project/dfx-agentguard/)
- [x] VS Code extension
- [x] GitHub App for PR reviews
- [x] Benchmark suite (28 samples, covering all detection rules)
- [x] Pre-commit hook (.pre-commit-hooks.yaml)
- [x] GitHub Action (action.yml)
- [x] Dockerfile for agentguard-app
- [x] PyPI Trusted Publishing (OIDC)
- [x] AST-based taint tracking (v0.5.0) -- traces source-to-sink data flow
- [ ] Language support: Rust, Go, Java
- [ ] Web dashboard (SaaS)
- [ ] REST API (Scan-as-a-Service)

See the full [ROADMAP.md](ROADMAP.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and feature requests welcome.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately -- do not open public issues.

## License

LGPL v3 -- see [LICENSE](LICENSE). AI agent SAST is a new category. The LGPL ensures the core remains open while protecting against cloud vendor appropriation (learned from Bandit's Apache 2.0 → $0 revenue path).

---

Built by [Dockfix Labs](https://github.com/dockfixlabs). Built for the AI agent era.


---

## AgentGuard Ecosystem

**[AgentGuard](https://github.com/dockfixlabs/agentguard)** is the core security scanner. Companion tools:

| Tool | Purpose | Install |
|------|---------|---------|
| [agentguard](https://github.com/dockfixlabs/agentguard) | AI agent code security scanner | `pip install dfx-agentguard` |
| [mcp-scanner](https://github.com/dockfixlabs/mcp-scanner) | MCP server security audit | `pip install dfx-mcp-scanner` |
| [agentguard-app](https://github.com/dockfixlabs/agentguard-app) | GitHub App for PR reviews | Install from Marketplace |
| [agentguard-vscode](https://github.com/dockfixlabs/agentguard-vscode) | VS Code inline diagnostics | Install from VS Code |
| [agentguard-benchmark](https://github.com/dockfixlabs/agentguard-benchmark) | Detection benchmark suite | `git clone` |
| [agentguard-demo](https://github.com/dockfixlabs/agentguard-demo) | Live demo with Code Scanning | `git clone` |

**22 detection rules | 139 tests | 28 benchmark samples | OWASP ASI Top 10 | 88% precision**
**GitHub Action:** [dockfixlabs/agentguard@v1](https://github.com/marketplace/actions/agentguard-security-scan)
