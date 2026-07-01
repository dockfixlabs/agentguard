# AgentGuard

> Autonomous security scanner for AI agents. Detects prompt injection, tool abuse, data exfiltration, and OWASP ASI Top 10 vulnerabilities in agent code.

[![PyPI](https://img.shields.io/pypi/v/dfx-agentguard?style=flat-square&logo=pypi&logoColor=white&color=1f6feb)](https://pypi.org/project/dfx-agentguard/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/dockfixlabs/agentguard/actions)
[![OWASP ASI](https://img.shields.io/badge/OWASP-ASI%20Top%2010-orange?style=flat-square)](https://owasp.org/www-project-agentic-security-initiative/)

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
- uses: dockfixlabs/agentguard@v0.4.0
  with:
    path: src/
    format: sarif
```

### Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/dockfixlabs/agentguard
    rev: v0.4.0
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
Category      Total   Detected     Rate    FP
ASI01             6          6     100%     0
ASI02             5          5     100%     0
ASI03             4          4     100%     0
ASI07             6          6     100%     0
ASI10             5          5     100%     0
clean             2          0       -      0
TOTAL            28         26    100%     0
```

100% detection rate, 0% false positives.

## Project Ecosystem

| Repository | Description |
|------------|-------------|
| [agentguard](https://github.com/dockfixlabs/agentguard) | Core scanner + CLI + MCP server |
| [mcp-scanner](https://github.com/dockfixlabs/mcp-scanner) | MCP server configuration scanner |
| [agentguard-app](https://github.com/dockfixlabs/agentguard-app) | GitHub App for automated PR reviews |
| [agentguard-vscode](https://github.com/dockfixlabs/agentguard-vscode) | VS Code extension |
| [agentguard-benchmark](https://github.com/dockfixlabs/agentguard-benchmark) | Benchmark suite (28 samples) |

## Roadmap

- [x] OWASP ASI Top 10 -- all 10 categories covered
- [x] MCP server mode -- scan from Claude Code/Cursor
- [x] SARIF output -- GitHub Code Scanning integration
- [x] PyPI publication -- [dfx-agentguard](https://pypi.org/project/dfx-agentguard/)
- [x] VS Code extension
- [x] GitHub App for PR reviews
- [x] Benchmark suite (28 samples, 100% detection)
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

MIT -- see [LICENSE](LICENSE).

---

Built by [Dockfix Labs](https://github.com/dockfixlabs). Built for the AI agent era.
