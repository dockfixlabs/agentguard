# 🛡️ AgentGuard

> **Autonomous security scanner for AI agents.** Detects prompt injection, tool abuse, data exfiltration, and OWASP ASI Top 10 vulnerabilities in agent code.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/dockfixlabs/agentguard/actions)
[![OWASP ASI](https://img.shields.io/badge/OWASP-ASI%20Top%2010-orange?style=flat-square)](https://owasp.org/www-project-agentic-security-initiative/)

---

## Why AgentGuard?

AI agents are being deployed at scale — in coding tools, customer support, trading bots, and autonomous systems. **Nobody is scanning their code for security vulnerabilities.**

Existing tools (Bandit, Semgrep, CodeQL) scan for traditional vulnerabilities. AgentGuard scans for **agent-specific** attack vectors:

- 📥 **Prompt Injection** — untrusted input reaching LLM prompts
- 🔧 **Tool Abuse** — agents with unrestricted shell/exec access
- 📤 **Data Exfiltration** — agents leaking data to external URLs
- 🔑 **Credential Exposure** — hardcoded API keys and wallet seeds
- ⚡ **Unsafe Eval** — `eval()`, `exec()`, `subprocess(shell=True)` with user input
- 🧠 **Context Manipulation** — unbounded context window attacks
- 🏰 **Trust Boundary Violations** — agents running as root, accessing host filesystem

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
```

## CLI Usage

```
agentguard [OPTIONS] [TARGET]

Arguments:
  TARGET  Directory or file to scan (default: current directory)

Options:
  --format [text|json|sarif]  Output format (default: text)
  --exit-code / --no-exit-code  Exit non-zero if findings found (default: on)
  --min-severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]  Minimum severity to report
  --help  Show help
```

## OWASP ASI Top 10 Coverage

| ID | Vulnerability | Status |
|----|--------------|--------|
| ASI01 | Prompt Injection | ✅ |
| ASI02 | Tool Abuse / Unintended Tool Use | ✅ |
| ASI03 | Data Exfiltration / Sensitive Data Leakage | ✅ |
| ASI04 | Unauthorized Actions / Excessive Agency | ✅ |
| ASI05 | Supply Chain / Untrusted Components | ✅ |
| ASI06 | Insecure Output Handling | ✅ |
| ASI07 | Credential / Secret Exposure | ✅ |
| ASI08 | Context Window Manipulation | ✅ |
| ASI09 | Agent Loop Exploitation | ✅ |
| ASI10 | Trust Boundary Violation | ✅ |

## CI/CD Integration

### GitHub Actions

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

### Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/dockfixlabs/agentguard
    rev: v0.1.0
    hooks:
      - id: agentguard
        args: ["--min-severity", "HIGH"]
```

## Programmatic Usage

```python
from agentguard.scanner import scan_directory
from agentguard.reporter import json_report

result = scan_directory("src/")

print(f"Found {len(result.findings)} issues")
print(f"Critical: {result.critical_count}")
print(f"High: {result.high_count}")

for finding in result.findings:
    print(f"  [{finding.severity}] {finding.rule_name} at {finding.file}:{finding.line}")
```

## Detection Rules

### ASI01 — Prompt Injection
Detects untrusted user input being concatenated into LLM prompts via f-strings, `.format()`, or string concatenation.

### ASI02 — Tool Abuse
Flags agents with access to `exec()`, `subprocess`, `os.system()`, shell tools, unrestricted tool registration, and missing rate limits.

### ASI03 — Data Exfiltration
Detects outbound HTTP requests to external URLs, webhook configurations, DNS exfiltration patterns, and secret+network correlation.

### ASI06 — Unsafe Eval
Flags `eval()`, `exec()`, `compile()` with user input, `pickle.load()`, `yaml.load()` without SafeLoader, `subprocess(shell=True)`.

### ASI07 — Credential Exposure
Detects hardcoded API keys (sk-, ghp_, AKIA), private keys, connection strings with passwords, and crypto wallet seeds.

### ASI08 — Context Manipulation
Flags missing token limits, unbounded context accumulation, and large files loaded directly into LLM context.

### ASI10 — Trust Boundary Violation
Detects agents running as root, host filesystem access, self-modifying code, and direct database access with user input.

## MCP Server Mode

Scan agent code directly from Claude Code, Cursor, or any MCP-compatible client:

```json
// ~/.claude/claude_code_config.json
{
  "mcpServers": {
    "agentguard": {
      "command": "python3",
      "args": ["-m", "agentguard.mcp_server"]
    }
  }
}
```

Then ask Claude: *"Scan my agent code for security vulnerabilities"*

### MCP Tools
- `scan_agent_code` — Scan a directory/file for vulnerabilities
- `list_rules` — List all detection rules and OWASP mapping
- `get_finding_details` — Get remediation guidance for a specific rule

## Roadmap

- [x] OWASP ASI Top 10 — all 10 categories covered
- [x] MCP server mode — scan from Claude Code/Cursor
- [x] SARIF output — GitHub Code Scanning integration
- [ ] PyPI publication
- [ ] Semantic analysis with LLM-assisted code review
- [ ] Language support: Rust, Go, Java
- [ ] VS Code extension
- [ ] GitHub App for automated PR reviews

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and feature requests welcome.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately — do not open public issues.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Dockfix Labs](https://github.com/dockfixlabs). Built for the AI agent era.
